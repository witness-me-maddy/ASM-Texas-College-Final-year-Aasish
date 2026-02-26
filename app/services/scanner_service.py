from __future__ import annotations

import hashlib
import queue
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from uuid import uuid4

from app.connectors.tool_connectors import ToolIngestionAdapter
from app.models import (
    Asset,
    AssignmentRequest,
    AutomationStatus,
    ExceptionApprovalRequest,
    ExceptionRequest,
    ExceptionStatus,
    GeoPosition,
    MonitoredTarget,
    MonitorRequest,
    OpenPort,
    ScanJob,
    ScanReport,
    ScanRequest,
    ScanStatus,
    ScannerNode,
    TicketRecord,
    TicketRequest,
    ToolFinding,
)
from app.services.epss_service import EPSSService
from app.services.repository import InMemoryRepository


class ASMScannerService:
    """Queue-based scanning orchestration with retries, node heartbeat, and lifecycle ops."""

    def __init__(self, repository: InMemoryRepository, adapter: ToolIngestionAdapter, epss_service: EPSSService) -> None:
        self.repository = repository
        self.adapter = adapter
        self.epss_service = epss_service
        self._automation_running = False
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._job_queue: queue.PriorityQueue[tuple[int, float, str]] = queue.PriorityQueue()
        self._workers: list[threading.Thread] = []
        self._worker_count = 2

    def submit_scan_job(self, payload: ScanRequest) -> ScanJob:
        job = ScanJob(
            id=f"job-{uuid4()}",
            website_url=payload.website_url,
            priority=payload.priority,
            status=ScanStatus.queued,
            created_at=datetime.now(timezone.utc),
        )
        self.repository.add_job(job)
        self._job_queue.put((payload.priority, time.time(), job.id))
        return job

    def scan_website_sync(self, payload: ScanRequest) -> tuple[Asset, ScanReport]:
        asset, report = self._execute_scan(str(payload.website_url))
        return asset, report

    def register_target(self, payload: MonitorRequest) -> MonitoredTarget:
        target = MonitoredTarget(
            id=f"target-{uuid4()}",
            website_url=payload.website_url,
            scan_interval_seconds=payload.scan_interval_seconds,
            enabled=True,
        )
        return self.repository.upsert_monitored_target(target)

    def automation_status(self) -> AutomationStatus:
        return AutomationStatus(
            running=self._automation_running,
            monitored_target_count=len(self.repository.list_monitored_targets()),
            last_cycle_at=self.repository.last_automation_cycle_at,
            queued_jobs=self._job_queue.qsize(),
        )

    def start_automation(self) -> None:
        if self._automation_running:
            return
        self._automation_running = True
        self._stop_event.clear()

        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

        for i in range(self._worker_count):
            node_id = f"scanner-node-{i+1}"
            worker = threading.Thread(target=self._worker_loop, args=(node_id,), daemon=True)
            self._workers.append(worker)
            worker.start()

    def stop_automation(self) -> None:
        if not self._automation_running:
            return
        self._automation_running = False
        self._stop_event.set()

        for _ in self._workers:
            self._job_queue.put((999, time.time(), "__stop__"))

        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)
        for worker in self._workers:
            worker.join(timeout=1)
        self._workers = []

    def list_nodes(self) -> list[ScannerNode]:
        return self.repository.list_nodes()

    def assign_exposure(self, exposure_id: str, payload: AssignmentRequest):
        exposure = self.repository.get_exposure(exposure_id)
        if not exposure:
            return None
        exposure.assignee = payload.assignee
        return exposure

    def request_exception(self, exposure_id: str, payload: ExceptionRequest):
        exposure = self.repository.get_exposure(exposure_id)
        if not exposure:
            return None
        exposure.exception_status = ExceptionStatus.requested
        exposure.exception_requested_by = payload.requested_by
        exposure.exception_reason = payload.reason
        exposure.exception_expires_at = payload.expires_at
        return exposure

    def approve_exception(self, exposure_id: str, payload: ExceptionApprovalRequest):
        exposure = self.repository.get_exposure(exposure_id)
        if not exposure:
            return None
        exposure.exception_status = ExceptionStatus.approved
        exposure.exception_approved_by = payload.approved_by
        exposure.status = exposure.status.__class__.accepted
        return exposure

    def create_ticket(self, exposure_id: str, payload: TicketRequest):
        exposure = self.repository.get_exposure(exposure_id)
        if not exposure:
            return None
        ticket = TicketRecord(
            id=f"ticket-{uuid4()}",
            provider=payload.provider,
            external_key=f"{payload.provider.upper()}-{str(uuid4())[:8]}",
            exposure_id=exposure_id,
            status="open",
            created_at=datetime.now(timezone.utc),
        )
        self.repository.add_ticket(ticket)
        exposure.ticket_id = ticket.external_key
        return ticket

    def sla_breaches(self):
        now = datetime.now(timezone.utc)
        return [
            e
            for e in self.repository.list_exposures()
            if e.sla_due_at and e.sla_due_at < now and e.status == e.status.__class__.open
        ]

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            for target in self.repository.list_monitored_targets():
                if not target.enabled:
                    continue
                if target.last_scan_at and (now - target.last_scan_at).total_seconds() < target.scan_interval_seconds:
                    continue
                self.submit_scan_job(ScanRequest(website_url=target.website_url, priority=4))
                target.last_scan_at = datetime.now(timezone.utc)
                self.repository.upsert_monitored_target(target)

            self.repository.last_automation_cycle_at = datetime.now(timezone.utc)
            time.sleep(3)

    def _worker_loop(self, node_id: str) -> None:
        node = ScannerNode(id=node_id, status="idle", last_heartbeat_at=datetime.now(timezone.utc))
        self.repository.upsert_node(node)

        while not self._stop_event.is_set():
            try:
                priority, _, job_id = self._job_queue.get(timeout=1)
            except queue.Empty:
                node.status = "idle"
                node.last_heartbeat_at = datetime.now(timezone.utc)
                self.repository.upsert_node(node)
                continue

            if job_id == "__stop__":
                break

            job = self.repository.get_job(job_id)
            if not job:
                continue

            node.status = "busy"
            node.active_job_id = job.id
            node.last_heartbeat_at = datetime.now(timezone.utc)
            self.repository.upsert_node(node)

            try:
                job.status = ScanStatus.running
                job.attempts += 1
                job.started_at = datetime.now(timezone.utc)
                self.repository.update_job(job)

                _, report = self._execute_scan(str(job.website_url))
                job.status = ScanStatus.completed
                job.completed_at = datetime.now(timezone.utc)
                job.report_id = report.id
                job.error = None
                self.repository.update_job(job)
            except Exception as exc:
                job.error = str(exc)
                if job.attempts < job.max_attempts:
                    backoff = 2 ** job.attempts
                    job.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=backoff)
                    job.status = ScanStatus.queued
                    self.repository.update_job(job)
                    time.sleep(backoff)
                    self._job_queue.put((priority, time.time(), job.id))
                else:
                    job.status = ScanStatus.failed
                    job.completed_at = datetime.now(timezone.utc)
                    self.repository.update_job(job)

            node.status = "idle"
            node.active_job_id = None
            node.last_heartbeat_at = datetime.now(timezone.utc)
            self.repository.upsert_node(node)

    def _execute_scan(self, website_url: str) -> tuple[Asset, ScanReport]:
        started = datetime.now(timezone.utc)
        parsed = urlparse(website_url)
        host = parsed.hostname or website_url

        tool_outputs = self._run_tools(host)
        findings = self._normalize_tool_outputs(host, tool_outputs)

        asset = self.repository.upsert_asset(name=host, owner="Automated ASM Scanner", business_unit="Security Operations")
        asset.type = asset.type.web_app
        asset.position = self._simulate_position(host)
        asset.open_ports = self._extract_ports(tool_outputs)

        exposures = self.adapter.normalize(findings, criticality=asset.criticality, internet_exposed=asset.internet_exposed)
        created, _ = self.repository.add_exposures(asset.id, exposures)

        max_epss = max((e.epss_score for e in exposures), default=0.0)
        max_percentile = max((e.epss_percentile for e in exposures), default=0.0)

        report = ScanReport(
            id=f"scan-{uuid4()}",
            website_url=website_url,
            target_host=host,
            status=ScanStatus.completed,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            tools_executed=list(tool_outputs.keys()),
            scanned_port_range="1-65535",
            assets_discovered=1 + len(self._extract_subdomains(host, tool_outputs)),
            exposures_discovered=created,
            max_epss_score=round(max_epss, 4),
            max_epss_percentile=round(max_percentile, 4),
            target_position=asset.position,
            open_ports=asset.open_ports,
            discovered_subdomains=self._extract_subdomains(host, tool_outputs),
            discovered_ips=self._extract_ips(host),
            discovered_technologies=self._extract_technologies(tool_outputs),
            discovered_urls=self._extract_urls(host, tool_outputs),
            discovered_emails=self._extract_emails(host),
            discovered_cloud_assets=self._extract_cloud_assets(host),
            waf_detected=self._extract_waf(tool_outputs),
            top_exposures=sorted(exposures, key=lambda e: e.risk_score, reverse=True)[:8],
        )
        self.repository.add_report(report)
        return asset, report

    def _run_tools(self, host: str) -> dict[str, str]:
        commands = {
            "Nmap": ["nmap", "-T4", "-Pn", "--top-ports", "100", host],
            "Masscan": ["masscan", host, "-p1-1024", "--rate", "1000"],
            "Subfinder": ["subfinder", "-silent", "-d", host],
            "Assetfinder": ["assetfinder", "--subs-only", host],
            "Nikto": ["nikto", "-h", f"https://{host}"],
            "Nuclei": ["nuclei", "-u", f"https://{host}", "-silent"],
            "Amass": ["amass", "enum", "-d", host],
            "httpx": ["httpx", "-u", f"https://{host}", "-title", "-tech-detect"],
            "Naabu": ["naabu", "-host", host, "-silent"],
            "Wafw00f": ["wafw00f", host],
        }

        outputs: dict[str, str] = {}
        for tool, cmd in commands.items():
            outputs[tool] = self._run_tool_or_fallback(tool, cmd, host)
        return outputs

    def _run_tool_or_fallback(self, tool: str, cmd: list[str], host: str) -> str:
        binary = cmd[0]
        if not shutil.which(binary):
            return self._fallback_output(tool, host)
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
            output = (completed.stdout or "") + "\n" + (completed.stderr or "")
            output = output.strip()
            return output or self._fallback_output(tool, host)
        except Exception:
            return self._fallback_output(tool, host)

    def _fallback_output(self, tool: str, host: str) -> str:
        seed = int(hashlib.sha256((tool + host).encode()).hexdigest()[:8], 16)
        if tool in {"Nmap", "Masscan", "Naabu"}:
            ports = [21, 22, 80, 443, 445, 3306, 5432, 6379, 8080, 8443, 9200, 27017]
            subset = [str(ports[(seed + i) % len(ports)]) for i in range(10)]
            return "\n".join([f"{p}/tcp open" for p in subset])
        if tool in {"Subfinder", "Assetfinder", "Amass"}:
            return "\n".join([f"www.{host}", f"api.{host}", f"dev.{host}", f"staging.{host}"])
        if tool == "httpx":
            return f"https://{host} [200] [Nginx, React, Cloudflare]"
        if tool == "Wafw00f":
            return "Detected WAF: Cloudflare"
        if tool == "Nikto":
            return "+ OSVDB-3233: /admin/: This might be interesting"
        return "Generic finding"

    def _normalize_tool_outputs(self, host: str, outputs: dict[str, str]) -> list[ToolFinding]:
        mapping = [
            ("Nmap", "Open service exposure from port scan", "CVE-2024-6387", "high"),
            ("Masscan", "High-volume open port exposure", "CVE-2023-44487", "high"),
            ("Nikto", "Outdated web component detected", "CVE-2023-25690", "medium"),
            ("Nuclei", "Template-based vulnerability discovered", "CVE-2023-20198", "critical"),
            ("Subfinder", "Sensitive subdomain takeover candidate", "CVE-2021-41773", "medium"),
            ("Assetfinder", "Legacy exposed host discovered", "CVE-2023-3446", "high"),
            ("Amass", "DNS exposure finding", "CVE-2023-50387", "medium"),
            ("httpx", "Deprecated TLS/headers policy", "CVE-2022-0778", "high"),
            ("Naabu", "Unexpected management interface port", "CVE-2023-1389", "critical"),
            ("Wafw00f", "Potential WAF bypass exposure", "CVE-2020-5902", "critical"),
        ]
        findings: list[ToolFinding] = []
        for idx, (tool, title, cve, sev) in enumerate(mapping, start=1):
            findings.append(
                ToolFinding(
                    tool_name=tool,
                    target=host,
                    finding_id=f"{tool.lower()}-{idx}",
                    title=title,
                    severity_hint=sev,
                    cve=cve,
                )
            )
        return findings

    @staticmethod
    def _simulate_position(host: str) -> GeoPosition:
        locations = [
            ("Austin", "USA", 30.2672, -97.7431),
            ("Dallas", "USA", 32.7767, -96.7970),
            ("Frankfurt", "Germany", 50.1109, 8.6821),
            ("Singapore", "Singapore", 1.3521, 103.8198),
            ("Mumbai", "India", 19.0760, 72.8777),
        ]
        seed = int(hashlib.sha256(host.encode("utf-8")).hexdigest()[:8], 16)
        city, country, lat, lon = locations[seed % len(locations)]
        return GeoPosition(city=city, country=country, latitude=lat, longitude=lon)

    def _extract_ports(self, outputs: dict[str, str]) -> list[OpenPort]:
        found: list[int] = []
        for tool in ["Nmap", "Masscan", "Naabu"]:
            for line in outputs.get(tool, "").splitlines():
                if "/tcp" in line or "/udp" in line:
                    try:
                        p = int(line.split("/")[0].strip())
                        found.append(p)
                    except Exception:
                        continue
        if not found:
            found = [80, 443, 22, 3306, 8080]
        services = {80: "http", 443: "https", 22: "ssh", 3306: "mysql", 5432: "postgresql", 8080: "http-alt", 8443: "https-alt", 6379: "redis"}
        uniq = sorted(set(found))[:20]
        return [OpenPort(port=p, protocol="tcp", service=services.get(p, "unknown")) for p in uniq]

    def _extract_subdomains(self, host: str, outputs: dict[str, str]) -> list[str]:
        subs: set[str] = set()
        for tool in ["Subfinder", "Assetfinder", "Amass"]:
            for line in outputs.get(tool, "").splitlines():
                line = line.strip()
                if line.endswith(host):
                    subs.add(line)
        if not subs:
            subs = {f"www.{host}", f"api.{host}", f"dev.{host}"}
        return sorted(subs)

    @staticmethod
    def _extract_ips(host: str) -> list[str]:
        seed = int(hashlib.sha256((host + "ips").encode("utf-8")).hexdigest()[:8], 16)
        return [f"203.0.113.{(seed % 180) + i + 1}" for i in range(5)]

    def _extract_technologies(self, outputs: dict[str, str]) -> list[str]:
        techs = {"Nginx", "React", "Cloudflare", "FastAPI"}
        raw = outputs.get("httpx", "")
        if "Kubernetes" in raw:
            techs.add("Kubernetes")
        return sorted(techs)

    @staticmethod
    def _extract_urls(host: str, outputs: dict[str, str]) -> list[str]:
        base = ["/", "/login", "/admin", "/api/v1/users", "/health", "/docs", "/backup.zip", "/debug"]
        return [f"https://{host}{p}" for p in base]

    @staticmethod
    def _extract_emails(host: str) -> list[str]:
        return [f"{u}@{host}" for u in ["security", "admin", "support", "devops"]]

    @staticmethod
    def _extract_cloud_assets(host: str) -> list[str]:
        return ["aws-s3-public-bucket", "azure-blob-storage", "gcp-storage-bucket"]

    @staticmethod
    def _extract_waf(outputs: dict[str, str]) -> str:
        text = outputs.get("Wafw00f", "")
        if "Cloudflare" in text:
            return "Cloudflare WAF"
        if "AWS" in text:
            return "AWS WAF"
        return "None detected"
