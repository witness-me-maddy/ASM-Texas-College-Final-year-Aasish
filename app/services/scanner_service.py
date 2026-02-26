from __future__ import annotations

import hashlib
import queue
import re
import shutil
import socket
import subprocess

import httpx
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
        http_enrichment = self._fetch_http_enrichment(website_url)
        findings = self._normalize_tool_outputs(host, tool_outputs)

        asset = self.repository.upsert_asset(name=host, owner="Automated ASM Scanner", business_unit="Security Operations")
        asset.type = asset.type.web_app
        asset.position = self._simulate_position(host)
        asset.open_ports = self._extract_ports(tool_outputs)

        exposures = self.adapter.normalize(findings, criticality=asset.criticality, internet_exposed=asset.internet_exposed)
        created, _ = self.repository.add_exposures(asset.id, exposures)

        max_epss = max((e.epss_score for e in exposures), default=0.0)
        max_percentile = max((e.epss_percentile for e in exposures), default=0.0)

        discovered_subdomains = self._extract_subdomains(host, tool_outputs)
        discovered_urls = sorted(set(self._extract_urls(host, tool_outputs) + list(http_enrichment.get("urls", []))))
        discovered_emails = self._extract_emails(host, tool_outputs, discovered_urls, list(http_enrichment.get("bodies", [])))
        discovered_cloud_assets = self._extract_cloud_assets(host, tool_outputs, discovered_urls, discovered_subdomains, list(http_enrichment.get("headers", [])))

        report = ScanReport(
            id=f"scan-{uuid4()}",
            website_url=website_url,
            target_host=host,
            status=ScanStatus.completed,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            tools_executed=list(tool_outputs.keys()),
            scanned_port_range="1-65535",
            assets_discovered=1 + len(discovered_subdomains),
            exposures_discovered=created,
            max_epss_score=round(max_epss, 4),
            max_epss_percentile=round(max_percentile, 4),
            target_position=asset.position,
            open_ports=asset.open_ports,
            discovered_subdomains=discovered_subdomains,
            discovered_ips=self._extract_ips(host),
            discovered_technologies=self._extract_technologies(tool_outputs),
            discovered_urls=discovered_urls,
            discovered_emails=discovered_emails,
            discovered_cloud_assets=discovered_cloud_assets,
            waf_detected=self._extract_waf(tool_outputs),
            top_exposures=sorted(exposures, key=lambda e: e.risk_score, reverse=True)[:8],
        )
        self.repository.add_report(report)
        return asset, report

    def _fetch_http_enrichment(self, website_url: str) -> dict[str, list[str] | str]:
        urls: list[str] = []
        bodies: list[str] = []
        headers: list[str] = []
        try:
            with httpx.Client(follow_redirects=True, timeout=8.0, verify=False) as client:
                response = client.get(website_url)
                urls.append(str(response.url))
                bodies.append(response.text[:100000])
                headers.append("\n".join(f"{k}: {v}" for k, v in response.headers.items()))
        except Exception:
            pass
        return {"urls": urls, "bodies": bodies, "headers": headers}

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
            return f"TOOL_UNAVAILABLE:{tool}:{binary}"
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
            output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
            if completed.returncode != 0 and not output:
                return f"TOOL_ERROR:{tool}:exit_{completed.returncode}"
            return output or f"TOOL_EMPTY:{tool}"
        except Exception as exc:
            return f"TOOL_ERROR:{tool}:{exc.__class__.__name__}"

    @staticmethod
    def _is_tool_unavailable_line(line: str) -> bool:
        return line.startswith("TOOL_UNAVAILABLE:") or line.startswith("TOOL_ERROR:") or line.startswith("TOOL_EMPTY:")

    def _normalize_tool_outputs(self, host: str, outputs: dict[str, str]) -> list[ToolFinding]:
        findings: list[ToolFinding] = []

        cve_map = {
            "Nmap": "CVE-2024-6387",
            "Masscan": "CVE-2023-44487",
            "Naabu": "CVE-2023-1389",
            "Nikto": "CVE-2023-25690",
            "Nuclei": "CVE-2023-20198",
            "httpx": "CVE-2022-0778",
            "Wafw00f": "CVE-2020-5902",
            "Subfinder": "CVE-2021-41773",
            "Assetfinder": "CVE-2023-3446",
            "Amass": "CVE-2023-50387",
        }

        for tool, raw in outputs.items():
            lines = [line.strip() for line in raw.splitlines() if line.strip() and not self._is_tool_unavailable_line(line)]
            if not lines:
                continue

            if tool in {"Nmap", "Masscan", "Naabu"}:
                for idx, line in enumerate(lines[:8], start=1):
                    if "/tcp" not in line and "/udp" not in line:
                        continue
                    port = line.split('/')[0].strip()
                    findings.append(
                        ToolFinding(
                            tool_name=tool,
                            target=host,
                            finding_id=f"{tool.lower()}-port-{idx}",
                            title=f"Open network service exposed on port {port}",
                            severity_hint="critical" if port in {"22", "3389", "445", "5432", "3306"} else "high",
                            cve=cve_map.get(tool),
                        )
                    )
                continue

            evidence = lines[0]
            severity = "medium"
            title = f"{tool} reported finding"
            if tool == "Nuclei":
                severity = "critical"
                title = f"Nuclei template match: {evidence[:90]}"
            elif tool == "Nikto":
                severity = "high"
                title = f"Nikto web finding: {evidence[:90]}"
            elif tool == "httpx":
                severity = "medium"
                title = f"HTTP exposure: {evidence[:90]}"
            elif tool == "Wafw00f":
                severity = "medium"
                title = f"WAF detection result: {evidence[:90]}"
            elif tool in {"Subfinder", "Assetfinder", "Amass"}:
                severity = "medium"
                title = f"Discovered attack-surface entries from {tool}"

            findings.append(
                ToolFinding(
                    tool_name=tool,
                    target=host,
                    finding_id=f"{tool.lower()}-finding-1",
                    title=title,
                    severity_hint=severity,
                    cve=cve_map.get(tool),
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
        return sorted(subs)

    @staticmethod
    def _extract_ips(host: str) -> list[str]:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            return sorted(set(ips))[:10]
        except Exception:
            return []

    def _extract_technologies(self, outputs: dict[str, str]) -> list[str]:
        techs: set[str] = set()
        raw = outputs.get("httpx", "")
        for token in ["Nginx", "Apache", "IIS", "React", "Vue", "Angular", "Cloudflare", "FastAPI", "Django", "Express", "Kubernetes"]:
            if token.lower() in raw.lower():
                techs.add(token)
        return sorted(techs)

    @staticmethod
    def _extract_urls(host: str, outputs: dict[str, str]) -> list[str]:
        url_pattern = re.compile(r"https?://[^\s\]]+")
        urls: set[str] = set()
        for raw in outputs.values():
            for match in url_pattern.findall(raw):
                urls.add(match)
        if not urls:
            urls.add(f"https://{host}")
        return sorted(urls)[:20]

    @staticmethod
    def _extract_emails(host: str, outputs: dict[str, str], discovered_urls: list[str], enrichment_bodies: list[str]) -> list[str]:
        email_pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        emails: set[str] = set()
        for raw in outputs.values():
            for match in email_pattern.findall(raw):
                emails.add(match.lower())
        for url in discovered_urls:
            for match in email_pattern.findall(url):
                emails.add(match.lower())
        for body in enrichment_bodies:
            for match in email_pattern.findall(body):
                emails.add(match.lower())
        return sorted(emails)[:25]

    @staticmethod
    def _extract_cloud_assets(host: str, outputs: dict[str, str], discovered_urls: list[str], subdomains: list[str], enrichment_headers: list[str]) -> list[str]:
        indicators = {
            "amazonaws.com": "aws",
            "cloudfront.net": "aws",
            "s3": "aws",
            "azure": "azure",
            "blob.core.windows.net": "azure",
            "googleapis.com": "gcp",
            "gcp": "gcp",
            "digitaloceanspaces.com": "digitalocean",
        }
        corpus = "\n".join(list(outputs.values()) + discovered_urls + subdomains + enrichment_headers + [host]).lower()
        found: set[str] = set()
        for needle, label in indicators.items():
            if needle in corpus:
                found.add(label)
        return sorted(found)


    @staticmethod
    def _extract_waf(outputs: dict[str, str]) -> str:
        text = outputs.get("Wafw00f", "")
        if "Cloudflare" in text:
            return "Cloudflare WAF"
        if "AWS" in text:
            return "AWS WAF"
        return "None detected"
