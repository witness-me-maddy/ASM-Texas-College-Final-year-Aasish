from __future__ import annotations

import hashlib
import os
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
    ToolRun,
    ToolRunStatus,
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


    @staticmethod
    def required_tool_binaries() -> dict[str, str]:
        return {
            "Nmap": "nmap",
            "Masscan": "masscan",
            "Subfinder": "subfinder",
            "Assetfinder": "assetfinder",
            "Nikto": "nikto",
            "Nuclei": "nuclei",
            "Amass": "amass",
            "httpx": "httpx",
            "Naabu": "naabu",
            "Wafw00f": "wafw00f",
        }

    @staticmethod
    def _tool_env_key(tool_name: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9]", "_", tool_name).upper()
        return f"ASM_TOOL_{normalized}_BIN"

    @staticmethod
    def _resolve_binary(binary: str) -> str | None:
        if os.path.isabs(binary):
            if os.path.exists(binary) and os.access(binary, os.X_OK):
                return binary
            return None
        return shutil.which(binary)

    def _resolve_tool_binary(self, tool_name: str, default_binary: str) -> tuple[str, str | None, str]:
        env_key = self._tool_env_key(tool_name)
        configured = os.getenv(env_key)
        candidate = configured.strip() if configured else default_binary
        resolved = self._resolve_binary(candidate)
        return candidate, resolved, env_key

    def scanner_environment_status(self) -> dict:
        tools = self.required_tool_binaries()
        availability: dict[str, dict] = {}
        for tool, default_binary in tools.items():
            candidate, resolved, env_key = self._resolve_tool_binary(tool, default_binary)
            availability[tool] = {
                "binary": candidate,
                "resolved_path": resolved,
                "available": bool(resolved),
                "env_var": env_key,
            }

        missing = [tool for tool, info in availability.items() if not info["available"]]
        return {
            "required_tools": availability,
            "missing_tools": missing,
            "all_tools_available": len(missing) == 0,
            "health": "healthy" if len(missing) == 0 else "degraded",
            "install_hint": "Install missing scanner binaries (nmap, masscan, subfinder, assetfinder, nikto, nuclei, amass, httpx, naabu, wafw00f) or set ASM_TOOL_<TOOL>_BIN env vars.",
        }

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

        tool_outputs, tool_runs = self._run_tools(host)
        http_enrichment = self._fetch_http_enrichment(website_url)
        findings = self._normalize_tool_outputs(host, tool_outputs)
        if not findings and http_enrichment.get("urls"):
            findings.append(
                ToolFinding(
                    tool_name="http-enrichment",
                    target=host,
                    finding_id="http-enrichment-1",
                    title="Internet-facing web endpoint discovered via live HTTP enrichment",
                    severity_hint="medium",
                    cve=None,
                )
            )

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
            tools_executed=[run.tool_name for run in tool_runs if run.status == ToolRunStatus.success],
            tools_failed=[run.tool_name for run in tool_runs if run.status != ToolRunStatus.success],
            tool_health_summary=self._build_tool_health_summary(tool_runs),
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
        for run in tool_runs:
            run.report_id = report.id
        self.repository.add_report(report)
        self.repository.set_tool_runs(report.id, tool_runs)
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

    def _run_tools(self, host: str) -> tuple[dict[str, str], list[ToolRun]]:
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
        runs: list[ToolRun] = []
        for tool, cmd in commands.items():
            candidate, resolved, _ = self._resolve_tool_binary(tool, cmd[0])
            effective_cmd = [resolved or candidate] + cmd[1:]
            output, run = self._run_tool_or_fallback(tool, effective_cmd, host)
            outputs[tool] = output
            runs.append(run)
        return outputs, runs

    @staticmethod
    def _build_tool_health_summary(tool_runs: list[ToolRun]) -> dict[str, int]:
        summary = {"success": 0, "unavailable": 0, "error": 0, "empty": 0}
        for run in tool_runs:
            summary[run.status.value] = summary.get(run.status.value, 0) + 1
        return summary

    def _run_tool_or_fallback(self, tool: str, cmd: list[str], host: str) -> tuple[str, ToolRun]:
        command_str = " ".join(cmd)
        started = time.time()
        binary = cmd[0]
        if not shutil.which(binary):
            run = ToolRun(
                report_id="pending",
                tool_name=tool,
                command=command_str,
                status=ToolRunStatus.unavailable,
                duration_ms=int((time.time() - started) * 1000),
                return_code=None,
                message=f"binary {binary} not found in runtime environment",
                recorded_at=datetime.now(timezone.utc),
            )
            return f"TOOL_UNAVAILABLE:{tool}:{binary}", run
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
            output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
            status = ToolRunStatus.success
            message = None
            if completed.returncode != 0:
                status = ToolRunStatus.error
                message = f"exit code {completed.returncode}"
            elif not output:
                status = ToolRunStatus.empty
                message = "command returned no output"

            run = ToolRun(
                report_id="pending",
                tool_name=tool,
                command=command_str,
                status=status,
                duration_ms=int((time.time() - started) * 1000),
                return_code=completed.returncode,
                message=message,
                recorded_at=datetime.now(timezone.utc),
            )
            if status == ToolRunStatus.error and not output:
                return f"TOOL_ERROR:{tool}:exit_{completed.returncode}", run
            if status == ToolRunStatus.empty:
                return f"TOOL_EMPTY:{tool}", run
            return output, run
        except Exception as exc:
            run = ToolRun(
                report_id="pending",
                tool_name=tool,
                command=command_str,
                status=ToolRunStatus.error,
                duration_ms=int((time.time() - started) * 1000),
                return_code=None,
                message=exc.__class__.__name__,
                recorded_at=datetime.now(timezone.utc),
            )
            return f"TOOL_ERROR:{tool}:{exc.__class__.__name__}", run

    @staticmethod
    def _is_tool_unavailable_line(line: str) -> bool:
        return line.startswith("TOOL_UNAVAILABLE:") or line.startswith("TOOL_ERROR:") or line.startswith("TOOL_EMPTY:")

    @staticmethod
    def _is_tool_failure_evidence(line: str) -> bool:
        normalized = line.lower()
        failure_markers = [
            "could not run",
            "command not found",
            "no module named",
            "traceback",
            "dependency",
            "not installed",
            "error while loading",
        ]
        return any(marker in normalized for marker in failure_markers)

    def _normalize_tool_outputs(self, host: str, outputs: dict[str, str]) -> list[ToolFinding]:
        findings: list[ToolFinding] = []

        # Only promote security-relevant scanner evidence to exposures.
        vuln_tools = {"Nmap", "Masscan", "Naabu", "Nikto", "Nuclei", "Wafw00f", "httpx"}

        for tool, raw in outputs.items():
            if tool not in vuln_tools:
                continue

            lines = [
                line.strip()
                for line in raw.splitlines()
                if line.strip() and not self._is_tool_unavailable_line(line) and not self._is_tool_failure_evidence(line)
            ]
            if not lines:
                continue

            for idx, line in enumerate(lines[:20], start=1):
                finding = self._line_to_finding(host, tool, line, idx)
                if finding is not None:
                    findings.append(finding)

        return findings

    def _line_to_finding(self, host: str, tool: str, line: str, idx: int) -> ToolFinding | None:
        if tool in {"Nmap", "Masscan", "Naabu"}:
            if "/tcp" not in line and "/udp" not in line:
                return None
            port = line.split('/')[0].strip()
            title = f"Open network service exposed on port {port}: {line[:90]}"
            severity = "critical" if port in {"22", "3389", "445", "5432", "3306"} else "high"
        else:
            title = line[:120]
            severity = self._severity_from_evidence(tool, line)

        return ToolFinding(
            tool_name=tool,
            target=host,
            finding_id=f"{tool.lower()}-finding-{idx}",
            title=title,
            severity_hint=severity,
            cve=self._extract_first_cve(line),
        )

    @staticmethod
    def _severity_from_evidence(tool: str, line: str) -> str:
        lowered = line.lower()
        if tool == "Nuclei":
            if "critical" in lowered:
                return "critical"
            if "high" in lowered:
                return "high"
            if "medium" in lowered:
                return "medium"
            if "low" in lowered:
                return "low"
            return "high"
        if tool == "Nikto":
            return "high"
        if tool == "Wafw00f":
            return "medium"
        if tool == "httpx":
            if "cve-" in lowered or "vulnerab" in lowered:
                return "medium"
            return "low"
        return "medium"

    @staticmethod
    def _extract_first_cve(text: str) -> str | None:
        match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)
        if not match:
            return None
        return match.group(0).upper()

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
