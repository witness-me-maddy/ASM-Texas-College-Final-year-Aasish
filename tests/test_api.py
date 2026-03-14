from fastapi.testclient import TestClient

from app.main import app

from app.connectors.tool_connectors import ToolIngestionAdapter
from app.services.epss_service import EPSSService
from app.services.repository import InMemoryRepository
from app.services.scanner_service import ASMScannerService

client = TestClient(app)


def _bootstrap_exposures():
    # Ensure repository has API-driven scan data before lifecycle/report assertions.
    client.post('/api/scan', json={'website_url': 'https://bootstrap.example.com'})


def test_summary_endpoint_uses_contextual_risk_framework():
    response = client.get('/api/summary')
    assert response.status_code == 200
    payload = response.json()
    assert payload['risk_framework'] == 'EPSS + contextual risk'


def test_scan_job_submission_and_nodes_endpoints():
    submit = client.post('/api/jobs/scan', json={'website_url': 'https://scanme.example.com', 'priority': 2})
    assert submit.status_code == 200
    assert submit.json()['job']['status'] in ['queued', 'running', 'completed']

    nodes = client.get('/api/scanner-nodes')
    assert nodes.status_code == 200
    assert isinstance(nodes.json()['nodes'], list)


def test_exposure_lifecycle_ticket_and_exception_flow():
    _bootstrap_exposures()
    exposures = client.get('/api/exposures')
    assert exposures.status_code == 200
    rows = exposures.json()['exposures']
    assert len(rows) >= 1
    exposure_id = rows[0]['id']

    assign = client.post(f'/api/exposures/{exposure_id}/assign', json={'assignee': 'secops@aasishasm.local'})
    assert assign.status_code == 200
    assert assign.json()['exposure']['assignee'] == 'secops@aasishasm.local'

    ticket = client.post(f'/api/exposures/{exposure_id}/ticket', json={'provider': 'jira'})
    assert ticket.status_code == 200
    assert ticket.json()['ticket']['external_key'].startswith('JIRA-')

    exc = client.post(
        f'/api/exposures/{exposure_id}/exception-request',
        json={'requested_by': 'risk-owner', 'reason': 'temporary maintenance window', 'expires_at': '2030-01-01T00:00:00Z'},
    )
    assert exc.status_code == 200
    assert exc.json()['exposure']['exception_status'] == 'requested'

    approve = client.post(f'/api/exposures/{exposure_id}/exception-approve', json={'approved_by': 'ciso'})
    assert approve.status_code == 200
    assert approve.json()['exposure']['exception_status'] == 'approved'


def test_sync_scan_contains_integrated_tools_and_intel_fields():
    response = client.post('/api/scan', json={'website_url': 'https://demo.aasishasm.com'})
    assert response.status_code == 200
    report = response.json()['report']

    assert report['scanned_port_range'] == '1-65535'
    for tool in ['Nmap', 'Masscan', 'Subfinder', 'Assetfinder', 'Nikto', 'Nuclei', 'Amass', 'httpx', 'Naabu', 'Wafw00f']:
        assert tool in report['tools_executed']
    assert isinstance(report['discovered_subdomains'], list)
    assert isinstance(report['open_ports'], list)
    assert report['exposures_discovered'] >= 0
    assert 'tool_health_summary' in report
    assert 'tools_failed' in report


def test_job_detail_endpoint_returns_submitted_job():
    submit = client.post('/api/jobs/scan', json={'website_url': 'https://detail.example.com', 'priority': 3})
    assert submit.status_code == 200
    job_id = submit.json()['job']['id']

    detail = client.get(f'/api/jobs/{job_id}')
    assert detail.status_code == 200
    assert detail.json()['job']['id'] == job_id


def test_approving_exception_sets_exposure_to_accepted():
    _bootstrap_exposures()
    exposures = client.get('/api/exposures')
    exposure_id = exposures.json()['exposures'][0]['id']

    approve = client.post(f'/api/exposures/{exposure_id}/exception-approve', json={'approved_by': 'ciso'})
    assert approve.status_code == 200
    payload = approve.json()['exposure']
    assert payload['exception_status'] == 'approved'
    assert payload['status'] == 'accepted'


def test_reporting_portfolio_endpoint_returns_enterprise_metrics():
    response = client.get('/api/reporting/portfolio')
    assert response.status_code == 200

    reporting = response.json()['reporting']
    assert 'kpis' in reporting
    assert 'business_units' in reporting
    assert 'source_tools' in reporting

    kpis = reporting['kpis']
    for key in ['assets', 'total_exposures', 'open_exposures', 'sla_breaches', 'reports_generated']:
        assert key in kpis


def test_assets_by_url_section_reflects_scanned_asset_mapping():
    client.post('/api/scan', json={'website_url': 'https://mapping.example.com'})
    response = client.get('/api/assets/by-url')
    assert response.status_code == 200
    sections = response.json()['sections']
    assert isinstance(sections, list)
    assert any(s['asset_name'] == 'mapping.example.com' for s in sections)


def test_scan_does_not_emit_tool_unavailable_as_findings():
    response = client.post('/api/scan', json={'website_url': 'https://quality.example.com'})
    assert response.status_code == 200
    report = response.json()['report']

    for exposure in report['top_exposures']:
        title = exposure['title']
        assert 'TOOL_UNAVAILABLE:' not in title
        assert 'TOOL_ERROR:' not in title
        assert 'could not run' not in title.lower()


def test_report_tool_runs_endpoint_returns_tool_telemetry():
    response = client.post('/api/scan', json={'website_url': 'https://telemetry.example.com'})
    assert response.status_code == 200
    report_id = response.json()['report']['id']

    telemetry = client.get(f'/api/reports/{report_id}/tool-runs')
    assert telemetry.status_code == 200
    runs = telemetry.json()['tool_runs']
    assert isinstance(runs, list)
    assert len(runs) >= 1
    assert {'tool_name', 'status', 'duration_ms'}.issubset(set(runs[0].keys()))


def test_scanner_environment_endpoint_exposes_missing_tools():
    response = client.get('/api/scanner-environment')
    assert response.status_code == 200
    payload = response.json()['environment']
    assert 'required_tools' in payload
    assert 'missing_tools' in payload
    assert 'health' in payload
    assert isinstance(payload['required_tools'], dict)
    one_tool = next(iter(payload['required_tools'].values()))
    assert {'binary', 'resolved_path', 'available', 'env_var'}.issubset(set(one_tool.keys()))


def test_scanner_extracts_cve_from_actual_tool_output_when_present():
    service = ASMScannerService(InMemoryRepository(), ToolIngestionAdapter(EPSSService()), EPSSService())
    findings = service._normalize_tool_outputs(
        'example.com',
        {
            'Nuclei': '[critical] SQL injection detected CVE-2023-9999 on https://example.com/login',
        },
    )
    assert len(findings) == 1
    assert findings[0].cve == 'CVE-2023-9999'


def test_scanner_ignores_non_vulnerability_discovery_tools_for_exposures():
    service = ASMScannerService(InMemoryRepository(), ToolIngestionAdapter(EPSSService()), EPSSService())
    findings = service._normalize_tool_outputs(
        'example.com',
        {
            'Assetfinder': 'api.example.com\nmail.example.com',
            'Subfinder': 'dev.example.com',
            'Nmap': '80/tcp open http',
        },
    )
    assert len(findings) == 1
    assert findings[0].tool_name == 'Nmap'
    assert findings[0].cve is None


def test_run_tool_uses_internal_fallback_when_binary_missing(monkeypatch):
    service = ASMScannerService(InMemoryRepository(), ToolIngestionAdapter(EPSSService()), EPSSService())

    monkeypatch.setattr('app.services.scanner_service.shutil.which', lambda _binary: None)
    monkeypatch.setattr(service, '_internal_tool_fallback', lambda tool, host: '80/tcp open http' if tool == 'Nmap' else '')

    output, run = service._run_tool_or_fallback('Nmap', ['nmap', '-T4', 'example.com'], 'example.com')
    assert 'TOOL_UNAVAILABLE:' not in output
    assert output == '80/tcp open http'
    assert run.status.value == 'success'
    assert 'fallback' in (run.message or '').lower()


def test_run_tool_reports_unavailable_when_no_binary_and_no_fallback(monkeypatch):
    service = ASMScannerService(InMemoryRepository(), ToolIngestionAdapter(EPSSService()), EPSSService())

    monkeypatch.setattr('app.services.scanner_service.shutil.which', lambda _binary: None)
    monkeypatch.setattr(service, '_internal_tool_fallback', lambda tool, host: '')

    output, run = service._run_tool_or_fallback('Nmap', ['nmap', '-T4', 'example.com'], 'example.com')
    assert output.startswith('TOOL_UNAVAILABLE:')
    assert run.status.value == 'unavailable'
