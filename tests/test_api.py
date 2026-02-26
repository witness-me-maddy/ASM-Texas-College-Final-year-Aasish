from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


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
    assert len(report['discovered_subdomains']) >= 1
    assert len(report['open_ports']) >= 1


def test_job_detail_endpoint_returns_submitted_job():
    submit = client.post('/api/jobs/scan', json={'website_url': 'https://detail.example.com', 'priority': 3})
    assert submit.status_code == 200
    job_id = submit.json()['job']['id']

    detail = client.get(f'/api/jobs/{job_id}')
    assert detail.status_code == 200
    assert detail.json()['job']['id'] == job_id


def test_approving_exception_sets_exposure_to_accepted():
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
