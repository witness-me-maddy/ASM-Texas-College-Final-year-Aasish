from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_summary_endpoint_uses_epss_framework():
    response = client.get('/api/summary')
    assert response.status_code == 200
    payload = response.json()
    assert payload['risk_framework'] == 'EPSS-first'


def test_seed_report_exists_and_report_details_endpoint_works():
    reports = client.get('/api/reports')
    assert reports.status_code == 200
    rows = reports.json()['reports']
    assert len(rows) >= 1

    report_id = rows[0]['id']
    detail = client.get(f'/api/reports/{report_id}')
    assert detail.status_code == 200
    report = detail.json()['report']
    assert report['scanned_port_range'] == '1-65535'
    assert report['waf_detected'] is not None


def test_scan_collects_comprehensive_target_intelligence():
    response = client.post('/api/scan', json={'website_url': 'https://scanme.example.com'})
    assert response.status_code == 200
    report = response.json()['report']

    assert report['status'] == 'completed'
    assert report['scanned_port_range'] == '1-65535'
    assert len(report['open_ports']) >= 10
    for tool in ['Nmap', 'Masscan', 'Subfinder', 'Assetfinder', 'Nikto', 'Nuclei', 'Amass', 'httpx', 'Naabu', 'Wafw00f']:
        assert tool in report['tools_executed']
    assert len(report['discovered_subdomains']) >= 5
    assert len(report['discovered_urls']) >= 5


def test_register_monitor_target_and_get_automation_status():
    register = client.post('/api/monitor-targets', json={'website_url': 'https://acme.io'})
    assert register.status_code == 200

    targets = client.get('/api/monitor-targets')
    assert targets.status_code == 200
    assert len(targets.json()['targets']) >= 1

    status = client.get('/api/automation')
    assert status.status_code == 200
    assert 'running' in status.json()['automation']
