from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_summary_endpoint_uses_epss_framework():
    response = client.get('/api/summary')
    assert response.status_code == 200
    payload = response.json()
    assert payload['risk_framework'] == 'EPSS-first'


def test_scan_collects_full_surface_details():
    response = client.post('/api/scan', json={'website_url': 'https://scanme.example.com'})
    assert response.status_code == 200
    payload = response.json()
    report = payload['report']
    assert report['status'] == 'completed'
    assert report['scanned_port_range'] == '1-65535'
    assert len(report['open_ports']) >= 8
    assert 'Nmap' in report['tools_executed']
    assert 'Masscan' in report['tools_executed']
    assert 'Subfinder' in report['tools_executed']
    assert 'Assetfinder' in report['tools_executed']
    assert 'Nikto' in report['tools_executed']


def test_register_monitor_target_and_get_automation_status():
    register = client.post('/api/monitor-targets', json={'website_url': 'https://acme.io'})
    assert register.status_code == 200

    targets = client.get('/api/monitor-targets')
    assert targets.status_code == 200
    assert len(targets.json()['targets']) >= 1

    status = client.get('/api/automation')
    assert status.status_code == 200
    assert 'running' in status.json()['automation']
