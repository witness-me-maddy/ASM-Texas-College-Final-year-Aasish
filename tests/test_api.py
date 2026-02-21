from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_summary_endpoint_uses_epss_framework():
    response = client.get('/api/summary')
    assert response.status_code == 200
    payload = response.json()
    assert payload['risk_framework'] == 'EPSS-first'


def test_scan_creates_report_with_position_and_ports():
    response = client.post('/api/scan', json={'website_url': 'https://scanme.example.com'})
    assert response.status_code == 200
    payload = response.json()
    assert payload['report']['status'] == 'completed'
    assert payload['report']['target_position']['city']
    assert len(payload['report']['open_ports']) >= 1


def test_register_monitor_target_and_get_automation_status():
    register = client.post(
        '/api/monitor-targets',
        json={'website_url': 'https://acme.io', 'scan_interval_seconds': 60},
    )
    assert register.status_code == 200

    targets = client.get('/api/monitor-targets')
    assert targets.status_code == 200
    assert len(targets.json()['targets']) >= 1

    status = client.get('/api/automation')
    assert status.status_code == 200
    assert 'running' in status.json()['automation']
