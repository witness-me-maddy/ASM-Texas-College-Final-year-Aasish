from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_summary_endpoint_uses_epss_framework():
    response = client.get('/api/summary')
    assert response.status_code == 200
    payload = response.json()
    assert payload['risk_framework'] == 'EPSS-first'
    assert payload['summary']['asset_count'] >= 2


def test_scan_creates_report_and_lists_it():
    response = client.post('/api/scan', json={'website_url': 'https://scanme.example.com'})
    assert response.status_code == 200
    payload = response.json()
    assert payload['report']['status'] == 'completed'
    assert payload['report']['exposures_discovered'] >= 1
    assert payload['report']['max_epss_score'] >= 0.0

    reports = client.get('/api/reports')
    assert reports.status_code == 200
    report_rows = reports.json()['reports']
    assert len(report_rows) >= 1
    assert report_rows[0]['website_url'] == 'https://scanme.example.com/'
