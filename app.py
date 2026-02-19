from flask import Flask, jsonify, render_template_string
from asm_system import AttackSurfaceManagementSystem, seed_demo_environment
import os

app = Flask(__name__)

# Initialize the ASM system
asm = seed_demo_environment()

@app.route('/')
def index():
    # Serve the frontend
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Enterprise Attack Surface Management Dashboard</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Enterprise Attack Surface Management</h1>
                <div class="header-stats">
                    <div class="stat-card">
                        <h3>Total Assets</h3>
                        <span id="total-assets">0</span>
                    </div>
                    <div class="stat-card">
                        <h3>Environment Risk</h3>
                        <span id="environment-risk">0</span>
                    </div>
                    <div class="stat-card">
                        <h3>Open Vulnerabilities</h3>
                        <span id="open-vulnerabilities">0</span>
                    </div>
                </div>
            </header>

            <main>
                <section class="charts-row">
                    <div class="chart-container">
                        <h2>Vulnerability Severity Distribution</h2>
                        <canvas id="severity-chart"></canvas>
                    </div>
                    <div class="chart-container">
                        <h2>Asset Exposure Levels</h2>
                        <canvas id="exposure-chart"></canvas>
                    </div>
                </section>

                <section class="charts-row">
                    <div class="chart-container full-width">
                        <h2>Top Risk Assets</h2>
                        <canvas id="risk-chart"></canvas>
                    </div>
                </section>

                <section class="tables-section">
                    <div class="table-container">
                        <h2>Top Risk Vulnerabilities</h2>
                        <table id="top-risks-table">
                            <thead>
                                <tr>
                                    <th>Asset ID</th>
                                    <th>Hostname</th>
                                    <th>Vulnerability</th>
                                    <th>Severity</th>
                                    <th>Risk Points</th>
                                    <th>Owner</th>
                                </tr>
                            </thead>
                            <tbody id="top-risks-body">
                            </tbody>
                        </table>
                    </div>
                </section>
            </main>
        </div>

        <script src="{{ url_for('static', filename='app.js') }}"></script>
    </body>
    </html>
    """
    return render_template_string(html_content)

@app.route('/api/dashboard')
def get_dashboard():
    """API endpoint to get dashboard data"""
    return jsonify(asm.dashboard())

@app.route('/api/assets')
def get_assets():
    """API endpoint to get all assets"""
    return jsonify([{
        'asset_id': asset.asset_id,
        'hostname': asset.hostname,
        'owner': asset.owner,
        'business_criticality': asset.business_criticality,
        'exposure_level': asset.exposure_level.value,
        'tags': asset.tags,
        'risk_score': asset.risk_score(),
        'vulnerabilities': len(asset.open_vulnerabilities())
    } for asset in asm.list_assets()])

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """API endpoint to get all vulnerabilities"""
    all_vulns = []
    for asset in asm.list_assets():
        for vuln in asset.open_vulnerabilities():
            all_vulns.append({
                'asset_id': asset.asset_id,
                'hostname': asset.hostname,
                'title': vuln.title,
                'severity': vuln.severity.value,
                'description': vuln.description,
                'cve': vuln.cve,
                'affected_service': vuln.affected_service,
                'discovered_at': vuln.discovered_at,
                'risk_points': vuln.risk_points(asset.exposure_level)
            })
    return jsonify(all_vulns)

if __name__ == '__main__':
    # Create static folder and copy frontend files
    os.makedirs('frontend/static', exist_ok=True)
    
    # Copy CSS and JS files to static folder
    import shutil
    shutil.copy('/workspace/frontend/styles.css', '/workspace/frontend/static/styles.css')
    shutil.copy('/workspace/frontend/app.js', '/workspace/frontend/static/app.js')
    
    app.run(debug=True, host='0.0.0.0', port=5000)