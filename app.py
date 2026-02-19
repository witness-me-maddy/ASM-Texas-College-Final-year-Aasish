from flask import Flask, jsonify, render_template
from asm_system import AttackSurfaceManagementSystem, seed_demo_environment
import os

app = Flask(__name__)

# Initialize the ASM system
asm = seed_demo_environment()

@app.route('/')
def index():
    # Serve the frontend
    return render_template('index.html')

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