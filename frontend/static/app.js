// Mock data for demonstration - in a real application, this would come from an API
const mockDashboardData = {
    asset_count: 156,
    environment_risk: 245.7,
    open_vulnerabilities: 89,
    exposure_summary: {
        internal: 98,
        partner: 32,
        public: 26
    },
    severity_summary: {
        low: 12,
        medium: 34,
        high: 31,
        critical: 12
    },
    top_risks: [
        {
            asset_id: "asset-001",
            hostname: "portal.texascollege.edu",
            vulnerability: "Outdated OpenSSL",
            severity: "high",
            risk_points: 10.8,
            owner: "IT Security",
            exposure: "public",
            service: "https",
            discovered_at: "2023-06-15T10:30:00+00:00"
        },
        {
            asset_id: "asset-002",
            hostname: "erp.internal.texascollege.edu",
            vulnerability: "Missing Security Patches",
            severity: "critical",
            risk_points: 13.0,
            owner: "Enterprise Apps",
            exposure: "internal",
            service: null,
            discovered_at: "2023-06-10T14:22:00+00:00"
        },
        {
            asset_id: "asset-003",
            hostname: "api.customer.texascollege.edu",
            vulnerability: "SQL Injection Vulnerability",
            severity: "critical",
            risk_points: 12.6,
            owner: "Dev Team A",
            exposure: "public",
            service: "https",
            discovered_at: "2023-06-18T09:15:00+00:00"
        },
        {
            asset_id: "asset-004",
            hostname: "intranet.partner.texascollege.edu",
            vulnerability: "Weak Authentication",
            severity: "high",
            risk_points: 9.2,
            owner: "Partner Services",
            exposure: "partner",
            service: "https",
            discovered_at: "2023-06-12T16:45:00+00:00"
        },
        {
            asset_id: "asset-005",
            hostname: "backup.internal.texascollege.edu",
            vulnerability: "Unencrypted Data Transfer",
            severity: "medium",
            risk_points: 4.2,
            owner: "IT Operations",
            exposure: "internal",
            service: "ftp",
            discovered_at: "2023-06-14T11:30:00+00:00"
        }
    ]
};

// Function to get severity color
function getSeverityColor(severity) {
    switch(severity) {
        case 'critical': return '#d32f2f';
        case 'high': return '#f44336';
        case 'medium': return '#ff9800';
        case 'low': return '#4caf50';
        default: return '#9e9e9e';
    }
}

// Function to format risk points
function formatRiskPoints(riskPoints) {
    return riskPoints.toFixed(1);
}

// Function to populate header stats
function populateHeaderStats(data) {
    document.getElementById('total-assets').textContent = data.asset_count;
    document.getElementById('environment-risk').textContent = data.environment_risk.toFixed(1);
    document.getElementById('open-vulnerabilities').textContent = data.open_vulnerabilities;
}

// Function to create severity chart
function createSeverityChart(data) {
    const ctx = document.getElementById('severity-chart').getContext('2d');
    
    // Prepare data for the chart
    const severityLabels = [];
    const severityData = [];
    const backgroundColors = [];
    
    for (const [severity, count] of Object.entries(data.severity_summary)) {
        severityLabels.push(severity.charAt(0).toUpperCase() + severity.slice(1));
        severityData.push(count);
        backgroundColors.push(getSeverityColor(severity));
    }
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: severityLabels,
            datasets: [{
                label: 'Vulnerability Count',
                data: severityData,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Vulnerability Severity Distribution'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Function to create exposure chart
function createExposureChart(data) {
    const ctx = document.getElementById('exposure-chart').getContext('2d');
    
    // Prepare data for the chart
    const exposureLabels = [];
    const exposureData = [];
    const backgroundColors = ['#1a237e', '#283593', '#3949ab'];
    
    for (const [exposure, count] of Object.entries(data.exposure_summary)) {
        exposureLabels.push(exposure.charAt(0).toUpperCase() + exposure.slice(1));
        exposureData.push(count);
    }
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: exposureLabels,
            datasets: [{
                data: exposureData,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                title: {
                    display: true,
                    text: 'Asset Exposure Levels'
                }
            }
        }
    });
}

// Function to create risk chart (top risky assets)
function createRiskChart(topRisks) {
    const ctx = document.getElementById('risk-chart').getContext('2d');
    
    // Extract asset IDs and risk points
    const assetIds = topRisks.map(item => item.asset_id);
    const riskPoints = topRisks.map(item => item.risk_points);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: assetIds,
            datasets: [{
                label: 'Risk Score',
                data: riskPoints,
                borderColor: '#1a237e',
                backgroundColor: 'rgba(26, 35, 126, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Top Risk Assets'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Function to populate top risks table
function populateTopRisksTable(topRisks) {
    const tbody = document.getElementById('top-risks-body');
    tbody.innerHTML = '';
    
    topRisks.forEach(item => {
        const row = document.createElement('tr');
        
        // Format severity with appropriate class
        const severityClass = `${item.severity}-severity`;
        
        row.innerHTML = `
            <td>${item.asset_id}</td>
            <td>${item.hostname}</td>
            <td>${item.vulnerability}</td>
            <td><span class="${severityClass}">${item.severity.toUpperCase()}</span></td>
            <td>${formatRiskPoints(item.risk_points)}</td>
            <td>${item.owner}</td>
        `;
        
        tbody.appendChild(row);
    });
}

// Main function to initialize the dashboard
function initDashboard() {
    // Populate header stats
    populateHeaderStats(mockDashboardData);
    
    // Create charts
    createSeverityChart(mockDashboardData);
    createExposureChart(mockDashboardData);
    createRiskChart(mockDashboardData.top_risks);
    
    // Populate top risks table
    populateTopRisksTable(mockDashboardData.top_risks);
    
    console.log("ASM Dashboard initialized with mock data");
}

// Initialize the dashboard when the page loads
document.addEventListener('DOMContentLoaded', initDashboard);