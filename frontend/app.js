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

// Function to fetch dashboard data from API
async function fetchDashboardData() {
    try {
        const response = await fetch('/api/dashboard');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        // Fallback to mock data if API fails
        return {
            asset_count: 0,
            environment_risk: 0,
            open_vulnerabilities: 0,
            exposure_summary: {
                internal: 0,
                partner: 0,
                public: 0
            },
            severity_summary: {
                low: 0,
                medium: 0,
                high: 0,
                critical: 0
            },
            top_risks: []
        };
    }
}

// Main function to initialize the dashboard
async function initDashboard() {
    // Fetch data from API
    const data = await fetchDashboardData();
    
    // Populate header stats
    populateHeaderStats(data);
    
    // Create charts
    createSeverityChart(data);
    createExposureChart(data);
    createRiskChart(data.top_risks);
    
    // Populate top risks table
    populateTopRisksTable(data.top_risks);
    
    console.log("ASM Dashboard initialized with data from API");
}

// Initialize the dashboard when the page loads
document.addEventListener('DOMContentLoaded', initDashboard);