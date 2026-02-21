const API_BASE = window.location.origin;

const summaryCards = document.getElementById('summaryCards');
const assetRows = document.getElementById('assetRows');
const businessUnitChart = document.getElementById('businessUnitChart');
const topFindings = document.getElementById('topFindings');
const reportRows = document.getElementById('reportRows');
const searchInput = document.getElementById('searchInput');
const riskFramework = document.getElementById('riskFramework');
const scanNowBtn = document.getElementById('scanNowBtn');
const scanUrlInput = document.getElementById('scanUrlInput');
const scanStatus = document.getElementById('scanStatus');

function riskBand(score) {
  if (score >= 0.7) return 'Critical';
  if (score >= 0.4) return 'High';
  if (score >= 0.2) return 'Medium';
  return 'Low';
}

async function safeFetch(url, options) {
  try {
    const response = await fetch(url, options);
    if (!response.ok) throw new Error('request failed');
    return await response.json();
  } catch {
    return null;
  }
}

function renderSummary(summary) {
  summaryCards.innerHTML = '';
  [
    ['Total Assets', summary.asset_count],
    ['Open Exposures', summary.open_exposure_count],
    ['High Risk by EPSS', summary.high_risk_exposure_count],
    ['Internet Exposed', summary.internet_exposed_assets],
    ['Mean EPSS', Number(summary.mean_epss).toFixed(2)],
  ].forEach(([label, value]) => {
    const card = document.createElement('article');
    card.className = 'card';
    card.innerHTML = `<h4>${label}</h4><p>${value}</p>`;
    summaryCards.append(card);
  });
}

function renderBusinessUnits(data) {
  businessUnitChart.innerHTML = '';
  const entries = Object.entries(data);
  const maxValue = Math.max(...entries.map(([, value]) => value), 1);

  entries.forEach(([name, value]) => {
    const row = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML = `
      <span class="bar-label">${name}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(value / maxValue) * 100}%"></div></div>
      <span class="bar-value">${value}</span>
    `;
    businessUnitChart.append(row);
  });
}

function renderTopFindings(assets) {
  topFindings.innerHTML = '';
  const exposures = assets
    .flatMap((asset) => asset.exposures
      .filter((e) => e.status === 'open')
      .map((e) => ({ ...e, asset: asset.name })))
    .sort((a, b) => b.epss_score - a.epss_score)
    .slice(0, 5);

  if (exposures.length === 0) {
    topFindings.innerHTML = '<li><span>No open findings yet.</span></li>';
    return;
  }

  exposures.forEach((e) => {
    const band = riskBand(e.epss_score);
    const li = document.createElement('li');
    li.innerHTML = `
      <div>
        <strong>${e.title}</strong>
        <div class="meta">${e.asset} • ${e.source_tool} • ${e.cve || 'No CVE'}</div>
      </div>
      <span class="badge bg-${band}">EPSS ${(e.epss_score * 100).toFixed(1)}%</span>
    `;
    topFindings.append(li);
  });
}

function renderAssets(rows) {
  assetRows.innerHTML = '';
  rows.forEach((item) => {
    const asset = item.asset || item;
    const exposures = asset.exposures.filter((e) => e.status === 'open');
    const top = exposures.reduce((acc, e) => Math.max(acc, e.epss_score), 0);
    const band = item.risk_band || riskBand(top);

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${asset.name}</td>
      <td>${asset.owner}</td>
      <td>${asset.business_unit}</td>
      <td>${exposures.length}</td>
      <td>${top.toFixed(2)}</td>
      <td><span class="badge bg-${band}">${band}</span></td>
    `;
    assetRows.append(tr);
  });
}

function renderReports(reports) {
  reportRows.innerHTML = '';
  reports.forEach((report) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${report.website_url}</td>
      <td>${report.status}</td>
      <td>${report.tools_executed.join(', ')}</td>
      <td>${report.exposures_discovered}</td>
      <td>${Number(report.max_epss_score).toFixed(2)}</td>
      <td>${new Date(report.completed_at).toLocaleString()}</td>
    `;
    reportRows.append(tr);
  });
}

async function loadDashboard(query = '') {
  const [summaryData, assetData, reportData] = await Promise.all([
    safeFetch(`${API_BASE}/api/summary`),
    safeFetch(`${API_BASE}${query ? `/api/search?query=${encodeURIComponent(query)}` : '/api/assets'}`),
    safeFetch(`${API_BASE}/api/reports`),
  ]);

  if (!summaryData || !assetData) {
    scanStatus.textContent = 'Backend unavailable. Start API service for live data.';
    return;
  }

  const rows = assetData.assets || assetData;
  renderSummary(summaryData.summary);
  renderBusinessUnits(summaryData.open_exposures_by_business_unit || {});
  riskFramework.textContent = summaryData.risk_framework;
  renderAssets(rows);
  renderTopFindings(rows.map((r) => r.asset || r));
  renderReports((reportData && reportData.reports) || []);
}

async function runWebsiteScan() {
  const websiteUrl = scanUrlInput.value.trim();
  if (!websiteUrl) {
    scanStatus.textContent = 'Enter a valid website URL.';
    return;
  }

  scanStatus.textContent = 'Running full attack-surface scan...';
  const response = await safeFetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ website_url: websiteUrl }),
  });

  if (!response) {
    scanStatus.textContent = 'Scan failed. Ensure backend API is running.';
    return;
  }

  scanStatus.textContent = `Scan complete for ${response.report.target_host}. Report generated with ${response.report.exposures_discovered} EPSS-ranked exposures.`;
  await loadDashboard(searchInput.value.trim());
}

searchInput.addEventListener('input', (event) => loadDashboard(event.target.value.trim()));
scanNowBtn.addEventListener('click', runWebsiteScan);

loadDashboard();
