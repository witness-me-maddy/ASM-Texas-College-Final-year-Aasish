const API_BASE = window.location.origin;

const reportRows = document.getElementById('reportRows');
const assetRows = document.getElementById('assetRows');
const topFindings = document.getElementById('topFindings');
const riskLegend = document.getElementById('riskLegend');
const assetLegend = document.getElementById('assetLegend');
const totalVulns = document.getElementById('totalVulns');
const trendCanvas = document.getElementById('trendCanvas');
const donutCanvas = document.getElementById('donutCanvas');
const searchInput = document.getElementById('searchInput');
const scanUrlInput = document.getElementById('scanUrlInput');
const scanNowBtn = document.getElementById('scanNowBtn');
const quickScanBtn = document.getElementById('quickScanBtn');
const scanStatus = document.getElementById('scanStatus');
const updatedAt = document.getElementById('updatedAt');
const monitorRows = document.getElementById('monitorRows');
const monitorUrlInput = document.getElementById('monitorUrlInput');
const monitorIntervalInput = document.getElementById('monitorIntervalInput');
const addMonitorBtn = document.getElementById('addMonitorBtn');
const automationState = document.getElementById('automationState');

function riskBand(score) {
  if (score >= 0.7) return 'Critical';
  if (score >= 0.4) return 'High';
  if (score >= 0.2) return 'Medium';
  return 'Low';
}

const fmtPosition = (position) => position ? `${position.city}, ${position.country} (${position.latitude.toFixed(2)}, ${position.longitude.toFixed(2)})` : 'unknown';
const fmtPorts = (ports) => (ports || []).map((p) => `${p.port}/${p.protocol} ${p.service}`).join(', ') || '-';

async function safeFetch(url, options) {
  try {
    const r = await fetch(url, options);
    if (!r.ok) throw new Error('bad');
    return await r.json();
  } catch {
    return null;
  }
}

function drawTrend() {
  const ctx = trendCanvas.getContext('2d');
  const w = trendCanvas.width; const h = trendCanvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = '#242a33';
  for (let i = 0; i < 5; i++) {
    const y = 30 + i * 45;
    ctx.beginPath(); ctx.moveTo(20, y); ctx.lineTo(w - 20, y); ctx.stroke();
  }
  const series = [
    { key: 'Subdomains', color: '#3a7bfd', values: [4, 4.2, 4.3, 4.5, 4.8, 5, 5.2] },
    { key: 'IP', color: '#ff8c1a', values: [0.8, 0.82, 0.84, 0.87, 0.88, 0.89, 0.92] },
    { key: 'Endpoint', color: '#f1c40f', values: [9.8, 10, 10.2, 10.4, 10.5, 10.9, 11.2] },
    { key: 'Website', color: '#2ecc71', values: [2.8, 2.9, 3.0, 3.1, 3.2, 3.25, 3.35] },
  ];
  series.forEach((s) => {
    ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.beginPath();
    s.values.forEach((v, i) => {
      const x = 30 + i * ((w - 60) / (s.values.length - 1));
      const y = h - 25 - (v / 12) * (h - 60);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  });
  assetLegend.innerHTML = series.map((s) => `<span><i class="dot" style="background:${s.color}"></i>${s.key}</span>`).join('');
}

function drawDonutFromAssets(assets) {
  const exposures = assets.flatMap((a) => a.exposures || []).filter((e) => e.status === 'open');
  const buckets = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  exposures.forEach((e) => { buckets[riskBand(e.epss_score)] += 1; });
  const data = [
    { label: 'Critical', value: buckets.Critical, color: '#ef3b3b' },
    { label: 'High risk', value: buckets.High, color: '#ff8c1a' },
    { label: 'Medium', value: buckets.Medium, color: '#f1c40f' },
    { label: 'Low risk', value: buckets.Low, color: '#3a7bfd' },
  ];
  const total = Math.max(data.reduce((a, b) => a + b.value, 0), 1);
  totalVulns.textContent = String(total);

  const ctx = donutCanvas.getContext('2d');
  const cx = donutCanvas.width / 2; const cy = donutCanvas.height / 2;
  const r = 88; const inner = 52;
  let start = -Math.PI / 2;
  ctx.clearRect(0, 0, donutCanvas.width, donutCanvas.height);
  data.forEach((d) => {
    const angle = (d.value / total) * Math.PI * 2;
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, r, start, start + angle); ctx.closePath();
    ctx.fillStyle = d.color; ctx.fill(); start += angle;
  });
  ctx.globalCompositeOperation = 'destination-out';
  ctx.beginPath(); ctx.arc(cx, cy, inner, 0, Math.PI * 2); ctx.fill();
  ctx.globalCompositeOperation = 'source-over';
  riskLegend.innerHTML = data.map((d) => `<span><i class="dot" style="background:${d.color}"></i>${d.label} ${d.value}</span>`).join('');
}

function renderAssets(rows) {
  assetRows.innerHTML = '';
  rows.forEach((item) => {
    const asset = item.asset || item;
    const ex = (asset.exposures || []).filter((e) => e.status === 'open');
    const top = ex.reduce((m, e) => Math.max(m, e.epss_score), 0);
    const band = riskBand(top);
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${asset.name}</td><td>${fmtPosition(asset.position)}</td><td>${fmtPorts(asset.open_ports)}</td><td>${ex.length}</td><td>${top.toFixed(2)}</td><td><span class="badge bg-${band}">${band}</span></td>`;
    assetRows.append(tr);
  });
}

function renderReports(reports) {
  reportRows.innerHTML = '';
  reports.forEach((r) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${r.target_host || r.website_url}</td><td>${fmtPosition(r.target_position)}</td><td>${fmtPorts(r.open_ports)}</td><td>${r.exposures_discovered}</td><td>${Number(r.max_epss_score).toFixed(2)}</td><td>${new Date(r.completed_at).toLocaleString()}</td>`;
    reportRows.append(tr);
  });
}

function renderMonitors(targets) {
  monitorRows.innerHTML = '';
  targets.forEach((t) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${t.website_url}</td><td>${t.scan_interval_seconds}</td><td>${t.last_scan_at ? new Date(t.last_scan_at).toLocaleString() : '-'}</td><td>${t.enabled ? 'enabled' : 'disabled'}</td>`;
    monitorRows.append(tr);
  });
}

function renderTopFindings(assets) {
  topFindings.innerHTML = '';
  const ex = assets.flatMap((a) => (a.exposures || []).map((e) => ({ ...e, asset: a.name })))
    .filter((e) => e.status === 'open')
    .sort((a, b) => b.epss_score - a.epss_score)
    .slice(0, 6);
  ex.forEach((e) => {
    const b = riskBand(e.epss_score);
    const li = document.createElement('li');
    li.innerHTML = `<div><strong>${e.title}</strong><div class="muted">${e.asset} • ${e.source_tool} • ${e.cve || 'No CVE'}</div></div><span class="badge bg-${b}">EPSS ${(e.epss_score * 100).toFixed(1)}%</span>`;
    topFindings.append(li);
  });
}

async function runScan(url) {
  return safeFetch(`${API_BASE}/api/scan`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ website_url: url }),
  });
}

async function addMonitorTarget() {
  const url = monitorUrlInput.value.trim();
  const interval = Number(monitorIntervalInput.value || 60);
  if (!url) return;
  await safeFetch(`${API_BASE}/api/monitor-targets`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ website_url: url, scan_interval_seconds: interval }),
  });
  monitorUrlInput.value = '';
  await refresh(searchInput.value.trim());
}

async function refresh(query = '') {
  const [summary, assetsData, reportsData, monitorData, automationData] = await Promise.all([
    safeFetch(`${API_BASE}/api/summary`),
    safeFetch(`${API_BASE}${query ? `/api/search?query=${encodeURIComponent(query)}` : '/api/assets'}`),
    safeFetch(`${API_BASE}/api/reports`),
    safeFetch(`${API_BASE}/api/monitor-targets`),
    safeFetch(`${API_BASE}/api/automation`),
  ]);

  if (!assetsData) {
    scanStatus.textContent = 'Backend unavailable. Start FastAPI server.';
    return;
  }

  const rows = assetsData.assets || assetsData;
  const assets = rows.map((r) => r.asset || r);
  renderAssets(rows);
  renderReports((reportsData && reportsData.reports) || []);
  renderMonitors((monitorData && monitorData.targets) || []);
  renderTopFindings(assets);
  drawTrend();
  drawDonutFromAssets(assets);

  if (automationData && automationData.automation) {
    const a = automationData.automation;
    automationState.textContent = a.running ? `running (${a.monitored_target_count} targets)` : 'stopped';
    automationState.className = `badge ${a.running ? 'bg-High' : 'bg-Low'}`;
  }

  if (summary && summary.risk_framework) {
    updatedAt.textContent = `Statistics updated on ${new Date().toLocaleString()} · ${summary.risk_framework}`;
  }
}

scanNowBtn.addEventListener('click', async () => {
  const url = scanUrlInput.value.trim();
  if (!url) { scanStatus.textContent = 'Please enter website URL.'; return; }
  scanStatus.textContent = 'Running full scan...';
  const result = await runScan(url);
  if (!result) { scanStatus.textContent = 'Scan failed. API unavailable.'; return; }
  scanStatus.textContent = `Scan completed for ${result.report.target_host}. Position, ports, and vulnerabilities updated.`;
  await refresh(searchInput.value.trim());
});

quickScanBtn.addEventListener('click', async () => {
  scanUrlInput.value = scanUrlInput.value.trim() || 'https://example.com';
  scanNowBtn.click();
});

addMonitorBtn.addEventListener('click', addMonitorTarget);
searchInput.addEventListener('input', (e) => refresh(e.target.value.trim()));

refresh();
setInterval(() => refresh(searchInput.value.trim()), 10000);
