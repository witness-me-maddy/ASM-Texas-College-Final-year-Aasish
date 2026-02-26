const API_BASE = window.location.origin;

const reportRows = document.getElementById('reportRows');
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
const addMonitorBtn = document.getElementById('addMonitorBtn');
const automationState = document.getElementById('automationState');
const kpiAssets = document.getElementById('kpiAssets');
const kpiExposures = document.getElementById('kpiExposures');
const kpiOpen = document.getElementById('kpiOpen');
const kpiSlaBreaches = document.getElementById('kpiSlaBreaches');
const kpiAccepted = document.getElementById('kpiAccepted');
const kpiReports = document.getElementById('kpiReports');
const businessUnitRows = document.getElementById('businessUnitRows');
const sourceToolRows = document.getElementById('sourceToolRows');
const assetByUrlRows = document.getElementById('assetByUrlRows');

const detailEmpty = document.getElementById('detailEmpty');
const detailView = document.getElementById('detailView');
const dTarget = document.getElementById('dTarget');
const dWaf = document.getElementById('dWaf');
const dPortRange = document.getElementById('dPortRange');
const dTopEpss = document.getElementById('dTopEpss');
const dTools = document.getElementById('dTools');
const dPorts = document.getElementById('dPorts');

const listTargets = {
  subs: document.getElementById('dSubs'),
  ips: document.getElementById('dIps'),
  tech: document.getElementById('dTech'),
  urls: document.getElementById('dUrls'),
  emails: document.getElementById('dEmails'),
  cloud: document.getElementById('dCloud'),
};

let latestReports = [];
let selectedReportId = null;

function normalizeWebsiteUrl(rawUrl) {
  const value = (rawUrl || '').trim();
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) return value;
  return `https://${value}`;
}

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

function drawDonutFromReports(reports) {
  const exposures = reports.flatMap((r) => r.top_exposures || []);
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

function renderReports(reports) {
  latestReports = reports;
  reportRows.innerHTML = '';
  if (reports.length === 0) {
    reportRows.innerHTML = '<tr><td colspan="7">No reports yet. Run a scan to generate comprehensive intelligence.</td></tr>';
    return;
  }

  reports.forEach((r) => {
    const tr = document.createElement('tr');
    tr.className = 'clickable-row';
    tr.innerHTML = `<td>${r.target_host || r.website_url}<div class="muted">subs: ${(r.discovered_subdomains || []).length} • ips: ${(r.discovered_ips || []).length}</div></td><td>${fmtPosition(r.target_position)}</td><td>${(r.open_ports || []).length} ports</td><td>${(r.tools_executed || []).join(', ')}</td><td>${r.exposures_discovered}</td><td>${Number(r.max_epss_score).toFixed(2)}</td><td>${new Date(r.completed_at).toLocaleString()}</td>`;
    tr.addEventListener('click', () => { selectedReportId = r.id; renderTargetDetails(r.id); });
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

function renderTopFindings(reports) {
  topFindings.innerHTML = '';
  const ex = reports
    .flatMap((r) => (r.top_exposures || []).map((e) => ({ ...e, target: r.target_host })))
    .filter((e) => {
      const title = (e.title || '').toLowerCase();
      return !title.includes('could not run') && !title.includes('tool_unavailable:') && !title.includes('tool_error:');
    })
    .sort((a, b) => b.epss_score - a.epss_score)
    .slice(0, 10);

  if (ex.length === 0) {
    topFindings.innerHTML = '<li><div>No EPSS findings available yet.</div></li>';
    return;
  }

  ex.forEach((e) => {
    const b = riskBand(e.epss_score);
    const li = document.createElement('li');
    li.innerHTML = `<div><strong>${e.title}</strong><div class="muted">${e.target} • ${e.source_tool} • ${e.cve || 'No CVE'}</div></div><span class="badge bg-${b}">EPSS ${(e.epss_score * 100).toFixed(1)}%</span>`;
    topFindings.append(li);
  });
}

function fillList(el, values) {
  el.innerHTML = '';
  values.slice(0, 10).forEach((v) => {
    const li = document.createElement('li');
    li.textContent = v;
    el.append(li);
  });
}

async function renderTargetDetails(reportId) {
  let report = latestReports.find((r) => r.id === reportId);
  const live = await safeFetch(`${API_BASE}/api/reports/${encodeURIComponent(reportId)}`);
  if (live && live.report) report = live.report;
  if (!report) return;

  selectedReportId = report.id;
  detailEmpty.classList.add('hidden');
  detailView.classList.remove('hidden');

  dTarget.textContent = `${report.target_host} (${fmtPosition(report.target_position)})`;
  dWaf.textContent = report.waf_detected || 'Unknown';
  dPortRange.textContent = `${report.scanned_port_range} | ${(report.open_ports || []).length} open ports discovered`;
  dTopEpss.textContent = `${(report.max_epss_score * 100).toFixed(1)}% (${(report.max_epss_percentile * 100).toFixed(1)} percentile)`;
  dTools.textContent = (report.tools_executed || []).join(', ');
  dPorts.textContent = fmtPorts(report.open_ports || []);

  fillList(listTargets.subs, report.discovered_subdomains || []);
  fillList(listTargets.ips, report.discovered_ips || []);
  fillList(listTargets.tech, report.discovered_technologies || []);
  fillList(listTargets.urls, report.discovered_urls || []);
  fillList(listTargets.emails, report.discovered_emails || []);
  fillList(listTargets.cloud, report.discovered_cloud_assets || []);
}

async function runScan(url) {
  const submitted = await safeFetch(`${API_BASE}/api/jobs/scan`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ website_url: url, priority: 2 }),
  });
  if (!submitted || !submitted.job) return { status: 'submission_failed' };

  const jobId = submitted.job.id;
  const maxAttempts = 45;
  for (let i = 0; i < maxAttempts; i++) {
    const jobResponse = await safeFetch(`${API_BASE}/api/jobs/${encodeURIComponent(jobId)}`);
    const job = jobResponse?.job;
    if (!job) return { status: 'submission_failed', jobId };
    if (job.status === 'completed') return { status: 'completed', job };
    if (job.status === 'failed') return { status: 'failed', job };
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  return { status: 'timeout', jobId };
}

async function addMonitorTarget() {
  const url = monitorUrlInput.value.trim();
  if (!url) return;
  await safeFetch(`${API_BASE}/api/monitor-targets`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ website_url: url }),
  });
  monitorUrlInput.value = '';
  await refresh(searchInput.value.trim());
}



function renderAssetByUrl(sectionsPayload) {
  assetByUrlRows.innerHTML = '';
  const sections = sectionsPayload?.sections || [];

  if (sections.length === 0) {
    assetByUrlRows.innerHTML = '<tr><td colspan="7">No scanned assets yet. Run a scan to populate enterprise asset mapping.</td></tr>';
    return;
  }

  sections.forEach((row) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${row.asset_name}</td><td>${row.asset_id}</td><td>${row.owner}</td><td>${row.business_unit}</td><td>${row.open_exposures}/${row.total_exposures}</td><td>${row.latest_report_id || '-'}</td><td>${row.latest_scanned_at ? new Date(row.latest_scanned_at).toLocaleString() : '-'}</td>`;
    assetByUrlRows.append(tr);
  });
}

function renderPortfolioReporting(reportingPayload) {
  const reporting = reportingPayload?.reporting;
  const kpis = reporting?.kpis;

  kpiAssets.textContent = String(kpis?.assets || 0);
  kpiExposures.textContent = String(kpis?.total_exposures || 0);
  kpiOpen.textContent = String(kpis?.open_exposures || 0);
  kpiSlaBreaches.textContent = String(kpis?.sla_breaches || 0);
  kpiAccepted.textContent = String(kpis?.accepted_risk_exposures || 0);
  kpiReports.textContent = String(kpis?.reports_generated || 0);

  businessUnitRows.innerHTML = '';
  const units = Object.entries(reporting?.business_units || {});
  if (units.length === 0) {
    businessUnitRows.innerHTML = '<tr><td colspan="5">No business-unit exposure data yet.</td></tr>';
  } else {
    units
      .sort((a, b) => (b[1].open || 0) - (a[1].open || 0))
      .forEach(([name, values]) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${name}</td><td>${values.total || 0}</td><td>${values.open || 0}</td><td>${values.critical || 0}</td><td>${values.high || 0}</td>`;
        businessUnitRows.append(tr);
      });
  }

  sourceToolRows.innerHTML = '';
  const tools = Object.entries(reporting?.source_tools || {});
  if (tools.length === 0) {
    sourceToolRows.innerHTML = '<tr><td colspan="2">No tool findings yet.</td></tr>';
  } else {
    tools.slice(0, 8).forEach(([tool, count]) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${tool}</td><td>${count}</td>`;
      sourceToolRows.append(tr);
    });
  }
}

async function refresh(query = '') {
  const [summary, reportsData, monitorData, automationData, portfolioData, assetsByUrlData] = await Promise.all([
    safeFetch(`${API_BASE}/api/summary`),
    safeFetch(`${API_BASE}/api/reports`),
    safeFetch(`${API_BASE}/api/monitor-targets`),
    safeFetch(`${API_BASE}/api/automation`),
    safeFetch(`${API_BASE}/api/reporting/portfolio`),
    safeFetch(`${API_BASE}/api/assets/by-url`),
  ]);

  if (!reportsData) {
    scanStatus.textContent = 'Backend unavailable. Start FastAPI server.';
    return;
  }

  const allReports = reportsData.reports || [];
  let reports = allReports;
  if (query) {
    reports = allReports.filter((r) => (r.target_host || '').toLowerCase().includes(query.toLowerCase()));
  }

  renderReports(reports);
  renderMonitors((monitorData && monitorData.targets) || []);
  renderTopFindings(allReports);
  drawTrend();
  drawDonutFromReports(allReports);
  if (reports.length > 0) {
    const preferred = selectedReportId && reports.find((r) => r.id === selectedReportId);
    renderTargetDetails((preferred || reports[0]).id);
  } else {
    detailView.classList.add('hidden');
    detailEmpty.classList.remove('hidden');
  }

  if (automationData && automationData.automation) {
    const a = automationData.automation;
    automationState.textContent = a.running ? `running (${a.monitored_target_count} targets)` : 'stopped';
    automationState.className = `badge ${a.running ? 'bg-High' : 'bg-Low'}`;
  }

  renderPortfolioReporting(portfolioData);
  renderAssetByUrl(assetsByUrlData);

  if (summary && summary.risk_framework) {
    updatedAt.textContent = `Statistics updated on ${new Date().toLocaleString()} · ${summary.risk_framework}`;
  }
}

scanNowBtn.addEventListener('click', async () => {
  const normalizedUrl = normalizeWebsiteUrl(scanUrlInput.value);
  if (!normalizedUrl) { scanStatus.textContent = 'Please enter website URL.'; return; }
  scanUrlInput.value = normalizedUrl;

  scanStatus.textContent = 'Queued scan job. Waiting for scanner nodes to complete...';
  const result = await runScan(normalizedUrl);

  if (result.status === 'completed') {
    const targetHost = result.job.website_url ? new URL(result.job.website_url).hostname : new URL(normalizedUrl).hostname;
    scanStatus.textContent = `Scan completed for ${targetHost}. Position, ports, and vulnerabilities updated.`;
    await refresh(searchInput.value.trim());
    return;
  }

  if (result.status === 'failed') {
    scanStatus.textContent = `Scan failed for job ${result.job.id}. Check scanner node/job status.`;
    return;
  }

  if (result.status === 'timeout') {
    scanStatus.textContent = `Scan job ${result.jobId} is still running. Dashboard auto-refresh will show results shortly.`;
    await refresh(searchInput.value.trim());
    return;
  }

  scanStatus.textContent = 'Unable to submit scan job. API unavailable.';
});

quickScanBtn.addEventListener('click', async () => {
  scanUrlInput.value = scanUrlInput.value.trim() || 'https://example.com';
  scanNowBtn.click();
});

addMonitorBtn.addEventListener('click', addMonitorTarget);
searchInput.addEventListener('input', (e) => refresh(e.target.value.trim()));

refresh();
setInterval(() => refresh(searchInput.value.trim()), 10000);
