const $ = (selector) => document.querySelector(selector);

const demoReport = {
  report_id: "demo-2026-10-26",
  target: "https://example.com",
  scanned_at: "2026-10-26T10:15:00Z",
  score: 82,
  grade: "Strong foundation",
  summary: "The public website presents a healthy baseline, with a few configuration improvements recommended.",
  site: { final_url: "https://example.com/", status_code: 200, content_type: "text/html", response_time_ms: 184, page_title: "Example Domain" },
  tls: { protocol: "TLSv1.3", expires_at: "2027-03-15", valid_from: "2026-03-15", days_remaining: 140, issuer: "Example Trust Services", subject: "example.com", serial_number: "4A:7C:9B:20:DE:71" },
  observed_controls: ["HTTPS redirect", "TLS 1.3", "Content Security Policy", "Secure cookies", "X-Content-Type-Options"],
  categories: [
    { name: "Transport", score: 92, note: "HTTPS and modern TLS are present." },
    { name: "Headers", score: 76, note: "Most browser safeguards are configured." },
    { name: "Cookies", score: 88, note: "Observed cookies use secure attributes." },
    { name: "Exposure", score: 72, note: "Review public informational endpoints." }
  ],
  findings: [
    { severity: "Medium", title: "Referrer-Policy is not set", evidence: "No Referrer-Policy response header was observed.", recommendation: "Set a restrictive policy such as strict-origin-when-cross-origin to limit URL information shared with third parties." },
    { severity: "Low", title: "Permissions-Policy is not set", evidence: "No Permissions-Policy response header was observed.", recommendation: "Explicitly disable browser features that the application does not need, such as camera, microphone, and geolocation." },
    { severity: "Info", title: "Server banner is visible", evidence: "A server-identifying response header was returned.", recommendation: "Minimize unnecessary implementation details in public response headers." }
  ]
};

let currentReport = demoReport;

function escapeHtml(value = "") { return String(value).replace(/[&<>'"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[c]); }
function formatDate(value) { return value ? new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(new Date(value)) : "Not available"; }
function severityClass(severity) { return String(severity || "Info").toLowerCase(); }

function normalizeReport(report) {
  if (Array.isArray(report.categories)) return report;
  const rawCategories = report.categories || {};
  const site = report.site || {};
  const finalUrl = report.final_url || report.target;
  const controls = (report.observed_controls || []).map((control) => typeof control === "string" ? control : control.name.replaceAll("-", " "));
  return {
    ...report,
    report_id: report.report_id || report.id,
    grade: report.grade || report.status || "Assessment complete",
    summary: report.summary || report.coverage || "Public web configuration signals collected.",
    site: { ...site, final_url: finalUrl, status_code: report.response_status || site.status_code, response_time_ms: report.duration_ms || site.response_time_ms, page_title: site.page_title || "Not collected" },
    tls: report.tls || {},
    observed_controls: controls,
    categories: Object.entries(rawCategories).map(([name, score]) => ({ name, score, note: "Public configuration assessment" })),
    findings: (report.findings || []).map((finding) => ({ ...finding, severity: String(finding.severity || "Info").replace(/^./, (letter) => letter.toUpperCase()), recommendation: finding.recommendation || finding.remediation || "Review this configuration against your organization’s security policy." }))
  };
}

function snapshot(report) {
  const site = report.site || {};
  const tls = report.tls || {};
  const categories = report.categories || [];
  const controls = report.observed_controls || [];
  const findings = report.findings || [];
  return `
    <section class="overview-grid">
      <article class="site-card panel">
        <div class="panel-title"><div><p class="card-kicker">Assessment target</p><h2>${escapeHtml(report.target)}</h2></div><span class="status-dot">Live</span></div>
        <dl class="detail-list"><div><dt>Website status</dt><dd>${escapeHtml(site.status_code || "-")} ${escapeHtml(site.content_type || "")}</dd></div><div><dt>Page title</dt><dd>${escapeHtml(site.page_title || "Not available")}</dd></div><div><dt>Response time</dt><dd>${escapeHtml(site.response_time_ms || "-")} ms</dd></div><div><dt>Final address</dt><dd class="truncate">${escapeHtml(site.final_url || report.target)}</dd></div></dl>
        <div class="certificate"><p class="card-kicker">SSL certificate</p><strong>${escapeHtml(tls.protocol || "Certificate details unavailable")}</strong><span>${escapeHtml(tls.issuer || "No issuer data")}</span><div><b>${escapeHtml(tls.days_remaining ?? "-")}</b> days remaining</div><small>Expires ${escapeHtml(formatDate(tls.expires_at))}</small></div>
      </article>
      <article class="posture-card panel">
        <div class="posture-top"><div><p class="card-kicker">Security posture</p><h2>${escapeHtml(report.grade || "Assessment complete")}</h2><p>${escapeHtml(report.summary || "Public-web signals collected.")}</p></div><div class="score"><b>${escapeHtml(report.score ?? "-")}</b><span>/100</span></div></div>
        <div class="bar-chart">${categories.map((item, index) => `<div class="chart-column"><div class="bar-track"><span style="height:${Math.max(16, Number(item.score) || 16)}%"></span></div><b>${escapeHtml(item.score)}</b><small>${escapeHtml(item.name)}</small></div>`).join("")}</div>
      </article>
    </section>
    <section class="lower-grid">
      <article class="controls-card panel"><div class="panel-title"><div><p class="card-kicker">Detected controls</p><h2>Present on this website</h2></div><span class="metric">${controls.length}</span></div><div class="control-list">${controls.length ? controls.map((item) => `<span>${escapeHtml(item)}</span>`).join("") : "<p>No observed controls were returned.</p>"}</div></article>
      <article class="findings-card panel"><div class="panel-title"><div><p class="card-kicker">Priority improvements</p><h2>What needs attention</h2></div><button class="text-button open-report" type="button">View report</button></div><div class="finding-preview">${findings.slice(0, 3).map((finding) => `<div><span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span><p>${escapeHtml(finding.title)}</p><small>${escapeHtml(finding.recommendation)}</small></div>`).join("") || "<p>No findings were reported.</p>"}</div></article>
    </section>`;
}

function fullReport(report) {
  const site = report.site || {}; const tls = report.tls || {}; const categories = report.categories || []; const findings = report.findings || [];
  return `<section class="report-summary panel"><div><p class="card-kicker">Posture score</p><div class="report-score">${escapeHtml(report.score ?? "-")}<span>/100</span></div><p>${escapeHtml(report.grade || "Assessment complete")}</p></div><p>${escapeHtml(report.summary || "Public-web signals collected.")}</p></section>
  <section class="report-grid"><article class="panel"><p class="card-kicker">Website details</p><dl class="detail-list"><div><dt>Target</dt><dd>${escapeHtml(report.target)}</dd></div><div><dt>Final URL</dt><dd>${escapeHtml(site.final_url || "-")}</dd></div><div><dt>HTTP status</dt><dd>${escapeHtml(site.status_code || "-")}</dd></div><div><dt>Response time</dt><dd>${escapeHtml(site.response_time_ms || "-")} ms</dd></div></dl></article><article class="panel"><p class="card-kicker">SSL certificate details</p><dl class="detail-list"><div><dt>Protocol</dt><dd>${escapeHtml(tls.protocol || "-")}</dd></div><div><dt>Issuer</dt><dd>${escapeHtml(tls.issuer || "-")}</dd></div><div><dt>Subject</dt><dd>${escapeHtml(tls.subject || "-")}</dd></div><div><dt>Expires</dt><dd>${escapeHtml(formatDate(tls.expires_at))} (${escapeHtml(tls.days_remaining ?? "-")} days)</dd></div></dl></article></section>
  <section class="panel section-panel"><div class="panel-title"><div><p class="card-kicker">Observed controls</p><h2>Present safeguards</h2></div></div><div class="control-list">${(report.observed_controls || []).map((item) => `<span>${escapeHtml(item)}</span>`).join("") || "<p>No observed controls were returned.</p>"}</div></section>
  <section class="panel section-panel"><div class="panel-title"><div><p class="card-kicker">Findings and recommendations</p><h2>Remediation guidance</h2></div></div><div class="finding-table">${findings.map((finding) => `<article><div><span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span><h3>${escapeHtml(finding.title)}</h3></div><p><b>Observed:</b> ${escapeHtml(finding.evidence)}</p><p><b>Suggested action:</b> ${escapeHtml(finding.recommendation)}</p></article>`).join("") || "<p>No findings were reported.</p>"}</div></section>`;
}

function render(report) {
  currentReport = normalizeReport(report);
  report = currentReport;
  $("#report-preview").innerHTML = snapshot(report);
  $("#full-report").innerHTML = fullReport(report);
  $("#report-title").textContent = `Assessment report`;
  $("#report-subtitle").textContent = `${report.target || "Website"} - assessed ${formatDate(report.scanned_at)}`;
  document.querySelectorAll(".open-report").forEach((button) => button.addEventListener("click", () => activate("report")));
}

function activate(id) {
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === id));
  document.querySelectorAll(".nav-link").forEach((link) => link.classList.toggle("active", link.dataset.view === id && !link.dataset.focusScan));
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function loadHistory() {
  const list = $("#history-list"); list.innerHTML = "<p class='loading'>Loading assessment history...</p>";
  try {
    const response = await fetch("/api/history"); if (!response.ok) throw new Error();
    const data = await response.json(); const reports = data.reports || data || [];
    list.innerHTML = reports.length ? reports.map((item) => `<button class="archive-item" data-id="${escapeHtml(item.report_id)}"><span>${escapeHtml(item.target || "Website")}</span><b>${escapeHtml(item.score ?? "-")}/100</b><small>${escapeHtml(formatDate(item.scanned_at))}</small></button>`).join("") : "<div class='empty-state'>No completed assessments yet.</div>";
  } catch { list.innerHTML = "<div class='empty-state'>History is available after the local API is running.</div>"; }
}

$("#scan-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const input = $("#target-url"); const alert = $("#scan-alert"); const button = event.submitter;
  alert.textContent = "Collecting public security signals..."; alert.className = "alert visible"; button.disabled = true; button.textContent = "Assessing...";
  try {
    const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: input.value.trim() }) });
    const data = await response.json(); if (!response.ok) throw new Error(data.detail || "Assessment could not be completed.");
    render(data); alert.textContent = "Assessment complete. Review the overview below."; alert.className = "alert visible success";
  } catch (error) { alert.textContent = error.message || "Assessment could not be completed."; alert.className = "alert visible error"; }
  finally { button.disabled = false; button.textContent = "Run assessment"; }
});

document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", () => { activate(link.dataset.view); if (link.dataset.focusScan) setTimeout(() => $("#target-url").focus(), 250); if (link.dataset.view === "history") loadHistory(); }));
$("#download-json").addEventListener("click", () => { const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `palisight-${currentReport.report_id || "report"}.json`; link.click(); URL.revokeObjectURL(link.href); });
$("#print-report").addEventListener("click", () => window.print());
render(demoReport);
