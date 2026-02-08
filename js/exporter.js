// exporter.js
// Upgraded: reliable exports + fixes duplicate function bug + optional summary export
// Works with analyzer.js by reading window.parsedRows (set by analyzer.js)

(function () {
  "use strict";

  /* -----------------------------
     File download helpers
  -------------------------------- */

  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();

    URL.revokeObjectURL(url);
  }

  function safeFilename(base, ext) {
    const clean = String(base || "github_log_analysis")
      .trim()
      .replace(/[<>:"/\\|?*\x00-\x1F]/g, "_")
      .replace(/\s+/g, "_")
      .slice(0, 80) || "github_log_analysis";

    return `${clean}.${ext}`;
  }

  /* -----------------------------
     Data helpers
  -------------------------------- */

  function getRowsOrWarn() {
    const rows = window.parsedRows || [];
    if (!Array.isArray(rows) || rows.length === 0) {
      alert("Analyze logs first, then export.");
      return null;
    }
    return rows;
  }

  function unionKeys(rows) {
    const keys = new Set();
    for (const r of rows) {
      if (r && typeof r === "object") {
        Object.keys(r).forEach((k) => keys.add(k));
      }
    }
    return [...keys];
  }

  function csvEscape(v) {
    const s = String(v ?? "");
    // Quote only when needed
    if (/[",\n\r]/.test(s)) return `"${s.replaceAll('"', '""')}"`;
    return s;
  }

  function toCSV(rows) {
    if (!rows.length) return "";
    const headers = unionKeys(rows);
    const lines = [headers.join(",")];

    for (const r of rows) {
      const line = headers.map((h) => csvEscape(r?.[h])).join(",");
      lines.push(line);
    }

    return lines.join("\n");
  }

  function summarize(rows) {
    const total = rows.length;

    const uniq = (key) => {
      const s = new Set();
      for (const r of rows) {
        const v = r?.[key];
        if (v !== undefined && v !== null && String(v).trim() !== "") s.add(String(v));
      }
      return s.size;
    };

    const countBy = (key) => {
      const m = new Map();
      for (const r of rows) {
        const raw = r?.[key];
        const v = raw === undefined || raw === null || String(raw).trim() === "" ? "(none)" : String(raw);
        m.set(v, (m.get(v) || 0) + 1);
      }
      return [...m.entries()].sort((a, b) => b[1] - a[1]);
    };

    const ok = rows.filter((r) => String(r?.status || "").startsWith("2")).length;
    const successRate = total ? Math.round((ok / total) * 100) : 0;

    // Time range
    const times = rows
      .map((r) => {
        const d = new Date(r?.timestamp);
        return isNaN(d.getTime()) ? null : d;
      })
      .filter(Boolean)
      .sort((a, b) => a - b);

    const from = times.length ? times[0].toISOString() : null;
    const to = times.length ? times[times.length - 1].toISOString() : null;

    return {
      total_requests: total,
      unique_users: uniq("username"),
      unique_repositories: uniq("repository"),
      unique_ip_addresses: uniq("ip_address"),
      success_rate_percent: successRate,
      time_from: from,
      time_to: to,
      top_users: countBy("username").slice(0, 10).map(([name, count]) => ({ name, count })),
      top_repositories: countBy("repository").slice(0, 10).map(([name, count]) => ({ name, count })),
      top_event_types: countBy("event_type").slice(0, 10).map(([name, count]) => ({ name, count })),
      status_codes: countBy("status").slice(0, 20).map(([code, count]) => ({ code, count })),
      exported_at: new Date().toISOString(),
    };
  }

  /* -----------------------------
     Exporters
  -------------------------------- */

  function exportData(format) {
    const rows = getRowsOrWarn();
    if (!rows) return;

    const base = document.getElementById("exportName")?.value || "github_log_analysis";

    if (format === "json") {
      downloadBlob(safeFilename(base, "json"), JSON.stringify(rows, null, 2), "application/json");
      return;
    }

    if (format === "csv") {
      downloadBlob(safeFilename(base, "csv"), toCSV(rows), "text/csv;charset=utf-8");
      return;
    }

    if (format === "summary") {
      const sum = summarize(rows);
      downloadBlob(safeFilename(base + "_summary", "json"), JSON.stringify(sum, null, 2), "application/json");
      return;
    }

    // Optional placeholders (wired later)
    if (format === "excel") {
      alert("Excel export not wired yet. Use CSV for Excel, or JSON.");
      return;
    }

    if (format === "pdf") {
      alert("PDF export not wired yet. Use CSV or JSON for now.");
      return;
    }

    if (format === "html") {
      const sum = summarize(rows);
      const html = buildHtmlReport(sum, rows);
      downloadBlob(safeFilename(base, "html"), html, "text/html;charset=utf-8");
      return;
    }

    alert("Unsupported export type. Use CSV, JSON, or HTML.");
  }

  function customExport() {
    const format = document.getElementById("exportFormat")?.value || "json";
    exportData(format);
  }

  function buildHtmlReport(summary, rows) {
    // lightweight offline report (no external assets)
    const topList = (title, items, keyLabel) => `
      <section class="card">
        <h2>${escapeHtml(title)}</h2>
        <ol>
          ${items.map((it) => `<li><b>${escapeHtml(it.name ?? it.code ?? "")}</b> <span class="muted">(${it.count})</span></li>`).join("")}
        </ol>
      </section>
    `;

    const sampleTable = rows.slice(0, 50);
    const headers = unionKeys(sampleTable);

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>GitHub Log Analyzer Report</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; margin:0; background:#0b1220; color:#e5e7eb;}
  header{padding:20px 18px; border-bottom:1px solid rgba(255,255,255,.12); background:rgba(15,23,42,.85);}
  .wrap{max-width:1100px; margin:0 auto; padding:18px;}
  .grid{display:grid; grid-template-columns:repeat(4,1fr); gap:12px;}
  .card{background:rgba(255,255,255,.07); border:1px solid rgba(255,255,255,.12); border-radius:14px; padding:14px;}
  h1{margin:0; font-size:18px;}
  h2{margin:0 0 10px; font-size:14px;}
  .kpi{display:flex; flex-direction:column; gap:4px;}
  .kpi b{font-size:20px;}
  .muted{color:#a7b0c0;}
  table{width:100%; border-collapse:collapse; overflow:hidden; border-radius:12px;}
  th,td{padding:10px 10px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; font-size:12px;}
  th{background:rgba(255,255,255,.06);}
  ol{margin:0; padding-left:18px;}
  @media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr);}}
  @media(max-width:520px){.grid{grid-template-columns:1fr;}}
</style>
</head>
<body>
<header>
  <div class="wrap">
    <h1>GitHub Log Analyzer Report</h1>
    <div class="muted">Exported at ${escapeHtml(summary.exported_at || "")}</div>
  </div>
</header>

<div class="wrap">
  <section class="grid">
    <div class="card kpi"><span class="muted">Total Requests</span><b>${summary.total_requests}</b></div>
    <div class="card kpi"><span class="muted">Unique Users</span><b>${summary.unique_users}</b></div>
    <div class="card kpi"><span class="muted">Repositories</span><b>${summary.unique_repositories}</b></div>
    <div class="card kpi"><span class="muted">Success Rate</span><b>${summary.success_rate_percent}%</b></div>
  </section>

  <section class="card" style="margin-top:12px;">
    <h2>Time Range</h2>
    <div class="muted">From: ${escapeHtml(summary.time_from || "-")}</div>
    <div class="muted">To: ${escapeHtml(summary.time_to || "-")}</div>
  </section>

  <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-top:12px;">
    ${topList("Top Users", summary.top_users || [], "name")}
    ${topList("Top Repositories", summary.top_repositories || [], "name")}
    ${topList("Top Event Types", summary.top_event_types || [], "name")}
  </div>

  <section class="card" style="margin-top:12px;">
    <h2>Sample Rows (first ${sampleTable.length})</h2>
    <div style="overflow:auto;">
      <table>
        <thead>
          <tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr>
        </thead>
        <tbody>
          ${sampleTable
            .map(
              (r) =>
                `<tr>${headers.map((h) => `<td>${escapeHtml(r?.[h] ?? "")}</td>`).join("")}</tr>`
            )
            .join("")}
        </tbody>
      </table>
    </div>
  </section>
</div>
</body>
</html>`;
  }

  function escapeHtml(str) {
    return String(str)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  /* -----------------------------
     Expose to window for buttons
  -------------------------------- */

  window.exportData = exportData;
  window.customExport = customExport;

  // Optional: quick export summary button hook (if you want it later)
  window.exportSummary = function () {
    exportData("summary");
  };
})();
