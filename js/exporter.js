// exporter.js
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

function toCSV(rows) {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  const escape = (v) => `"${String(v ?? "").replaceAll('"', '""')}"`;
  const lines = [headers.join(",")];
  for (const r of rows) lines.push(headers.map(h => escape(r[h])).join(","));
  return lines.join("\n");
}

function exportData(fmt) {
  if (!window.parsedRows || window.parsedRows?.length === 0) {
    alert("Analyze logs first.");
    return;
  }
}

function exportData(format) {
  // parsedRows is in analyzer.js scope, but we can access via window if needed
  const rows = window.parsedRows || [];
  if (!rows.length) {
    alert("Analyze logs first.");
    return;
  }

  if (format === "json") {
    downloadBlob("github_log_analysis.json", JSON.stringify(rows, null, 2), "application/json");
  } else if (format === "csv") {
    downloadBlob("github_log_analysis.csv", toCSV(rows), "text/csv");
  } else {
    alert("That export type is not wired yet. Use CSV or JSON for now.");
  }
}

function customExport() {
  const format = document.getElementById("exportFormat")?.value || "json";
  exportData(format);
}

window.exportData = exportData;
window.customExport = customExport;
