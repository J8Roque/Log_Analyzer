// analyzer.js
// FULL UPGRADE (GitHub Pages friendly, Demo works, no infinite loading, better errors, better sample loading)
// Notes are included as comments where upgrades matter.

let uploadedFiles = [];
let parsedRows = [];

const $ = (id) => document.getElementById(id);

/* =============================
   UPGRADE NOTES (high level)
   1) Demo now loads from /samples/sample_github_logs.json (real repo file) OR falls back to generated data
   2) analyzeLogs() no longer hangs: it always hides spinner in finally{}
   3) Better file parsing: JSON array, JSON object, NDJSON (one JSON per line), CSV
   4) Better time range output + duration
   5) Safe DOM access (won’t crash if an element missing)
   6) Clear user feedback via toast() that does not block the UI
============================= */

/* -----------------------------
   Simple non blocking toast (replaces alert)
-------------------------------- */
function toast(msg, type = "info") {
  const container = $("toastContainer");
  if (!container) {
    console.log(`[${type}]`, msg);
    return;
  }

  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `
    <div class="toast-inner">
      <div class="toast-dot ${type}"></div>
      <div class="toast-text">${escapeHtml(msg)}</div>
      <button class="toast-x" aria-label="Close">×</button>
    </div>
  `;

  container.appendChild(el);

  const close = () => {
    el.classList.add("hide");
    setTimeout(() => el.remove(), 180);
  };

  el.querySelector(".toast-x")?.addEventListener("click", close);
  setTimeout(close, 2600);
}

/* -----------------------------
   Navigation helpers
-------------------------------- */
function showSection(id) {
  document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));
  const el = document.querySelector(id);
  if (el) el.classList.add("active");

  document.querySelectorAll(".nav-link").forEach((a) => a.classList.remove("active"));
  document.querySelectorAll(`.nav-link[href="${id}"]`).forEach((a) => a.classList.add("active"));

  history.replaceState(null, "", id);
  window.scrollTo({ top: 0, behavior: "smooth" });
}
window.showSection = showSection;

/* -----------------------------
   Upload UI
-------------------------------- */
function getSelectedLogType() {
  const el = document.querySelector('input[name="logType"]:checked');
  return el ? el.value : "auto";
}

function clearFiles() {
  uploadedFiles = [];
  parsedRows = [];
  if ($("fileInput")) $("fileInput").value = "";
  renderFileList();
  setAnalyzeEnabled(false);
  toast("Cleared files.", "info");
}
window.clearFiles = clearFiles;

function setAnalyzeEnabled(enabled) {
  const btn = $("analyzeBtn");
  if (btn) btn.disabled = !enabled;
}

function renderFileList() {
  const list = $("fileList");
  if (!list) return;

  if (uploadedFiles.length === 0) {
    list.innerHTML = `
      <div class="no-files">
        <i class="fas fa-file-alt"></i>
        <p>No files selected</p>
      </div>
    `;
    return;
  }

  list.innerHTML = uploadedFiles
    .map(
      (f, idx) => `
    <div class="file-item">
      <div class="file-info">
        <i class="fas fa-file file-icon"></i>
        <div class="file-details">
          <div class="file-name" title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</div>
          <div class="file-size">${(f.size / 1024).toFixed(1)} KB</div>
        </div>
      </div>
      <button class="file-remove" title="Remove" onclick="removeFile(${idx})">
        <i class="fas fa-times"></i>
      </button>
    </div>
  `
    )
    .join("");
}

function removeFile(i) {
  uploadedFiles.splice(i, 1);
  renderFileList();
  setAnalyzeEnabled(uploadedFiles.length > 0);
}
window.removeFile = removeFile;

function setupUpload() {
  const input = $("fileInput");
  const dropArea = $("dropArea");

  if (input) {
    input.addEventListener("change", (e) => {
      addFiles([...e.target.files]);
    });
  }

  if (dropArea) {
    ["dragenter", "dragover"].forEach((evt) => {
      dropArea.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach((evt) => {
      dropArea.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.remove("dragover");
      });
    });

    dropArea.addEventListener("drop", (e) => {
      addFiles([...e.dataTransfer.files]);
    });

    // UPGRADE: click on dropArea opens file picker
    dropArea.addEventListener("click", () => input?.click());
  }
}

function addFiles(files) {
  const allowed = [".json", ".csv", ".txt", ".log", ".ndjson"];
  const good = files.filter((f) => allowed.some((ext) => f.name.toLowerCase().endsWith(ext)));

  if (good.length === 0) {
    toast("No supported files. Use .json, .csv, .txt, .log, .ndjson", "warn");
    return;
  }

  uploadedFiles.push(...good);
  renderFileList();
  setAnalyzeEnabled(uploadedFiles.length > 0);
  toast(`Added ${good.length} file(s).`, "success");
}

/* -----------------------------
   Parsing helpers
-------------------------------- */
async function readFileText(file) {
  return await file.text();
}

function autoDetect(text) {
  const s = text.trimStart();
  if (s.startsWith("{") || s.startsWith("[")) return "json";
  const first = text.split(/\r?\n/)[0] || "";
  if (first.includes(",")) return "csv";
  return "text";
}

function normalizeRow(obj) {
  // UPGRADE: normalize common field names + keep raw as fallback
  const ts = obj.timestamp || obj.created_at || obj.time || obj.date || obj.datetime || "";
  const user = obj.username || obj.user || obj.actor || obj.login || "";
  const repo = obj.repository || obj.repo || obj.repo_name || obj.full_name || "";
  const ev = obj.event_type || obj.action || obj.event || obj.type || obj.eventName || "";
  const st = obj.status || obj.status_code || obj.code || obj.http_status || "";
  const ip = obj.ip_address || obj.ip || obj.remote_ip || obj.client_ip || "";

  return {
    timestamp: ts,
    username: user,
    repository: repo,
    event_type: ev,
    status: st,
    ip_address: ip,
    _raw: obj,
  };
}

function parseJsonLoose(text) {
  // UPGRADE: supports JSON array, JSON object, NDJSON lines
  const trimmed = text.trim();
  if (!trimmed) return [];

  // If it begins with [ or { treat as normal JSON
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    const obj = JSON.parse(trimmed);
    if (Array.isArray(obj)) return obj.map(normalizeRow);
    if (obj && typeof obj === "object") return [normalizeRow(obj)];
    return [];
  }

  // NDJSON fallback
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    try {
      rows.push(normalizeRow(JSON.parse(s)));
    } catch {
      // ignore bad lines
    }
  }
  return rows;
}

function parseTextLines(text) {
  return text
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean)
    .map((line) => ({
      timestamp: "",
      username: "",
      repository: "",
      event_type: line.slice(0, 120),
      status: "",
      ip_address: "",
    }));
}

/* -----------------------------
   Analysis UI helpers
-------------------------------- */
function showLoading(on, message = "Processing your log files") {
  const loading = $("loadingState");
  const results = $("analysisResults");
  const msg = $("loadingMessage");
  const pf = $("progressFill");

  if (msg) msg.textContent = message;
  if (pf) pf.style.width = on ? "10%" : "0%";

  if (loading) loading.style.display = on ? "block" : "none";
  if (results) results.style.display = on ? "none" : "block";
}

function setProgress(pct) {
  const pf = $("progressFill");
  if (pf) pf.style.width = `${pct}%`;
}

function safeSetText(id, value) {
  const el = $(id);
  if (el) el.textContent = value;
}

function parseDateSafe(v) {
  if (!v) return null;
  const d = new Date(v);
  if (!isNaN(d.getTime())) return d;
  return null;
}

function formatDate(d) {
  return d ? d.toLocaleString() : "-";
}

function durationHuman(ms) {
  if (!isFinite(ms) || ms < 0) return "-";
  const sec = Math.floor(ms / 1000);
  const min = Math.floor(sec / 60);
  const hr = Math.floor(min / 60);
  const day = Math.floor(hr / 24);
  if (day > 0) return `${day}d ${hr % 24}h`;
  if (hr > 0) return `${hr}h ${min % 60}m`;
  if (min > 0) return `${min}m ${sec % 60}s`;
  return `${sec}s`;
}

function topN(rows, key, n = 5) {
  const m = new Map();
  for (const r of rows) {
    const v = r[key];
    if (!v) continue;
    const k = String(v);
    m.set(k, (m.get(k) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

function fillTopList(elId, items) {
  const el = $(elId);
  if (!el) return;

  if (!items.length) {
    el.innerHTML = `<div class="list-item"><span class="list-rank">-</span><span class="list-name">No data</span><span class="list-count">0</span></div>`;
    return;
  }

  el.innerHTML = items
    .map(
      (it, idx) => `
    <div class="list-item">
      <span class="list-rank">${idx + 1}</span>
      <span class="list-name" title="${escapeHtml(it[0])}">${escapeHtml(it[0])}</span>
      <span class="list-count">${it[1].toLocaleString()}</span>
    </div>
  `
    )
    .join("");
}

/* -----------------------------
   MAIN: analyze logs
-------------------------------- */
async function analyzeLogs() {
  // UPGRADE: if parsedRows already set (Demo), analyze directly without file reading
  const usingMemoryRows = Array.isArray(parsedRows) && parsedRows.length > 0 && uploadedFiles.length === 0;

  if (!usingMemoryRows && uploadedFiles.length === 0) {
    toast("Upload a file or run Demo first.", "warn");
    return;
  }

  showSection("#analyze");
  showLoading(true, "Analyzing logs...");
  setProgress(5);

  try {
    if (!usingMemoryRows) {
      parsedRows = [];
      const forced = getSelectedLogType();

      for (let i = 0; i < uploadedFiles.length; i++) {
        const f = uploadedFiles[i];
        const txt = await readFileText(f);
        const type = forced === "auto" ? autoDetect(txt) : forced;

        if (type === "csv") {
          const res = Papa.parse(txt, { header: true, skipEmptyLines: true });
          const rows = (res.data || []).map(normalizeRow);
          parsedRows.push(...rows);
        } else if (type === "json") {
          const rows = parseJsonLoose(txt);
          parsedRows.push(...rows);
        } else {
          parsedRows.push(...parseTextLines(txt));
        }

        const pct = Math.round(((i + 1) / uploadedFiles.length) * 70) + 10;
        setProgress(pct);
      }
    }

    // UPGRADE: validate results
    if (!parsedRows.length) {
      toast("No events found in your file(s). Try a different format or run Demo.", "warn");
      setProgress(100);
      return;
    }

    // Summary
    const total = parsedRows.length;
    const users = new Set(parsedRows.map((r) => r.username).filter(Boolean));
    const repos = new Set(parsedRows.map((r) => r.repository).filter(Boolean));
    const ok = parsedRows.filter((r) => String(r.status).startsWith("2")).length;
    const successRate = total ? Math.round((ok / total) * 100) : 0;

    safeSetText("totalRequests", total.toLocaleString());
    safeSetText("uniqueUsers", users.size.toLocaleString());
    safeSetText("uniqueRepos", repos.size.toLocaleString());
    safeSetText("successRate", `${successRate}%`);

    // Time range
    const times = parsedRows.map((r) => parseDateSafe(r.timestamp)).filter(Boolean).map((d) => d.getTime());
    if (times.length) {
      const min = new Date(Math.min(...times));
      const max = new Date(Math.max(...times));
      safeSetText("timeFrom", formatDate(min));
      safeSetText("timeTo", formatDate(max));
      safeSetText("timeDuration", durationHuman(max.getTime() - min.getTime()));
    } else {
      safeSetText("timeFrom", "-");
      safeSetText("timeTo", "-");
      safeSetText("timeDuration", "-");
    }

    // Top lists
    fillTopList("topUsersList", topN(parsedRows, "username", 5));
    fillTopList("topReposList", topN(parsedRows, "repository", 5));
    fillTopList("topIPsList", topN(parsedRows, "ip_address", 5));

    setProgress(90);

    // Charts via visualizer.js
    if (window.renderAnalysisCharts) {
      window.renderAnalysisCharts(parsedRows);
    }

    setProgress(100);
    toast(`Analysis complete: ${total.toLocaleString()} events`, "success");
  } catch (err) {
    console.error(err);
    toast(`Analyze failed: ${err?.message || err}`, "danger");
  } finally {
    // UPGRADE: guarantees spinner stops even on error
    showLoading(false);
  }
}
window.analyzeLogs = analyzeLogs;

/* -----------------------------
   Demo / Samples
-------------------------------- */

// UPGRADE: load sample from your repo file: samples/sample_github_logs.json
async function loadSample(kind = "json") {
  // clear uploaded files so analyze reads from memory (fast + reliable)
  uploadedFiles = [];
  renderFileList();

  // 1) Try fetch real sample file in repo
  try {
    const url = "samples/sample_github_logs.json";
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`Sample fetch failed (${res.status})`);
    const data = await res.json();

    if (Array.isArray(data)) {
      parsedRows = data.map(normalizeRow);
    } else if (data && typeof data === "object") {
      parsedRows = [normalizeRow(data)];
    } else {
      parsedRows = [];
    }

    setAnalyzeEnabled(true);
    toast("Sample loaded from repo. Click Analyze Logs.", "success");
    showSection("#upload");
    return;
  } catch (e) {
    console.warn("Sample fetch fallback:", e);
  }

  // 2) Fallback: generate sample events
  parsedRows = generateSampleRows(320);
  setAnalyzeEnabled(true);
  toast("Sample generated. Click Analyze Logs.", "success");
  showSection("#upload");
}
window.loadSample = loadSample;

function runDemo() {
  // UPGRADE: demo is async safe
  loadSample("json");
}
window.runDemo = runDemo;

function generateSampleRows(n = 300) {
  const out = [];
  const now = Date.now();

  const users = ["octocat", "jr_support", "alice", "bob", "sam", "devops_kim"];
  const repos = ["j8roque/Log_Analyzer", "github/docs", "openai/openai-python", "nodejs/node"];
  const events = ["push", "pull_request", "issue_comment", "login", "repo_create", "release"];
  const statuses = ["200", "201", "204", "301", "404", "500"];
  const ips = ["192.168.1.1", "10.0.0.5", "172.16.0.9", "203.0.113.10", "198.51.100.23"];

  for (let i = 0; i < n; i++) {
    out.push(
      normalizeRow({
        timestamp: new Date(now - i * 45 * 60 * 1000).toISOString(),
        username: users[i % users.length],
        repository: repos[i % repos.length],
        event_type: events[i % events.length],
        status: statuses[i % statuses.length],
        ip_address: ips[i % ips.length],
      })
    );
  }
  return out;
}

/* -----------------------------
   Init
-------------------------------- */
window.addEventListener("load", () => {
  setupUpload();

  // UPGRADE: ensure default section loads
  const hash = window.location.hash || "#upload";
  showSection(hash);

  // UPGRADE: make Analyze button work even if user loaded sample
  setAnalyzeEnabled(false);

  // UPGRADE: toast CSS inject (only if your CSS doesn't include it yet)
  ensureToastStyles();
});

/* -----------------------------
   Small helpers
-------------------------------- */
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function ensureToastStyles() {
  if (document.getElementById("toastStyles")) return;

  const s = document.createElement("style");
  s.id = "toastStyles";
  s.textContent = `
    .toast { 
      background: rgba(15,23,42,0.92);
      border: 1px solid rgba(255,255,255,0.12);
      border-radius: 14px;
      box-shadow: 0 10px 24px rgba(0,0,0,0.22);
      padding: 0.7rem 0.85rem;
      max-width: 360px;
      backdrop-filter: blur(10px);
      animation: toastIn 180ms ease;
    }
    .toast.hide { opacity: 0; transform: translateY(6px); transition: 180ms ease; }
    .toast-inner { display:flex; gap:0.65rem; align-items:center; }
    .toast-dot { width:10px; height:10px; border-radius:999px; background:#60a5fa; }
    .toast-dot.success { background:#22c55e; }
    .toast-dot.warn { background:#fbbf24; }
    .toast-dot.danger { background:#fb7185; }
    .toast-text { color:#e5e7eb; font-weight:800; line-height:1.3; }
    .toast-x { margin-left:auto; border:none; background:transparent; color:#e5e7eb; font-size:18px; cursor:pointer; opacity:0.8; }
    .toast-x:hover { opacity:1; }
    @keyframes toastIn { from { opacity:0; transform: translateY(8px);} to { opacity:1; transform: translateY(0);} }
  `;
  document.head.appendChild(s);
}
