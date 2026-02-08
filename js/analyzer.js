// analyzer.js
// Purpose: handle uploads + parsing + analysis + wiring the Demo sample into the same pipeline

let uploadedFiles = [];
let parsedRows = [];

const $ = (id) => document.getElementById(id);

/* -----------------------------
   Notes: what each part does
--------------------------------
uploadedFiles  = files chosen by user (File objects)
parsedRows     = normalized log rows ready for stats/charts

setupUpload()  = wires drag drop + file input
addFiles()     = validates extensions and stores files
analyzeLogs()  = reads either demo data OR uploaded files, parses, normalizes, computes stats
normalizeRow() = converts many possible field names into a consistent schema
fillTopList()  = renders Top Users, Top Repos, Top IPs
loadSample()   = creates a quick fake dataset in memory (not needed if you use runDemo from app.js)
-------------------------------- */

function toast(msg) {
  // super simple toast (you can replace later with a real toast UI)
  alert(msg);
}

function getSelectedLogType() {
  // reads the radio selection: auto, json, csv, text
  const el = document.querySelector('input[name="logType"]:checked');
  return el ? el.value : "auto";
}

function clearFiles() {
  uploadedFiles = [];
  parsedRows = [];
  window.__uploadedLogs = undefined; // also clear demo data if present

  if ($("fileInput")) $("fileInput").value = "";
  renderFileList();
  if ($("analyzeBtn")) $("analyzeBtn").disabled = true;

  toast("Cleared files.");
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
          <div class="file-name">${escapeHtml(f.name)}</div>
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
  if ($("analyzeBtn")) $("analyzeBtn").disabled = uploadedFiles.length === 0;
}

function setupUpload() {
  const input = $("fileInput");
  const dropArea = $("dropArea");

  // file picker
  if (input) {
    input.addEventListener("change", (e) => {
      addFiles([...e.target.files]);
    });
  }

  // drag drop
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
  }
}

function addFiles(files) {
  const allowed = [".json", ".csv", ".txt", ".log", ".ndjson"];
  const good = files.filter((f) => allowed.some((ext) => f.name.toLowerCase().endsWith(ext)));

  if (good.length === 0) {
    toast("No supported files. Use .json, .csv, .txt, .log, .ndjson");
    return;
  }

  uploadedFiles.push(...good);
  renderFileList();
  if ($("analyzeBtn")) $("analyzeBtn").disabled = uploadedFiles.length === 0;

  // if user uploads files, demo data should not interfere
  window.__uploadedLogs = undefined;
}

async function readFileText(file) {
  return await file.text();
}

function autoDetect(text) {
  // quick format detection
  const s = text.trimStart();
  if (s.startsWith("{") || s.startsWith("[")) return "json";
  const first = text.split(/\r?\n/)[0] || "";
  if (first.includes(",")) return "csv";
  return "text";
}

/**
 * normalizeRow(obj)
 * Converts different field names into one consistent shape your UI expects.
 * This makes your analyzer work with different log formats.
 */
function normalizeRow(obj) {
  return {
    timestamp: obj.timestamp || obj.created_at || obj.time || obj.date || "",
    username: obj.username || obj.user || obj.actor || obj.login || "",
    repository: obj.repository || obj.repo || obj.repo_name || obj.repo_full_name || "",
    event_type: obj.event_type || obj.event || obj.type || obj.action || "",
    status: obj.status || obj.status_code || obj.code || "",
    ip_address: obj.ip_address || obj.ip || obj.remote_ip || "",
  };
}

/* -----------------------------
   Upgrade: unified analyzer
   - Works with demo (window.__uploadedLogs)
   - Works with uploads (uploadedFiles)
-------------------------------- */
async function analyzeLogs() {
  // Show analyze section and loading
  safeDisplay("#analysisResults", "none");
  safeDisplay("#loadingState", "block");
  if (typeof showSection === "function") showSection("#analyze");

  // 1) Demo path: window.__uploadedLogs exists and has data
  if (Array.isArray(window.__uploadedLogs) && window.__uploadedLogs.length > 0) {
    parsedRows = window.__uploadedLogs.map(normalizeRow);
    updateProgress(100);
    renderAnalysis(parsedRows);
    return;
  }

  // 2) Upload path
  if (uploadedFiles.length === 0) {
    safeDisplay("#loadingState", "none");
    toast("Upload a file first or click Demo.");
    return;
  }

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
      const obj = JSON.parse(txt);

      // NDJSON support: sometimes "json" is actually line delimited
      if (typeof obj === "string") {
        // ignore
      }

      if (Array.isArray(obj)) {
        parsedRows.push(...obj.map(normalizeRow));
      } else if (obj && typeof obj === "object") {
        parsedRows.push(normalizeRow(obj));
      }
    } else {
      // text/log: store each line as an event_type so you still see something
      txt
        .split(/\r?\n/)
        .filter(Boolean)
        .forEach((line) => {
          parsedRows.push({
            timestamp: "",
            username: "",
            repository: "",
            event_type: line.slice(0, 120),
            status: "",
            ip_address: "",
          });
        });
    }

    const pct = Math.round(((i + 1) / uploadedFiles.length) * 100);
    updateProgress(pct);
  }

  renderAnalysis(parsedRows);
}

/* -----------------------------
   Analysis rendering (UI updates)
-------------------------------- */
function renderAnalysis(rows) {
  // compute summary
  const total = rows.length;

  const users = new Set(rows.map((r) => r.username).filter(Boolean));
  const repos = new Set(rows.map((r) => r.repository).filter(Boolean));

  // "success" = HTTP 2xx
  const ok = rows.filter((r) => String(r.status).startsWith("2")).length;
  const successRate = total ? Math.round((ok / total) * 100) : 0;

  if ($("totalRequests")) $("totalRequests").textContent = total.toLocaleString();
  if ($("uniqueUsers")) $("uniqueUsers").textContent = users.size.toLocaleString();
  if ($("uniqueRepos")) $("uniqueRepos").textContent = repos.size.toLocaleString();
  if ($("successRate")) $("successRate").textContent = successRate + "%";

  // top lists
  const topN = (arr, key) => {
    const m = new Map();
    for (const r of arr) {
      const v = r[key];
      if (!v) continue;
      m.set(v, (m.get(v) || 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  };

  fillTopList("topUsersList", topN(rows, "username"));
  fillTopList("topReposList", topN(rows, "repository"));
  fillTopList("topIPsList", topN(rows, "ip_address"));

  // chart hook (if your visualizer.js defines this)
  if (window.renderAnalysisCharts) {
    window.renderAnalysisCharts(rows);
  }

  // done states
  safeDisplay("#loadingState", "none");
  safeDisplay("#analysisResults", "block");
}

function fillTopList(elId, items) {
  const el = $(elId);
  if (!el) return;

  if (!items.length) {
    el.innerHTML = `
      <div class="list-item">
        <span class="list-rank">-</span>
        <span class="list-name">No data</span>
        <span class="list-count">0</span>
      </div>`;
    return;
  }

  el.innerHTML = items
    .map(
      (it, idx) => `
    <div class="list-item">
      <span class="list-rank">${idx + 1}</span>
      <span class="list-name">${escapeHtml(it[0])}</span>
      <span class="list-count">${Number(it[1]).toLocaleString()}</span>
    </div>
  `
    )
    .join("");
}

/* -----------------------------
   Optional: quick fake sample generator
   Not required if you use runDemo() in app.js that fetches the repo sample JSON.
-------------------------------- */
function loadSample() {
  const sample = [];
  const now = Date.now();
  const users = ["octocat", "dev_j", "alice", "bob", "sam"];
  const repos = ["j8roque/Log_Analyzer", "github/docs", "openai/openai-python"];
  const events = ["push", "pull_request", "issue_comment", "login", "repo_create"];
  const statuses = ["200", "201", "204", "404", "500"];
  const ips = ["192.168.1.1", "10.0.0.5", "172.16.0.9", "203.0.113.10"];

  for (let i = 0; i < 300; i++) {
    sample.push({
      timestamp: new Date(now - i * 3600_000).toISOString(),
      username: users[i % users.length],
      repository: repos[i % repos.length],
      event_type: events[i % events.length],
      status: statuses[i % statuses.length],
      ip_address: ips[i % ips.length],
    });
  }

  parsedRows = sample;
  window.__uploadedLogs = sample; // make it compatible with the unified analyzeLogs()
  if ($("analyzeBtn")) $("analyzeBtn").disabled = false;
  toast("Loaded sample data.");
}

/* -----------------------------
   Utilities
-------------------------------- */
function updateProgress(pct) {
  const pf = $("progressFill");
  if (pf) pf.style.width = pct + "%";
}

function safeDisplay(selector, displayValue) {
  const el = document.querySelector(selector);
  if (el) el.style.display = displayValue;
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
   IMPORTANT UPGRADE NOTE
--------------------------------
Delete ANY runDemo() inside this file.
runDemo() must live only in app.js so it does not get overwritten.
-------------------------------- */

// Boot
window.addEventListener("load", setupUpload);
