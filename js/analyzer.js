// analyzer.js
let uploadedFiles = [];
let parsedRows = [];

const $ = (id) => document.getElementById(id);

function toast(msg) {
  // super simple toast
  alert(msg);
}

function getSelectedLogType() {
  const el = document.querySelector('input[name="logType"]:checked');
  return el ? el.value : "auto";
}

function clearFiles() {
  uploadedFiles = [];
  parsedRows = [];
  if ($("fileInput")) $("fileInput").value = "";
  renderFileList();
  $("analyzeBtn").disabled = true;
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

  list.innerHTML = uploadedFiles.map((f, idx) => `
    <div class="file-item">
      <div class="file-info">
        <i class="fas fa-file file-icon"></i>
        <div class="file-details">
          <div class="file-name">${f.name}</div>
          <div class="file-size">${(f.size / 1024).toFixed(1)} KB</div>
        </div>
      </div>
      <button class="file-remove" title="Remove" onclick="removeFile(${idx})">
        <i class="fas fa-times"></i>
      </button>
    </div>
  `).join("");
}

function removeFile(i) {
  uploadedFiles.splice(i, 1);
  renderFileList();
  $("analyzeBtn").disabled = uploadedFiles.length === 0;
}

function setupUpload() {
  const input = $("fileInput");
  const dropArea = $("dropArea");

  if (input) {
    input.addEventListener("change", (e) => {
      addFiles([...e.target.files]);
    });
  }

  if (dropArea) {
    ["dragenter","dragover"].forEach(evt => {
      dropArea.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.add("dragover");
      });
    });
    ["dragleave","drop"].forEach(evt => {
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
  const allowed = [".json",".csv",".txt",".log",".ndjson"];
  const good = files.filter(f => allowed.some(ext => f.name.toLowerCase().endsWith(ext)));
  if (good.length === 0) {
    toast("No supported files. Use .json, .csv, .txt, .log, .ndjson");
    return;
  }
  uploadedFiles.push(...good);
  renderFileList();
  $("analyzeBtn").disabled = uploadedFiles.length === 0;
}

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
  // try to standardize keys you likely have
  return {
    timestamp: obj.timestamp || obj.created_at || obj.time || obj.date || "",
    username: obj.username || obj.user || obj.actor || "",
    repository: obj.repository || obj.repo || obj.repo_name || "",
    event_type: obj.event_type || obj.action || obj.event || obj.type || "",
    status: obj.status || obj.status_code || obj.code || "",
    ip_address: obj.ip_address || obj.ip || obj.remote_ip || "",
  };
}

async function analyzeLogs() {
  if (uploadedFiles.length === 0) {
    toast("Upload a file first.");
    return;
  }

  // show analyze section and loading
  document.querySelector("#analysisResults").style.display = "none";
  document.querySelector("#loadingState").style.display = "block";
  showSection("#analyze");

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
      let obj = JSON.parse(txt);
      if (Array.isArray(obj)) {
        parsedRows.push(...obj.map(normalizeRow));
      } else if (obj && typeof obj === "object") {
        parsedRows.push(normalizeRow(obj));
      }
    } else {
      // text: store each line as event_type
      txt.split(/\r?\n/).filter(Boolean).forEach(line => {
        parsedRows.push({ timestamp: "", username: "", repository: "", event_type: line.slice(0, 80), status: "", ip_address: "" });
      });
    }

    // update progress bar if present
    const pct = Math.round(((i + 1) / uploadedFiles.length) * 100);
    const pf = $("progressFill");
    if (pf) pf.style.width = pct + "%";
  }

  // compute summary
  const total = parsedRows.length;
  const users = new Set(parsedRows.map(r => r.username).filter(Boolean));
  const repos = new Set(parsedRows.map(r => r.repository).filter(Boolean));
  const ok = parsedRows.filter(r => String(r.status).startsWith("2")).length;
  const successRate = total ? Math.round((ok / total) * 100) : 0;

  $("totalRequests").textContent = total.toLocaleString();
  $("uniqueUsers").textContent = users.size.toLocaleString();
  $("uniqueRepos").textContent = repos.size.toLocaleString();
  $("successRate").textContent = successRate + "%";

  // top lists
  const topN = (arr, key) => {
    const m = new Map();
    for (const r of arr) {
      const v = r[key];
      if (!v) continue;
      m.set(v, (m.get(v) || 0) + 1);
    }
    return [...m.entries()].sort((a,b) => b[1]-a[1]).slice(0, 5);
  };

  fillTopList("topUsersList", topN(parsedRows, "username"));
  fillTopList("topReposList", topN(parsedRows, "repository"));
  fillTopList("topIPsList", topN(parsedRows, "ip_address"));

  // charts
  if (window.renderAnalysisCharts) {
    window.renderAnalysisCharts(parsedRows);
  }

  // done
  document.querySelector("#loadingState").style.display = "none";
  document.querySelector("#analysisResults").style.display = "block";
}

function fillTopList(elId, items) {
  const el = $(elId);
  if (!el) return;
  if (!items.length) {
    el.innerHTML = `<div class="list-item"><span class="list-rank">-</span><span class="list-name">No data</span><span class="list-count">0</span></div>`;
    return;
  }
  el.innerHTML = items.map((it, idx) => `
    <div class="list-item">
      <span class="list-rank">${idx + 1}</span>
      <span class="list-name">${it[0]}</span>
      <span class="list-count">${it[1].toLocaleString()}</span>
    </div>
  `).join("");
}

function loadSample(kind) {
  // quick demo dataset
  const sample = [];
  const now = Date.now();
  const users = ["octocat","dev_j","alice","bob","sam"];
  const repos = ["j8roque/Log_Analyzer","github/docs","openai/openai-python"];
  const events = ["push","pull_request","issue_comment","login","repo_create"];
  const statuses = ["200","201","204","404","500"];
  const ips = ["192.168.1.1","10.0.0.5","172.16.0.9","203.0.113.10"];

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
  $("analyzeBtn").disabled = false;
  toast("Loaded sample data. Click Analyze Logs.");
}

function runDemo() {
  loadSample("json");
  analyzeLogs();
}

window.addEventListener("load", setupUpload);
