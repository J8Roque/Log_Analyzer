// visualizer.js
// Upgraded: tab switching + charts that render reliably after Demo/Analyze
// Requires: Chart.js loaded in index.html BEFORE this file

let charts = {};
let _lastRows = [];

/* -----------------------------
   Utilities
-------------------------------- */

/** Destroy an existing Chart.js instance safely */
function destroyChart(id) {
  if (charts[id]) {
    charts[id].destroy();
    delete charts[id];
  }
}

/** Count rows by a field, return sorted [label, count] */
function countBy(rows, key) {
  const m = new Map();
  for (const r of rows) {
    const raw = r?.[key];
    const v = raw === undefined || raw === null || String(raw).trim() === "" ? "(none)" : String(raw);
    m.set(v, (m.get(v) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

/** Parse ISO timestamp or return null */
function parseTS(v) {
  if (!v) return null;
  const d = new Date(v);
  if (!isNaN(d.getTime())) return d;
  return null;
}

/** Group counts by time granularity */
function groupByTime(rows, granularity) {
  const map = new Map();

  for (const r of rows) {
    const d = parseTS(r.timestamp);
    if (!d) continue;

    let key = "";
    if (granularity === "hour") {
      // YYYY-MM-DD HH:00
      key = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:00`;
    } else if (granularity === "week") {
      // ISO-like week key: YYYY-W##
      const wk = isoWeek(d);
      key = `${wk.year}-W${pad2(wk.week)}`;
    } else if (granularity === "month") {
      key = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}`;
    } else {
      // day
      key = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
    }

    map.set(key, (map.get(key) || 0) + 1);
  }

  const labels = [...map.keys()].sort();
  const data = labels.map((k) => map.get(k));
  return { labels, data };
}

/** Build hourly histogram 0-23 */
function hourlyHistogram(rows) {
  const arr = new Array(24).fill(0);
  for (const r of rows) {
    const d = parseTS(r.timestamp);
    if (!d) continue;
    arr[d.getHours()] += 1;
  }
  return arr;
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

/** ISO week calculation */
function isoWeek(date) {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
  return { year: d.getUTCFullYear(), week };
}

/** Safe get 2D context */
function getCtx(canvasId) {
  const el = document.getElementById(canvasId);
  if (!el) return null;
  return el.getContext("2d");
}

/** If Chart.js is missing, don’t crash */
function chartReady() {
  return typeof Chart !== "undefined";
}

/* -----------------------------
   Public hook called by analyzer.js
-------------------------------- */

window.renderAnalysisCharts = function (rows) {
  _lastRows = Array.isArray(rows) ? rows : [];

  // Analysis section charts
  renderEventDoughnut(_lastRows);
  renderStatusGrid(_lastRows);

  // Visualization section charts (if user clicks Visualize)
  renderTimeline(_lastRows);
  renderHourly(_lastRows);
  renderEventsBar(_lastRows);
  renderStatusPieAndTable(_lastRows);

  // Plotly dashboards are optional; we only render if Plotly exists
  renderDashboard(_lastRows);
};

/* -----------------------------
   Analysis section: event doughnut + status pills
-------------------------------- */

function renderEventDoughnut(rows) {
  if (!chartReady()) return;

  const eventData = countBy(rows, "event_type").slice(0, 10);
  const ctx = getCtx("eventChart");
  if (!ctx) return;

  destroyChart("eventChart");
  charts["eventChart"] = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: eventData.map((x) => x[0]),
      datasets: [{ data: eventData.map((x) => x[1]) }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom" },
        title: { display: false },
      },
    },
  });
}

function renderStatusGrid(rows) {
  const statusGrid = document.getElementById("statusGrid");
  if (!statusGrid) return;

  const statuses = countBy(rows, "status").slice(0, 12);
  statusGrid.innerHTML = statuses
    .map(
      ([code, cnt]) => `
      <div class="status-pill">
        <div class="code">${escapeHtml(code)}</div>
        <div class="count">${Number(cnt).toLocaleString()}</div>
      </div>
    `
    )
    .join("");
}

/* -----------------------------
   Visualize tabs: charts
-------------------------------- */

function renderTimeline(rows) {
  if (!chartReady()) return;
  const ctx = getCtx("timelineChart");
  if (!ctx) return;

  const gran = document.getElementById("timelineGranularity")?.value || "day";
  const { labels, data } = groupByTime(rows, gran);

  destroyChart("timelineChart");
  charts["timelineChart"] = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{ label: "Requests", data }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { maxTicksLimit: 10 } },
        y: { beginAtZero: true },
      },
    },
  });
}

function renderHourly(rows) {
  if (!chartReady()) return;
  const ctx = getCtx("hourlyChart");
  if (!ctx) return;

  const data = hourlyHistogram(rows);
  const labels = Array.from({ length: 24 }, (_, i) => `${pad2(i)}:00`);

  destroyChart("hourlyChart");
  charts["hourlyChart"] = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "Requests", data }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { maxTicksLimit: 12 } },
        y: { beginAtZero: true },
      },
    },
  });

  // Insights
  const max = Math.max(...data);
  const min = Math.min(...data);
  const peakHour = data.indexOf(max);
  const quietHour = data.indexOf(min);
  const avg = data.reduce((a, b) => a + b, 0) / (data.length || 1);

  setText("peakHour", `${pad2(peakHour)}:00 - ${pad2((peakHour + 1) % 24)}:00`);
  setText("quietHour", `${pad2(quietHour)}:00 - ${pad2((quietHour + 1) % 24)}:00`);
  setText("avgHourly", `${Math.round(avg).toLocaleString()} per hour`);
}

function renderEventsBar(rows) {
  if (!chartReady()) return;
  const ctx = getCtx("eventsChart");
  if (!ctx) return;

  const sortMode = document.getElementById("eventsSort")?.value || "frequency";
  let items = countBy(rows, "event_type").slice(0, 20);

  if (sortMode === "alphabetical") {
    items = items.slice().sort((a, b) => a[0].localeCompare(b[0]));
  }

  destroyChart("eventsChart");
  charts["eventsChart"] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: items.map((x) => x[0]),
      datasets: [{ label: "Count", data: items.map((x) => x[1]) }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { maxTicksLimit: 10 } },
        y: { beginAtZero: true },
      },
    },
  });
}

function renderStatusPieAndTable(rows) {
  if (!chartReady()) return;
  const ctx = getCtx("statusChart");
  if (!ctx) return;

  const items = countBy(rows, "status").slice(0, 12);
  const total = items.reduce((s, x) => s + x[1], 0) || 1;

  destroyChart("statusChart");
  charts["statusChart"] = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: items.map((x) => x[0]),
      datasets: [{ data: items.map((x) => x[1]) }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom" } },
    },
  });

  // Table
  const tbody = document.getElementById("statusTableBody");
  if (tbody) {
    tbody.innerHTML = items
      .map(([code, cnt]) => {
        const pct = Math.round((cnt / total) * 100);
        return `
          <tr>
            <td>${escapeHtml(code)}</td>
            <td>${statusCategory(code)}</td>
            <td>${Number(cnt).toLocaleString()}</td>
            <td>${pct}%</td>
          </tr>`;
      })
      .join("");
  }
}

function statusCategory(code) {
  const s = String(code);
  if (s.startsWith("2")) return "Success";
  if (s.startsWith("3")) return "Redirect";
  if (s.startsWith("4")) return "Client Error";
  if (s.startsWith("5")) return "Server Error";
  return "Other";
}

/* -----------------------------
   Dashboard (Plotly) optional
-------------------------------- */

function renderDashboard(rows) {
  if (typeof Plotly === "undefined") return;

  // Requests over time (daily)
  const t = groupByTime(rows, "day");
  const timelineDiv = document.getElementById("dashboardTimeline");
  if (timelineDiv) {
    Plotly.react(
      timelineDiv,
      [{ x: t.labels, y: t.data, type: "scatter", mode: "lines" }],
      { margin: { t: 30, l: 40, r: 20, b: 40 }, title: "" },
      { displayModeBar: false, responsive: true }
    );
  }

  // Event treemap
  const treemapDiv = document.getElementById("dashboardTreemap");
  if (treemapDiv) {
    const items = countBy(rows, "event_type").slice(0, 30);
    Plotly.react(
      treemapDiv,
      [{
        type: "treemap",
        labels: items.map((x) => x[0]),
        parents: items.map(() => ""),
        values: items.map((x) => x[1]),
      }],
      { margin: { t: 10, l: 10, r: 10, b: 10 } },
      { displayModeBar: false, responsive: true }
    );
  }

  // User activity (top 10)
  const usersDiv = document.getElementById("dashboardUsers");
  if (usersDiv) {
    const items = countBy(rows, "username").slice(0, 10);
    Plotly.react(
      usersDiv,
      [{ x: items.map((x) => x[0]), y: items.map((x) => x[1]), type: "bar" }],
      { margin: { t: 20, l: 40, r: 20, b: 60 } },
      { displayModeBar: false, responsive: true }
    );
  }

  // Hourly heatmap (simple 1x24)
  const heatDiv = document.getElementById("dashboardHeatmap");
  if (heatDiv) {
    const h = hourlyHistogram(rows);
    Plotly.react(
      heatDiv,
      [{
        z: [h],
        x: Array.from({ length: 24 }, (_, i) => pad2(i)),
        y: ["Hour"],
        type: "heatmap",
      }],
      { margin: { t: 20, l: 50, r: 20, b: 40 } },
      { displayModeBar: false, responsive: true }
    );
  }
}

/* -----------------------------
   Tab switching (fixes your “round tabs”)
-------------------------------- */

window.showVizTab = function (tab) {
  // Toggle active pill buttons
  document.querySelectorAll(".viz-tab").forEach((b) => b.classList.remove("active"));

  const btn = Array.from(document.querySelectorAll(".viz-tab")).find((b) =>
    (b.getAttribute("onclick") || "").includes(`'${tab}'`)
  );
  if (btn) btn.classList.add("active");

  // Toggle panels
  document.querySelectorAll(".viz-tab-content").forEach((c) => c.classList.remove("active"));

  const panel = document.getElementById(tab + "Tab");
  if (panel) panel.classList.add("active");

  // When switching tabs, re-render charts so they appear (Chart.js needs visible canvas size)
  if (_lastRows.length) {
    if (tab === "timeline") renderTimeline(_lastRows);
    if (tab === "hourly") renderHourly(_lastRows);
    if (tab === "events") renderEventsBar(_lastRows);
    if (tab === "status") renderStatusPieAndTable(_lastRows);
    if (tab === "dashboard") renderDashboard(_lastRows);
  }
};

// Dropdown updates
window.updateTimeline = function () {
  if (_lastRows.length) renderTimeline(_lastRows);
};

window.updateEventsChart = function () {
  if (_lastRows.length) renderEventsBar(_lastRows);
};

// Dashboard refresh button
window.refreshDashboard = function () {
  if (_lastRows.length) renderDashboard(_lastRows);
};

/* -----------------------------
   Download chart (optional)
-------------------------------- */

window.downloadChart = function (which) {
  const map = {
    timeline: charts["timelineChart"],
    hourly: charts["hourlyChart"],
    events: charts["eventsChart"],
    status: charts["statusChart"],
  };

  const chart = map[which];
  if (!chart) {
    alert("Nothing to download yet. Load data then open this tab.");
    return;
  }

  const a = document.createElement("a");
  a.href = chart.toBase64Image();
  a.download = `github_log_${which}.png`;
  a.click();
};

/* -----------------------------
   Helpers
-------------------------------- */

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
