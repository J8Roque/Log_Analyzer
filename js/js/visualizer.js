// visualizer.js
let charts = {};

function destroyChart(id) {
  if (charts[id]) {
    charts[id].destroy();
    delete charts[id];
  }
}

function countBy(rows, key) {
  const m = new Map();
  for (const r of rows) {
    const v = r[key] || "(none)";
    m.set(v, (m.get(v) || 0) + 1);
  }
  return [...m.entries()].sort((a,b)=>b[1]-a[1]);
}

window.renderAnalysisCharts = function(rows) {
  // Event distribution pie
  const eventData = countBy(rows, "event_type").slice(0, 10);
  const ctx = document.getElementById("eventChart")?.getContext("2d");
  if (ctx) {
    destroyChart("eventChart");
    charts["eventChart"] = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: eventData.map(x => x[0]),
        datasets: [{ data: eventData.map(x => x[1]) }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: "bottom" } }
      }
    });
  }

  // Status grid
  const statusGrid = document.getElementById("statusGrid");
  if (statusGrid) {
    const statuses = countBy(rows, "status").slice(0, 12);
    statusGrid.innerHTML = statuses.map(([code, cnt]) => `
      <div class="status-pill">
        <div class="code">${code}</div>
        <div class="count">${cnt.toLocaleString()}</div>
      </div>
    `).join("");
  }
};

// Viz tabs
function showVizTab(tab) {
  document.querySelectorAll(".viz-tab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".viz-tab-content").forEach(c => c.classList.remove("active"));

  const btn = Array.from(document.querySelectorAll(".viz-tab")).find(b => b.getAttribute("onclick")?.includes(`'${tab}'`));
  if (btn) btn.classList.add("active");

  const panel = document.getElementById(tab + "Tab");
  if (panel) panel.classList.add("active");
}
window.showVizTab = showVizTab;
