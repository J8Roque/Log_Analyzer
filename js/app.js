// app.js
// Purpose: single page navigation + mobile menu + demo loader (samples/sample_github_logs.json)

/* -----------------------------
   Navigation (single page)
-------------------------------- */

/**
 * showSection(id)
 * Shows one <section> by toggling the "active" class and updates the nav + URL hash.
 * @param {string} id - "#upload" | "#analyze" | "#visualize" | "#export"
 */
function showSection(id) {
  // Hide all sections
  document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));

  // Show the requested section
  const el = document.querySelector(id);
  if (el) el.classList.add("active");

  // Update desktop nav active state
  document.querySelectorAll(".nav-link").forEach((a) => a.classList.remove("active"));
  document.querySelectorAll(`.nav-link[href="${id}"]`).forEach((a) => a.classList.add("active"));

  // Keep URL hash in sync without reloading
  history.replaceState(null, "", id);

  // Scroll to top for clean transitions
  window.scrollTo({ top: 0, behavior: "smooth" });
}

/**
 * toggleMobileMenu()
 * Opens/closes the mobile nav drawer.
 */
function toggleMobileMenu() {
  document.getElementById("mobileMenu")?.classList.toggle("active");
}

/* Desktop nav clicks */
document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    showSection(link.getAttribute("href"));
  });
});

/* Mobile nav clicks */
document.querySelectorAll(".mobile-nav-link").forEach((link) => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    toggleMobileMenu();
    showSection(link.getAttribute("href"));
  });
});

/* First load: go to hash or default upload */
window.addEventListener("load", () => {
  const hash = window.location.hash || "#upload";
  showSection(hash);
});

/* -----------------------------
   Demo loader (sample file)
-------------------------------- */

/**
 * runDemo()
 * Loads a sample file from the repo: samples/sample_github_logs.json
 * Then stores it in a global variable and triggers analysis.
 *
 * Requirements:
 * - You have a file at: /samples/sample_github_logs.json
 * - Your analyzer code reads from one of these:
 *      window.__uploadedLogs  (recommended)
 *   OR window.uploadedLogs / window.logsData (we set a few aliases below)
 * - Your analyze function exists:
 *      analyzeLogs()
 */
async function runDemo() {
  try {
    // Optional: show toast if you have a toast system
    if (typeof showToast === "function") showToast("Loading demo sample...", "info");

    // Fetch the sample from your repo (works on GitHub Pages)
    const res = await fetch("samples/sample_github_logs.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`Sample not found (HTTP ${res.status}). Check path + commit.`);

    // Parse JSON
    const data = await res.json();

    // Store globally so analyzer.js can use it
    window.__uploadedLogs = data;

    // Compatibility aliases (in case your analyzer uses a different variable name)
    window.uploadedLogs = data;
    window.logsData = data;

    // Enable Analyze button if it exists
    const analyzeBtn = document.getElementById("analyzeBtn");
    if (analyzeBtn) analyzeBtn.disabled = false;

    // Move user to analyze section
    showSection("#analyze");

    // Trigger analysis if your function exists
    if (typeof analyzeLogs === "function") {
      analyzeLogs(); // your analyzer.js should read window.__uploadedLogs
    } else {
      console.warn("analyzeLogs() not found. Make sure analyzer.js defines it.");
      alert("Demo loaded, but analyzeLogs() was not found. Check analyzer.js.");
    }

    if (typeof showToast === "function") showToast("Demo loaded!", "success");
  } catch (err) {
    console.error(err);
    if (typeof showToast === "function") showToast(`Demo failed: ${err.message}`, "error");
    alert(`Demo failed: ${err.message}`);
  }
}
