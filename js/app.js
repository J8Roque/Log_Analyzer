// app.js
function showSection(id) {
  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  const el = document.querySelector(id);
  if (el) el.classList.add("active");

  document.querySelectorAll(".nav-link").forEach(a => a.classList.remove("active"));
  document.querySelectorAll(`.nav-link[href="${id}"]`).forEach(a => a.classList.add("active"));

  // keep URL hash in sync
  history.replaceState(null, "", id);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function toggleMobileMenu() {
  document.getElementById("mobileMenu")?.classList.toggle("active");
}

document.querySelectorAll(".nav-link").forEach(link => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    showSection(link.getAttribute("href"));
  });
});

document.querySelectorAll(".mobile-nav-link").forEach(link => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    toggleMobileMenu();
    showSection(link.getAttribute("href"));
  });
});

// on first load, go to hash or upload
window.addEventListener("load", () => {
  const hash = window.location.hash || "#upload";
  showSection(hash);
});
