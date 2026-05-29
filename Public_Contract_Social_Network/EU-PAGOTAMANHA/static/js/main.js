(function () {
  const root = document.documentElement;

  if (!root.dataset.theme) {
    const savedTheme = localStorage.getItem("theme");
    root.dataset.theme = savedTheme === "dark" ? "dark" : "light";
  }

  const btn = document.querySelector("[data-theme-toggle]");
  const label = document.querySelector("[data-theme-label]");

  function syncThemeButton() {
    if (label) {
      label.textContent = root.dataset.theme === "dark" ? "Dark" : "Light";
    }
  }

  syncThemeButton();
  root.classList.add("theme-ready");

  if (btn) {
    btn.addEventListener("click", () => {
      root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
      localStorage.setItem("theme", root.dataset.theme);
      syncThemeButton();
    });
  }

  const navToggle = document.querySelector('[data-nav-toggle]');
  const navLinks = document.querySelector('[data-nav-links]');
  if (navToggle && navLinks) {
    navToggle.addEventListener('click', () => navLinks.classList.toggle('is-open'));
  }

  const encryptionToggle = document.querySelector('[data-encryption-toggle]');
  const panel = document.querySelector('[data-encryption-panel]');
  if (encryptionToggle && panel) {
    function syncEncryptionPanel() {
      panel.hidden = !encryptionToggle.checked;
    }
    encryptionToggle.addEventListener('change', syncEncryptionPanel);
    syncEncryptionPanel();
  }
})();