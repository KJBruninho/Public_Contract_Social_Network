(function () {
  const root = document.documentElement;
  const saved = localStorage.getItem('theme') || 'light';
  root.dataset.theme = saved;
  const btn = document.querySelector('[data-theme-toggle]');
  function sync() { if (btn) btn.textContent = root.dataset.theme === 'dark' ? '☾' : '☀︎'; }
  sync();
  if (btn) btn.addEventListener('click', () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('theme', root.dataset.theme);
    sync();
  });
  const navToggle = document.querySelector('[data-nav-toggle]');
  const navLinks = document.querySelector('[data-nav-links]');
  if (navToggle && navLinks) navToggle.addEventListener('click', () => navLinks.classList.toggle('is-open'));
  const encryptionToggle = document.querySelector('[data-encryption-toggle]');
  const panel = document.querySelector('[data-encryption-panel]');
  if (encryptionToggle && panel) encryptionToggle.addEventListener('change', () => { panel.hidden = !encryptionToggle.checked; });
})();
