(function () {
  var theme = localStorage.getItem('ndns-theme') || 'system';
  var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  var isDark = theme === 'dark' || (theme === 'system' && prefersDark);
  if (isDark) document.documentElement.classList.add('dark');
})();
