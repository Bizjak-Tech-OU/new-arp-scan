(function () {
  const storageKey = "new-arp-scan-theme";

  function apply(theme) {
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }

  function init() {
    const stored = localStorage.getItem(storageKey);
    if (stored === "light" || stored === "dark") {
      apply(stored);
      return;
    }
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    apply(prefersDark ? "dark" : "light");
  }

  window.toggleNewArpScanTheme = function () {
    const next = document.documentElement.classList.contains("dark") ? "light" : "dark";
    localStorage.setItem(storageKey, next);
    apply(next);
  };

  init();
})();
