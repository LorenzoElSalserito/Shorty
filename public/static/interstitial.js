// Interstitial countdown. The server enforces the same delay on go.php,
// so this script is a courtesy, not a control.
(function () {
  var btn = document.getElementById('continue');
  var out = document.getElementById('countdown');
  if (!btn || !out) return;
  var left = parseInt(btn.getAttribute('data-delay') || '0', 10);
  if (!(left > 0)) return;
  var label = btn.textContent;
  btn.disabled = true;
  out.hidden = false;
  function tick() {
    if (left <= 0) {
      btn.disabled = false;
      btn.textContent = label;
      out.hidden = true;
      return;
    }
    out.textContent = 'Puoi continuare tra ' + left + (left === 1 ? ' secondo.' : ' secondi.');
    left -= 1;
    setTimeout(tick, 1000);
  }
  tick();
})();
