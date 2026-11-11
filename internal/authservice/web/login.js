(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var form = $('f'), userEl = $('username'), passEl = $('password'), err = $('err'), go = $('go'), local = $('local'),
    localBox = $('local-box'), show = $('show'), theme = $('theme');
  var root = document.documentElement;

  // Light or dark: the saved choice, else the system setting.
  try {
    var saved = localStorage.getItem('uxTheme');
    if (saved === 'dark' || saved === 'light') root.setAttribute('data-theme', saved);
    else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) root.setAttribute('data-theme', 'dark');
  } catch (e) { /* storage blocked: keep the default */ }
  theme.addEventListener('click', function () {
    var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('uxTheme', next); } catch (e) { /* ignore */ }
  });

  show.addEventListener('click', function () {
    var hidden = passEl.type === 'password';
    passEl.type = hidden ? 'text' : 'password';
    show.textContent = hidden ? 'Hide' : 'Show';
    passEl.focus();
  });

  // The local (break-glass) button only appears when the service has local accounts configured.
  fetch('/auth-ui/config', { credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (c) { if (c && c.local) localBox.hidden = false; })
    .catch(function () { /* stays hidden */ });

  function showErr(msg) { err.textContent = msg; err.hidden = false; }

  var busy = false;
  function submit(path) {
    if (busy) return;
    err.hidden = true;
    var name = userEl.value.trim();
    if (!name || !passEl.value) { showErr('Enter your username and password.'); return; }
    busy = true; go.disabled = true; local.disabled = true;
    fetch(path, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: name, password: passEl.value })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, body: j }; });
    }).then(function (res) {
      if (res.status === 200) {
        // Keep a deep link (#/workspace/...) but never land back on a Penpot login route. The query makes it a
        // new address, so the browser loads it instead of only moving inside this page.
        var hash = location.hash;
        if (/^#\/auth\//.test(hash)) hash = '';
        location.replace('/?_=' + Date.now() + hash);
        return;
      }
      showErr((res.body && res.body.error_description) || (res.status === 429 ? 'Too many attempts. Try again later.' : 'Sign-in failed.'));
    }).catch(function () {
      showErr('Cannot reach the server. Try again.');
    }).then(function () { busy = false; go.disabled = false; local.disabled = false; });
  }

  form.addEventListener('submit', function (e) { e.preventDefault(); submit('/auth-ui/login'); });
  local.addEventListener('click', function () { submit('/auth-ui/login/local'); });
})();
