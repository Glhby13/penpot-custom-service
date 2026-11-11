(function () {
  'use strict';
  var f = document.getElementById('f');
  var err = document.getElementById('err');
  var errText = document.getElementById('err-text');
  var errClose = document.getElementById('err-close');
  var btnSubmit = document.getElementById('submit');
  var btnLocal = document.getElementById('local-btn');
  var localBox = document.getElementById('local-box');
  var uInput = document.getElementById('username');
  var pInput = document.getElementById('password');
  var togglePw = document.getElementById('toggle');
  var themeToggle = document.getElementById('theme-toggle');
  var themeIcon = document.getElementById('theme-icon');
  var brandLogo = document.getElementById('brand-logo');

  // Initial theme from localStorage or system preference
  var currentTheme = 'light';
  try {
    var saved = localStorage.getItem('uxstudio_theme');
    if (saved === 'dark' || saved === 'light') {
      currentTheme = saved;
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      currentTheme = 'dark';
    }
  } catch (e) { /* ignore */ }

  var themeTransTimer = null;
  function makeThemeSvg(isDark) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '18');
    svg.setAttribute('height', '18');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    if (isDark) {
      // Lucide sun icon (to switch to light mode)
      var c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('cx', '12'); c.setAttribute('cy', '12'); c.setAttribute('r', '4');
      svg.appendChild(c);
      ['M12 2v2', 'M12 20v2', 'm4.93 4.93 1.41 1.41', 'm17.66 17.66 1.41 1.41', 'M2 12h2', 'M20 12h2', 'm6.34 17.66-1.41 1.41', 'm19.07 4.93-1.41 1.41'].forEach(function (d) {
        var p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        p.setAttribute('d', d);
        svg.appendChild(p);
      });
    } else {
      // Lucide moon icon (to switch to dark mode)
      var p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      p.setAttribute('d', 'M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z');
      svg.appendChild(p);
    }
    return svg;
  }

  function applyTheme(mode, animate) {
    currentTheme = mode === 'dark' ? 'dark' : 'light';
    var root = document.documentElement;
    if (animate) {
      clearTimeout(themeTransTimer);
      root.classList.add('theme-transition');
      themeTransTimer = setTimeout(function () {
        root.classList.remove('theme-transition');
      }, 400);
    }
    root.setAttribute('data-theme', currentTheme);

    if (brandLogo) {
      var nextSrc = currentTheme === 'dark' ? '/auth-ui/assets/logo-dark.png' : '/auth-ui/assets/logo.png';
      if (animate && brandLogo.getAttribute('src') !== nextSrc) {
        brandLogo.style.opacity = '0.35';
        setTimeout(function () {
          brandLogo.src = nextSrc;
          brandLogo.style.opacity = '1';
        }, 120);
      } else {
        brandLogo.src = nextSrc;
      }
    }

    if (themeIcon) {
      themeIcon.textContent = '';
      if (animate) {
        themeIcon.classList.remove('pop');
        void themeIcon.offsetWidth;
        themeIcon.classList.add('pop');
      }
      themeIcon.appendChild(makeThemeSvg(currentTheme === 'dark'));
    }

    try { localStorage.setItem('uxstudio_theme', currentTheme); } catch (e) { /* ignore */ }
  }

  // Initial application
  applyTheme(currentTheme, false);

  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      applyTheme(currentTheme === 'dark' ? 'light' : 'dark', true);
    });
  }

  if (togglePw && pInput) {
    togglePw.addEventListener('click', function () {
      var isPw = pInput.type === 'password';
      pInput.type = isPw ? 'text' : 'password';
      togglePw.textContent = isPw ? 'Hide' : 'Show';
      pInput.focus();
    });
  }

  function showErr(msg) {
    if (errText) errText.textContent = msg;
    if (err) err.hidden = false;
  }
  function clearErr() {
    if (err) err.hidden = true;
    if (errText) errText.textContent = '';
  }

  if (errClose) {
    errClose.addEventListener('click', clearErr);
  }

  // Check if local login should be shown
  fetch('/auth-ui/config', { credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (c) { if (c && c.local && localBox) localBox.hidden = false; })
    .catch(function () { /* ignore */ });

  var busy = false;
  function doSubmit(path) {
    if (busy) return;
    clearErr();
    var user = uInput ? uInput.value.trim() : '';
    var pass = pInput ? pInput.value : '';
    if (!user || !pass) {
      showErr('Enter your username and password.');
      return;
    }
    busy = true;
    if (btnSubmit) btnSubmit.disabled = true;
    if (btnLocal) btnLocal.disabled = true;

    fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        return { status: r.status, body: j };
      });
    }).then(function (res) {
      if (res.status === 200) {
        var hash = location.hash;
        if (!hash || /^#\/auth\//.test(hash)) hash = '#/dashboard';
        location.replace('/' + hash);
        return;
      }
      var msg = (res.body && res.body.error_description) ||
        (res.status === 429 ? 'Too many failed attempts. Please try again later.' : 'Username or password is incorrect.');
      showErr(msg);
    }).catch(function () {
      showErr('Cannot reach the authentication server. Please try again.');
    }).then(function () {
      busy = false;
      if (btnSubmit) btnSubmit.disabled = false;
      if (btnLocal) btnLocal.disabled = false;
    });
  }

  if (f) {
    f.addEventListener('submit', function (e) {
      e.preventDefault();
      doSubmit('/auth-ui/login');
    });
  }
  if (btnLocal) {
    btnLocal.addEventListener('click', function () {
      doSubmit('/auth-ui/login/local');
    });
  }
})();
