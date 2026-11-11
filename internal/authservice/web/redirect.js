// Added to Penpot's HTML by penpot-auth-service. Penpot's own login screen is never shown: whenever the app moves to
// its login route (session expired or sign-out) the page is hidden at once and "/" is loaded again, which without a
// session is the sign-in page of this service.
(function () {
  'use strict';
  var KEY = 'penpotAuthRedirectedAt';
  var root = document.documentElement;
  function onLogin() { return /^#\/auth\/login/.test(location.hash); }
  function check() {
    if (!onLogin()) { root.removeAttribute('data-uxstudio-login-route'); return; }
    // Hide the stock form immediately, even if the redirect below is held back.
    root.setAttribute('data-uxstudio-login-route', 'true');
    try {
      // A redirect that came straight back (session check failed) is not repeated for 10 s: no redirect loop.
      var last = parseInt(sessionStorage.getItem(KEY) || '0', 10);
      if (Date.now() - last < 10000) { root.removeAttribute('data-uxstudio-login-route'); return; }
      sessionStorage.setItem(KEY, String(Date.now()));
    } catch (e) { return; }
    location.replace('/');
  }
  check();
  window.addEventListener('hashchange', check);
})();
