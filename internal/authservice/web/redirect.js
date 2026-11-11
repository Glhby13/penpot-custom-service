// Added to Penpot's HTML by penpot-auth-service. When Penpot's own app moves to its login route (session expired or
// sign-out), load "/" again: without a session that is the sign-in page of this service.
(function () {
  'use strict';
  var KEY = 'penpotAuthRedirectedAt';
  function check() {
    if (!/^#\/auth\/login/.test(location.hash)) return;
    try {
      // At most once per 10 s, so a failed session check can never turn this into a redirect loop.
      var last = parseInt(sessionStorage.getItem(KEY) || '0', 10);
      if (Date.now() - last < 10000) return;
      sessionStorage.setItem(KEY, String(Date.now()));
    } catch (e) { return; }
    location.replace('/?_=' + Date.now());
  }
  check();
  window.addEventListener('hashchange', check);
})();
