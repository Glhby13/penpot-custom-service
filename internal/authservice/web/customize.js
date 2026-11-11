// Author / Agent: Codex. UI capabilities are server-derived, never inferred from local storage or user input.
// This script is presentation only; the gateway independently protects token RPCs and MCP transports.
(function () {
  'use strict';
  var root = document.documentElement;
  var status = 'pending';
  var refreshing = false;

  function hideEnterprisePromotion() {
    // Upstream gives promotion and license-renewal warnings the same CSS class and no action/test ID.
    // Match the exact English heading in that scoped component, never arbitrary page text. If upstream
    // changes the heading or the user selects another language, leave the card visible instead of
    // accidentally hiding a renewal warning. Verified with the stock Penpot 2.18.4 source.
    document.querySelectorAll('.main_ui_dashboard_subscription__nitrate-banner').forEach(function (banner) {
      var title = banner.querySelector('.main_ui_dashboard_subscription__nitrate-title');
      var promotional = title && title.textContent.trim() === 'Unlock Enterprise features';
      if (promotional) banner.setAttribute('data-uxstudio-enterprise-promo', 'true');
      else banner.removeAttribute('data-uxstudio-enterprise-promo');
    });
  }

  function integrationsRoute() {
    return /^#\/settings\/integrations(?:[/?]|$)/.test(location.hash);
  }

  function guardRoute() {
    if (status === 'denied' && integrationsRoute()) {
      location.replace('#/settings/profile');
    }
  }

  function setStatus(next) {
    status = next;
    root.setAttribute('data-uxstudio-mcp', next);
    guardRoute();
  }

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    setStatus('pending');
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 5000);
    try {
      var response = await fetch('/auth-ui/capabilities', {
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      });
      if (!response.ok) throw new Error('capability unavailable');
      var capability = await response.json();
      setStatus(capability.mcp === true ? 'allowed' : 'denied');
    } catch (_) {
      setStatus('denied');
    } finally {
      clearTimeout(timeout);
      refreshing = false;
    }
  }

  setStatus('pending');
  hideEnterprisePromotion();
  // The SPA mounts the dashboard after this script. Watch content only, not our own attribute changes.
  new MutationObserver(hideEnterprisePromotion).observe(root, {
    childList: true, subtree: true, characterData: true
  });
  refresh();
  window.addEventListener('hashchange', function () {
    guardRoute();
    refresh();
  });
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) refresh();
  });
  // Refresh on the existing page too, so a removed role doesn't leave a stale menu until reload.
  setInterval(function () {
    if (!document.hidden) refresh();
  }, 30000);
})();
