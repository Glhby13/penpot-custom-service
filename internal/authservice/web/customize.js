// Author / Agent: Codex. UI capabilities are server-derived, never inferred from local storage or user input.
// This script is presentation only; the gateway independently protects token RPCs, MCP transports and the user
// directory. Author / Agent (invite autocomplete, hidden "Create org"): Claude Code.
// Server data is only ever written with textContent / attributes, never parsed as HTML.
(function () {
  'use strict';
  var root = document.documentElement;
  var status = 'pending';
  var refreshing = false;

  // ---- Pure helpers (also exported for the node tests) ----
  var ORG_TRIGGER_BUTTON = '.main_ui_dashboard_sidebar__create-organization';
  var ORG_TRIGGER_ITEM = '.main_ui_dashboard_sidebar__organization-dropdown-item.main_ui_dashboard_sidebar__action';
  var ORG_ITEM_TEXT = 'Create org';
  var INVITE_PLACEHOLDER = /^Emails, comma separated/i;

  // The invite field only ever holds the token being typed (confirmed entries become chips), but be safe with commas.
  function currentToken(value) {
    var parts = String(value || '').split(/[,;\s]+/);
    return parts[parts.length - 1];
  }

  function replaceLastToken(value, email) {
    var v = String(value || '');
    var m = /[,;\s]+(?=[^,;\s]*$)/.exec(v);
    return (m ? v.slice(0, m.index + m[0].length) : '') + email;
  }

  function normalizeUsers(body) {
    var list = body && Array.isArray(body.users) ? body.users : [];
    var out = [];
    for (var i = 0; i < list.length && out.length < 10; i++) {
      var u = list[i];
      if (!u || typeof u.email !== 'string' || u.email.indexOf('@') < 1) continue;
      out.push({
        username: typeof u.username === 'string' ? u.username : '',
        name: typeof u.name === 'string' ? u.name : '',
        email: u.email
      });
    }
    return out;
  }

  // Debounced lookup; only the newest request may deliver results, older ones are aborted and ignored.
  function createSuggester(o) {
    var timer = null, seq = 0, controller = null;
    function abort() { if (controller) { controller.abort(); controller = null; } }
    function cancel() {
      seq++;
      if (timer !== null) { o.clearTimer(timer); timer = null; }
      abort();
    }
    return {
      cancel: cancel,
      input: function (token) {
        cancel();
        if (typeof token !== 'string' || token.length < (o.minChars || 2)) { o.onResults([]); return; }
        var mine = seq;
        timer = o.setTimer(function () {
          timer = null;
          abort();
          controller = new AbortController();
          o.fetchUsers(token, controller.signal).then(function (users) {
            if (mine === seq) o.onResults(users);
          }, function () {
            if (mine === seq) o.onResults([]);
          });
        }, o.delay === undefined ? 250 : o.delay);
      }
    };
  }

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

  function subscriptionsRoute() {
    return /^#\/settings\/subscriptions?(?:[/?]|$)/.test(location.hash);
  }

  function guardRoute() {
    if (subscriptionsRoute()) {
      location.replace('#/settings/profile');
      return;
    }
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

  // ---- "Create org": Penpot OSS has no organizations, the stock button only opens an Enterprise upsell ----
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function createOrgTrigger(target) {
    if (!target || !target.closest) return null;
    var button = target.closest(ORG_TRIGGER_BUTTON);
    if (button) return button;
    var item = target.closest(ORG_TRIGGER_ITEM);
    return item && item.textContent.trim() === ORG_ITEM_TEXT ? item : null;
  }

  // The dropdown entry has no stable marker; tag it by its exact English label so CSS can fail closed.
  // If the label differs (other language, upstream change) it stays visible; the capture handler below still keeps
  // the upsell from opening wherever the trigger matched.
  function markOrgItems() {
    document.querySelectorAll(ORG_TRIGGER_ITEM).forEach(function (item) {
      if (item.textContent.trim() === ORG_ITEM_TEXT) item.setAttribute('data-uxstudio-org-create', 'true');
    });
  }

  // Capture phase on document runs before Penpot's own handlers, so the Enterprise upsell never opens.
  function onDocumentClick(event) {
    var trigger = createOrgTrigger(event.target);
    if (!trigger) return;
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
  }

  // ---- Invite members: e-mail autocomplete from the directory ----
  var acSyntheticKeys = false;
  var ac = null; // { input, list, items, active, suggester, synthetic }
  var acId = 0;

  function inviteInput(target) {
    return target && target.tagName === 'INPUT' && INVITE_PLACEHOLDER.test(target.getAttribute('placeholder') || '') ? target : null;
  }

  function acClose() {
    if (!ac) return;
    var a = ac;
    ac = null;
    a.suggester.cancel();
    if (a.list) a.list.remove();
    a.input.setAttribute('aria-expanded', 'false');
    a.input.removeAttribute('aria-activedescendant');
    a.input.removeAttribute('aria-controls');
    window.removeEventListener('resize', acReposition);
    document.removeEventListener('scroll', acReposition, true);
  }

  function checkInviteDetached() {
    if (ac && !ac.input.isConnected) acClose();
  }

  function acReposition() {
    if (!ac || !ac.list) return;
    var r = ac.input.getBoundingClientRect();
    ac.list.style.left = r.left + 'px';
    ac.list.style.top = (r.bottom + 4) + 'px';
    ac.list.style.width = r.width + 'px';
  }

  function acSetActive(index) {
    if (!ac || !ac.list) return;
    var options = ac.list.children;
    for (var i = 0; i < options.length; i++) {
      var on = i === index;
      options[i].setAttribute('aria-selected', on ? 'true' : 'false');
      if (on) {
        ac.input.setAttribute('aria-activedescendant', options[i].id);
        if (options[i].scrollIntoView) options[i].scrollIntoView({ block: 'nearest' });
      }
    }
    if (index < 0) ac.input.removeAttribute('aria-activedescendant');
    ac.active = index;
  }

  function acRender(users) {
    if (!ac) return;
    if (ac.list) { ac.list.remove(); ac.list = null; }
    ac.items = users;
    ac.active = -1;
    if (!users.length) {
      ac.input.setAttribute('aria-expanded', 'false');
      ac.input.removeAttribute('aria-activedescendant');
      return;
    }
    var list = el('ul', 'uxs-ac');
    list.id = 'uxs-ac-list-' + (++acId);
    list.setAttribute('role', 'listbox');
    users.forEach(function (u, i) {
      var li = el('li', 'uxs-ac-item');
      li.id = list.id + '-opt-' + i;
      li.setAttribute('role', 'option');
      li.setAttribute('aria-selected', 'false');
      li.appendChild(el('span', 'uxs-ac-name', u.name || u.username || u.email));
      var meta = [u.username, u.email].filter(Boolean).join(' \u00b7 ');
      li.appendChild(el('span', 'uxs-ac-meta', meta));
      li.addEventListener('mousedown', function (event) { event.preventDefault(); }); // keep focus in the field
      li.addEventListener('click', function () { acSelect(i); });
      list.appendChild(li);
    });
    ac.list = list;
    ac.input.setAttribute('aria-controls', list.id);
    ac.input.setAttribute('aria-expanded', 'true');
    document.body.appendChild(list);
    acReposition();
  }

  function setNativeValue(input, value) {
    var setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (setter && setter.set) setter.set.call(input, value);
    else input.value = value;
  }

  function dispatchKey(input, type) {
    input.dispatchEvent(new KeyboardEvent(type, {
      key: ',', code: 'Comma', keyCode: 188, which: 188, bubbles: true, cancelable: true
    }));
  }

  function acSelect(index) {
    if (!ac || !ac.items[index]) return;
    var input = ac.input;
    var email = ac.items[index].email;
    ac.synthetic = true;
    try {
      setNativeValue(input, replaceLastToken(input.value, email));
      input.dispatchEvent(new Event('input', { bubbles: true }));
    } finally {
      ac.synthetic = false;
    }
    acClose();
    input.focus();
    // Penpot turns the typed text into a chip on Enter/comma/space; React must re-render the new value first.
    setTimeout(function () {
      if (!input.isConnected) return;
      acSyntheticKeys = true;
      try { dispatchKey(input, 'keydown'); dispatchKey(input, 'keyup'); } finally { acSyntheticKeys = false; }
    }, 0);
  }

  function acFetchUsers(q, signal) {
    return fetch('/auth-ui/directory/users?q=' + encodeURIComponent(q), {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Accept': 'application/json' },
      signal: signal
    }).then(function (response) {
      return response.ok ? response.json().then(normalizeUsers) : [];
    });
  }

  function acAttach(input) {
    if (ac && ac.input === input) return ac;
    acClose();
    ac = {
      input: input, list: null, items: [], active: -1, synthetic: false,
      suggester: createSuggester({
        delay: 250, minChars: 2,
        setTimer: function (fn, ms) { return setTimeout(fn, ms); },
        clearTimer: function (t) { clearTimeout(t); },
        fetchUsers: acFetchUsers,
        onResults: acRender
      })
    };
    input.setAttribute('role', 'combobox');
    input.setAttribute('aria-autocomplete', 'list');
    input.setAttribute('aria-expanded', 'false');
    window.addEventListener('resize', acReposition);
    document.addEventListener('scroll', acReposition, true);
    return ac;
  }

  function onDocumentInput(event) {
    var input = inviteInput(event.target);
    if (!input) return;
    var a = acAttach(input);
    if (a.synthetic) return;
    a.suggester.input(currentToken(input.value));
  }

  function onDocumentKeydown(event) {
    if (acSyntheticKeys || !ac || event.target !== ac.input) return;
    var n = ac.items.length;
    var open = !!ac.list && n > 0;
    switch (event.key) {
      case 'ArrowDown':
        if (!open) return;
        event.preventDefault(); acSetActive((ac.active + 1) % n); break;
      case 'ArrowUp':
        if (!open) return;
        event.preventDefault(); acSetActive(ac.active <= 0 ? n - 1 : ac.active - 1); break;
      case 'Enter':
      case 'Tab':
        if (open && ac.active >= 0) {
          event.preventDefault(); event.stopPropagation(); event.stopImmediatePropagation();
          acSelect(ac.active);
        }
        break;
      case 'Escape':
        if (open) { event.preventDefault(); event.stopPropagation(); event.stopImmediatePropagation(); acClose(); }
        break;
      default:
    }
  }

  function onDocumentFocusout(event) {
    if (ac && event.target === ac.input) setTimeout(function () { if (ac && document.activeElement !== ac.input) acClose(); }, 120);
  }

  function updateSidebarBrand() {
    if (!document || typeof document.querySelector !== 'function') return;
    var org = document.querySelector('.main_ui_dashboard_sidebar__selected-organization');
    if (!org) return;
    for (var i = 0; i < org.childNodes.length; i++) {
      var n = org.childNodes[i];
      if (n.nodeType === 3 && n.textContent && n.textContent.trim() === 'Penpot') {
        n.textContent = 'Studio';
      }
    }
  }

  function updateFavicon() {
    if (!document || typeof document.querySelectorAll !== 'function') return;
    var links = document.querySelectorAll('link[rel*="icon"]');
    for (var i = 0; i < links.length; i++) {
      if (links[i].href && links[i].href.indexOf('/auth-ui/assets/icon.png') === -1 && links[i].href.indexOf('/auth-ui/assets/favicon.png') === -1) {
        links[i].href = '/auth-ui/assets/icon.png';
      }
    }
    if (!links.length && document.head && typeof document.createElement === 'function') {
      var link = document.createElement('link');
      link.rel = 'icon';
      link.href = '/auth-ui/assets/icon.png';
      document.head.appendChild(link);
    }
  }

  function updateTitle() {
    if (document && typeof document.title === 'string' && document.title.indexOf('Penpot') !== -1) {
      document.title = document.title.replace(/Penpot/g, 'UX Studio');
    }
  }

  window.__uxstudioCustomize = {
    isOrgTrigger: createOrgTrigger, currentToken: currentToken, replaceLastToken: replaceLastToken, normalizeUsers: normalizeUsers,
    createSuggester: createSuggester, updateSidebarBrand: updateSidebarBrand, updateTitle: updateTitle
  };

  setStatus('pending');
  hideEnterprisePromotion();
  updateSidebarBrand();
  updateFavicon();
  updateTitle();
  // The SPA mounts the dashboard after this script. Watch content only, not our own attribute changes.
  new MutationObserver(function () {
    hideEnterprisePromotion();
    markOrgItems();
    checkInviteDetached();
    updateSidebarBrand();
    updateFavicon();
    updateTitle();
  }).observe(root, {
    childList: true, subtree: true, characterData: true
  });
  markOrgItems();
  document.addEventListener('click', onDocumentClick, true);
  document.addEventListener('input', onDocumentInput, true);
  document.addEventListener('keydown', onDocumentKeydown, true);
  document.addEventListener('focusout', onDocumentFocusout, true);
  refresh();
  window.addEventListener('hashchange', function () {
    guardRoute();
    refresh();
  });
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) refresh();
  });
  // Refresh on the existing page too, so a removed MCP role doesn't leave a stale menu until reload.
  setInterval(function () {
    if (!document.hidden) refresh();
  }, 30000);
})();
