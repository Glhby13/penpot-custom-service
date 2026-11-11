// Author / Agent: Codex. Run with node --test internal/authservice/web/customize.test.cjs.
// Exercises the shipped script's capability/routing behavior without external packages or a live identity provider.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/customize.js', 'utf8');

async function harness(responses, hash = '#/dashboard/recent', banners = []) {
  const attrs = {};
  const listeners = {};
  const requests = [];
  const replacements = [];
  let interval;
  const location = { hash, replace(target) { replacements.push(target); this.hash = target; } };
  const context = {
    document: {
      hidden: false,
      documentElement: { setAttribute(key, value) { attrs[key] = value; } },
      querySelectorAll() { return banners; },
      addEventListener(name, fn) { listeners[name] = fn; }
    },
    window: { addEventListener(name, fn) { listeners[name] = fn; } },
    location,
    AbortController,
    MutationObserver: class { constructor(callback) { listeners.mutation = callback; } observe() {} },
    setTimeout() { return 1; },
    clearTimeout() {},
    setInterval(fn) { interval = fn; },
    async fetch(path, options) {
      requests.push({ path, options });
      const response = responses.shift();
      if (response instanceof Error) throw response;
      if (typeof response === 'function') return response();
      return { ok: true, async json() { return response; } };
    }
  };
  vm.runInNewContext(source, context);
  const flush = async () => { await new Promise(setImmediate); };
  await flush();
  return { attrs, requests, replacements, listeners, location, flush, interval: () => interval() };
}

test('permitted session shows Integrations and keeps a direct route', async () => {
  const h = await harness([{ mcp: true }], '#/settings/integrations');
  assert.equal(h.attrs['data-uxstudio-mcp'], 'allowed');
  assert.deepEqual(h.replacements, []);
  assert.equal(h.requests[0].path, '/auth-ui/capabilities');
  assert.equal(h.requests[0].options.cache, 'no-store');
  assert.equal(h.requests[0].options.credentials, 'same-origin');
});

test('denied session hides Integrations and redirects direct route including query', async () => {
  const h = await harness([{ mcp: false }], '#/settings/integrations?tab=mcp');
  assert.equal(h.attrs['data-uxstudio-mcp'], 'denied');
  assert.deepEqual(h.replacements, ['#/settings/profile']);
});

test('malformed capability cannot grant access by truthiness', async () => {
  for (const capability of [{ mcp: 'true' }, {}, { admin: true }, { mcp: 1 }]) {
    const h = await harness([capability]);
    assert.equal(h.attrs['data-uxstudio-mcp'], 'denied');
  }
});

test('backend outage fails closed', async () => {
  const h = await harness([new Error('upstream unavailable')], '#/settings/integrations/');
  assert.equal(h.attrs['data-uxstudio-mcp'], 'denied');
  assert.deepEqual(h.replacements, ['#/settings/profile']);
});

test('removed role is reflected on the open page during refresh', async () => {
  const h = await harness([{ mcp: true }, { mcp: false }], '#/settings/integrations');
  assert.equal(h.attrs['data-uxstudio-mcp'], 'allowed');
  h.interval();
  await h.flush();
  assert.equal(h.attrs['data-uxstudio-mcp'], 'denied');
  assert.deepEqual(h.replacements, ['#/settings/profile']);
});

test('SPA navigation rechecks current capability and does not rely on DOM mount order', async () => {
  const h = await harness([{ mcp: false }, { mcp: false }]);
  h.location.hash = '#/settings/integrations';
  h.listeners.hashchange();
  await h.flush();
  assert.deepEqual(h.replacements, ['#/settings/profile']);
  assert.equal(h.requests.length, 2);
});

test('Password settings remain available with no MCP role', async () => {
  const h = await harness([{ mcp: false }], '#/settings/password');
  assert.deepEqual(h.replacements, []);
  assert.equal(h.location.hash, '#/settings/password');
});

test('unknown initial capability stays hidden while request is pending', async () => {
  const h = await harness([() => new Promise(() => {})], '#/settings/integrations');
  assert.equal(h.attrs['data-uxstudio-mcp'], 'pending');
  assert.deepEqual(h.replacements, []);
});

test('only scoped Unlock Enterprise promotion is hidden; renewal warning stays visible', async () => {
  function banner(text) {
    const attrs = {};
    return {
      attrs,
      title: { textContent: text },
      querySelector() { return this.title; },
      setAttribute(key, value) { attrs[key] = value; },
      removeAttribute(key) { delete attrs[key]; }
    };
  }
  const promotion = banner('Unlock Enterprise features');
  const warning = banner('Renew your subscription');
  const currentPlan = banner('Your subscription');
  const h = await harness([{ mcp: false }], '#/settings/profile', [promotion, warning, currentPlan]);
  assert.equal(promotion.attrs['data-uxstudio-enterprise-promo'], 'true');
  assert.equal(warning.attrs['data-uxstudio-enterprise-promo'], undefined);
  assert.equal(currentPlan.attrs['data-uxstudio-enterprise-promo'], undefined);
  promotion.title.textContent = 'Your subscription has expired';
  h.listeners.mutation();
  assert.equal(promotion.attrs['data-uxstudio-enterprise-promo'], undefined);
});
