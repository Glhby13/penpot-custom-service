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
      querySelectorAll(sel) { return String(sel).indexOf('nitrate-banner') >= 0 ? banners : []; },
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
  return { attrs, requests, replacements, listeners, location, flush, context, interval: () => interval() };
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

const J = (x) => JSON.parse(JSON.stringify(x)); // vm contexts have their own Array realm

// ---- "Create org" is hidden for everybody ----
test('upsell click is swallowed for everybody and never reaches Penpot', async () => {
  const h = await harness([{ mcp: false }]);
  const calls = [];
  const target = { closest(sel) { return sel.indexOf('create-organization') >= 0 ? { focus() {} } : null; } };
  h.listeners.click({ target, preventDefault() { calls.push('pd'); }, stopPropagation() { calls.push('sp'); }, stopImmediatePropagation() { calls.push('sip'); } });
  assert.deepEqual(calls, ['pd', 'sp', 'sip']);
  // unrelated clicks are untouched
  const other = [];
  h.listeners.click({ target: { closest() { return null; } }, preventDefault() { other.push(1); }, stopPropagation() { other.push(1); }, stopImmediatePropagation() { other.push(1); } });
  assert.deepEqual(other, []);
});

test('dropdown entry matches only the exact "Create org" label', async () => {
  const h = await harness([{}]);
  const mk = (text) => ({ target: { closest(sel) { return sel.indexOf('organization-dropdown-item') >= 0 && sel.indexOf('create-organization') < 0 ? { textContent: ' ' + text + ' ' } : null; } }, preventDefault() { this.hit = true; }, stopPropagation() {}, stopImmediatePropagation() {} });
  const a = mk('Create org'); h.listeners.click(a); assert.equal(a.hit, true);
  const b = mk('Acme org'); h.listeners.click(b); assert.equal(b.hit, undefined);
});

// ---- Invite autocomplete ----
test('token extraction and replacement', async () => {
  const { currentToken, replaceLastToken } = (await harness([{}])).context.window.__uxstudioCustomize;
  assert.equal(currentToken('ali'), 'ali');
  assert.equal(currentToken('a@x.id, bo'), 'bo');
  assert.equal(currentToken('a@x.id,'), '');
  assert.equal(replaceLastToken('ali', 'ali@x.id'), 'ali@x.id');
  assert.equal(replaceLastToken('a@x.id, bo', 'bob@x.id'), 'a@x.id, bob@x.id');
  assert.equal(replaceLastToken('a@x.id,bo', 'bob@x.id'), 'a@x.id,bob@x.id');
  assert.equal(replaceLastToken('', 'z@x.id'), 'z@x.id');
});

test('directory response is normalised: max 10, strings only, valid emails', async () => {
  const { normalizeUsers } = (await harness([{}])).context.window.__uxstudioCustomize;
  assert.deepEqual(J(normalizeUsers(null)), []);
  assert.deepEqual(J(normalizeUsers({ users: 'x' })), []);
  const users = [{ username: 'a', name: 'A', email: 'a@x.id' }, { email: 'bad' }, { email: 5 }, null, { name: 3, username: {}, email: 'b@x.id' }];
  assert.deepEqual(J(normalizeUsers({ users })), [{ username: 'a', name: 'A', email: 'a@x.id' }, { username: '', name: '', email: 'b@x.id' }]);
  const many = Array.from({ length: 30 }, (_, i) => ({ email: 'u' + i + '@x.id' }));
  assert.equal(normalizeUsers({ users: many }).length, 10);
});

function fakeTimers() {
  let now = 0, id = 0; const q = new Map();
  return {
    setTimer(fn, ms) { q.set(++id, { fn, at: now + ms }); return id; },
    clearTimer(t) { q.delete(t); },
    advance(ms) { now += ms; for (const [k, v] of [...q]) if (v.at <= now) { q.delete(k); v.fn(); } },
    pending: () => q.size
  };
}

test('suggester: <2 chars never fetches; debounce collapses keystrokes to one request', async () => {
  const { createSuggester } = (await harness([{}])).context.window.__uxstudioCustomize;
  const t = fakeTimers(); const fetched = []; const results = [];
  const s = createSuggester({ ...t, fetchUsers: (q) => { fetched.push(q); return Promise.resolve([{ email: q + '@x.id' }]); }, onResults: (r) => results.push(r) });
  s.input('a'); t.advance(1000);
  assert.deepEqual(fetched, []);
  assert.deepEqual(J(results), [[]]);
  s.input('al'); t.advance(100); s.input('ali'); t.advance(100); s.input('alic'); t.advance(249);
  assert.deepEqual(fetched, []);
  t.advance(1); await new Promise(setImmediate);
  assert.deepEqual(fetched, ['alic']);
  assert.deepEqual(J(results[results.length - 1]), [{ email: 'alic@x.id' }]);
});

test('suggester: stale responses are aborted and ignored; errors yield an empty list', async () => {
  const { createSuggester } = (await harness([{}])).context.window.__uxstudioCustomize;
  const t = fakeTimers(); const pending = []; const results = []; const signals = [];
  const s = createSuggester({ ...t, fetchUsers: (q, signal) => { signals.push(signal); return new Promise((res, rej) => pending.push({ q, res, rej })); }, onResults: (r) => results.push(r) });
  s.input('ab'); t.advance(250);
  s.input('abc'); t.advance(250);
  assert.equal(signals[0].aborted, true);
  pending[0].res([{ email: 'old@x.id' }]); await new Promise(setImmediate);
  assert.deepEqual(results, []);
  pending[1].res([{ email: 'new@x.id' }]); await new Promise(setImmediate);
  assert.deepEqual(J(results), [[{ email: 'new@x.id' }]]);
  s.input('abcd'); t.advance(250);
  pending[2].rej(new Error('429')); await new Promise(setImmediate);
  assert.deepEqual(J(results[results.length - 1]), []);
  // cancel() drops an in-flight result and a pending timer
  s.input('zz'); t.advance(250); s.cancel(); pending[3].res([{ email: 'late@x.id' }]); await new Promise(setImmediate);
  s.input('yy'); s.cancel(); assert.equal(t.pending(), 0);
  assert.notDeepEqual(J(results[results.length - 1]), [{ email: 'late@x.id' }]);
});
