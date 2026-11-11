// Author / Agent: Codex. Lab-only live MCP authorization/transport abuse tests.
// Prerequisites: deployed MCP; lab-admin has Penpot mcp-access; e2e-team1 does not.
// Only lab-test MCP membership is temporarily granted/revoked, then restored in finally. Tokens stay in memory.
import { launch, password } from '../../drawio-custom-service/e2e/lib.mjs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const base = 'https://uxstudio.lab.local';
const helperPath = resolve(dirname(fileURLToPath(import.meta.url)), '../../scripts/e2e');
let passed = 0, failed = 0;
function check(name, ok) { console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`); ok ? passed++ : failed++; }
function requireCheck(name, ok) { check(name, ok); if (!ok) throw new Error('precondition failed'); }
const sleep = ms => new Promise(r => setTimeout(r, ms));

function membership(mode, state = null) {
  const code = `import sys,json,urllib.parse
sys.path.insert(0,sys.argv[1]); import kc
mode=sys.argv[2]; state=json.loads(sys.argv[3])
u=kc.api('GET','/users?exact=true&username=lab-test')
assert len(u)==1
uid=u[0]['id']; cl=kc.api('GET','/clients?clientId=penpot-lab')[0]['id']
role=kc.api('GET',f'/clients/{cl}/roles/mcp-access')
tops=kc.api('GET','/groups?search=penpot&max=100'); p=next(g for g in tops if g['name']=='penpot')
g=next(g for g in kc.api('GET',f"/groups/{p['id']}/children?max=100") if g['name']=='mcp-access')['id']
groups=kc.api('GET',f'/users/{uid}/groups?max=100')
direct=kc.api('GET',f'/users/{uid}/role-mappings/clients/{cl}')
current={'group':any(x['id']==g for x in groups),'direct':any(x['id']==role['id'] for x in direct)}
if mode=='revoke':
 if current['group']: kc.api('DELETE',f'/users/{uid}/groups/{g}')
 if current['direct']: kc.api('DELETE',f'/users/{uid}/role-mappings/clients/{cl}',[role])
elif mode=='grant':
 if not current['group']: kc.api('PUT',f'/users/{uid}/groups/{g}')
elif mode=='restore':
 if state['group'] and not current['group']: kc.api('PUT',f'/users/{uid}/groups/{g}')
 if not state['group'] and current['group']: kc.api('DELETE',f'/users/{uid}/groups/{g}')
 if state['direct'] and not current['direct']: kc.api('POST',f'/users/{uid}/role-mappings/clients/{cl}',[role])
 if not state['direct'] and current['direct']: kc.api('DELETE',f'/users/{uid}/role-mappings/clients/{cl}',[role])
print(json.dumps(current))`;
  try {
    return JSON.parse(execFileSync('python3', ['-c', code, helperPath, mode, JSON.stringify(state)], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']
    }));
  } catch (_) { throw new Error('lab-test membership operation failed'); }
}

function decodeTransit(raw) {
  const cache = [];
  function expand(v, key = false) {
    if (typeof v === 'string') {
      if (v.startsWith('^') && v !== '^ ') {
        let n = 0; for (const c of v.slice(1)) n = n * 44 + c.charCodeAt(0) - 48;
        return cache[n];
      }
      if (v.length > 3 && (key || /^~[:$#]/.test(v))) cache.push(v);
      return v;
    }
    if (Array.isArray(v)) return v.map((x, i) => expand(x, v[0] === '^ ' && i % 2 === 1));
    return v;
  }
  function plain(v) {
    if (Array.isArray(v) && v[0] === '^ ') {
      const o = {}; for (let i = 1; i + 1 < v.length; i += 2) o[v[i].replace(/^~:/, '')] = plain(v[i + 1]);
      return o;
    }
    if (Array.isArray(v)) return v.map(plain);
    if (typeof v === 'string' && v.startsWith('~u')) return v.slice(2);
    return v;
  }
  return plain(expand(JSON.parse(raw)));
}
const transit = fields => JSON.stringify(['^ ', ...Object.entries(fields).flatMap(([k, v]) => ['~:' + k, v])]);
async function request(ctx, method, path, body, headers = {}) {
  const r = await ctx.request.fetch(base + path, {
    method, data: body, headers, failOnStatusCode: false, maxRedirects: 0, timeout: 45000
  });
  return { status: r.status(), headers: r.headers(), text: await r.text() };
}
async function rpc(ctx, cmd, fields = {}, options = {}) {
  return request(ctx, options.method || 'POST', (options.prefix || '/api/rpc/command/') + cmd,
    transit(fields), { 'Content-Type': 'application/transit+json', Accept: 'application/transit+json', ...options.headers });
}
async function login(browser, user) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const r = await ctx.request.post(base + '/auth-ui/login', { data: { username: user, password: password(user) }, timeout: 30000 });
  requireCheck(`${user} AD login`, r.status() === 200);
  return ctx;
}
async function capability(ctx) {
  const r = await request(ctx, 'GET', '/auth-ui/capabilities');
  return r.status === 200 && JSON.parse(r.text).mcp === true;
}
async function createToken(ctx) {
  const r = await rpc(ctx, 'create-access-token', { name: 'lab-security-abuse', type: 'mcp' });
  requireCheck('authorized MCP token creation', r.status === 200);
  const row = decodeTransit(r.text);
  requireCheck('token is gateway-wrapped and response uncached', typeof row.token === 'string' && row.token.startsWith('ppm1.') && r.headers['cache-control'] === 'no-store');
  return row;
}
const streamPath = token => '/mcp/stream?userToken=' + encodeURIComponent(token);
async function initialize(ctx, token, sid = null) {
  const headers = { Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json' };
  if (sid) headers['Mcp-Session-Id'] = sid;
  return request(ctx, 'POST', streamPath(token), JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'lab-security-abuse', version: '1' } } }), headers);
}

let browser, originalMembership, membershipChanged = false;
const contexts = [], created = [];
try {
  originalMembership = membership('inspect');
  membershipChanged = true; membership('grant');
  browser = await launch();
  const permitted = await login(browser, 'lab-test'); contexts.push(permitted);
  const admin = await login(browser, 'lab-admin'); contexts.push(admin);
  const denied = await login(browser, 'e2e-team1'); contexts.push(denied);
  const anonymous = await browser.newContext({ ignoreHTTPSErrors: true }); contexts.push(anonymous);
  requireCheck('role holder capability enabled', await capability(permitted));
  requireCheck('second role holder capability enabled', await capability(admin));
  check('non-role user capability disabled', !(await capability(denied)));
  check('anonymous capability disabled', !(await capability(anonymous)));

  for (const prefix of ['/api/rpc/command/', '/api/main/methods/']) {
    for (const cmd of ['create-access-token', 'get-access-tokens', 'get-current-mcp-token', 'delete-access-token']) {
      const r = await rpc(denied, cmd, { type: 'mcp' }, { prefix });
      check(`non-role denied ${prefix}${cmd}`, r.status === 403);
    }
    check(`anonymous denied ${prefix}create-access-token`, (await rpc(anonymous, 'create-access-token', { type: 'mcp' }, { prefix })).status === 403);
    check(`identity mutation denied ${prefix}`, (await rpc(denied, 'request-email-change', { email: 'unused-mcp-test@lab.local' }, { prefix })).status === 403);
  }
  check('Password change guard preserved', (await rpc(permitted, 'update-profile-password', { password: 'not-a-real-password' })).status === 403);
  check('cross-origin token RPC denied', (await rpc(permitted, 'get-access-tokens', {}, { headers: { Origin: 'https://evil.example' } })).status === 403);
  check('cross-site metadata denied', (await rpc(permitted, 'get-access-tokens', {}, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status === 403);
  check('GET token creation denied', (await rpc(permitted, 'create-access-token', {}, { method: 'GET' })).status === 403);
  check('GET token deletion denied', (await rpc(permitted, 'delete-access-token', {}, { method: 'GET' })).status === 403);
  check('query override token creation denied', (await request(permitted, 'POST', '/api/rpc/command/create-access-token?type=access-token', transit({ type: 'mcp', name: 'abuse' }), { 'Content-Type': 'application/transit+json' })).status === 403);
  check('non-MCP personal token creation denied', (await rpc(permitted, 'create-access-token', { name: 'abuse', type: 'access-token' })).status === 403);
  for (const path of ['/api/rpc/command/%67et-access-tokens', '/mcp/%73tream', '/mcp/messages', '/mcp/sse']) {
    const r = await request(permitted, 'GET', path);
    check(`noncanonical/legacy route rejected ${path}`, r.status === 400 || r.status === 403);
  }

  const tokenA = await createToken(permitted); created.push({ ctx: permitted, id: tokenA.id });
  const tokenB = await createToken(admin); created.push({ ctx: admin, id: tokenB.id });
  const listed = await rpc(permitted, 'get-access-tokens');
  check('token listing remains wrapped', listed.status === 200 && decodeTransit(listed.text).some(row => row.type === 'mcp' && row.token === tokenA.token));
  const native = JSON.parse(Buffer.from(tokenA.token.split('.')[1], 'base64url').toString('utf8')).token;
  for (const [name, token] of [['raw native token', native], ['tampered envelope', tokenA.token + 'x'], ['malformed token', 'ppm1.bad.bad']]) {
    check(`${name} rejected`, (await initialize(permitted, token)).status === 403);
  }
  check('duplicate query tokens rejected', (await request(permitted, 'POST', streamPath(tokenA.token) + '&userToken=other', '{}')).status === 403);
  check('missing query token rejected', (await request(permitted, 'POST', '/mcp/stream', '{}')).status === 403);
  check('cross-origin MCP transport denied', (await request(permitted, 'POST', streamPath(tokenA.token), '{}', { Origin: 'https://evil.example' })).status === 403);

  const initA = await initialize(permitted, tokenA.token);
  requireCheck('official MCP initialize succeeds', initA.status === 200 && /protocolVersion/.test(initA.text));
  const sid = initA.headers['mcp-session-id'];
  requireCheck('MCP session identifier is gateway-bound', typeof sid === 'string' && sid.includes('.'));
  check('cross-user MCP session swap denied', (await initialize(admin, tokenB.token, sid)).status === 403);
  check('raw native session ID rejected', (await initialize(permitted, tokenA.token, 'not-signed')).status === 403);

  const page = await permitted.newPage();
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  const websocketOpen = await page.evaluate(token => new Promise(resolve => {
    const ws = new WebSocket('wss://' + location.host + '/mcp/ws?userToken=' + encodeURIComponent(token));
    window.__abuseWS = ws;
    window.__abuseWSClosed = false;
    window.__abuseTaskCount = 0;
    // A synthetic plugin answers only this exact read-only probe; never eval incoming code.
    ws.onmessage = event => {
      const task = JSON.parse(event.data);
      if (task.task === 'executeCode' && task.params?.code === 'return "lab-read-only-probe";') {
        window.__abuseTaskCount++;
        ws.send(JSON.stringify({ id: task.id, success: true, data: { result: 'lab-read-only-probe', log: '' } }));
      }
    };
    ws.onclose = () => { window.__abuseWSClosed = true; resolve(false); };
    ws.onopen = () => resolve(true);
    ws.onerror = () => resolve(false);
    setTimeout(() => resolve(false), 8000);
  }), tokenA.token);
  check('authorized official MCP WebSocket opens', websocketOpen);
  if (websocketOpen) {
    const headers = { Accept: 'application/json, text/event-stream', 'Content-Type': 'application/json', 'Mcp-Session-Id': sid, 'MCP-Protocol-Version': '2025-03-26' };
    await request(permitted, 'POST', streamPath(tokenA.token), JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }), headers);
    const probe = await request(permitted, 'POST', streamPath(tokenA.token), JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'execute_code', arguments: { code: 'return "lab-read-only-probe";' } } }), headers);
    const taskSeen = await page.evaluate(() => window.__abuseTaskCount > 0);
    check('official MCP Redis PubSub task roundtrip with synthetic read-only plugin', probe.status === 200 && probe.text.includes('lab-read-only-probe') && taskSeen);
  }

  membership('revoke');
  await sleep(17000);
  check('removed role disables current browser capability', !(await capability(permitted)));
  check('removed role denies preexisting token HTTP access', (await initialize(permitted, tokenA.token, sid)).status === 403);
  check('removed role denies new token creation', (await rpc(permitted, 'create-access-token', { name: 'abuse', type: 'mcp' })).status === 403);
  if (websocketOpen) {
    const closed = await page.waitForFunction(() => window.__abuseWSClosed === true, null, { timeout: 25000 }).then(() => true).catch(() => false);
    check('removed role closes already-open WebSocket within bound', closed);
  }
  membership('grant');
  await sleep(17000);
  requireCheck('restored role restores current browser capability', await capability(permitted));
  const deletion = await rpc(permitted, 'delete-access-token', { id: '~u' + tokenA.id });
  check('native token deletion succeeds', deletion.status >= 200 && deletion.status < 300);
  await sleep(17000);
  check('deleted native token denies old MCP stream', (await initialize(permitted, tokenA.token, sid)).status === 403);
} catch (_) {
  failed++;
  console.error('FAIL live MCP abuse run stopped; no credentials or raw URLs logged');
} finally {
  if (membershipChanged && created.length) { try { membership('grant'); } catch (_) {} }
  for (const item of created) {
    try { await rpc(item.ctx, 'delete-access-token', { id: '~u' + item.id }); } catch (_) { /* report cleanup status without token */ }
  }
  if (membershipChanged && originalMembership) {
    try {
      membership('restore', originalMembership);
      const restored = membership('inspect');
      requireCheck('lab-test original MCP assignment restored', restored.group === originalMembership.group && restored.direct === originalMembership.direct);
    }
    catch (_) { failed++; console.error('FAIL restore lab-test membership; lead must restore original MCP assignment'); }
  }
  for (const ctx of contexts) await ctx.close().catch(() => {});
  if (browser) await browser.close();
}
console.log(`RESULT ${passed} passed ${failed} failed`);
process.exitCode = failed ? 1 : 0;
