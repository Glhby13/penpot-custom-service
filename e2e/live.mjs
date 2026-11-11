// Author / Agent: Codex. Lab-only UI/API regression. Secrets remain in memory.
import { launch, password } from '../../drawio-custom-service/e2e/lib.mjs';
const base = 'https://uxstudio.lab.local';
const browser = await launch();
let failed=0, passed=0;
function check(name, ok) { console.log(`${ok?'PASS':'FAIL'} ${name}`); ok?passed++:failed++; }
try {
  const ctx = await browser.newContext({ignoreHTTPSErrors:true});
  const page = await ctx.newPage();
  await page.goto(base, {waitUntil:'domcontentloaded'});
  await page.locator('#username').fill(process.env.PENPOT_TEST_USER || 'lab-test');
  await page.locator('#password').fill(password(process.env.PENPOT_TEST_USER || 'lab-test'));
  await page.locator('#submit').click();
  await page.waitForURL(u=>u.hash.includes('dashboard'),{timeout:45000});
  check('AD login reaches dashboard',true);
  const dashboardURL = page.url();
  await page.waitForTimeout(2500);
  if(process.env.TEST_TEMPLATE==='true') {

    const profile=await page.evaluate(()=>fetch('/api/rpc/command/get-profile',{headers:{Accept:'application/transit+json'}}).then(r=>r.text()));

    const templates=await page.evaluate(()=>fetch('/api/rpc/command/get-builtin-templates').then(r=>r.text()));
    console.log('TEMPLATES list available: '+(JSON.parse(templates).length));
    {
      const raw=JSON.parse(profile), index=raw.indexOf('~:default-project-id');
      const project=raw[index+1];
      const result=await page.evaluate(async ({project})=> {
        const r=await fetch('/api/rpc/command/clone-template',{method:'POST',headers:{'Content-Type':'application/transit+json','Accept':'text/event-stream'},body:JSON.stringify(['^ ','~:project-id',project,'~:template-id','prototype-examples'])});
        const text=await r.text();return {status:r.status,text};
      },{project});
      const fileId=/~u([a-f0-9-]{36})/.exec(result.text)?.[1];
    check('import returns file identifier', !!fileId);
    if(fileId){
      const read=await page.evaluate(async id=>{const r=await fetch('/api/rpc/command/get-file?id='+id,{headers:{Accept:'application/json'}});return {status:r.status,data:await r.json()}},fileId);
      check('imported file can be read back',read.status===200);
      if(read.status===200 && read.data.name){
        await page.goto(dashboardURL);
        await page.getByText(read.data.name,{exact:true}).first().dblclick({timeout:15000});
        await page.waitForURL(u=>u.hash.includes('workspace'),{timeout:30000});
        await page.waitForTimeout(2500);
        check('imported template opens in official editor',!await page.getByText('Something bad happened.',{exact:true}).isVisible());
      }
    }
      check('prototype template assets imported', result.status===200 && !/event: error|~:type","~:exception|~:error/.test(result.text));
    }
  } else {
    await page.waitForFunction(()=>document.documentElement.dataset.uxstudioMcp !== 'pending',{timeout:20000});
    const cap=await page.evaluate(()=>fetch('/auth-ui/capabilities').then(r=>r.json()));
    check('MCP capability is boolean',typeof cap.mcp==='boolean');
    check('expected MCP role matches capability',cap.mcp === (process.env.EXPECT_MCP==='true'));
    check('first-user onboarding hidden',await page.getByText('Where would you like to get started?',{exact:true}).count()===0);
    const promo=page.locator('[data-uxstudio-enterprise-promo="true"]');
    check('Enterprise promotion hidden',await promo.count()===0 || !(await promo.first().isVisible()));
    await page.goto(base+'/#/settings/profile');
    const integrations=page.locator('[data-testid="settings-integrations"]');
    await page.waitForTimeout(1000);
    check('Integrations visibility follows MCP role', await integrations.isVisible()===cap.mcp);
    await page.goto(base+'/#/settings/password');
    check('Password page remains usable',await page.getByRole('heading',{name:'Change password',exact:true}).isVisible());
    if(!cap.mcp){
      await page.goto(base+'/#/settings/integrations');
      await page.waitForFunction(()=>location.hash==='#/settings/profile',{timeout:15000});
      check('unauthorized Integrations deep link redirected',true);
    }
  }
  await ctx.close();
} catch(e) {failed++; console.error('FAIL live test: '+String(e.message).replace(/userToken=[^&\s]+/g,'userToken=[redacted]').slice(0,600));}
finally {await browser.close();}
console.log(`RESULT ${passed} passed ${failed} failed`);
process.exitCode=failed?1:0;
