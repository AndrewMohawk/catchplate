#!/usr/bin/env node
// Real deployed API responses through a local transport adapter. This verifies
// browser/API behavior, not an existing human Authelia session or hardware.
const { execFileSync } = require('node:child_process');
const { chromium, request } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

async function main() {
  const container = 'serverware-sandbox-serverware-1';
  const topology = JSON.parse(execFileSync('docker', ['inspect', container], {encoding:'utf8'}))[0];
  const address = topology.NetworkSettings.Networks['serverware-sandbox_sandbox'].IPAddress;
  if (!/^172\.16\.249\.[0-9]+$/.test(address)) throw new Error('Unexpected sandbox network');
  const token = execFileSync('docker', ['exec', container, 'python', '-c',
    "from pathlib import Path; print(Path('/run/secrets/serverware/admin.token').read_text(),end='')"], {encoding:'utf8'}).trim();
  const origin = 'https://serverware-sandbox.example.com';
  const backend = await request.newContext({extraHTTPHeaders:{
    'X-Serverware-Admin-Token': token, 'Host':'serverware-sandbox.example.com', 'X-Forwarded-Proto':'https'
  }});
  const browser = await chromium.launch({headless:true,args:['--no-sandbox']});
  let page;
  let proxyCheckPassed = false;
  const errors = [], failures = [];
  try {
    page = await browser.newPage({viewport:{width:1440,height:1000}});
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => {if(m.type()==='error') errors.push(m.text());});
    await page.route('**/*', async route => {
      const incoming = route.request(), url = new URL(incoming.url());
      if (url.origin !== origin) return route.abort();
      try {
      const response = await backend.fetch(`http://${address}:3000${url.pathname}${url.search}`, {
        method:incoming.method(), ...(incoming.postDataBuffer() ? {data:incoming.postDataBuffer()} : {}), timeout:60000,
        headers: {Origin:origin, ...(incoming.headers()['content-type'] ? {'Content-Type':incoming.headers()['content-type']} : {})}
      });
      if(response.status()>=400) failures.push({path:url.pathname,status:response.status()});
      await route.fulfill({response});
      } catch (_) { failures.push({path:url.pathname,status:'transport_error'}); await route.abort().catch(() => {}); }
    });
    const start = performance.now();
    await page.goto(origin, {waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForFunction(() => document.getElementById('operator-auth-status')?.textContent.includes('sandbox-operator'), null, {timeout:20000});
    await page.locator('#credentials').getByText('Demo bearer token', {exact:true}).waitFor({timeout:20000});
    const firstLoadMs = Math.round(performance.now()-start);
    if (!(await page.locator('#admin-token').isHidden())) throw new Error('Operator token input remained visible');
    const banner = await page.locator('#development-sandbox-banner').innerText();
    if (!banner.includes('synthetic credentials only')) throw new Error('Sandbox boundary banner missing');
    if (!banner.includes('Streaming request transformations are unsupported and refused.')) throw new Error('Unsupported feature boundary missing');
    if (process.env.SANDBOX_BROWSER_CHECK_PROXY === '1') {
      await page.locator('#sandbox-run-check').click();
      await page.waitForFunction(() => /^(Passed|Check failed:)/.test(document.getElementById('sandbox-check-result').textContent), null, {timeout:60000});
      const result = await page.locator('#sandbox-check-result').innerText();
      if(!result.startsWith('Passed')) throw new Error(result);
      proxyCheckPassed = true;
    }
    const chainResponse = page.waitForResponse(r => new URL(r.url()).pathname === '/api/audit/verify');
    await page.getByRole('button', {name:'Verify chain',exact:true}).click();
    const chain = await (await chainResponse).json();
    if (chain.ok !== true || chain.complete !== true) throw new Error('Audit chain did not verify completely');
    const reloadStart = performance.now();
    await page.reload({waitUntil:'domcontentloaded'});
    await page.locator('#credentials').getByText('Demo bearer token', {exact:true}).waitFor({timeout:20000});
    const reloadMs = Math.round(performance.now()-reloadStart);
    await page.evaluate(() => window.scrollTo({top:0,left:0,behavior:'instant'}));
    await page.screenshot({path:'/tmp/serverware-sandbox-browser.png',fullPage:false});
    if ((await page.content()).includes(token)) throw new Error('Service credential appeared in browser content');
    console.log(JSON.stringify({ok:errors.length===0 && failures.length===0, boundary:'real backend; browser transport adapter, not human SSO',
      title:await page.title(),url:page.url(),firstLoadMs,reloadMs,proxyCheckPassed,auditChainVerified:true,errors,failures,screenshot:'/tmp/serverware-sandbox-browser.png'}));
    if(errors.length || failures.length) process.exitCode=1;
  } catch (error) {
    if(page) {
      await page.screenshot({path:'/tmp/serverware-sandbox-browser-failed.png',fullPage:false}).catch(() => {});
      console.log(JSON.stringify({ok:false,errorClass:error.name,errors,failures,
        auth:await page.locator('#operator-auth-status').textContent().catch(() => null),
        credentialRows:await page.locator('#credentials tr').count().catch(() => 0)}));
    }
    process.exitCode=1;
  } finally {for(const context of browser.contexts()) for(const page of context.pages()) await page.unrouteAll({behavior:'wait'}); await browser.close();await backend.dispose();}
}
main().catch(e => {console.error('Sandbox browser verification failed: '+e.name);process.exitCode=1;});
