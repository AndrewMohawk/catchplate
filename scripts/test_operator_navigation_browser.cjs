#!/usr/bin/env node
// Rendered navigation and task orientation; intercepted synthetic GETs only.
const assert = require('node:assert/strict');
const {fixture, ready, view} = require('./test_operator_catalog_browser.cjs');

async function run(browser) {
  const results = [];
  await fixture(browser, {}, async (page, state) => {
    await ready(page); await page.clock.resume();
    for (const width of [1280, 390]) {
      await page.setViewportSize({width, height: 960});
      await view(page, 'overview');
      assert(await page.locator('#overview-next-action').isVisible());
      assert(await page.locator('#overview-developer-action').isVisible());
      assert.equal(await page.locator('#overview-next-action').getAttribute('href'), '#credentials');
      if (width === 390) {
        const menu = page.locator('#workspace-menu-toggle');
        assert.equal(await menu.getAttribute('aria-expanded'), 'false');
        assert(await page.locator('#workspace-navigation').isHidden());
        await page.evaluate(() => scrollTo(0, 0));
        await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
        const top = (await page.locator('#overview-title').boundingBox()).y;
        assert(top < 260, 'task starts near the top, not below a full mobile sitemap');
        await menu.focus(); await page.keyboard.press('Enter');
        assert.equal(await menu.getAttribute('aria-expanded'), 'true');
        assert(await page.locator('#workspace-navigation').isVisible());
        await page.keyboard.press('Escape');
        assert.equal(await menu.getAttribute('aria-expanded'), 'false');
        assert(await menu.evaluate(el => el === document.activeElement));
        await menu.click(); await page.locator('nav a[href="#credentials"]').click();
        await page.locator('#credentials').waitFor({state: 'visible'});
        assert(await page.locator('#credentials-title').evaluate(el => el === document.activeElement));
        assert(await page.locator('#workspace-navigation').isHidden());
        await view(page, 'overview');
      }
      await page.locator('#overview-developer-action').click();
      await page.locator('#proxy').waitFor({state: 'visible'});
      assert(await page.locator('#client-selection').isVisible());
      assert(await page.locator('#proxy-operator-settings').isHidden());
      assert.equal(await page.locator('#proxy-client-tab').getAttribute('aria-current'), 'page');
      assert.equal(state.xConfigurationReads, width === 1280 ? 0 : 1, 'developer navigation does not discover operator settings');
      assert.equal(await page.locator('#client-existing-settings').evaluate(el => el.open), false);
      assert.equal(await page.locator('#client-template-title').innerText(), 'Client configuration');
      await page.locator('#proxy-settings-tab').click();
      await page.locator('#proxy-operator-settings').waitFor({state: 'visible'});
      assert(await page.locator('#proxy-setup-content').isHidden());
      assert(await page.locator('#proxy-settings-refresh').isVisible());
      assert.equal(await page.locator('#proxy-settings-tab').getAttribute('aria-current'), 'page');
      await page.locator('a[href="#google-configuration-panel"]').last().click();
      await page.waitForFunction(() => location.hash === '#google-configuration-panel');
      assert(await page.locator('#proxy-operator-settings').isVisible(), 'old deep links open the administrator panel');
      await page.locator('#proxy-client-tab').click();
      await page.locator('#client-selection').waitFor({state: 'visible'});
      assert(await page.locator('#proxy-operator-settings').isHidden());
      assert(await page.locator('#ca-download').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      results.push({width,clientPageHeight:await page.locator('#proxy').evaluate(el=>el.getBoundingClientRect().height)});
      await page.screenshot({path:'/tmp/catchplate-navigation-proxy-'+width+'.png',fullPage:false});
      await view(page, 'overview');
      await page.screenshot({path:'/tmp/catchplate-navigation-overview-'+width+'.png',fullPage:false});
    }
    assert.deepEqual(state.posts, [], 'all navigation stays read only');
    assert(state.requests.every(r => r.method === 'GET'));
  });
  return {ok:true,results,scope:'synthetic browser navigation; no provider or live mutations'};
}
async function main() {
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless:true,args:['--no-sandbox']});
  try { console.log(JSON.stringify(await run(browser))); } finally { await browser.close(); }
}
if(require.main===module) main().catch(e=>{console.error(e.stack);process.exitCode=1;});
module.exports={run};
