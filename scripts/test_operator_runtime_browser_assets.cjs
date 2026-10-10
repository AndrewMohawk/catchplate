#!/usr/bin/env node
'use strict';
// Pure current-source renderer/checker agreement. No browser, app startup,
// Docker, sockets, private files, provider calls, or runtime receipt writes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const ASSETS = path.join(ROOT, 'serverware/operator_demo_web');
const CHECKER = path.join(__dirname, 'check_operator_runtime_browser.cjs');
const source = fs.readFileSync(CHECKER, 'utf8');
const entrypoint = '\n(async () => {\n';
assert.equal(source.split(entrypoint).length, 2, 'one explicit runtime entrypoint');
const declarations = source.split(entrypoint)[0];

// Invoke the actual standalone Python renderer, not a second JS rendering
// implementation. Its only imports are stdlib; do not import serverware/app.
const reference = JSON.parse(execFileSync(process.env.SERVERWARE_TEST_PYTHON || '/usr/bin/python3',
  ['-I', '-B', '-c', `
import base64, importlib.util, json, pathlib, sys
def deny_runtime(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in {'os.system', 'os.fork', 'os.posix_spawn'}:
        raise AssertionError('renderer attempted runtime I/O')
sys.addaudithook(deny_runtime)
spec = importlib.util.spec_from_file_location('public_renderer_only', pathlib.Path(sys.argv[1]))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps({'scripts': module.SCRIPT_FILES,
    'html': base64.b64encode(module.render().encode('utf-8')).decode('ascii')}))
`, path.join(ROOT, 'serverware/operator_demo_portal.py')],
  {encoding: 'utf8', timeout: 10000, maxBuffer: 4 * 1024 * 1024,
    env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'}}));
const expected = Buffer.from(reference.html, 'base64');
assert(expected.length > 0 && expected.length <= 2 * 1024 * 1024);
let forbiddenCalls = 0;
function forbidden() { forbiddenCalls++; throw new Error('pure asset test attempted runtime I/O'); }

function fixture(overrides = {}) {
  const reads = [];
  const context = vm.createContext({Buffer, structuredClone, __dirname, __filename: CHECKER,
    fixtureRoot: ROOT, fixtureReply: null, fixtureRequests: [],
    require(name) {
      if (name === 'node:path') return path;
      if (name === 'node:crypto') return require(name);
      if (name === 'node:fs') return {
        readFileSync(filename, encoding) {
          assert.equal(path.dirname(filename), ASSETS, 'only selected public assets may be read');
          assert.equal(encoding, 'utf8');
          const name = path.basename(filename); reads.push(name);
          if (Object.hasOwn(overrides, name)) {
            if (overrides[name] instanceof Error) throw overrides[name];
            return overrides[name];
          }
          return fs.readFileSync(filename, encoding);
        }, realpathSync: forbidden, mkdirSync: forbidden, writeFileSync: forbidden};
      if (name === 'node:child_process') return {execFile: forbidden};
      if (name.endsWith('/lib/node_modules/playwright')) return {chromium: {launch: forbidden}};
      throw new Error('unexpected checker dependency');
    }, setTimeout: forbidden, clearTimeout: forbidden});
  const run = code => vm.runInContext(code, context, {timeout: 1000});
  run(declarations);
  run('source = fixtureRoot; bridge = async payload => { fixtureRequests.push(payload); return fixtureReply; };');
  return {context, reads, run,
    render(managed) { context.mode = managed; return run('managedGoogle = mode; documentBytes()'); },
    async getActual(body) {
      context.fixtureReply = {status: 200, headers: [['content-type', 'text/html']], body_base64: body.toString('base64')};
      return run('get("/")');
    }};
}

const tests = [
  ['actual documentBytes matches current Python renderer in both checker modes', async () => {
    for (const managed of [false, true]) {
      const f = fixture();
      const names = JSON.parse(f.run('JSON.stringify(SCRIPTS)'));
      assert.deepEqual(names, reference.scripts);
      assert.equal(new Set(names).size, names.length);
      assert.equal(names[names.indexOf('workspace_npm.js') + 1], 'workspace_npm_publish.js');
      assert.deepEqual(names.slice(-2), ['workspace_google_configuration.js', 'app.js']);
      const actual = f.render(managed);
      assert(actual.equals(expected), 'exact UTF-8 HTML bytes must match actual renderer');
      assert.deepEqual(f.reads, ['index.html', ...reference.scripts, 'style.css']);
      f.context.fixtureExpected = actual; f.run('expectedHtml = fixtureExpected');
      const response = await f.getActual(expected);
      assert(response.body.equals(expected));
      assert.equal(f.context.fixtureRequests.length, 1);
      assert.equal(f.context.fixtureRequests[0].path, '/');
      assert.equal(f.context.fixtureRequests[0].op, 'get');
      assert.equal(f.context.fixtureRequests[0].managed_google_unconfigured, managed ? true : undefined);
    }
  }],
  ['missing or reordered modules and any changed response byte fail exact HTML comparison', async () => {
    for (const change of [
      'SCRIPTS.splice(SCRIPTS.indexOf("workspace_npm_publish.js"), 1)',
      'SCRIPTS.splice(SCRIPTS.indexOf("workspace_google_configuration.js"), 1)',
      '[SCRIPTS[2], SCRIPTS[3]] = [SCRIPTS[3], SCRIPTS[2]]']) {
      const f = fixture(); f.run(change);
      const wrong = f.render(true); assert(!wrong.equals(expected));
      f.context.fixtureExpected = wrong; f.run('expectedHtml = fixtureExpected');
      await assert.rejects(f.getActual(expected), error => error.message === 'actual_renderer_mismatch');
    }
    const f = fixture(); f.context.fixtureExpected = f.render(false); f.run('expectedHtml = fixtureExpected');
    const changed = Buffer.from(expected); changed[changed.length - 1] ^= 1;
    await assert.rejects(f.getActual(changed), error => error.message === 'actual_renderer_mismatch');
  }],
  ['raw-text escapes and missing or duplicated HTML markers still refuse', () => {
    for (const [name, value] of [['workspace_npm_publish.js', '/* </ScRiPt> */'], ['style.css', '/* </StYlE> */']]) {
      for (const managed of [false, true]) assert.throws(() => fixture({[name]: value}).render(managed),
        error => error.message === 'renderer_raw_text_terminator');
    }
    const html = fs.readFileSync(path.join(ASSETS, 'index.html'), 'utf8');
    for (const marker of ['__OPERATOR_DEMO_STYLE__', '__OPERATOR_DEMO_SCRIPT__']) {
      for (const value of [html.replace(marker, ''), html.replace(marker, marker + marker)]) {
        assert.throws(() => fixture({'index.html': value}).render(true), error => error.message === 'renderer_marker');
      }
    }
  }],
  ['a missing selected asset fails closed without fallback or runtime work', () => {
    for (const name of ['workspace_npm_publish.js', 'workspace_google_configuration.js']) {
      const failure = Object.assign(new Error('synthetic missing public asset'), {code: 'ENOENT'});
      for (const managed of [false, true]) assert.throws(() => fixture({[name]: failure}).render(managed),
        error => error === failure);
    }
    assert.equal(forbiddenCalls, 0);
  }],
  ['actual navigation helper awaits visibility before view inspection and preserves timeouts', async () => {
    for (const name of ['proxy', 'applications', 'notifications']) {
      const f = fixture(), calls = [];
      let release, entered, visible = false;
      const waiting = new Promise(resolve => { entered = resolve; });
      const visibility = new Promise(resolve => { release = resolve; });
      f.context.navigationName = name;
      f.context.fixturePage = {locator(selector) {
        if (selector === `nav a[href="#${name}"]`) return {
          async click() { calls.push('click'); },
          async getAttribute(attribute) { assert(visible); assert.equal(attribute, 'aria-current'); calls.push('aria'); return 'page'; }};
        if (selector === 'section.page#' + name) return {async waitFor(options) {
          assert.deepEqual(JSON.parse(JSON.stringify(options)), {state: 'visible'});
          calls.push('wait'); entered(); await visibility;
        }};
        assert.equal(selector, 'section.page:visible');
        return {async count() { assert(visible); calls.push('count'); return 1; }};
      }};
      const navigation = f.run('navigateSection(fixturePage, navigationName)');
      try {
        await Promise.race([waiting, navigation.then(() => assert(visible, 'navigation returned before visibility wait'))]);
        assert.deepEqual(calls, ['click', 'wait'], 'no aria/count/view checks before visibility resolves');
      } finally { visible = true; release(); }
      await navigation;
      assert.deepEqual(calls, ['click', 'wait', 'aria', 'count']);

      const timeout = Object.assign(new Error('synthetic navigation timeout'), {name: 'TimeoutError'});
      calls.length = 0; visible = false;
      const locator = f.context.fixturePage.locator;
      f.context.fixturePage.locator = selector => selector === 'section.page#' + name ?
        {async waitFor() { calls.push('wait'); throw timeout; }} : locator(selector);
      await assert.rejects(f.run('navigateSection(fixturePage, navigationName)'), error => error === timeout);
      assert.deepEqual(calls, ['click', 'wait']);
    }
    for (const [current, count] of [[null, 1], ['page', 0], ['page', 2]]) {
      const f = fixture();
      f.context.fixturePage = {locator: () => ({async click() {}, async waitFor() {},
        async getAttribute() { return current; }, async count() { return count; }})};
      await assert.rejects(f.run('navigateSection(fixturePage, "proxy")'), error => error.message === 'navigation_state_mismatch');
    }
    const f = fixture(); f.context.fixturePage = {locator: forbidden};
    await assert.rejects(f.run('navigateSection(fixturePage, "audit")'), error => error.message === 'navigation_section_refused');
  }],
  ['proxy-default refusal records only the five fixed booleans and success adds no diagnostic', async () => {
    const expectedChecks = {panel_visible: true, effective_fixture: true, form_hidden: true,
      no_review_get: true, restart_notice_present: true};
    for (const failed of [null, ...Object.keys(expectedChecks)]) {
      const f = fixture(), canary = 'synthetic-private-DOM-canary';
      f.context.fixturePage = {locator(selector) {
        if (selector === '#proxy-upstreams') return {
          async isVisible() { return failed !== 'panel_visible'; },
          async innerText() { return failed === 'restart_notice_present' ? canary :
            'Apps still need permission. Changes require a controlled restart.'; }};
        if (selector === '#upstreams-effective') return {async innerText() {
          return failed === 'effective_fixture' ? canary : 'https://demo-upstream:8443'; }};
        assert.equal(selector, '#upstreams-form');
        return {async isHidden() { return failed !== 'form_hidden'; }};
      }};
      if (failed === 'no_review_get') f.run('seen[UPSTREAMS] = 1');
      if (failed === null) {
        await f.run('verifyProxyDefault(fixturePage)');
        assert.equal(f.run('Object.hasOwn(receipt, "proxy_default_checks")'), false);
      } else {
        await assert.rejects(f.run('verifyProxyDefault(fixturePage)'), error => error.message === 'proxy_default_mismatch');
        const projection = f.run('JSON.stringify(receipt.proxy_default_checks)');
        assert.deepEqual(JSON.parse(projection), {...expectedChecks, [failed]: false});
        assert(!projection.includes(canary));
      }
      assert.equal(f.context.fixtureRequests.length, 0);
    }
  }],
];

(async () => {
  for (const [name, test] of tests) { await test(); process.stdout.write('PASS ' + name + '\n'); }
  assert.equal(forbiddenCalls, 0);
  process.stdout.write(`PASS ${tests.length} pure runtime-browser asset groups; no browser or service calls\n`);
})().catch(error => { console.error(error); process.exitCode = 1; });
