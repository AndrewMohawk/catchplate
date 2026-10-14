// Actual pinned Viem + Undici HTTP serialization into an in-memory Duplex via
// the public Agent connector hook. No sockets, DNS or TLS;
// this is NOT proxy/provider acceptance or a fake successful provider claim.
import assert from 'node:assert/strict';
import dns from 'node:dns';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { Duplex } from 'node:stream';
import test from 'node:test';
import { configuration, failure } from './client.mjs';
import { boundedDispatcher, createSdk, perform, RESPONSE_LIMIT, SDK_VERSION, UNDICI_VERSION } from './request.mjs';

const ENV = { SERVERWARE_PROXY_URL: 'https://proxy.example.test',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token', SERVERWARE_CA_FILE: '/not-read.pem',
  SERVERWARE_ALCHEMY_CHAIN: 'eth-mainnet' };

async function fixture(t, responseFor) {
  const forbid = () => { throw new Error('Offline SDK fixture forbids networking'); };
  t.mock.method(net.Socket.prototype, 'connect', forbid);
  t.mock.method(dns, 'lookup', forbid);
  const calls = [];
  class Wire extends Duplex {
    constructor(options) { super(); this.options = options; this.bytes = Buffer.alloc(0); this.replied = false; }
    _read() {}
    setTimeout() { return this; }
    setNoDelay() { return this; }
    setKeepAlive() { return this; }
    ref() { return this; }
    unref() { return this; }
    _write(chunk, encoding, callback) {
      try {
        this.bytes = Buffer.concat([this.bytes, chunk]);
        assert.ok(this.bytes.length <= 16384);
        const split = this.bytes.indexOf('\r\n\r\n');
        if (split >= 0 && !this.replied) {
          const [line, ...fields] = this.bytes.subarray(0, split).toString('ascii').split('\r\n');
          const headers = Object.fromEntries(fields.map((field) => {
            const colon = field.indexOf(':'); return [field.slice(0, colon).toLowerCase(), field.slice(colon + 1).trim()];
          }));
          const length = Number(headers['content-length']);
          assert.ok(Number.isInteger(length) && length > 0 && length < 1024);
          if (this.bytes.length === split + 4 + length) {
            this.replied = true;
            const body = JSON.parse(this.bytes.subarray(split + 4).toString('utf8'));
            const call = { line, headers, body, hostname: this.options.hostname, raw: this.bytes.toString('utf8') };
            calls.push(call);
            const reply = responseFor(call, calls.length);
            const payload = JSON.stringify(reply.body ?? { jsonrpc: '2.0', id: body.id,
              result: body.method === 'eth_chainId' ? '0x1' : '0x123' });
            const extra = reply.headers ?? '';
            setImmediate(() => {
              this.push(`HTTP/1.1 ${reply.status ?? 200} Fixture\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(payload)}\r\nConnection: close\r\n${extra}\r\n${payload}`);
              this.push(null);
            });
          }
        }
        callback();
      } catch (error) { callback(error); }
    }
  }
  assert.equal(JSON.parse(readFileSync(new URL('./node_modules/viem/package.json', import.meta.url))).version, SDK_VERSION);
  assert.equal(JSON.parse(readFileSync(new URL('./node_modules/undici/package.json', import.meta.url))).version, UNDICI_VERSION);
  const { createPublicClient, http } = await import('viem');
  const { Agent, fetch, interceptors } = await import('undici');
  const agent = new Agent({ connections: 1, pipelining: 0, allowH2: false,
    connect(options, callback) { callback(null, new Wire(options)); } });
  t.after(async () => { await agent.destroy(); });
  const config = configuration(ENV);
  const sdk = createSdk(config, boundedDispatcher(agent, interceptors), { createPublicClient, http, fetch });
  assert.equal(sdk.type, 'publicClient');
  assert.equal(sdk.transport.type, 'http');
  return { config, sdk, calls };
}

test('actual SDK serializes exactly two permitted JSON-RPC POSTs without discovery', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, () => ({}));
  assert.deepEqual(await perform(f.config, f.sdk), {
    ok: true, operation: 'chain-status', chain: 'eth-mainnet', chainId: '0x1', blockNumber: '0x123',
  });
  assert.equal(f.calls.length, 2);
  for (const [index, call] of f.calls.entries()) {
    assert.equal(call.line, 'POST /v2 HTTP/1.1');
    assert.equal(call.hostname, 'eth-mainnet.g.alchemy.com');
    assert.deepEqual(call.body, { jsonrpc: '2.0', id: index,
      method: index === 0 ? 'eth_chainId' : 'eth_blockNumber', params: [] });
    assert.deepEqual(Object.keys(call.headers).sort(), ['accept', 'accept-encoding', 'accept-language',
      'authorization', 'connection', 'content-length', 'content-type', 'host', 'sec-fetch-mode', 'user-agent']);
    assert.equal(call.headers.authorization, 'Bearer serverware-alchemy-placeholder-v1');
    assert.equal(call.headers.accept, 'application/json');
    assert.equal(call.headers['accept-encoding'], 'identity');
    assert.equal(call.headers['accept-language'], '*');
    assert.equal(call.headers['sec-fetch-mode'], 'cors');
    assert.equal(call.headers['user-agent'], 'undici');
    assert.equal(call.headers.connection, 'close');
    assert.equal(call.headers['content-type'], 'application/json');
    assert.equal(call.headers.host, 'eth-mainnet.g.alchemy.com');
    for (const value of [ENV.SERVERWARE_APP_ID, ENV.SERVERWARE_PROXY_TOKEN, 'proxy-authorization']) {
      assert.equal(call.raw.includes(value), false);
    }
  }
});

test('actual SDK HTTP429 is one attempt without Retry-After stall or second RPC', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, () => ({ status: 429, headers: 'Retry-After: 999\r\n', body: { error: 'private_canary' } }));
  await assert.rejects(perform(f.config, f.sdk));
  assert.equal(f.calls.length, 1);
});

test('HTTP421 cannot trigger a hidden fetch replay or the second RPC', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, () => ({ status: 421, body: { error: 'private_canary' } }));
  let error;
  try { await perform(f.config, f.sdk); } catch (caught) { error = caught; }
  assert.ok(error);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].body.method, 'eth_chainId');
  assert.equal(JSON.stringify(failure(error)).includes('private_canary'), false);
});

test('POST redirect is not followed by the actual SDK', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, () => ({ status: 302,
    headers: 'Location: https://eth-mainnet.g.alchemy.com/unapproved\r\n', body: {} }));
  await assert.rejects(perform(f.config, f.sdk));
  assert.equal(f.calls.length, 1);
});

test('HTTP200 JSON-RPC error remains failure, without provider text in output', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, (call) => ({ body: { jsonrpc: '2.0', id: call.body.id,
    error: { code: -32000, message: 'private_canary', data: 'private_canary' } } }));
  let error;
  try { await perform(f.config, f.sdk); } catch (caught) { error = caught; }
  assert.ok(error);
  assert.equal(f.calls.length, 1);
  assert.equal(JSON.stringify(failure(error)).includes('private_canary'), false);
});

test('wrong-chain response stops before the second actual SDK read', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, (call) => ({ body: { jsonrpc: '2.0', id: call.body.id, result: '0xaa36a7' } }));
  await assert.rejects(perform(f.config, f.sdk));
  assert.equal(f.calls.length, 1);
});

test('transport method allowlist refuses other RPC methods without a request', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, () => ({}));
  await assert.rejects(f.sdk.request({ method: 'web3_clientVersion', params: [] }));
  assert.equal(f.calls.length, 0);
});

test('bounded actual SDK response rejects oversized JSON without retry', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, (call) => ({ body: { jsonrpc: '2.0', id: call.body.id, result: 'x'.repeat(RESPONSE_LIMIT) } }));
  await assert.rejects(perform(f.config, f.sdk));
  assert.equal(f.calls.length, 1);
});
