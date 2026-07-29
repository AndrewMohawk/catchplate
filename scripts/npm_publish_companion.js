#!/opt/serverware/node/bin/node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const PROCESS_TIMEOUT_MS = 30000;
const INPUT_VERSION = "serverware.npmOneUseRequest/v2";
const RESULT_VERSION = "serverware.npmOneUseResult/v2";
const NPM_CLI = "/opt/serverware/npm/bin/npm-cli.js";
const NODE = "/opt/serverware/node/bin/node";
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const TOKEN = /^[0-9a-f]{64}$/;

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Number.isSafeInteger(value)) {
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("unsupported JSON value");
}

function digest(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function exactKeys(value, keys, label) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    canonical(Object.keys(value).sort()) !== canonical([...keys].sort())
  ) {
    throw new Error(`${label} fields are not exact`);
  }
}

function requireToken(value, label) {
  if (typeof value !== "string" || !TOKEN.test(value)) {
    throw new Error(`${label} is invalid`);
  }
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} is invalid`);
  }
}

function safePort(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65535) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function parseInput(raw) {
  if (raw.length < 2 || raw.length > MAX_INPUT_BYTES || raw[raw.length - 1] !== 0x0a) {
    throw new Error("input must be one bounded newline-terminated JSON frame");
  }
  if (raw.subarray(0, raw.length - 1).includes(0x0a)) {
    throw new Error("input contains multiple frames");
  }
  const text = raw.subarray(0, raw.length - 1).toString("ascii");
  const value = JSON.parse(text);
  if (canonical(value) !== text) {
    throw new Error("input is not canonical JSON");
  }
  exactKeys(
    value,
    [
      "apiVersion",
      "attempt",
      "caPem",
      "lane",
      "laneOneUseNonce",
      "laneSequence",
      "leaseId",
      "manifestSha256",
      "operation",
      "operationInputSha256",
      "packageTarballBase64",
      "packageTarballSha256",
      "promotionReceiptSha256",
      "proxyPort",
      "registryPort",
      "requestNonce",
      "sequence",
    ],
    "request",
  );
  if (
    value.apiVersion !== INPUT_VERSION ||
    value.operation !== "npm.publish.fixture" ||
    value.lane !== "portal-browser-oauth" ||
    value.laneSequence !== 10 ||
    ![1, 2].includes(value.attempt) ||
    value.sequence !== value.attempt
  ) {
    throw new Error("request selected an unsupported operation");
  }
  requireToken(value.leaseId, "lease");
  requireToken(value.laneOneUseNonce, "lane one-use nonce");
  requireToken(value.requestNonce, "request nonce");
  requireDigest(value.manifestSha256, "manifest digest");
  requireDigest(value.operationInputSha256, "operation input digest");
  requireDigest(value.packageTarballSha256, "tarball digest");
  requireDigest(value.promotionReceiptSha256, "promotion receipt digest");
  safePort(value.proxyPort, "proxy port");
  safePort(value.registryPort, "registry port");
  if (
    typeof value.caPem !== "string" ||
    !value.caPem.startsWith("-----BEGIN CERTIFICATE-----\n") ||
    !value.caPem.endsWith("-----END CERTIFICATE-----\n")
  ) {
    throw new Error("CA certificate is invalid");
  }
  if (
    typeof value.packageTarballBase64 !== "string" ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value.packageTarballBase64)
  ) {
    throw new Error("tarball base64 is invalid");
  }
  const tarball = Buffer.from(value.packageTarballBase64, "base64");
  if (
    tarball.length === 0 ||
    tarball.length > 1024 * 1024 ||
    tarball.toString("base64") !== value.packageTarballBase64 ||
    digest(tarball) !== value.packageTarballSha256
  ) {
    throw new Error("tarball bytes are invalid");
  }
  const operationPayload = {
    apiVersion: "serverware.npmOperationInput/v1",
    caPem: value.caPem,
    operation: value.operation,
    packageTarballBase64: value.packageTarballBase64,
    packageTarballSha256: value.packageTarballSha256,
    proxyPort: value.proxyPort,
    registryPort: value.registryPort,
  };
  if (digest(Buffer.from(canonical(operationPayload), "ascii")) !== value.operationInputSha256) {
    throw new Error("operation input digest is invalid");
  }
  return { value, tarball };
}

function boundedAppend(target, chunk) {
  if (target.bytes + chunk.length > MAX_OUTPUT_BYTES) {
    throw new Error("npm output exceeded its bound");
  }
  target.chunks.push(chunk);
  target.bytes += chunk.length;
}

async function run() {
  const chunks = [];
  let inputBytes = 0;
  for await (const chunk of process.stdin) {
    inputBytes += chunk.length;
    if (inputBytes > MAX_INPUT_BYTES) {
      throw new Error("input exceeded its bound");
    }
    chunks.push(chunk);
  }
  const { value, tarball } = parseInput(Buffer.concat(chunks));
  const root = "/work/npm-one-use";
  fs.mkdirSync(root, { recursive: false, mode: 0o700 });
  const home = path.join(root, "home");
  const cache = path.join(root, "cache");
  const tmp = path.join(root, "tmp");
  for (const directory of [home, cache, tmp]) {
    fs.mkdirSync(directory, { mode: 0o700 });
  }
  const tarballPath = path.join(root, "fixture.tgz");
  const configPath = path.join(root, "empty.npmrc");
  const caPath = path.join(root, "registry-ca.pem");
  fs.writeFileSync(tarballPath, tarball, { mode: 0o600, flag: "wx" });
  fs.writeFileSync(configPath, "", { encoding: "ascii", mode: 0o600, flag: "wx" });
  fs.writeFileSync(caPath, value.caPem, { encoding: "ascii", mode: 0o600, flag: "wx" });

  const argv = [
    NPM_CLI,
    "publish",
    tarballPath,
    `--registry=https://127.0.0.1:${value.registryPort}/`,
    `--https-proxy=http://127.0.0.1:${value.proxyPort}`,
    `--cafile=${caPath}`,
    "--strict-ssl=true",
    "--fetch-retries=0",
    "--ignore-scripts=true",
    "--tag=latest",
    "--access=public",
    "--json",
    "--loglevel=error",
    "--progress=false",
  ];
  const env = {
    CI: "true",
    HOME: home,
    LANG: "C",
    LC_ALL: "C",
    NO_PROXY: "",
    PATH: "/opt/serverware/node/bin",
    TMPDIR: tmp,
    npm_config_audit: "false",
    npm_config_cache: cache,
    npm_config_fund: "false",
    npm_config_globalconfig: configPath,
    npm_config_tmp: tmp,
    npm_config_update_notifier: "false",
    npm_config_userconfig: configPath,
  };
  const stdout = { bytes: 0, chunks: [] };
  const stderr = { bytes: 0, chunks: [] };
  const child = spawn(NODE, argv, {
    cwd: root,
    env,
    detached: false,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let outputError = null;
  const capture = (target, chunk) => {
    try {
      boundedAppend(target, chunk);
    } catch (error) {
      outputError = error;
      child.kill("SIGKILL");
    }
  };
  child.stdout.on("data", (chunk) => capture(stdout, chunk));
  child.stderr.on("data", (chunk) => capture(stderr, chunk));
  child.stdout.once("error", (error) => {
    outputError = error;
    child.kill("SIGKILL");
  });
  child.stderr.once("error", (error) => {
    outputError = error;
    child.kill("SIGKILL");
  });
  const exitCode = await new Promise((resolve, reject) => {
    let timedOut = false;
    let settled = false;
    let processError = null;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, PROCESS_TIMEOUT_MS);
    child.once("error", (error) => {
      processError = error;
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (processError !== null) {
        reject(processError);
        return;
      }
      if (outputError !== null) {
        reject(outputError);
        return;
      }
      if (timedOut) {
        reject(new Error("npm companion exceeded its fixed deadline"));
        return;
      }
      if (signal !== null || !Number.isSafeInteger(code)) {
        reject(new Error("npm companion terminated abnormally"));
        return;
      }
      resolve(code);
    });
  });
  const stdoutBytes = Buffer.concat(stdout.chunks);
  const stderrBytes = Buffer.concat(stderr.chunks);
  const reported428 = /(?:\bE428\b|\b428\b[^\r\n]*precondition required\b)/i.test(
    Buffer.concat([stdoutBytes, Buffer.from("\n"), stderrBytes]).toString("utf8"),
  );
  if (
    exitCode !== (value.attempt === 1 ? 1 : 0) ||
    reported428 !== (value.attempt === 1)
  ) {
    throw new Error("npm companion outcome differs from the fixed two-attempt contract");
  }
  const output = {
    apiVersion: RESULT_VERSION,
    argvSha256: digest(Buffer.from(canonical([NODE, ...argv]), "ascii")),
    attempt: value.attempt,
    environmentSha256: digest(Buffer.from(canonical(env), "ascii")),
    exitCode,
    leaseId: value.leaseId,
    manifestSha256: value.manifestSha256,
    operationInputSha256: value.operationInputSha256,
    promotionReceiptSha256: value.promotionReceiptSha256,
    requestNonce: value.requestNonce,
    stderrBytes: stderrBytes.length,
    stderrSha256: digest(stderrBytes),
    stdoutBytes: stdoutBytes.length,
    stdoutSha256: digest(stdoutBytes),
  };
  const result = { ...output, resultSha256: digest(Buffer.from(canonical(output), "ascii")) };
  process.stdout.write(`${canonical(result)}\n`);
}

run().catch((error) => {
  process.stderr.write(`${String(error && error.message ? error.message : error)}\n`);
  process.exitCode = 2;
});
