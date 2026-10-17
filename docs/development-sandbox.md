> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Persistent synthetic development sandbox

This explicitly selected profile runs the real operator portal, policy compiler,
encrypted credential storage, Rust HTTPS proxy, response filtering and durable
audit against a local HTTPS demo upstream. It avoids creating a measured pilot
for each browser test. Data and local test keys survive browser refresh and
container restart. It is not production, hardware, enclave or real-provider
acceptance.

The deployment lives in the homelab repository's `docker/catchplate-sandbox`.
The browser address is `https://catchplate-sandbox.example.com`, protected
by the existing Authelia middleware and an exact operator/Traefik-peer check.
No operator token needs to be copied into the browser. Select **Run synthetic
proxy check** to exercise the actual internal TLS path and inspect the result.

## Scope

- Dedicated runner: `python -m catchplate.development_sandbox_runner`, with
  explicit `CATCHPLATE_DEVELOPMENT_SANDBOX=1`. The ordinary runner never
  activates this profile, and production selections are refused.
- Fresh, private marked data directory. Existing unmarked data is never
  adopted. Local test keys, a genuinely signed fixed `catchplate-demo` policy,
  encrypted synthetic credential and demo routes are created once.
- Separate SQLite policy/nonce database. Nonce replay checks are transactional
  and persist across restarts. No PostgreSQL authority receipts are fabricated.
- Rust independently requires the explicit sandbox flag, exact development
  profile, private synthetic marker, local service URLs and signed demo-only
  destinations. It pins the signed policy hash for that process. Ordinary and
  native constructors keep their commissioning requirement. Sandbox serving
  readiness is distinct from policy-shadow commissioning readiness, which
  remains false rather than claiming a completed ceremony.
- Only the fixed synthetic proxy check, demo seed and real internal
  credential-lease/audit writes are admitted. Production configuration,
  provider authorization, enrollment and authority mutation are unavailable.
- The proxy and app have only an internal Docker network; no host ports,
  external DNS forwarding or provider egress. The HTTP edge alone joins
  Traefik's network. Service tokens remain private runtime files.
- The deployment sets `CATCHPLATE_DATA_PLANE_AUDIT_BATCH_MAX=1` for this
  synthetic legacy transport. Multi-event retries can otherwise combine an
  already-committed event with new events, which the immutable audit store
  correctly rejects. Singleton batching preserves signed acknowledgements and
  exact event-ID replay checks; it does not relax the database or repair the
  general multi-event retry implementation.
- Full atomic/JIT/quota commissioning and hardware workflows are not supplied
  by this profile. The separate measured pilot remains unchanged.

## Verification

`scripts/test_development_sandbox_store.py` exercises real signed policy
admission, persistence, replay/capacity/expiry and concurrent nonce reservations.
`scripts/test_development_sandbox_runtime.py` launches the actual runner twice
with fresh synthetic data and checks the portal, authentication, bootstrap,
refused configuration writes and persistent data identity.

`scripts/check_development_sandbox.py` runs only against an explicitly identified
sandbox. It checks the selected Rust executable digest, CONNECT/TLS, credential
injection and filtering, negative dispatch controls, response-field projection
and correlated stored audit events. Transforming request streams, including
nested JSON, are deliberately unsupported by the current proxy authorization
path: the checker proves their explicit HTTP 422 refusal without upstream
dispatch, not bidirectional streaming redaction. The portal invokes this same
bounded checker, accepting no arbitrary target or test input.

`scripts/check_development_sandbox_browser.cjs` uses local Playwright against
real deployed backend responses through a transport adapter. It checks rendered
data, reload and optionally the proxy-check button. This is not proof of an
already signed-in human Authelia session. Edge identity/Origin controls and the
public sign-in redirect must also be checked separately.

`scripts/probe_development_sandbox_lease.py` independently checks the actual
loopback broker: both metadata and synthetic-secret leases must decrypt with
their real recipient bindings, and each exact nonce replay must return 409.
It refuses a non-sandbox target and prints only status/verification labels,
never tokens, plaintext credentials or encrypted envelopes.

`scripts/diagnose_development_sandbox_audit.py` records the bounded, operator-
gated recovery used for the observed 15-event retry batch. Capture is limited to
the named sandbox pair, eight seconds and one MiB; bodies stay in process memory.
Its optional recovery refuses any state other than the reviewed exact 1-present,
14-missing, zero-conflict case and replays only those original events through
the authenticated API. It is not a startup action or a general repair/reset tool.

See the deployment README and its verification record for the actual runtime
artifact, measured timings, test outcomes and remaining boundaries. Cached
images provide dependencies only; Python source and the selected freshly built
Rust executable are read-only overlays, not a newly built production release.
