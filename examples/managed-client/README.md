# Managed workload client (Python)

This standalone Linux example keeps a workload's Serverware proxy login renewed
under an explicit, finite administrator enrollment. It does not receive a real
provider credential, extend its enrollment, acquire new permissions, or provide
native/hardware-backed authority. The ordinary renewal feature is deployed;
see the [recorded checkpoint](../../docs/project-completion.md#current-checkpoint--october-13-workload-renewal-rollout).
The source and offline tests alone do **not** establish proxy continuity or a
successful GitHub request. No existing client was automatically enrolled.

`managed_client.py` uses only the Python standard library and `cryptography`.
`github_read_loop.py` adds unmodified `requests` for repeated read-only GitHub
issues-list calls. Neither imports private Serverware server modules.

## Enroll once

Use CPython 3.11+ on a trusted Linux host, a dedicated application per worker/replica, and a
private directory on a local filesystem supporting `flock`, atomic rename and
`fsync`. Do not use shared/network filesystems or share the directory across
replicas. The directory must be owned by the current user and mode `0700`; files
must be owned by that user, mode `0600`, regular, and not multiply hard-linked.
Symlinked state directories and state files are refused, not silently repaired.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
.venv/bin/python -B managed_client.py --state-dir /absolute/private/workload init
```

The command generates an Ed25519 private key locally and prints **only its public
key**. Running it again displays the same key; it does not rotate it. Enroll that
public key in the application's managed-renewal UI, choose the finite enrollment
deadline and token lifetime, then download its public setup JSON. The server and
browser do not need this directory or the private key.

Save the application's existing one-time proxy token in a separate `0600` file
using your secret manager. Do not put the token in command arguments, environment
variables, shell history or the setup JSON. An already expired proxy token can be
imported when the key enrollment is still valid: renewal authenticates with the
enrolled key, not that expired token. The imported old token remains required by
this example's initial local state; it is never sent to the renewal endpoint.

```bash
.venv/bin/python -B managed_client.py --state-dir /absolute/private/workload \
  configure --setup-file /absolute/public/setup.json \
  --token-file /absolute/private/bootstrap-token
.venv/bin/python -B managed_client.py --state-dir /absolute/private/workload status
```

The closed public setup document is:

```json
{
  "schema": "serverware.managedClientSetup/v1",
  "application_id": "11111111-1111-4111-8111-111111111111",
  "enrollment_id": "22222222-2222-4222-8222-222222222222",
  "audience": "https://your-proxy-host/v1/workload/renew",
  "public_key_fingerprint": "sha256:<64 lowercase hex characters>",
  "token_generation": 1,
  "token_expires_at_epoch_ms": 1800003600000,
  "enrollment_expires_at_epoch_ms": 1800086400000,
  "token_lifetime_seconds": 3600,
  "overlap_seconds": 300
}
```

Download your real document; those illustrative values are not an enrollment.
The helper checks the fingerprint against its locally derived public key.
`configure` refuses to overwrite an existing journal. Token output is deliberately
absent from `init`, `configure`, `renew` and `status` (only `init` prints the public
key). Keep local state and bootstrap files out of version control and backups
unless those backups are designed to hold credentials.

## Run a worker

For the example below, enable **Basic proxy authentication** on this application,
save a GitHub PAT or GitHub App connection on Serverware, and grant only the
**GitHub issues: read** preset for the exact repository. Download the proxy's
interception CA. A GitHub App's private key and installation tokens stay on the
server. The public `token serverware-github-placeholder-v1` request header is
replaced by the proxy after permission checks; never supply a real GitHub token.

```bash
.venv/bin/python -B github_read_loop.py \
  --state-dir /absolute/private/workload \
  --ca-file /absolute/public/serverware-ca.pem \
  --owner your-owner --repo your-repository --interval 30
```

Use `--iterations 3` for a finite **real provider** run; do not run it until that
provider contact is intended. Each iteration makes at most one GET, asks for one
issue, reads at most 64 KiB, refuses redirects and disables transport retries.
It prints only the number of issues observed and token generation. The loop has
a ten-second total provider-read deadline and checks the manager at least every
60 seconds. A normal request/renewal/sleep cycle is bounded below five minutes.
On generation change it closes the previous Requests session before building
the replacement. On an unavailable lease or request failure it closes its pool;
no expired login is silently retained. Ctrl-C/SIGTERM closes the pool and lock.

Both outer HTTPS proxy TLS and intercepted provider TLS remain verified. The
Requests example uses a temporary bundle containing certifi roots plus the
downloaded CA for **both** layers; those trust policies are not isolated.
Renewal itself connects directly to the configured public HTTPS proxy origin
using normal system trust, without an interception CA, environment proxies,
administrator tokens, browser cookies, or an existing proxy login. Its request
is signed, bounded to 4 KiB, and its JSON response to 8 KiB. A short-lived child
process bounds DNS/connect/read/response handling to 15 seconds. Redirects are
refused. No global trust or SDK configuration is modified.

The stock Requests proxy URL contains percent-encoded application ID/token in
process memory only. It is not written to an environment, log or command line,
but a same-user debugger/process dump can still expose it. Do not enable HTTP
debug logging, print leases/session objects, or use this as a secure enclave.

## Embed in another long-running worker

```python
from managed_client import ManagedClient

with ManagedClient("/absolute/private/workload") as manager:
    lease = manager.lease()  # May perform one bounded renewal/recovery attempt.
    # Construct the SDK with lease.token using its normal proxy interface.
    # Before every bounded provider operation, call lease() again.
    # If lease.generation changes, close and replace the SDK connection pool.
```

Hold the manager for the worker's lifetime on its construction thread; other
threads/processes cannot use that owner. Only one writer is supported. Calling
`lease()` regularly is required—there is no background refresh thread. The first
lease immediately attempts signed renewal, even if the imported manual token is
long-lived or clipped to the grant deadline. Subsequent renewal begins within ten
minutes of token expiry, except when that managed token already ends at the
enrollment deadline. `TokenLease.pool_refresh_by_epoch_ms` communicates
the previous-token cutoff; a previously expired token has no overlap, so the
handoff is immediate. The example always hands off immediately, not at the last
possible second. Do not hand a token permanently to an SDK and forget the manager.
Wall-clock rollback is refused. Host suspension does not extend any expiry.

The helper does not wrap, replay, retry or make decisions about provider writes.
After a token change, only your application can decide whether a new operation
is appropriate. Never automatically replay a write after an uncertain response.

## Lost responses and restart recovery

Before networking, the helper persists the candidate token and **exact signed
request bytes** by file fsync, atomic rename, and directory fsync. It keeps the
old token until the response joins the operation ID, signed digest, application,
enrollment, generations, verifier, issuance/rotation/expiry and previous cutoff,
plus the current public application, at least one active permission, active
application access, and matching **active** policy observation. A globally loaded
policy without an assigned application permission is not sufficient.
The immutable receipt and current policy observation are separate objects.

If dispatch or activation is uncertain, the candidate is not installed and the
journal is retained. Restart the same helper on the same directory, or run:

```bash
.venv/bin/python -B managed_client.py --state-dir /absolute/private/workload renew
```

Recovery resends only that same operation; it never generates a new candidate,
UUID, signature, or deadline while one is unresolved. A committed operation can
be recovered after its original request window expires, but its token/enrollment
expiry does not move. If the request never committed before expiry, obtain
operator assistance; do not delete the journal and guess. If the candidate itself
expires, it is not installed. Cancellation, replacement or manual rotation may
require a new enrollment and a new private directory.

A lost response may mean the server already rotated. The old token is usable
locally only until its original expiry or the earliest possible five-minute
overlap cutoff, whichever comes first. After that the worker stops provider
requests until exact recovery succeeds. A persistence error poisons that manager;
close and reopen it so the actual journal determines recovery. Preserve that
journal rather than overwriting it. Same-user file tampering and disk/host loss
are outside the protection of Unix permissions.

## Offline checks and evidence boundary

From this directory, with the pinned dependencies installed:

```bash
.venv/bin/python -B -m unittest discover -s . -p 'test_*.py'
```

For the complete repository suite, provision both dependency inputs into an
isolated test environment (networked setup, not offline acceptance):

```bash
python3 -m venv .test-venv
.test-venv/bin/python -m pip install --require-hashes --only-binary=:all: \
  -r ../../requirements.lock -r requirements.lock
.test-venv/bin/python -B ../../scripts/test_managed_client.py
```

The example lock includes the exact Requests dependency closure and wheel hashes
from each release's official PyPI metadata. Shared versions match the server
lock. CI provisions both into its isolated dependency mount before entering the
network-disabled ordinary lane; no Requests dependency is added to the production
image or production lock. The older CODER isolated-image lane does not carry
this example and does not claim to run it. Missing/mismatched real dependencies
fail the ordinary suite instead of skipping or substituting Requests.

The wire-parity test also needs the repository's server dependencies available;
only that test imports `serverware.operator_workload_renewal`. Other tests use
real temporary disk journals and fake HTTP to exercise crash/restart, exact
replay, private permissions, single-writer locking, response refusal, expiry,
overlap and stock Requests pool handoff. They make no network/provider requests.
An isolated check separately exercised real renewal HTTP, loaded normal-proxy
policy, old/new CONNECT sessions and stock Requests 2.31.0 handoff against a
synthetic provider. It did not use this helper's default HTTPS renewal transport
or its newer locked Requests graph. Those exact helper/transport checks and a
real enrolled provider job remain open; do not treat the deployed read-only UI
check as their acceptance. See the [renewal contract](../../docs/operator-workload-renewal.md).
