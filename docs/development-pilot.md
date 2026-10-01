# Local development pilot

Status: **preparation in progress, not yet a verified running pilot**. The
selected source is `17ab194b`, with isolated Compose project
`serverware-pilot-17ab194b`. The addresses below are the selected deployment
ports, not a claim that services are listening. Wait for the operator's runtime
handoff and public CA file before trying this walkthrough.

This exercises the actual control UI and Rust proxy against a synthetic HTTPS
upstream. It is **non-TEE and non-production**: host administrators can inspect
process memory; development authentication, keys and attestation are not
production trust. Use no real provider credentials or personal data. This
does not replace or satisfy the [full production goal](../goal.md).

## 1. Open the local UI

Open `http://127.0.0.1:13000/` on the deployment host. All published pilot ports
are loopback-only; this is not a public URL or authorization to expose them.

For access from your own computer, use an authorized SSH account on the actual
pilot host. Replace the two uppercase placeholders below; keep the tunnel open,
then use the same localhost URL. The second forward also permits the request
check from your computer after obtaining the public CA and checker from the
operator. Do not change Compose to bind publicly.

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:13000:127.0.0.1:13000 \
  -L 127.0.0.1:18080:127.0.0.1:18080 \
  YOUR_SSH_USER@YOUR_PILOT_HOST
```

1. Enter `dev-admin-token` in **Admin token or OIDC JWT**, then click **Refresh**.
   This is the explicit development operator token, not a username/password
   login. The optional **Sign in** button is for separately configured OIDC.
2. The operator seeds this isolated pilot once during startup. Do not click
   **Seed demo** during the walkthrough: it replaces demo data and advances
   the policy sequence. If the demo data is missing, stop and ask the operator.
3. Inspect **Credentials** for **Demo bearer token** and **Policies** for the
   demo policy/`demo.echo` route. Do not enter an upstream token yourself.
   After the requests below, **Audit** can show the resulting traffic.

The larger **Setup** workflow, OAuth provider connection and hardware assurance
are outside this first demonstration. A loaded page, a health check or an
attestation panel alone does not establish a working credential-replacement flow.
Do not edit credentials, publish policy or approve requests in this walkthrough.

## 2. Check credential replacement and denial

From the provided checkout, use Bash, Python 3 and curl. Replace the example
path with the absolute path to the public CA supplied in the runtime handoff:

```bash
SERVERWARE_PILOT_CA=/absolute/path/to/serverware-ca.pem \
  bash scripts/check_development_pilot.sh
```

Expected output, only after both real requests satisfy their checks:

```text
PASS: synthetic upstream credential used; raw credentials and proxy identity absent
PASS: valid workload identity denied access to an unlisted route (HTTP 403)
```

The [checker](../scripts/check_development_pilot.sh) uses the fixed local Rust
proxy at `http://127.0.0.1:18080` and supplies only a public development
**workload** token. `/echo` must return HTTP 200 with the synthetic upstream's
`initial` credential marker, while raw authorization, credential digest and
proxy identity fields must be absent. The same valid identity requesting
`/not-allowed` must return HTTP 403 with `unknown_route_denied`.

The upstream credential is not supplied by the client or printed by the checker.
TLS verification remains enabled; do not install the CA system-wide or add a
hosts-file entry. The proxy resolves `demo-upstream` inside its Compose network.
The check makes no credential/policy changes and does not seed data; requests
can create normal traffic/audit records. It does not prove enclave custody.

A connection failure, certificate failure, HTTP 500/503 or blank response is
not a successful denial check. Stop and give the operator the fixed error;
do not bypass authentication/TLS, change production controls or expose raw
credential-bearing responses for diagnosis.

## 3. Stop or resume the pilot

Use only the operator-provided, project-scoped status/start/stop commands.
Their final paths and successful stop/start evidence are still pending; this
guide does not authorize running an arbitrary Compose project or rebuilding
images. Stop preserves the pilot's data. Do not use `make reset`, delete
volumes or remove another stack's data. End an SSH tunnel with Ctrl-C.

## Runtime handoff and evidence

The operator must still confirm the exact images, public CA path, live UI and
both requests above, plus retained evidence and clean shutdown. No such result
is claimed by this draft.

The existing implementation references are the [development setup recipe](development-reference.md),
[UI and seed route](../serverware/app.py), [demo policy](../policies/demo.policy.json),
and the focused Rust [CONNECT](../scripts/test_decision_gate_connect.sh),
[MITM](../scripts/test_decision_gate_mitm.sh) and
[forwarding](../scripts/test_decision_gate_forward.sh) checks. Those scripts
also cover additional cases; this walkthrough intentionally selects only one
allowed request and one denied route.
