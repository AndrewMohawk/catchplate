> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Local development pilot

Status: **not yet a working pilot; walkthrough pending commissioning**. The
current launcher targets the unsigned `33140e27` package in an isolated guest,
with the exact retained `17ab194b` Rust executable and measured guest libraries.
The Rust build inputs match the selected source; this is not a rebuilt image.
Six distinct proxy service credentials and read-only runtime disks are prepared.
The existing `serverware-pilot-17ab194b` database, witness and synthetic upstream
support that guest; its normal app and proxy have not run. No demo seed,
verified CA handoff, browser acceptance or proxy request has completed.

The required [commissioning sequence](pilot-commissioning.md) includes
[local-authority startup](trusted-host-local-startup.md), actual signed-package
installation and authentication/schema bootstrap, genuine policy genesis and
its offline development file install. The
repaired demo seed reuses an already committed policy; it cannot publish one.
SQLite/non-atomic
settings do **not** provide a supported substitute. The addresses and commands
below describe the intended handoff, not a currently usable release. Wait for
the operator's verified runtime handoff and public CA file before using them.

This exercises the actual control UI and Rust proxy against a synthetic HTTPS
upstream. It is **non-TEE and non-production**: host administrators can inspect
process memory; development authentication, keys and attestation are not
production trust. Use no real provider credentials or personal data. This
does not replace or satisfy the [full production goal](../goal.md).

## 1. Connect and complete first enrollment

The browser and physical FIDO2 YubiKey belong on your own computer, not in the
AWS console or an unattended server browser. The selected browser origin is
**https://serverware.example.com/**. Use this exact HTTPS hostname, not
localhost, the lab alias or the server's IP address. Sign in through the usual
homelab Authelia login with the `operator` account. The pilot ingress permits
only that operator; Authelia login does not itself enroll a Serverware key or
grant an application administrator session.

No SSH tunnel is needed for the browser. The [homelab ingress](homelab-deployment.md)
keeps the internal listeners private and preserves the browser's exact origin.
An authentication redirect or a commissioning-unavailable response is not a
working pilot. Have your YubiKey inserted and its PIN available, then tell the
operator you are ready.
The page does not run until the operator starts enrollment and announces that
the registration browser is ready. Do not start the launch just to probe it:
its original approval windows are short and are not renewed automatically.

Open the exact HTTPS URL when instructed and complete these four prompts:

1. **Create registration credential** using the external YubiKey.
2. On that same page, **Confirm final completion with your key**.
3. Wait for the operator to announce the policy browser, then reload the same
   URL and choose **Approve exact policy preparation**.
4. On that page, **Approve exact policy finalization**.

No manually entered admin or bootstrap token is needed for these four prompts.
Enter the PIN only in the browser/system prompt, never in chat. Respond promptly;
completion and final policy approval have particularly short remaining windows.
If an operation expires, is cancelled or fails, stop and let the operator inspect
the retained outcome. Do not refresh mid-ceremony or repeat the action.

### Normal application after commissioning

Wait for the operator's application-ready announcement before continuing. The
same URL changes from enrollment pages to the normal application; the enrollment
pages alone do not prove application startup or proxy readiness.

1. Enter the scoped operator token provided through the private runtime handoff
   in **Admin token or OIDC JWT**, then click **Refresh**. There is no fixed
   published admin password or token. Do not paste it into chat. The optional
   **Sign in** button is for separately configured OIDC.
2. The selected launcher's continuation calls the existing authenticated demo
   seed endpoint once, after genuine policy commissioning and before CA/proxy
   startup. Wait for its actual success announcement. Do not click **Seed demo**
   again or attempt to manufacture policy-authority records. If demo data is
   missing, stop and ask the operator; an uncertain seed request is not retried.
3. Inspect **Credentials** for **Demo bearer token** and **Policies** for the
   demo policy/`demo.echo` route. Do not enter an upstream token yourself.
   After the requests below, **Audit** can show the resulting traffic.

The larger **Setup** workflow, OAuth provider connection and production hardware
assurance are outside this first demonstration. A loaded page, a health check or an
attestation panel alone does not establish a working credential-replacement flow.
Do not edit credentials, publish policy or approve requests in this walkthrough.

## 2. Check credential replacement and denial

Run this on the pilot host, or forward only the private proxy port over your
existing authorized SSH access:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:18080:127.0.0.1:18080 YOUR_SSH_USER@YOUR_PILOT_HOST
```

This optional tunnel is for the command-line proxy check, not browser enrollment.
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
hosts-file entry on your computer. In the selected guest, `demo-upstream`
resolves to a fixed virtual endpoint that forwards only to the existing
synthetic TLS upstream. The signed destination policy and TLS checks remain.
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
