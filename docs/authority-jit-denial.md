> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# JIT denial source repair

Status: source implementation with passing focused, PostgreSQL and ordinary CI
component results. The subsequent metadata-reader repair also passed its
56-suite CI inventory. The original-expiry repair below passed focused tests;
its expanded CI inventory is pending. This is not a completed
ordinary approval journey or deployment acceptance. The live application
remains `a3899a95`; this repair has not been deployed.

## Connected denial contract

The former mismatch between the denial API, its challenge target, verified
evidence, transition kernel and writer history is repaired in source. The path
still requires an already-issued, genuine review receipt and the existing
authority owners; it does not create an alternate review or approval authority.

In [`app.py`](../catchplate/app.py), both denial routes require the authenticated
`approver` dependency, a pending and unexpired request, current policy, an
eligible actor and that actor's active review receipt for the same request:

- `POST /api/approvals/{approval_id}/deny/webauthn/options` accepts
  `reviewReceiptId` and optional `reason`. It issues an authority challenge for
  exactly `jit.deny`, bound to the original decision arguments.
- `POST /api/approvals/{approval_id}/deny` additionally requires the original
  `assertion` and `authorityChallengeId`. It forwards the same reason, review
  digest, actor and stored policy bindings to `db.deny_request`; it returns only
  the public approval summary. Neither denial request accepts a grant TTL.

The shared note validator admits at most 500 UTF-8 bytes, without silently
trimming or normalizing text; leading/trailing whitespace, C0/DEL controls and
invalid Unicode are rejected. `null` and an empty note remain supported. This
removes the former 2,000-character API versus 500-byte kernel mismatch.
[`webauthn.py`](../catchplate/webauthn.py) shares the options producer with
approval, but keeps `jit.decide` and `jit.deny` as distinct challenge targets.
An unavailable denial outcome is not permission to resubmit: the API requires
checking approval status before another decision and performs no automatic retry.

## Kernel and independent writer checks

[`authority_transition_jit_denial.py`](../catchplate/authority_transition_jit_denial.py)
requires independently verified v9 assertion evidence and the exact raw
assertion bytes. It rechecks the actor, current roles/policy, credential/trust,
challenge, request and review bindings. One eligible actor can deny even when
approval needs multiple approvers. A fresh denial consumes the review and
challenge, advances the authenticator counter and records the denied request
plus `approval.denied` audit event. It creates no approval vote or grant and
refuses an existing grant. Exact kernel replay is read-only and remains subject
to its original evidence/currentness checks; the HTTP route does not accept a
new decision against an already-terminal request.

[`jit_denial_sql.py`](../catchplate/authority_store/jit_denial_sql.py), called
inside the existing v9 executor, independently rejects a mismatched selected
row, mutation, actor/policy, review, capability, deadline or raw-receipt binding.
It requires the exact denial update and refuses grant/vote mutations. The
existing assertion, trust, challenge/counter and business-row CAS checks are
not replaced by this denial-specific check.

The executor also retains the admitted raw WebAuthn receipt through
[`webauthn_receipt_history.py`](../catchplate/authority_store/webauthn_receipt_history.py)
in the same transaction, before the decision's history dependency. Later CAS
or commit failure rolls it back with the decision. A committed executor replay
only checks exact original history; it cannot backfill a missing receipt or
turn historical evidence into fresh authority.

## Evidence and remaining work

The component suites deliberately retain these evidence boundaries:

- [`test_jit_denial_api.py`](../scripts/test_jit_denial_api.py): actual
  source-selected models, route functions, argument and options producers with
  explicit DB/authority/dependency doubles. This is not full ASGI or native
  review-opening acceptance.
- [`test_authority_jit_denial.py`](../scripts/test_authority_jit_denial.py): real
  ES256/Ed25519 verification and kernel controls using synthetic roots and
  selected originals; optional disposable PostgreSQL checks exercise actual
  denial/history/CAS SQL helpers. The SQL fixture is not the full installed
  executor or a genuinely admitted authority capability.

The initial component runs passed 12 API units and seven pure denial controls
after correcting a fixture's revoked-key identifier. The denial PostgreSQL run
passed ten controls (the same seven pure controls plus three actual SQL and
rollback controls; not ten additional tests). The first PostgreSQL attempt
refused the socket directory mode before tests; the directory was corrected to
`0700` without relaxing the guard. Both failure and corrected-run evidence are
retained under `jit-denial.6WXPZoci` and `jit-denial-fixed.ZDnMSB` in the
operator-workspace evidence directory.

The existing approval PostgreSQL regression then failed on its second-vote
path: shared-core floating-point epoch conversion rounded an equal timestamp
by 64 nanoseconds, making it appear to be in the future. The source now uses
exact integer epoch-nanosecond conversion in
[`authority_transition_core.py`](../catchplate/authority_transition_core.py),
with no tolerance or deadline extension. Deterministic precision controls in
[`test_authority_jit_approval.py`](../scripts/test_authority_jit_approval.py)
cover equal instants and rejection of genuinely future nanosecond/microsecond
values.

Final reruns passed, with source unchanged across 2,849 Python files:

| Retained result under `jit-denial-final.I47aN5` | Observed result | SHA256 |
| --- | --- | --- |
| `focused/result.json` | 7/7 suites, 53 tests, zero skips, 27.661 seconds | `d0643ab520a0afab6524d9285748d351442779b63c8415d8db5ffe1eb8fc6b4a` |
| `postgres/result.json` | 2/2 suites, 20 tests, zero skips, 34.394 seconds | `99a77dfd3d9bcb5094140ff42326d892c936f3ca899c6fd787d73011596f397a` |

The PostgreSQL total includes denial's seven pure plus three SQL controls and
approval's five pure plus five SQL controls: **eight additional PostgreSQL
controls**, not 20 additional tests beyond the focused run. PostgreSQL 16.15
ran network-none without host ports, through the exact owned `0700` Unix-socket
directory, with fsync, full-page writes, synchronous commit and checksums
enabled. No fixture schemas or public tables remained before clean shutdown;
the container and empty owned temporary directory were removed. The full
532.011-second session stayed inside its original 600-second deadline.
Independent source review and the Make dry-run passed; failures above remain
retained. The closeout receipt is `closeout.json`, SHA256
`74252fe6a4c7c5dfd5ac01df1f3a53ceb134f635608f2bae0786a5bacfa34aa7`.

At `4975b194`, [CI 38384885637](https://github.com/example/private-deployment)
passed all 55 suites: 476 Python tests and 145 Node groups, zero skips,
427.696 seconds. The retained result is
`ci-38384885637.ifT6I5FC/quick/result.json`, SHA256
`d7526eadf84bd23f21ee213228ebf023e1df88322727c898b23f5c53ca5be0f8`.
This is ordinary component CI, not production acceptance.

### Metadata-only decision preflight

The subsequent repair adds `db.get_approval_request_metadata`, an exact-ID,
explicit-column read of public metadata and the complete stored approver policy.
Approve, deny, both WebAuthn-options paths and private-review preflight use it;
they no longer invoke private-document decryption just to check eligibility.
The actual private-review reader remains a separate, legacy operation. This
does not implement native private opening or turn metadata into authority proof.

The isolated `approval-metadata.mpWBMrrq/results/result.json` run passed six
suites / 58 tests, zero skips, in 24.992 seconds, with selected source unchanged.
SHA256: `ed190167e964a326acaad7fba3f2fa61c6f6f9820a09847bc94e64eb54432f01`.
The eight metadata/history tests use actual SQLite queries and public
projection; a database authorizer refuses private columns and writes. Sixteen
route/model units retain explicit dependency doubles and stop at the private
opening boundary. Other suites cover pure denial, approval, policy and the
regression runner. No PostgreSQL service, live data, provider or installed
authority was used; the network-isolated test container was removed.

At `7e3fc8e3`, [CI 38386777401](https://github.com/example/private-deployment)
passed all 56 suites: 488 Python tests and 145 Node groups, zero skips,
443.426 seconds. Retained result: `ci-38386777401.hMZUS2C6/quick/result.json`,
SHA256 `ead715c16777a93b8417e13b7b6544c2346e383e8f10a4119401ac43ab2c7e93`.

### Original request expiry

`jit.request` previously computed a fresh pending deadline from database time,
even when the authenticated opaque documents expired earlier. It now requires
finite original expiries on both documents and stores the earliest of those
two limits and database time plus the configured TTL. It rounds down to the
database's microsecond precision and uses that same exact value for the
aggregate expiry. A replay preserves the original row/audit without renewal;
malformed retained expiry or one beyond the documents' bounds is refused.

`jit-original-expiry.hEn36oMR/results/result.json` passed seven suites / 68 tests,
zero skips, in 32.953 seconds, with selected source unchanged. SHA256:
`99ca79476a2a95d8fa2e3964f33fec05c36d19700cf255ea5e3fc6d5c022ac48`.
The request suite's six new controls run the real kernel, opaque/evidence and
aggregate consumers over explicitly synthetic admitted rows, not a genuine
native seal or PostgreSQL commit. Adjacent private-input, material, registry,
approval, denial and runner suites passed. The offline container was removed.

The ordinary inventory now has 57 suites, adding that existing request suite;
the expanded inventory has not yet run in CI. The affected JIT/metadata suites
remain excluded from the historical Coder inventory, not prepared native tests.
No broker roster was changed.

The next integration target is the actual atomic `release.reserve` path.
Rust refuses standalone legacy JIT composition, and the versioned reserve
facade does not pass through standalone `jit.request` private-v2 ingress.
Adding a producer only to that standalone service branch would not connect
real proxy requests. Native-origin sealing needs the original authenticated
CONNECT session/request owner and signed prepare-response originals carried
through canonical preparation, under the original request deadline. The
versioned reserve then needs commitment-only private decomposition and atomic
custody/evidence/approval retention. These connections are not implemented by
the expiry repair; do not repurpose bootstrap mTLS or treat a principal string,
parsed DTO or unsigned preparation as caller authority.

Still open: native authenticated private-review opening; the connected
ordinary approval UI; approve/deny/expire terminal presentation and expiry
handling; exact-request continuation after approval; and an actionable ordinary
pending-request notification source. This source repair does not enable any of
them or bypass their owners. The four independently configured action/audit
Slack/webhook destinations remain separate, and the legacy ordinary JIT action
source stays disabled. Receiver acknowledgement is never human approval; see
[notification boundaries](operator-notifications.md).

Genuine measured-authority execution, authenticated operator/physical-key
ceremony, end-to-end ordinary continuation, and deployment acceptance remain
separate requirements in the [completion ledger](project-completion.md).
