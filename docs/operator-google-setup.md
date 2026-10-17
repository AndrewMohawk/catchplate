> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Enable Google without replacing the operator catalog

This is administrator provider setup, not account consent or an application
grant. It applies only to the non-production operator workspace. Native pilot,
hardware custody, cloud routing and production acceptance remain separate.

The retained operator store pins its destination list. Changing the environment
alone must not replace that pin or discard existing credentials. The explicit
setup workflow prepares a public configuration while Google is disabled, then
admits that exact configuration during a controlled cold restart.

## Administrator API

All routes use the existing administrator boundary. Mutations require the exact
console Origin, strictly parsed JSON and bounded request bodies. Secret values,
secret-file paths, token endpoints and arbitrary scopes are not API inputs.

| Route | Purpose |
| --- | --- |
| `GET /api/operator-demo/oauth/google/setup` | Review the current catalog/policy/settings and proposed destination change. |
| `POST /api/operator-demo/oauth/google/setup` | Prepare one first-Google setup operation; does not enable Google. |
| `GET /api/operator-demo/oauth/google/setup/{operation_id}` | Read the owning administrator's exact operation, including after a lost response. |
| `POST /api/operator-demo/oauth/google/setup/cancel` | Explicitly cancel a pending operation against the current review. |

Preparation accepts only `operation_id` (canonical UUID), `client_id`,
`expected_settings_digest`, `expected_revision` and `expected_policy_hash`, in at
most 4096 bytes. Cancellation accepts `operation_id`, `expected_revision` and
`expected_policy_hash`, in at most 2048 bytes. Keep the operation UUID before
submitting. A lost acknowledgement requires a status read, not a repeated POST.

The callback is derived from the admitted console URL plus
`/api/oauth/callback/google`. Permissions are the existing **Read Gmail** profile,
not all Google services. An existing pending operation must be cancelled before
preparing another; completed and cancelled IDs are not reusable.

Message-age limits are a separate application-permission choice, not a different
OAuth scope or administrator setup. All mail remains the unrestricted default.
The additive last-N-days mode passed focused and connected synthetic checks;
source `8b0277f0` / normal Rust `13ad08c0…` is deployed with preserved state and
passing public/browser checks. Google remains unconfigured; real-Google acceptance
is separate. See its [contract and verification boundary](operator-gmail-job-verification.md#optional-last-n-days-policy--connected-acceptance-passed-and-deployed).

## Retained-state contract

Preparation retains the original destination order and fixture CIDRs, appending
only `https://gmail.googleapis.com` if absent. It stores the exact future public
OAuth binding and advances the catalog revision with an audit event. Runtime
destinations, account capabilities and signed policy do not change at this step.

On restart, a read-only preflight checks the prepared configuration before the
ordinary database initializer. The activation transaction checks it again under
publication ownership. A changed client, callback, destination list, fixture
CIDR, catalog revision or policy refuses activation; there is no automatic
rebasing or repair. Even an existing catalog that already permits Gmail requires
preparation before its first Google profile. Legacy operator data must first be
upgraded with Google disabled; it is not fresh state.

Activation atomically updates the destination pin, initializes the first Google
profile and its lifecycle metadata, marks the operation activated, advances the
catalog revision and appends audit evidence. It does not rewrite credential
ciphertexts, application tokens or expiry, access rules, signed policy bytes,
policy sequence/high-water state, or CA material. Retained policy is verified
before and after the transition. A genuinely fresh deployment retains its
existing explicit cold-profile initialization path.

Neither stage contacts Google, obtains account consent, creates application
permissions or proves that an upstream request works. Account connection and
application grants remain subsequent explicit actions.

## Deployment and recovery

Use the [optional deployment layer and maintenance sequence](../docker/catchplate-operator-demo/GOOGLE-SETUP.md).
First deploy the setup-capable source with Google still disabled. Prepare the
operation, stop the old writers/gate, verify a consistent private backup, then
restart the reviewed app/gate pair with the exact approved configuration and
private client-secret mount. This API is not proof that old processes stopped.

Once activated, removing the Google flag or restoring only selected database
files is not rollback. The profile remains pinned; use reviewed forward repair
or a separately authorized consistent recovery. Existing service authentication,
public routing and policy checks are not relaxed by the deployment layer.

## Verification status

The final focused run on 2026-10-09 passed all six selected groups, using 18
sequential fresh-process workers, in 163.685 seconds. There were no failures,
errors, skips or unattempted groups. Production implementation was commit
`42ee12bf`; all tested source files remained unchanged throughout the run.

The checks exercised real cold configuration, startup preflight, SQLite,
encryption, signing, CA material and ASGI routes. They covered:

- Preparation, activation and a second restart preserving credential
  ciphertexts/generations, app identities/verifiers/expiry, rules, seeded nonce,
  signed policy bytes and sequence, CA identity, and the existing audit prefix.
- Authentication, exact Origin, strict JSON/body limits, review comparisons,
  actor-owned status recovery, cancellation after a real policy-changing
  mutation, and retained one-shot operation IDs, including SQL replacement.
- Refusal of changed client, origins, fixture CIDRs and stale catalog revision
  before database initialization; retained Gmail destinations and legacy data
  still require explicit preparation. Genuinely fresh Google data still starts.
- Real audit-insert failures during preparation and activation, and a real
  preparation commit followed by a lost acknowledgement with exact-ID recovery.
  Activation rollback compares the entire SQL dump and key/CA/policy evidence
  immediately around the original operator bootstrap. Ordinary core startup
  runs first and may legitimately update a migration timestamp.

The container used cached dependencies, network `none`, read-only root/source,
UID 1000, one CPU, 1 GiB RAM with no additional swap, 96 PIDs, dropped
capabilities and a 600-second outer deadline. It exited zero with no OOM and no
remaining process. A fail-on-contact provider sentinel recorded no calls.

Evidence is retained under
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/google-setup.4euAcMeR`:
`test-final.log`, `test-final-result.json`, `source-final-before.sha256`, and
`containers-terminal.json`. The result receipt SHA-256 is
`a033a56720cfa5847b02a4beef0c0c9769f5d5aceb4e6080ba7b7ca5b7f0235e`;
the verified source-manifest SHA-256 is
`2fd2fa7a9cecf7927e509372b4e1717915e77af756f7f27bff594c0548937724`.
Final test-file SHA-256 values are:

| File under `scripts/` | SHA-256 |
| --- | --- |
| `test_operator_google_setup.py` | `315a41ad24e365643fea2c5b84b907209c4b81188f186816c6ff1ee815ef90d5` |
| `operator_google_setup_api_checks.py` | `c76c043db5dcc0e44e978b476bed40fb162128652cbf0a94c25b02ef1cac64ba` |
| `operator_google_setup_lifecycle_checks.py` | `f3c8b5cbca79d884769204251434ccacc187547f534bdee39788eb11c5f84a7f` |

The earlier six-group run also passed in 158.402 seconds with 17 workers. The
final run repeated the whole selection after removing a premature test import,
isolating the legacy-origin control and adding the activation-failure check;
production implementation was unchanged. Both receipts remain in the evidence
directory. Syntax, diff-whitespace and staged secret scans also passed.

This is focused synthetic transition verification, not the full project suite,
Rust proxy traffic, a browser journey, real Google configuration/consent/refresh,
or live deployment. The optional Compose layer was rendered separately with
synthetic inputs; it does not establish provider connectivity. The live demo
was not changed by this work, and native pilot acceptance remains separate.
