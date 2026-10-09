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

Use the [optional deployment layer and maintenance sequence](../docker/serverware-operator-demo/GOOGLE-SETUP.md).
First deploy the setup-capable source with Google still disabled. Prepare the
operation, stop the old writers/gate, verify a consistent private backup, then
restart the reviewed app/gate pair with the exact approved configuration and
private client-secret mount. This API is not proof that old processes stopped.

Once activated, removing the Google flag or restoring only selected database
files is not rollback. The profile remains pinned; use reviewed forward repair
or a separately authorized consistent recovery. Existing service authentication,
public routing and policy checks are not relaxed by the deployment layer.

## Verification status

Implementation and focused verification are in progress. No real Google
configuration, consent, provider request, or live deployment is established by
this document. Synthetic transition tests cannot establish those outcomes.
