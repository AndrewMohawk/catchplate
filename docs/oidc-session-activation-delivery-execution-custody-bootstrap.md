# Purpose-bound consume receiving custody bootstrap

`oidc_session_activation_delivery_execution_custody_bootstrap.py` admits a distinct
root-signed receiving purpose: `grant`, process
`oidc-session-activation-delivery-execution-authorizer`, UID/GID `65500`.
It does not reuse the consume-planning history purpose or extend an old generic
grant enrollment. The closed envelope and payload schemas are
`serverware.signedOidcSessionActivationDeliveryExecutionCustody/v1` and
`serverware.oidcSessionActivationDeliveryExecutionCustody/v1`.

## Original inputs and joins

`_verify_on_work` requires `custody_bytes`, `planner_bootstrap_bytes`,
`planner_history_custody_bytes`, `receiving_history_custody_bytes`, the independent
`root_public_key`, and the original `live_window`, `transport_deadline_ns`, `work`.
The outer signature binds detached byte-count/SHA-256 descriptors, avoiding
another base64 copy of large nested originals. The outer bound is 16 KiB; the
consume planner and each history original retain their actual 4 MiB / 8 MiB
limits, with a shared 64 MiB original aggregate ceiling.

Admission genuinely verifies the [consume planner v2](oidc-session-activation-delivery-planner-bootstrap.md)
and its separate planning-history v2 original, then the distinct consume-grant
history v3 original. It joins:

- The exact canonical typed consume-request bytes and their root-pinned original
  identity; neither a request digest alone nor a received material object suffices.
- The exact original activation-planner bootstrap bytes inside both histories,
  current source/configuration/generation/runtime cohort, and independent
  receiving identity. The receiving identity is not copied from the sender.
  Fixed receiving UID/GID `65500` must not collide with any generic runtime role's
  service UID/GID in the genuinely admitted planner configuration.
- The execution-export key pin, historical activation-bundle key pin and delivery
  key pin. These and the consume/historical journal pins must be distinct; the
  receiver needs no planner signing or journal private key.

All key fields here are root-authenticated metadata, not actual key custody.
`_produce_on_work` captures its closed payload, performs the same genuine nested
admission, and signs with the actual independent root keypair. Both APIs retain
the supplied cumulative work and inherited deadline; neither accepts successful
material or an arbitrary verifier callback as authority.

## Time and authority boundary

The fresh receiving interval fits within the authentic consume-planner,
planning-history and separate receiving-history launch intervals. Their original
clock samples and the unchanged current processing window remain checked through
return. The old activation planner is admitted as history only; its expired
interval is not compared to current time as a live allowance and is never renewed.
A later consume-plan receiver must still enforce that plan's original live
lifetime and genuinely replay its original proofs.

The returned private material contains owned facts and raw originals for the
actual receiving owner, not an accepted proof-result input. This bootstrap alone
does not deliver descriptors, inspect actual AES keys, decrypt a bundle, replay
consume effects, authorize public/user permission, issue a grant, execute SQL or
release a token. No profile creates completion or SQL execution authority.

This is source-only, unbuilt, unexecuted and uninstalled. These receiving-custody
contracts are distinct from the separately composed grant service and do not
provide production-gate evidence.

## Separate reserve and pending-receiver profiles

The old `_verify_on_work` / `_produce_on_work` remain strictly grant/v1/65500.
The new `_verify_reserve_on_work` / `_produce_reserve_on_work` and
`_verify_sql_issuer_on_work` / `_produce_sql_issuer_on_work` have the same exact
explicit original/key/window/work arguments, but each selects a separate closed
root-signed profile, never an envelope-selected fallback:

| Receiving envelope/payload version | Consumer role | Process mode | UID/GID | Required history |
| --- | --- | --- | --- | --- |
| v1 | `grant` | `oidc-session-activation-delivery-execution-authorizer` | 65500 | v3 consume-grant |
| v2 | `reserve` | `oidc-session-activation-delivery-execution-reserver` | 65499 | v4 consume-reserve |
| v3 | `sql-issuer` | `oidc-session-activation-delivery-execution-sql` | 65498 | v5 consume-sql-issuer |

All profiles retain the same immutable original bounds, exact typed-request and
activation-planner joins, key separation and original live interval checks.
The selected fixed UID/GID must be distinct from the independently admitted
generic configuration roles. Each receiver needs its own root signature and
matching independently established identity; grant or planning custody cannot
be lent to another role. Ordinary material is still output-only metadata.
The `sql-issuer` profile is a library prerequisite for
[independent pending admission](oidc-session-activation-delivery-pending-admission.md),
not an implemented cold SQL consumer, issuance permission or proof of commit.
