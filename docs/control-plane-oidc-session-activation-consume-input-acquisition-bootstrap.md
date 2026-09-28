# Public consume-input acquisition configuration

Explicit `serverware.signedControlPlaneEnrollmentBootstrap/v13` and payload
`serverware.controlPlaneEnrollmentBootstrap/v13` add one nullable field,
`oidcSessionActivationConsumeInputAcquisition`. All v2–v12 closed shapes, caps
and purpose reservations remain unchanged. No additional key or descriptor is
delivered to the public application.

## Fixed endpoint and original policy

The nested schema is
`serverware.controlPlaneOidcSessionActivationConsumeInputAcquisition/v1`.
Its exact fields are `schema`, `endpoint` and `issuerPolicy`. The endpoint has
exactly these fields:

| Field | Required value |
| --- | --- |
| `path` | `/run/serverware/oidc-session-activation-consume-inputs/grants.sock` |
| `timeoutSeconds` | Exact integer from 1 through 30 |
| `peerUid` | Exact integer `0` |
| `peerGid` | Exact integer `0` |

`issuerPolicy` is the established original wrapper with only `base64Url` and
`byteCount`, containing 2 bytes through 64 KiB of exact signed issuer-policy bytes. The whole
nested configuration is limited to 128 KiB, 64 nodes and depth 4. The endpoint
uses the actual fixed transport grammar; no alternate path, root/private key,
planner original, request data or resource selector is added to this object.

Non-null configuration requires actual parent activation planning and execution,
including the existing consume-planner key, measurement and reservation pins.
The activation-planner original comes only from that actual parent planning
configuration. Null disables the lane; older parent versions append
`consume_input_acquisition=None` by default.

## Cold signature and static joins only

The parent authenticates its canonical original and root signature before
nested admission. The nested helper owns the entire bounded graph before key
callbacks, checks the genuine inner issuer-policy signature and canonical
original, and joins:

- Its activation-planner identity to the exact parent planner original, already
  admitted against the parent's configuration, generation and runtime cohort.
- Its actual consume-planner public key/SPKI and measurement to the independently
  configured execution pins.
- Its independently signed activation predecessor to the parent's exact
  reservation predecessor.
- The state-enrollment bytes decoded from that exact parent planner original to
  the execution lane's original state enrollment.

The state extraction is a bounded data comparison, not another planner admission.
No cold clock window is created and the policy's signed interval is not declared
currently live. The returned material holds only endpoint data and original
policy bytes, not an admitted-policy object or successful acquisition.

```text
_admit_on_work(*, consume_input_acquisition, activation_planning,
    activation_execution, runtime_root_public_key, work)
_ConsumeInputAcquisitionMaterial(endpoint, issuer_policy_bytes)
```

The new `_produce_v13_on_work` retains every v12 producer input and adds
`oidc_session_activation_consume_input_acquisition`. It performs the genuine
parent/static admissions and root-pair check before signing in the distinct v13
domain, with the existing output reservation and original-stability readback.
Earlier signature domains cannot authorize the new field.

## Actual owner and request boundary

The startup owner's `consume_input_acquisition_enabled` property reports cold
configuration availability after actual owner continuity, not permission or
freshness. Its no-argument `_acquire_oidc_session_activation_consume()` facade
requires the actual active parent-owned permission and calls
`permission.acquire_and_prepare_consume()`. It cannot create or resume a context,
take posted root inputs or grant a replacement work/window/deadline.

The request composition must run the full issuer-policy verifier before issuer
contact, using these exact originals and the actual permission's original
allowance; returned originals require genuine receiving admission afterward.
Cold signature admission never substitutes for either check. The existing direct
prepare API and release acquisition behaviors are unchanged.

This source-only configuration does not provision an issuer, listener, key,
database role, TLS identity or planner/history resource. It is unbuilt and
unexecuted and supplies no token release, public HTTP/cookie, recovery, portal
or production-readiness evidence.

## Separate historical bridge in parent v21

Parent v21 adds the nullable `historicalConsumeInputAcquisition` field. It does
not replace or widen the ordinary v1 acquisition above. Its closed nested v2
shape keeps the same endpoint and original-policy wrapper, but requires the
[current-root-signed issuer policy v2](oidc-session-activation-consume-input-bridge-policy.md).
Null disables historical acquisition; older parents retain a null material
field. No additional descriptor or private key is delivered.

`_admit_historical_on_work` uses the actual admitted activation archive and the
inherited startup work/window/deadline. The signed configuration and planner
receipt select exactly one archived scope. Its old root, generation, original
interval and genuine caller/grant/state enrollment identities must match the
bridge. The helper re-admits the original policy and old planner, then requires
the embedded current planner to equal the actual current parent's original.
Current consume state, planner key and measurement must match the actual current
execution lanes. Complete state-payload equality permits independent root
signatures, not a database or generation migration.

The returned material appends `historical_scope` and `bridge_interval`; these
are same-call cold admission results, not externally accepted authority. Startup
rechecks exact archive membership and bridge lifetime before private-key intake.
Request processing must later re-admit the original policy under its own live
permission and unchanged cumulative allowance.

```text
_produce_v21_on_work(*, payload, history_current_interval,
    history_now_epoch_ns, history_live_window, history_transport_deadline_ns,
    runtime_root_private_key, runtime_root_public_key, work)
```

The provisioner accepts the complete closed v21 payload as configuration data,
genuinely admits all nested lanes, checks the current root pair, reserves output
and signs in the v21 domain. It rechecks archive/bridge lifetime and original
stability around signing; a successful material object is not a producer input.
The policy's 6 MiB individual ceiling does not increase the sealed parent's
4 MiB aggregate or the original work ceiling. Oversized combinations are refused.

This is cold configuration only. The real request caller and protected
delivery-plan old/current authority split remain unfinished; the historical
effect actor is still disabled. Merely configuring v21 cannot authorize consume,
retry an uncertain operation or release a credential.
