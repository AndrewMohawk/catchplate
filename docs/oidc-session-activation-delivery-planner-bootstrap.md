# Consume-planner root-original admission

`oidc_session_activation_delivery_planner_bootstrap.py` defines a distinct signed
v2-only profile for `oidc.session.activation-delivery.consume`, with no v1 fallback.
It authenticates the
actual root signature and current source/configuration/runtime cohort before
selecting any private resource. `_verify_on_work` requires immutable outer and
history originals, an independent root key, and the existing work/window/deadline;
`_produce_on_work` signs independently established claims under the same bounds.

The closed payload binds the exact typed consume request and its commitments to
the original [consume-planning history purpose](oidc-session-activation-delivery-history-custody.md),
not the UID 65503 completion purpose. It independently pins the historical
receiver identity, original activation expectations and pending scope, current
authentication/trust policy, dedicated planner key/identity, genuine generation,
state enrollment, complete current root-vector original and fixed state endpoint.
The vector is a signed snapshot, not an action-time lock or execution authority.

The dedicated planner key is separate from root, generic configured roles,
configured enrollment/evidence/transition purposes, historical activation planner,
and enrolled state/computation/completion keys. The consume journal key is separate
from the historical bundle/delivery/original-journal keys. Its directory identity
cannot reuse either historical activation journal or export directory. The v2
`executionBundleKeyDigest` pins another independent exact raw32 AES key: it cannot
reuse the consume journal or any of those historical keys. The execution store
cannot reuse the consume journal, historical activation journal or historical
export directory identity. These are explicit root assertions joined again to
the actual delivered resources, not identities inferred from a posted result.

The fixed [OS delivery profile](oidc-session-activation-delivery-planner-delivery.md)
is UID/GID 65501, peer 65532, process
`oidc-session-activation-delivery-planner`:

| FD | Declared original/resource |
|---|---|
| 198–200 | Root key, outer bootstrap, listener |
| 201–203 | History original, bundle key, delivery key |
| 204–206 | Consume signer, independent journal key, journal directory |
| 207–208 | Independent consume-execution bundle key, execution store directory |

The listener path is `/run/serverware/oidc-session-activation/delivery-planner.sock`;
the journal path is `/var/lib/serverware/oidc-session-activation-delivery-planner`.
The execution store path is
`/var/lib/serverware/oidc-session-activation-delivery-execution`; its key path is
`/run/secrets/serverware-oidc-session-activation-delivery-execution-bundle-key`.
The closed v2 launch requires all eleven FDs and independently pins export-store
device/inode, fixed path, record count and quota (at most 1,024 records / 8 GiB).
Both private directories are owned by UID/GID 65501, mode `0700`; neither is
created or repaired by admission.
Strict verifier DB/TLS identity and byte/digest pins use the fixed
`/run/serverware/oidc-session-activation-delivery-planner-tls/` paths. Database ID
is an independent root assertion; it is not inferred from a DSN database name.
The state endpoint is the existing fixed state socket with root-created kernel
peer 0:0. Socket permissions/provisioning remain independent.

The signed outer interval is at most 300 seconds. Admission samples actual time
under the supplied original allowance; it never renews the expired activation
plan or its historical launch. Policy must not widen the nested history purpose.

The [cold factory](oidc-session-activation-delivery-cold-planning.md) consumes
these originals itself and is source-connected to the actual retained plan
owner and independent journal; the matching UID 65501 history purpose is checked
again before actual planning or retained replay. The v2 launcher and
[private service](oidc-session-activation-delivery-planner-service.md) separately
admit these originals and connect sealed FD delivery to that factory. The new
export resources are for retaining exact encrypted consume originals, not
independent receiver or execution-grant authority. No service
was provisioned or executed. This bootstrap issues no grant, reserves no state,
executes no SQL, consumes no delivery, releases no token and establishes no fresh
public consent. Source-only checks are not runtime or production verification;
protected execution and release remain open.
