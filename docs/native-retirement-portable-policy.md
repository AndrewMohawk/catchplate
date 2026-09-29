# Native retirement receipt policy dependency closure

This source slice makes the actual capture-retirement and staged-pending
retirement receipt consumers use portable policy and grant validators. It does
not establish helper-image execution, provider retirement success, or pilot
readiness. No runtime or test was executed for this slice.

## Actual callers and dependencies

Both `native_oauth_capture_retirement_receipts.py` and
`native_oauth_pending_retirement_receipts.py` authenticate the original writer
configuration and call their codec's `policy_key` and `verify_grant` functions.
Those calls now reach the same predicates used by the respective CP policy's
verifier and planner:

| Purpose | Shared policy and signature module | Grant data |
| --- | --- | --- |
| Pre-subject capture retirement | `oauth_capture_retirement_policy.py` | Existing `native_oauth_capture_retirement.py` |
| Staged-pending family retirement | `oauth_pending_retirement_policy.py` | `oauth_pending_retirement_values.py` |

`oauth_retirement_policy_values.py` supplies the exact bounded native-assignment,
Nitro trust-configuration certificate parsing, and signed enrollment data
predicates. The existing `oauth_retirement_values.py` supplies scalar, provider,
and encrypted-envelope data grammar. These dependencies use only the standard
library, pinned `cryptography`, and the existing packaged native codecs; they do
not import CP storage, policy-authority execution, or the Nitro verification
script. The capture codec also retains its separate CP-only signing and request
commitment entrypoints; the native receipt call chain does not invoke those.

The four new modules are included in the measured broker runtime's explicit
module allowlist and both frozen source inventories. The capture codec's scalar/envelope
dependency extraction and `oauth_retirement_values.py` are prerequisites from
the preceding packaging slice, not replaced by this change. Importing a module
alone is not verification of this runtime call chain or of the resulting image.

The existing isolated data-grammar test script also contains a fresh-interpreter
probe that refuses all control-plane authority imports while calling both native
receipt policy/grant entrypoints. It covers optional versus mandatory missing
policy handling and invalid-input refusal, not valid signed admission. It is
authored for the later consolidated no-build pass and has not been executed.

## Preserved authority boundaries

The two policy blocks retain their distinct exact fields, operation names,
grant schemas, and original signature preimages. Neither purpose accepts an old
cleanup grant or translates a generic scalar-validation projection into
permission. Configuration/grant/role/native/control-plane signing keys remain
separated. Independently admitted assignments retain the derived holder, native
boot/key, PCR/EIF/module/age bounds, provider/application/KEK/TLS pins, exact
exchange or pending selection, and bounded historical recovery authorization.

The pending native consumer no longer keeps its weaker private policy/grant
checks. It shares the full CP predicates: exact provider configuration and text
grammar, signed enrollment schema, canonical originals, purpose root and
historical enrollment key bindings, maximum 24 ordered unique lineages, positive
signed-i64 credential versions, and original grant lifetime. Its original raw
enrollment SHA binding is also retained in the shared signature verifier.

Fresh grants still require the original configuration, source revision and
unexpired epoch interval. Recovery remains a historical-original path with its
separate admitted recovery digest and unchanged caller checks; it gains no new
time interval. No enrollment expiry or authority is reconstructed from current
metadata. Wire schemas, row/attempt identities, encodings and response ceilings
are unchanged.

Portable trust-root parsing is not quote verification. CP `verify_original`
still verifies the actual native statement signature, derived nonce, original
Nitro document, independent assignment and original time bounds. The receipt
consumers still verify actual signed writer originals, retained helper identity,
application material, exact requests, phase transitions and currentness. Store
verification/planning and provider-contact owners remain separate. Packaging and
real positive/negative execution of these paths remain required acceptance work.
