# Finalization completion originals and receiving verification

This source-only slice adds the distinct bounded completion exchange and an
original-input receiver for `webauthn.registration.finalize`. It is unbuilt and
unexecuted. It does not add the control-plane caller profile, retained completion
association, public completion/recovery permission or portal controls. F07
therefore remains open despite the new [cold service](registration-finalization-completion-service.md).

## Fixed exchange

The [transport](../serverware/authority_registration_finalization_completion_transport.py)
uses `/run/serverware/registration-finalization/completion.sock`, root listener
peer `0:0`, request magic `SWRFCM01` and response magic `SWRFCR01`.

- Raw2 request: `recover-registration-finalization-completion`, followed by a
  canonical ASCII packet digest independently admitted by the caller and service.
- Raw4 acknowledgment: `acknowledged`, completion-request digest, exact original
  signed completion request, exact original signed state acknowledgment.
- Raw4 uncertainty: `uncertain`, then three empty byte bodies.

The source fixes body counts and bounds before allocation and requires exact
EOF. One mandatory original absolute deadline covers the single exchange;
there is no arbitrary endpoint, automatic reconnect or retry. Shared helpers
validate only the operation-neutral raw4 byte carrier, never evidence-purpose
authority. Neither framing nor Unix peer credentials authenticate signed
completion. The response contains no packet ID.

## Original-derived completion verification

The [receiver](../serverware/authority_registration_finalization_completion_response.py)
requires the original finalization raw4 plan, reserve request/snapshot/state
receipt, current-root and grant enrollment originals, signed grant, independently
admitted historical expectations/keys/caller-authorization digest, database,
generation and pending sequence/head/fence. No returned request, marker or
successful-admission object supplies those expected values.

On the caller's unchanged work and original window it:

1. Bounds and holds the complete original inventory, then captures the genuine
   fixed-finalization historical replay expectations.
2. Invokes actual completion-only plan/pending replay to derive the complete
   marker and after-vector; it never re-executes credential mutation.
3. Verifies the original grant against that same replay and the independent
   authorization digest.
4. Authenticates both the enrolled completion signature and original state
   acknowledgment, then joins the framed identity to the actual request digest.
5. Compares the signed complete-action fields to the original-derived marker,
   and verifies the exact canonical embedded observation, full after-vector
   digest and original observation interval.

Only genuine original bytes and their authenticated identities are returned.
That private result is not accepted as input by any admission API. The shared
marker/observation helpers are operation-neutral; the candidate always comes
from actual finalization replay in this invocation, not an evidence verifier or
an incoming proof token. `uncertain` establishes no authenticated result.

Historical completion expiry is not renewed. The receiver establishes signed
historical claims under supplied independent scope, not live database truth,
latest-head currentness, packet provenance or permission to activate a session.
Cross-generation authority resolution remains its own unfinished checkpoint.

## Remaining caller integration

The caller still needs independently root-admitted completion endpoint/packet
and historical scope, genuine retained subject and present-purpose admission,
durable authenticated completion/reconciliation association, and distinct public
complete/recover actions. Unsigned SQL packet locators cannot fill the expected
packet pin. A pending-session completion flow must account for the credential
already inserted by SQL rather than reusing the pre-execution no-credential
branch unchanged; session activation remains a separate transition.

The new [state v3 profile](current-root-finalization-peer.md) permits the fixed
finalization completion peer and enforces signed-operation agreement before a
historical or new receipt. Its lookup remains a nonce-bound shared state
observation, not an external current-head lease. Local key/storage custody and
static root claims do not supply off-host rollback protection. Provisioning,
frozen verification and all six production acceptance gates remain outstanding.
