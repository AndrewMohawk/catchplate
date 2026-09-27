# Private consume completion receiving

The dedicated response verifier authenticates original consume completion and
state acknowledgment against independently supplied original caller, grant,
plan, reservation and pending scope. It is source-only, unbuilt and unexecuted.
A successful response is historical completion evidence, not token release,
current browser authentication or permission to execute again.

## Private caller boundary

`authority_oidc_session_activation_delivery_completion_response._request_on_work`
performs one fixed private raw2/raw4 exchange, followed by genuine original
verification. The caller must already own an independently root-admitted
`OidcSessionActivationDeliveryCompletionCustody`, including its original
configuration, enrollment, request/vector bindings and private history keys.
Those keys never enter the generic application client or request packet.

The actual custodian requires process mode
`oidc-session-activation-delivery-completion` and UID/GID **65497**. Accordingly,
the new completion listener admits only **65497:65497**, not ordinary authority
caller 65532. The server and private receiver are separate processes within the
same completion purpose; the receiver does not acquire the server's completion
signer, database readers or journal merely by calling this API. Each must be
independently provisioned and admitted. This same-UID arrangement is not an OS
isolation guarantee between the two processes or protection from hostile root.

The fixed endpoint is
`/run/serverware/oidc-session-activation-delivery-execution/completion.sock`.
The actual inherited listener has kernel identity **0:0**, separately from its
pathname ownership and the server's dropped identity. Neither a pathname nor a
root peer substitutes for authenticating the original signed response.

The private caller's cold packaging, application dispatch and public permissions
are later public-handoff work; this does not silently expose completion to the
control-plane process. No accounts, keys, socket access or services are installed.

## Original-only verification

`_verify_on_work` accepts raw response originals and independent raw2 plan,
enrollments, caller/grant/reserve/ACK/snapshot originals, scope, keys and custody.
It accepts no successful replay, marker DTO or service-generated expected pins.
Dedicated consume frame limits and aggregate response reservation precede
expectation capture, native callbacks and network body allocation. The generic
execution inventory remains closed to consume.

The receiving path:

1. Holds every original, expectation graph, key reference and pending pin before
   callbacks, and retains the caller's real current work/window/deadline.
2. Authenticates its actual private custodian and narrows that same allowance;
   one fixed socket exchange neither opens a new allowance nor retries.
3. Runs genuine historical consume admission once, deriving actual effects,
   snapshot and marker from the signed/encrypted originals rather than a reply.
4. Verifies the enrolled completion signature and original state ACK, joins the
   returned request identity and every marker field to that replay, and checks
   the signed inner commit observation against the exact complete after-vector.
5. Returns only four immutable original byte/digest fields after final current
   custody and processing checks. No downstream API accepts that carrier as
   authority instead of originals.

Old execution and acknowledgment intervals are historical data, not renewed
execution lifetimes. The packet digest selects the server request; the raw4
response has no packet-ID field, so receiving makes no returned packet-identity
or latest-head claim. `uncertain` raises a closed uncertainty error with no
authenticated identity, SQL failure assertion or retry grant.

The server's [durable completion](oidc-session-activation-delivery-completion.md),
[cold service](oidc-session-activation-delivery-completion-service.md) and
[state peer](current-root-delivery-completion-peer.md) retain their own original
admission and publication duties. Lost responses may follow durable publication.
Independent release/TEE/witness evidence and end-to-end frozen verification
remain separate production gates.
