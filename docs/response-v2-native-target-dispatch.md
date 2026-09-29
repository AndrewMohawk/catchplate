# Native gate execution and raw capture

This is a source-only integration, not a tested enclave deployment or a complete
response-v2 transaction. The separately signed guest configuration may select
`targetDispatch` only with genuine guest delivery, guest listener, native gate
measurement and a current purpose assignment. `ledgerRawPersistence` is a
separate prerequisite checked before DispatchBegin, not write permission inferred
from a capture signature. Old host paths retain their existing contracts.

The router remains zero-key. The actual gate retains its native identity, broker,
credential lease, policy snapshot and currentness dispatch guard. It applies the
real injection plan and retains the final HTTP/1.1 request privately. Its fresh
purpose-bound role4 NSM evidence binds that request hash, the credential-free
staged descriptor, actual authenticated router session, generation, policy,
attempt/fence and original deadline. The independently admitted assignment pins
the native key, native boot, kernel boot, control-plane key, release, configuration,
binary, CA, PCRs/EIF, module and Nitro roots. Currentness permission is not reused
as capture permission. Real assignment/key provisioning remains external.

CredentialTransport verifies that original evidence and queries the actual signed
Reserve/Stage originals under the fresh sequence profile. It signs CredentialUse
with its actual `credential-authority` subkey, executes the genuine signed
DispatchBegin, checks the retained complete frame witness and signed successor,
then signs a one-use permit with `target-transport`. Receipt hashes cover the
entire authenticated RpcRequestFrame, not a reconstructed unsigned request.

The gate consumes that verified permit once. It opens the assigned literal-origin
AF_VSOCK relay and performs origin-authenticated TLS inside the enclave using the
same cold PEM roots as its configured upstream client. No new network right is
given to router, state or ledger. TLS resumption/early data are disabled; HTTP/1.1
is the only ALPN and the retained request is sent once. The parent carries TLS
records only. Exact decrypted response bytes are captured from that connection,
bounded to 34,603,008 bytes, and require authenticated TLS closure plus the existing
strict HTTP/1.1 parser. The evidence records peer-chain and exporter hashes; these
are observations, not a provider signature or a claim about provider internals.

The original operation allowance is narrowed to whole milliseconds before Hello.
All later operations preserve it; epoch bounds are also capped by the actual
credential lease and native lifetime. No contact retry, reopened session, renewed
deadline, alternate route or ordinary proxy fallback follows uncertainty. The
shadow barrier binds the final injected request, never the staged template.

CapturePersist carries one immutable sealed memfd on the same authenticated gate
session. CredentialTransport and the ledger independently admit the original
capture. The actual ledger put returns its durable CAS/ArtifactCommit/state
originals. RecordOutcome consumes that returned revision, and the gate validates
the signed OBSERVED successor before projecting its existing public DISPATCHED
state. It does not apply the old single-step `+1` cursor rule. The actual response
secret guard remains retained through final response release.

The paired schema exposes `capturePersist`, `permit`, `stateReceipt` and
`postState` for the raw persistence schema. These are data declarations, never
permission constructors. `postState` in this path explicitly has null proof
material, because the query does not request unrelated release proof material.

## Still required

The authenticated lower-level sequence store/query does not implement public
Reserve/Authorize/Stage orchestration or credential-free staged CAS production.
The gate's public transaction still reaches those real existing operations first;
missing signed originals cause refusal. Their actual producer is a separate
required source task, not a provisioning checkbox or a successful readiness DTO.
No diagnostic adapter or synthetic staged state is provided here. Full later
terminal/release integration, real provisioning, build verification, negative
tests and a real isolated one-provider transaction remain required before pilot
or N06 closure. No such execution was performed for this batch.
