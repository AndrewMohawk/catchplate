# Callable native startup sequence

Status: source-only, unbuilt and unexecuted. The main-private
[native_startup::run](../data-plane/decision-gate-rs/src/native_startup.rs)
composes actual cold startup through generated native identity, existing custody
and service checks, signed-policy preparation, listener creation and owned
serving. The [explicit pinned-original CLI](native-startup-config.md) now selects
this sequence before legacy environment loading. It is not signed configuration
admission or evidence that a complete enclave deployment has run.

## Explicit inputs, no host-ready placeholders

The callable interface is
`run(inputs, parameters, shadow_config, v2_config, public_identity_stdout) -> Result<(), String>`.
The final boolean selects only the public startup export described below.
`GateStateInputs` must be cold: its shadow control and response-observation-v2
client are both absent. It contains no generated proof signer, snapshot, HTTP
client, resolver or TLS authority. The actual generated proof material enters
`GateStateRuntime` later, rather than satisfying cold input types with a dummy
or imported signer.

`NativeStartupParametersV1` supplies ordinary typed configuration:

- Runtime release/policy/configuration commitments; original CA and ingress
  validity intervals; ingress host and client-root DERs; separate role-3 and
  role-4 quote nonces; one absolute boottime deadline.
- The explicit control-plane Ed25519 verifying key and expected SPKI key ID,
  plus the existing attempt-ledger directory. No private key is supplied.
- Literal relay assignments, listener port, original signed-policy bytes,
  expected policy-signing key ID and positive sequence/rollback floors.
- Explicit control-plane TLS configuration and already bounded native runtime
  worker/queue/interval settings.

The ingress SPIFFE identity comes from the cold inputs' canonical instance ID;
there is no second independently selectable instance label. Typed values and
matching digests do not admit their provenance. The caller still owns trusted
configuration, current roots, freshness/nonces and release/PCR mapping.

## One real composition

```text
cold/static checks + explicit checked shadow/v2 construction
    -> actual NSM + generated CA and same-identity native proof custody
    -> actual quoted mandatory-mTLS ingress + retained relay cohort
    -> genuine initial signed-policy and owner/checkpoint joins
    -> bind fixed-parent listener, then owned readiness/serving/shutdown
```

Static checks precede NSM/key/service work: existing native URL/token/resource,
SPIFFE, forbidden-path and external-command guards; v2 production configuration
checks; and bounded startup parameters. These include policy bytes up to 8 MiB,
a live positive CA interval of at most 24 hours, a live ingress interval within
it, a bounded DNS/IP ingress host, 1–32 distinct client roots of at most 64 KiB
each/1 MiB total, 1–32 basic literal relay assignments, nonzero 32-byte quote
nonces, valid ports and an absolute bounded ledger path. The actual public
control-plane key is joined to its expected SPKI digest before key generation.
Actual constructors still perform complete root parsing, relay-table and ledger
checks; these cheap checks do not replace them.

The trust source must be an unused attested control-plane source with its
explicit pinned verifier. The
[shadow constructor](../data-plane/decision-gate-rs/src/policy_shadow_generation.rs)
uses `PolicyShadowGenerationControl::from_config(true, true, config)`, not
environment loading. It reads and checks the pinned trust manifest, fixed
verifier/custody configuration and original startup authorization. Pending
startup-generation installation is rejected. The later preparation still
performs the genuine signed-snapshot/startup-authorization join; the constructor
alone is not that authorization or independent hardware admission.

The explicit
[v2 constructor](../data-plane/decision-gate-rs/src/response_v2/mod.rs)
requires production TEE configuration, the pinned verifier, local topology,
distinct custody UID and existing role/source/transparency pins. It performs
the actual authenticated hello under the shorter of its startup timeout and
the original deadline. Its health flag preserves the actual `providers_ready`
value, which can be false; successful construction does not assert readiness.
The owned runtime performs fresh probes and readiness checks before accepting
sessions. This source path does not turn an external v2 service into an
enclave-owned authority or remove its provisioning requirements.

Only then does startup open the actual NSM and generate its CA. It calls
`CustodyRuntime::generate_native_with_control_plane_response_public_key` against
that same identity, explicit public key/key ID, nonce, deadline and existing
ledger, then consumes that runtime through the real native proof initializer.
It generates and quotes the mandatory TLS-1.3 mTLS ingress using the same CA and
the actual installed client roots. There is no imported private key, external
attestation-command fallback or copied successful quote-verification result.

`EnclaveBootstrapV1` retains the identity, quoted ingress and actual relay table.
`prepare_native_tls_gate_state(inputs, proof, bootstrap, ...)` then performs the
[initial native policy acquisition](enclave-bootstrap.md): real native trust
transport and current-executable measurement, strict signed-policy compilation,
scope/release/shadow/proof joins and exact supplied high-water checks. The
freshly generated proof material is separate from cold configuration and is
rejoined to the actual identity before sharing state.

No external vsock ingress is bound until preparation succeeds; preparation can
create its private loopback bridges for outbound TLS. The optional
[`--public-identity-stdout` export](native-public-identity.md) writes actual
public ingress and unchanged startup-quote originals after preparation and
before this bind. It does not prove readiness, supply a fresh client challenge
or authorize CA installation. The final bind uses
the supplied fixed port and expected Nitro parent CID **3**, with the unchanged
original deadline. CID is routing scope, not authentication; mandatory mTLS
remains inside the enclave. The prepared object and listener are consumed by
the [owned native lifecycle](native-runtime-lifecycle.md), which retains the
actual health/readiness barriers, scoped background work and joined shutdown.

## Lifetime and admission limits

A startup lifetime guard checks the creator process and original boottime bound
between operations. Serving installs its cancellation owner with the same
absolute deadline, not a newly granted interval. Failed preparation never
falls back to legacy startup; owned values unwind on error. Existing synchronous
NSM, filesystem, verifier and service operations can still block, so an external
watchdog remains necessary. Local wall-clock observations are not trusted-time
or rollback evidence.

The filesystem attempt ledger remains development rollback protection, not an
independently latest off-host witness. The actual native proof key remains in
the gate's address space; it is not a separate-UID security boundary. Original
NSM quotes and checked local owners still require the independent admission
described in [proof custody](enclave-proof-custody.md) and
[runtime identity](enclave-runtime-identity.md).

The source-level opt-in CLI provides selection, not service/ledger provisioning,
independently admitted configuration or hardware, KMS Recipient
release, current witness/rollback custody, or complete deployment. Immutable
packaging and consolidated frozen build/runtime/failure validation remain
required. No source inspection or callable API substitutes for those gates.
