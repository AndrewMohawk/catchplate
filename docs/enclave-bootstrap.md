# Native initial policy bootstrap

Status: source-only, unbuilt and unexecuted. This composes actual retained native
key/quote/transport owners with initial signed-policy acquisition before a new
`GateState` is shared. It does not introduce a CLI or environment mode, admit
configuration or activate a complete enclave deployment.
The separate [explicit native CLI](native-startup-config.md) now selects this
path through pinned configuration and launch originals; it does not supply
independent configuration or release admission.
The enclosing [callable native startup](native-startup.md) now generates and
joins the actual owners, constructs explicit shadow/v2 clients and binds the
fixed-parent listener only after this preparation succeeds.

## One owned startup lifetime

[EnclaveBootstrapV1](../data-plane/decision-gate-rs/src/enclave_bootstrap_v1.rs)
consumes an actual `EnclaveRuntimeIdentityV1`, `QuotedMutualTlsIngressV1`, fixed
relay assignments, a wall-clock observation and an absolute boottime deadline.
It joins the retained identity and ingress and permanently narrows their local
deadlines and the new relay owner's deadline to one original minimum. It does
not rewrite the original NSM document or its signed claims.

The owner is neither Clone nor Debug. Checked accessors borrow retained owners;
creator-process drift or a failed check poisons reuse. `bind_policy` compares
the genuinely compiled policy digest with the actual identity's declared scope.
`into_parts` consumes the owner only after that binding and a fresh owner check.
Neither a supplied digest nor a matching quote scope independently verifies the
quote, release, policy provenance or clock. Generated TLS configurations still
need actual serving cancellation; a copied `Arc` is not self-revoking.

## Actual initial acquisition, then fresh state

The private [native gate constructor](../data-plane/decision-gate-rs/src/native_gate_bootstrap.rs)
is `prepare_native_tls_gate_state(inputs, proof, bootstrap, policy_bytes,
expected_signing_key_id, control_plane_config, minimum_sequence,
minimum_rollback_epoch)`. Its inputs are cold values, not a running or previously
admitted host `GateState`.

```text
retained native owners and cold inputs
    -> fixed native trust transport and original signed-policy compilation
    -> policy scope, release/shadow, proof-key and exact checkpoint checks
    -> fresh empty state, then the prepared native serving object
```

The constructor requires a nonempty original policy of at most 8 MiB, a canonical
expected signing-key digest and positive monotonic floors. It requires an
unused attested control-plane trust source with the existing pinned verifier,
then installs the retained native service transport **before** fetching trust.
Cold inputs contain no snapshot, HTTP client, resolver, MITM authority, ingress
material or proof signer; these are separate `GateStateRuntime` fields, not
host-ready placeholders. The actual proof material is supplied separately.

The trust request retains the existing nonce, genuine quote-verifier, TLS-peer
SPKI, policy/response-key, policy digest and attested high-water joins. The
constructor measures the current executable with the existing actual-byte
reader and rejects a different supplied binary digest. Strict parsing and the
real signed-policy compiler then verify the original bundle, explicit signing
pin, attested binary/policy identities, schema and capabilities. Initial epoch
and trust generation are set to one; the actual compiled policy hash is bound
back to the retained native owner.

Before assembly, the constructor keeps the production release-authority and
shadow startup authorization checks. It joins the actual proof signer's
control-plane response key to the freshly loaded snapshot before checking
policy high-water state. The candidate must meet both positive floors and the
supplied checkpoint's exact policy hash, sequence and rollback epoch. This path
does not advance a checkpoint, create a local high-water file or derive a new
checkpoint from the candidate. Consistency with an ordinary supplied checkpoint
is **not** proof that it is the independently latest off-host state.

The [cold-input validator](../data-plane/decision-gate-rs/src/native_gate_inputs.rs)
requires both production configuration and an actual production-created shadow
control. A pending shadow startup request is rejected: this constructor does
not silently skip or perform its installation. Policy/checkpoint/release-evidence
filesystem paths or mtimes and external recipient/proof-attestation commands are
also rejected. Canonical HTTPS URLs are capped at 4,096 bytes and retain the
existing URL/token pairing and required service-token checks.

The actual [native custody signer](enclave-proof-custody.md) is required; its
retained verifying key, PEM, key ID and copied metadata must agree. A UDS signer
is rejected on this native path; the legacy different-UID check remains in the
separate UDS path. Before state is shared, the actual native proof owner is
rejoined to the consumed runtime identity's CA, complete role-4 scope and
original deadline, permanently narrowing key use. The actual native backend
supplies fresh original response quotation; it has no command fallback. A
canonical SPIFFE instance ID and the existing response-observation v2 client
remain required. The distinct native envelope still requires its own admitted
client verification profile. The [explicit native proof-client profile](native-proof-client.md)
combines actual capture checks with separately pinned quote verification and
labels its result `native-unadmitted`, not production admission.
These are checks of actual held material and configuration, not independent proof-key provenance;
in particular, v2 client presence is not evidence that it was production-created
or that its authority is native.
The enclosing startup constructs it through the explicit production validator
and actual hello; that still does not establish native authority or readiness.

Cold resource checks preserve existing ranges: grant/lease caches 1..1,000,000;
lease renewal workers 1..32, queue 1..65,536 and interval 50..1,000 ms; audit
batches 1..200; request-head deadline 100..30,000 ms and body/write deadlines
1,000..600,000 ms. Audit queue and Gmail cache require positive values, without
inventing an aggregate allocation or independently admitted capacity claim.

[GateStateInputs::into_state(runtime)](../data-plane/decision-gate-rs/src/gate_state_init.rs)
only assembles fresh state with empty caches, queues and counters. It loads no
environment/file, contacts no service, creates no key and starts no worker.
The native constructor supplies a `GateStateRuntime` containing its actual
same-call snapshot, clients, resolver, ingress metadata and native authority,
retains the original policy bytes and relay owner, and only then shares the
completed state through the prepared `NativeTlsGateV1`.

## Refresh and client custody

The retained native policy bytes, not `policy_path`, are recompiled when native
trust refresh runs. The legacy file loader rejects a native trust source.
Native refresh skips policy-file and release-evidence mtime reads. Native
active/candidate compilation uses the retained explicit signing
pin instead of the legacy environment override. These are source paths, not
new background workers or a completed policy-update publication protocol.

[ControlPlaneClientConfig](../data-plane/decision-gate-rs/src/control_plane_client_config.rs)
separates supplied TLS roots from legacy environment/file loading. Its PEM
constructor requires actual parsable certificates and preserves exclusive
custom-root behavior; the caller must bound and independently admit the PEM
input. `builtin()` preserves the legacy default-root option, not independent
root admission. Builders disable ambient proxies and redirects and retain TLS
peer information.

The [service transport](enclave-service-transport.md) supplies the initial
two-second shared client, five-second trust client and separate three-second
broker client under the same retained deadline. Shared/trust clients disable
idle pooling; provider resolution uses only the retained fixed address
inventory. Origin routing does not authorize application paths, service roles
or credentials. Original service and response-verification gates remain.

## What this does not admit or start

The normal environment-driven `main` remains a separate legacy startup. The
native constructor does not run it, copy its ready state, start workers, bind
listeners or install a daemon. The separate [owned native lifecycle](native-runtime-lifecycle.md)
consumes the prepared object and actual listener, starts scoped policy/audit/
lease/health work, checks readiness and serves with shared cancellation and
joined shutdown. This callable run does not activate CLI startup or provision
its inputs. The [enclosing startup sequence](native-startup.md) now composes
owner generation, this preparation, listener binding and that run without
invoking the legacy entrypoint. Its separate explicit CLI performs the input
loading and mode selection described above.

Supplied configuration, service tokens, verifier/release pins, TLS roots and
ordinary checkpoint values require independent admission. Existing proof and
response-observation owners retain their protocol checks; accepting those
owners here does not establish an independently admitted enclave or proof
authority. The native proof key is actually retained in the gate's address
space, not isolated by a separate UID. Independently current off-host
checkpoint/rollback custody, proof-key admission and KMS release, immutable
deployment, startup provisioning, session revocation and complete frozen
runtime verification remain required.
Local wall-clock samples and deadline checks are not trusted-time evidence or a
hard syscall/watchdog guarantee. See [runtime identity](enclave-runtime-identity.md)
for the remaining full-enclave boundary.
