# Native receiving factory and constructed-driver admission

This source slice connects the gate's actual retained lifecycle owner and four
authenticated facade sessions to the real production configuration factory and
generation/RPC supervisor. It is not runtime acceptance, deployment, installed
generation success, final request custody, or readiness evidence.

## Explicit selection and acyclic ordering

Existing lifecycle policies/receivers v1 and v2 remain unchanged. The new
`nativeShadowDriverLifecyclePolicy/v3` is nested in the existing independently
signed bootstrap configuration/window. It adds one independently supplied
`constructedAdmissionAuthority`: the actual assigned supervisor key's public
ID, SPKI, material digest and raw public key. It must differ from the bootstrap
and phase-two keys. The gate selects the closed receiver/v3; there is no host
fallback. Current native bridge runtimes v5 through v8 are retained exactly.

The real source-owned caller order is:

1. `DriverBootstrap.start()` retains the actual final phase-one driver and its
   original clone parent's PIDFD/start/executable, original bootstrap window,
   and real observations. No future PID or descriptor list is accepted.
2. `admit_bootstrap_driver(signing_key_fd=...)` signs the observed phase-one
   driver and same live parent under the separate
   `nativeShadowBootstrapDriverAdmission.signature/v1` purpose. The key FD must
   contain an independently supplied 32-byte Ed25519 seed in a root-owned,
   0400, sealed memfd; no key is generated, printed or transmitted. This is a
   software operator signature, not an NSM key or native attestation.
3. `generation_manifest(assignment_original=..., production=...)` gives an
   unsigned deterministic recipe for the independently signed five-service
   grants. It does not approve an assignment. It derives the parent identity
   only from the held early original. The exact early-original hash supplies
   the explicit native prior-driver binding, before grant/runtime/C9 authoring.
4. Existing real `OperationalInputs` preparation and `continue_scope` transfer
   the independently signed phase-two originals and actual FDs. The latter
   recomputes the recipe using the retained C9 assignment/production originals
   and requires all five grants' manifest/driver/prior-admission roots to agree.
5. After the genuine inspected bridge constructor has completed,
   `admit_constructed_driver(signing_key_fd=...)` performs one fixed export,
   signs one constructed admission, and submits it once. The actual parent
   supplies its complete retained operational descriptor/descendant census
   plus the same sealed public-admission FD used by the gate. Caller-authored
   measurements are not accepted. Lost replies remain consumed/unknown.
   The completed-constructor startup timer is retired before its one-shot
   construction notice so it cannot race the retained operational FD census;
   the original lifetime timer remains owned throughout.
6. The existing generation-install caller selects the retained native owner.
   It independently verifies the actual assignment/current key material, both
   new purpose signatures, exact early/late census associations, signed native
   closure, role-key authorization, admission authorization, actual possession
   signatures, and both distinct external verifier result domains over the
   same exact quote/context/configuration. Only then is the remote-native
   configuration activated and the four actual retained sessions consumed by
   the bounded RPC workers. The real generation authorities still perform
   their recovery/prepare/commit/certification protocol; no admission substitutes
   for those effects or signatures.

The late census cannot be placed in already-signed pre-construction grants.
The existing generation `retainedDescriptorSetSha256` is sourced from the
driver's actual bootstrap-four descriptor manifest; that commitment keeps its
original scope. The new mandatory constructed admission independently commits
the complete later operational census. Both are retained and checked; they
are never equated. The stable parent identity uses its observed kernel start
ticks as the single invocation ownership epoch. Its pre-grant identity is
recomputed from, and must match, the later same-parent census. An independently
restarted parent or changed census cannot be adopted.

## Verification and ownership boundaries

`native_constructed_driver.rs` is the opaque receiving owner.
`native_closure_remote.rs` is a distinct receiving closure, never a fabricated
same-process `NativeCustodyClosureOwner`. `admission_remote.rs` verifies exact
public preimages and current independent signatures without constructing local
keys or an NSM context. `native_remote_factory.rs` reconstructs the same native
configuration binding from those originals and checks the actual five grant
pins. The real `policy_shadow_generation` caller invokes the native factory;
the legacy process/v4 host factory remains separate and cannot be used as a
successful native fallback.

The bootstrap and constructed admission signatures use the existing
`serverware.signedEnvelope/v1` ASCII/integer preimage with their distinct named
domains. Public acquisition/hashes are not signature verification. A parent's
`retained` or `live` reply is only authenticated observation, not new authority.
The gate uses its real `EnvelopeKeyTrust` and `TrustedTime`, never issuer wall
time as trusted time. Native RPC workers recheck current signatures and exact
live census before contact and after a response; failure preserves the existing
unknown/generation fences. Every operation stays inside the original BOOTTIME
lifetime minus cleanup reserve. No inspection grants a new interval.

## Bounds and remaining execution boundary

Original limits remain: four sessions, queue depth 32, fixed original startup
and lifetime, at most 16 descendant processes and 256 operational descriptors,
48 KiB census, 64 KiB control packet, 8 MiB sealed public-original FD, 8 KiB early
admission and 16 KiB constructed admission. The early signature has at most a
30-second epoch validity; the later signature cannot extend it or the actual
key authorization. The existing quote/result freshness remains independent.
No automatic refresh, new parent adoption, new generation from a stale owner,
unresolved-contact retry, or changed descriptor population is permitted.

Provisioning must supply the genuinely independent authorities, signed native
configuration/assignment and five service grants, actual protected resources,
verifier outputs and native workload. This source command does not provision
them. The lifecycle parent remains privileged trusted host code. Its live
census is not stop-the-world memory proof and is not the five-service terminal
settlement. All actual request effects, cleanup/settlement signatures, canary
coverage and final receipt still require their genuine owners. No broad tests,
build, interpreter/parser run, runtime launch, signing, cloud or provider calls
were performed for this slice; connected pilot acceptance remains required.
