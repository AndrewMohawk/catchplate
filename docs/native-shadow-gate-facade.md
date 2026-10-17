# Native gate receiving sessions and public admission originals

This source slice connects actual native gate bind to four real bridge RPC
sessions and to the bridge's retained public admission originals. It does not
activate a gate-side native configuration or replace the missing signed
operational-census/dispatch-manifest association. No runtime was executed.

Select the explicit nested `nativeShadowDriverLifecyclePolicy/v2` in the
independently signed bootstrap v4 configuration and the closed
`nativeShadowCustodyLifecycleReceiver/v2` in the gate's root-admitted custody
file. Both retain their predecessors' exact field inventories and original
startup/lifetime. Policy v1 and receiver v1 retain their previous behavior;
there is no environment/default selection or host-factory fallback.

## Actual producer and caller sequence

1. The original driver parent retains the real same-child PIDFD/start,
   executable, signed phase-two runtime, and C9 production listener. It binds
   only that child, never a PID/path provided by the gate. The current signed
   runtime's complete expected driver identity and configuration-generation
   commitments remain mandatory.
2. After its single genuine combined NSM/key admission, the bridge copies only
   retained public originals into one memfd, seals it against all changes,
   retains it, and attempts one same-parent send. There is no software signature
   replacement, new verifier result, key export or encrypted-delivery export.
3. The parent compares bootstrap/phase originals and the exact independently
   pinned closure, assignment, key-configuration and admission originals. It
   retains that actual file. These comparisons do not replace the receiving
   consumer's independent current signature/quote validation.
4. The existing final-role listener notice releases the gate's pending bind.
   `PreparedNativeShadowControl::bind` now reaches the receiver-v2 connection
   owner through its real lifecycle bind. The gate makes four one-shot final-role
   connections. For each, the parent obtains actual SO_PEERPIDFD/credentials,
   confirms the same child before any proc read, measures executable/cgroup/
   SO_PEERSEC, compares the full signed runtime driver commitment, and invokes
   unchanged `AuthenticatedInheritedSeqpacket::from_inherited_direct` plus
   `revalidate_packet_pidfd`. These measurements are not predicted isolation
   fields or a caller-authored verdict.
5. The gate retains four `AuthenticatedInheritedSeqpacket` sessions. Every
   later common-session revalidation uses the same serialized lifecycle channel
   and exact retained socket ordinal/inode. The parent retains its duplicate
   capabilities through real subtree cleanup. No replacement session/reconnect
   or arbitrary target is admitted.
6. The parent forwards the exact public sealed file once, after all four gate
   sessions have been inspected. The gate retains and checks the file/original
   hashes. This step can precede the driver's constructed notice; it is data
   admission, not construction/readiness. That ordering avoids deadlocking the
   existing four-session bridge constructor.

## Frozen receiving seam

`NativeCustodyLifecycleOwner::public_admission_original(expected_source)`
returns actual checked public bytes. The closed object is
`catchplate.nativeShadowDriverPublicAdmission/v1`, exact ten fields: apiVersion,
bootstrapObservationOriginal, phaseScopeOriginal, phaseBundleOriginal,
closureOriginal, assignmentOriginal, keyConfigurationOriginal,
admissionAuthorizationOriginal, evidenceOriginal, combinedResultOriginal.
Every original is preserved as its complete canonical ASCII string, not a
digest standing in for policy/authority bytes.

`take_facade_sessions(self: &Arc<Self>, expected_source)` moves the four actual
connected common sessions once. A native factory must retain the same lifecycle
owner; session inspection uses a weak reference and refuses if that owner dies.
Neither accessor constructs or returns a `ProductionCustodyConfiguration`.

The 64 KiB packet ceiling is unchanged. Only the sealed public file uses the
existing 8 MiB receiving-original capacity. Its component limits remain the
actual source limits (including combined verifier result 32 KiB); overflow
refuses before transfer. A selected independently approved seccomp image must
permit this actual memfd/sealing path. A failed attempt, invalid original,
overflow, dead peer or lost ACK poisons continuation; no deadline is renewed.

## Exact remaining join

`install_retained_generation` still has the separate legacy
`ProductionProcessConfigV4` path. A native successor must independently validate
all current assignment/checkpoint, closure/admission signatures, possession,
single quote and both distinct verifier-result domains, then consume the actual
sessions and retained lifecycle owner. It must also obtain the genuine signed
association between the complete operational descriptor/process census and
dispatch/stable-reaper manifest. Bootstrap's four-descriptor root is not that
operational census. The parent's actual subtree reaping is not independently
owned ordinary-service settlement. No ready/native-activation claim is made
until those exact receiving joins and the connected pre-pilot acceptance gate
exist. Independent authority provisioning and runtime execution remain external
deployment steps; this source task performed neither.
