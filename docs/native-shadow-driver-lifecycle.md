# Native driver lifecycle and gate receiving owner

This source slice connects the actual root clone parent to an actual native
gate before and after permanent privilege drop. It is a prerequisite for the
external native custody facade, not a completed native generation installation.
No build, parser, runtime, signer, provider, or provisioning was executed.

## Explicit selection and original ownership

Bootstrap configuration/v4 retains v3's combined single-key/NSM full admission,
adds a closed lifecycle policy, and selects continuation preparation/v3. It uses
the same original signed startup/lifetime window. Phase-two scope/v4 has its
own signature domain over all original scope fields; old v1-v3 stay strict.
The cold policy approves only the gate executable SHA and final UID/GID 65534,
not a future PID. A cleanup reserve of 1 ms to 5 s ends operation before, never
after, the original lifetime. Startup must finish before that cutoff.

The original parent becomes a subreaper before its actual driver clone exists,
refuses preexisting descendants, and creates one fresh protected fixed listener
at `/run/serverware-shadow-driver-lifecycle/listener.sock`. Existing path residue
is a refusal, not an automatic adoption or deletion. Recovery/removal remains
an explicit operator action after proving all retained owners have exited.
Root owns inspection and signal capabilities; this is trusted host machinery,
not a read-only security sandbox or native attestation signer.

The explicit `nativeShadowCustodyLifecycleReceiver/v1` original comes from the
gate's already root-admitted retained custody configuration file. Its exact
parent peer claim undergoes unchanged direct kernel/proc authentication while
the gate is root. Its configuration/window/bootstrap-original pins, startup,
and lifetime remain fixed. It is deliberately not accepted as the legacy
`ProductionProcessConfigV4` or deserialized into a native bridge configuration.

## Actual order and callers

1. `DriverBootstrap.start()` owns the real supervisor/driver PIDFDs and obtains
   the original final driver observation. Independently supplied receiver
   configuration can now pin that real original and the actual root parent.
2. Native shadow preparation calls `PreparedNativeCustodyLifecycle::open` with
   its actual retained configuration FD and root preparation owner. A one-shot
   prepare exchange authenticates the root parent before gate drop.
3. Native shadow bind consumes the actual permanent-serving owner. The parent
   authenticates the same gate PIDFD/start/executable with final kernel UID/GID.
   It emits `nativeShadowDriverGateBound/v1` to the original operator channel.
   The gate's bind reply remains pending under its original startup deadline.
4. `DriverBootstrap.await_gate_binding()` retains the genuine gate PIDFD and
   returns that authenticated original for independent phase-two signing.
   `OperationalInputs.prepare` and the Rust parent require the signed runtime's
   `expectedFacadePeer` to match the actually available gate identity. Cgroup,
   IMA, label, and configuration-generation fields are not invented from this
   limited observation; the full privileged facade inspector must check them.
5. Root's paired native facade/peer source produces the fixed
   `nativeShadowDriverFacadeListening/v1` notice only after actual final-role
   `listen`. The parent validates the same child, observation/scope hashes, and
   the actual retained signed `production-listener` FD. Only then does it send
   the pending gate bind reply. Listening is neither constructed nor ready.
6. The existing actual bridge construction notice alone disarms its startup
   timer. The retained gate owner is checked again at generation admission.
   Missing future native facade/configuration joins fail closed; there is no
   host-mode fallback and no observation-to-authority projection.

Both sides use their actual source-owned process/lifetime guards and kernel
SCM credentials/PIDFDs. All sends are one attempt. Lost replies, errors, changed
FD identity, unknown state, and overflow never renew admission or permit replay.

## Census and cleanup are different from configuration authority

The worker has a purpose-fixed postconstruction observation path. It enumerates
the actual driver descriptor set, retains actual `pidfd_getfd` duplicates, checks
FD numbers/metadata twice, and retains a bounded descendant census. Bounds are
256 descriptors, 16 descendants, 256 threads per process, and a 64 KiB complete
response. These are live identity observations, not immutable file-content
commitments or a stop-the-world proof. The original four bootstrap descriptors
are never relabeled as the complete operational set. The postconstruction
observation API still needs the actual remote native facade factory caller.

On original control half-close, failure, or retirement cutoff, the original
parent kills and `waitid`-reaps its actual driver and all adopted descendants.
It emits a terminal original only after its subtree is empty, with real PIDFD,
start, terminal code/status, and reap-time records, all before original lifetime.
Python `close()` keeps the authenticated receive direction open, consumes that
exact terminal original, then reaps its own supervisor. Unknown cleanup does
not release retained business originals or reset the invocation. A parent
crash or timer kill does not manufacture a terminal proof.

This subtree excludes the independently launched ordinary five services and
external proof endpoints. Their lifecycle/settlement owners remain distinct.
The terminal record is authenticated local data, not a signed stable-reaper
manifest, cleanup grant, generation settlement, or fleet-readiness evidence.

## Remaining work

The paired [facade inspection](native-shadow-facade-inspection.md) now supplies
the real final-role listener notice and outgoing ordinary connection owners.
Both bootstrap v3 and v4 select full native inspection; only v4 selects the
lifecycle protocol. The parent retains the actual signed production listener.

The next required implementation is the receiving-side native factory and
actual four-session RPC connection, plus independently authorized binding of
the complete operational descriptor census and genuine retained reaper to the
existing generation/assignment/checkpoint. The present preconstruction signed
grant/runtime roots cannot silently become postconstruction census roots, and
including signed originals in their own commitment would create a fixed point.
No JSON reconstitution of the bridge-local Arc, hash-as-ownership shortcut, or
legacy host factory is acceptable. Connected bridge-to-ordinary/signer peer
inspection and post-drop connect ordering do not by themselves supply the
missing gate factory or establish native serving.

Independent signing operators, actual pinned executable/security/cgroup inputs,
deployment resources, and the connected pre-pilot execution gate remain required.
