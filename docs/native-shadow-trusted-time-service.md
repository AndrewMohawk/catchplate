# Native TrustedTime proof service

This source slice adds a real time-response signer and consumer. It has not
been built, started, provisioned, exercised on a kernel, or accepted as a
working production bridge.

The fixed guest selects `catchplate.nativeShadowTrustedTimeGuestLaunch/v1`
explicitly. The closed launch contains `keyAdmission` and a separately pinned
`trustedTime` service assignment. Existing key-only, retrieval and retrieval
bridge selectors retain their previous behavior. The assignment is outside
C9's transitive hashes: it is independently approved after the actual C9
delivery original exists, not folded back into that delivery.

## Actual producer

The original native guest pipeline remains required: protected C9 delivery,
same retained closure/process/parent PIDFD and absolute lifetime, pre-key NSM
time exchange, independently signed interval anchor, encrypted role-key
delivery and external native key-admission result. The service does not turn
that key admission into operational permission. Its separate grant is signed
by the assignment's current independent `CustodySupervisorCapability` key
under `catchplate.nativeShadowTrustedTimeServiceAssignment.signature/v1`,
using the existing complete signed-envelope canonical-ASCII framing.

The grant pins the full original server Guest13, assignment, key authorization,
time-bootstrap digest, exact client Peer14, current checkpoint/revocation root
and original epoch window. Every operation rechecks these retained originals
and the full trusted interval. The response key is the actual admitted local
`CustodyTrustedTimeResponse` role; no key is generated or exported here.

The service consumes the actual signed `trusted-time-listener` FD6, bound but
not listening at `/run/catchplate-shadow-trusted-time/listener.sock`. The
root-owned directory is 0711; the named socket is server-UID:client-GID 0660.
The final nonroot service starts listening only through its retained private
inspector, after permanent drop and actual key admission. Both endpoints stay
nondumpable. The privileged parent retains exact process/socket/PIDFD/path
owners; there is no same-UID, dumpable or root-serving fallback.

`native_shadow_trusted_time_inputs.TrustedTimeActivation.prepare` creates and
retains that exact fresh bound socket and protected directories. It accepts
independently pinned cold C9 configuration and approved Peer14 originals, not
an arbitrary socket path. `activation` reports actual FD6 metadata;
`sign_delivery` signs the supplied exact C9 payload only with its existing
independent authority key; `take_for_launch` transfers a single duplicate
once. No automatic unlink, process launch, key generation, service readiness
or successful cleanup is implied. `sign_service_grant` separately verifies
the original full18/key-admission configuration, approved bootstrap/peer
pins, local role and independently held supervisor key before authoring the
new purpose-specific grant. Nothing in this module provisions either key.

## Sample and consumer

The closed `sample-trusted-time` request binds the actual original production
operation hash, endpoint request hash, replay and BOOTTIME deadline. The
signed `trusted-time-interval` result contains Sample16: source assignment and
guest, anchor/bootstrap originals, actual kernel boot/time namespace, exact
sampled BOOTTIME, earliest/latest Unix nanoseconds, drift bound, original
anchor expiry/lifetime, and operation hash. The existing v4 endpoint
signature additionally binds exact request/replay/key/result hashes. A used
replay cannot obtain a fresh sample; uncertainty refuses rather than resets.

Only the actual clock owner samples: the original anchor and bootstrap are
rechecked, BOOTTIME rollback/lifetime is refused, and the full interval is
advanced conservatively. No `SystemTime`, wall-clock arrival sample,
midpoint, caller epoch or expiry extension is used. The independent issuer's
timestamp-error and clock-rate assumptions remain assumptions, not an NSM
accuracy guarantee.

The separate `catchplate.nativeProofBridgeLaunch/v1` fixes all four proof
kinds—Retrieval, Persistence, TrustedTime and GenerationInstallEnvelope—using
their source-fixed directories and signed runtime peers. Four directory FDs
are retained alongside the original sockets. One actual inherited private
FD4 channel multiplexes only this closed kind set; it has one serialized
sequence and separate socket/PIDFD/original-path owners for every kind.
Connection, before-send, after-receive and after-signature phases require
the real packet and matching parent/child/server kernel identities.

`ConcreteFive` enables this profile only after all four actual inspected
sessions are constructed, retaining the real `AdmittedGuest`, not a flag
from request JSON. It still requires all five existing service sessions,
ten receipt endpoints, histories, journal and genuine driver prerequisites.
The time endpoint reply must pass exact signature and post-reply peer checks
before the private `AuthenticatedTimeReply` can become a `VerifiedSample`.
The consuming bridge validates its separate operational grant and original
assignment/key/closure windows with the full current interval and the
conservative interval projected to the unchanged operation deadline. It
retains that sample across dispatch and rechecks before response creation.
Thus not-before uses earliest and expiry uses latest throughout the new
caller path. Host/existing retrieval-only clock contracts are unchanged.

## Required next joins and acceptance

The direct fixed parent/service and bridge factory are connected in source.
The existing parked-child release implementation is explicitly only a
retrieval pair: it refuses these new selectors. A genuine expanded cohort
must precreate actual children, retain their sealed executable/PIDFD/start
identities, admit independently signed actual peer/C9/grant originals, and
release them under the same original watchdog. No PID or inode prediction
is provided by this slice. The independent time issuer and verifier runtimes,
their trust/keys/pins, fixed guest images, NSM/kernel support, cgroup/labels,
all remaining receipt services and real generation coordinator are also
required. A fixed fourth endpoint registry entry does not implement or
advertise that coordinator.

The paired schema is `native-shadow-trusted-time-service.v1.schema.json`.
Build, runtime, failure/cleanup, real deployment and end-to-end pilot evidence
remain unperformed; this source work is not full bridge readiness or production
acceptance.
