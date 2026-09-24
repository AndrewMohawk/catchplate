# Measured configuration for the revocation writer

Status: source implementation and read-only review only. This tree has not
been built or executed. The new private factory does not activate a service
route or complete production admission.

## What the factory binds

`authority_revocation_writer_configuration` constructs the genuine
`RevocationPlannerPersistence` owner from the complete configuration payload,
its independently supplied digest, active-generation bindings and the local
writer DSN. It reuses the existing bounded configuration capture and canonical
commitment; unused payload fields are included, and finite fractional timeout
values retain their original spelling in that commitment.

The configured planner, verifier and planner-writer must have their exact
process modes. Planner and verifier public keys are decoded from canonical
raw32 encodings and checked against their measured SPKI digests. The writer's
explicit planner session, signing-SPKI and public-key aliases must match the
planner role before either key callback. The writer's own response-signing
SPKI is a separate pin: it is not equated with the planner key and no response
signer is loaded by this factory.

The seven-item owner configuration retains the writer DSN, bounded timeout,
the two actual public keys, planner/verifier identity triples and independent
writer role/TLS pins. The verifier session uses the existing configuration,
measurement and attestation framing. Writer timeouts must be finite values in
`2..300` before flooring to the integer used by libpq. The database role is
exactly `serverware_policy_authority_planner_writer`; TLS expectations never
come from the signed plan or the connection's own observations.

The mapper uses the existing caller work: four hashes for the configuration
commitment, two SPKIs and verifier-session framing. Captures, encodings and
comparisons—including the writer/planner alias comparison—charge their actual
byte/node work. No private signer pairing, third key decode, new allowance,
database access, clock sampling or successful-verification object is involved.

## Private service boundary

`AuthorityProcess._revocation_planner_persistence` requires the writer role,
writer process mode and exact `MeasuredConfiguration` type. It captures the
full payload and held digest before guarded callbacks, then checks the active
writer launch, reads only the writer-exclusive DSN descriptor and takes the
generation snapshot immediately before mapping. Descriptor/launch callbacks
cannot redirect the captured configuration or silently change the work meter.

Source `.62` factors the post-capture continuation into a fixed module-level
helper, preserving this factory's API and work. The private
[writer action](authority-revocation-writer-action.md) supplies its own held
configuration to that same continuation after caller-input and policy capture;
it does not call the factory to recapture mutable process configuration.

These checks do not turn an arbitrary dataclass into admitted configuration.
The actual service still depends on root-signed configuration loading, topology,
runtime closure, attestation, active launch and descriptor custody. Constructing
the owner opens no socket and verifies no plan. Its later operations retain the
actual [connection-admission and cleanup checks](authority-revocation-writer-connection.md).

## What is not activated

There is no new serving purpose or authenticated writer RPC. The `.62` private
action owns bounded original byte strings, planned timestamp and all fifteen
independent expectations before callbacks. Its exact UTC database instant
remains outside JSON, and its historical age/skew policy must match the same
owned measured configuration. Request/history/root provenance still needs
authentication. This factory neither derives those inputs from a retained
record nor configures them on the seven-item owner.

Source `.61` adds private [atomic retain-and-reserve](authority-revocation-atomic.md)
to the configured owner; `.62` connects it to the private measured action but
does not enable dispatch.
Sources `.63` through `.65` add detached signature commitments, private
authenticated composition and immutable original-request custody with exact
retry checks. Source `.66` adds a separate startup-only
[writer response signer](authority-revocation-writer-signer.md); it does not
change this mapper's four-hash, two-key schedule or seven-item owner. Signed
acknowledgment custody, serving integration and the whole-message size contract
remain unfinished. Legacy writer routes and planner-only peer restrictions are
unchanged. Registry closure and four WebAuthn gates are
still incomplete. Production Nitro/KMS, signing and independent witness
services are unprovisioned.

Component fixtures use real configuration/key helpers but synthetic local
configuration commitments; source-linkage checks do not execute the service.
Neither is configuration enrollment, launch, database or deployment evidence.
Follow [goal.md](../goal.md) before any build or verification.
