# Guest public generation artifacts

The seven custody services use distinct UIDs. Their private state directories
remain `0700`; placing group-readable files inside those directories does not
make the files reachable by another service. This explicit guest layout fixes
that generation-coordination connection without exposing private state or keys.

## Cold selection and exact paths

The signed-delivery-bound custody configuration selects:

```json
"guestPublicArtifacts": {
  "apiVersion": "catchplate.responseV2.guestPublicArtifacts/v1"
}
```

The [closed schema](../schemas/response-v2-guest-public-artifacts.v1.schema.json)
allows no path, owner or permission override. Omission preserves existing host
paths; explicit null is rejected. The fixed native cohort requires this profile,
the explicit guest listener, signed guest delivery and TEE generation admission.

```text
/run/catchplate-response-v2-public/     root:65519, 0711
  <each of the seven closed role names>/ signed role UID:65519, 0750
    generation-role-readiness-artifact.json       0440
  state-authority/
    generation-activation-context.json           0440
  custody-router/
    generation-router-topology-attestation.json  0440
```

Each publisher owns only its directory. The shared group permits the other
custody roles to traverse and read signed public artifacts, but not to create,
replace or modify another role's files. The root-owned parent prevents a role
from renaming or replacing its directory. The serving gate does not join this
group or acquire directory-read permission.

## Preparation and retained ownership

Before any role starts, the cohort supplies all seven actual
`PreparedRoleDelivery` owners and the genuine native `Prepared` owner. Layout
preparation checks original configuration, generation, trust checkpoint, boot,
role inventory and unexpired signed startup bounds. Role identity and layout
selection come from these originals, not from a caller-supplied directory list.
No role signing seed is opened by root preparation.

The implementation walks fixed components using descriptor-relative operations
without following symlinks. It creates the public root and every role directory
fresh, initially root-controlled, then installs exact ownership and modes.
Existing paths refuse; partial creation is retained for explicit diagnosis, not
silently removed or adopted by a second attempt. This is not crash recovery.

The cohort retains `O_PATH` descriptors and checks actual named/held directory
device, inode, mode and owner, including after permanent gate privilege drop.
Directory timestamps, size and link count may change during genuine publication;
they are not mistaken for immutable file identity. Original process, boot and
native lifetime checks still apply. Path consumers verify the fixed layout and
signed role ownership before using the existing publication/read routines.

Only three existing public artifact path getters select the new layout. Their
canonical serialization, signatures, generation binding and exact `0440`
file checks remain mandatory. Layout ownership and local startup messages do
not create signed readiness or independently authorize generation activation.

## Boundaries and verification still required

Private state/CAS directories stay `0700`. Role seeds, delivered manifest and
trust-key originals, socket/backend paths and private bootstrap readiness remain
outside this public tree; the signed configuration and delivery admission reject
overlap. This change does not provision role keys, implement the ledger's private
exact-read connection or raw-object writer, supply a durable backend or produce
genuine generation quotes.

Source unit cases cover closed profile decoding, null versus omission and public
tree exclusion for private inputs. They have not been run in this batch. Frozen
runtime verification must prove seven distinct UIDs can publish/read the correct
signed artifacts, another role cannot replace them, the gate retains directory
identity checks without group access, and missing/replaced/symlinked or wrong-mode
paths refuse. Full startup, independent signature/quote verification and failure
cleanup remain separate acceptance requirements. This is source integration,
not an executed pilot or production acceptance result.
