# Initial independent commissioning policy

`serverware.native_pilot_supervisor_policy.SupervisorPolicy` admits one complete
independently selected policy and implements the first `driver-bootstrap`
decision. The separate precreation composer implements the next two jobs. This
is not a complete sixty-job decision service, a runnable pilot supervisor, or
approval of unimplemented future jobs. The decision spine must refuse startup
while fixed-job coverage remains incomplete.

## External approval boundary

The independent commissioning authority supplies the literal policy on a
protected FD and its independently authenticated SHA256. Computing the digest
locally, owning a root pipe, or passing validation is not that approval. Runtime
inventories, approved image/source identities, existing keys, original cold
configurations and the already signed driver window remain externally
provisioned. No key, timestamp, invocation, permission, history or genesis is
generated here.

The source API is:

```text
SupervisorPolicy.open(policy_fd=..., policy_sha256=...) -> policy
process.prepare_bootstrap()                            # retain installed originals
policy.bind(actual_authority_coordinator_process)        # before start
policy.bootstrap(process, actual_pending_job_request) -> (input_raw, approval_raw)
policy.close()                                         # after definite cleanup
```

Policy admission duplicates and retains the existing public FD with CLOEXEC.
The shared input contract requires isolated/no-bytecode root execution and a
root:root mode0400 single-link read-only original, or an equivalently fully
sealed public memfd. The complete policy is canonical ASCII JSON without LF,
bounded to 4 MiB. Original identity and literal bytes, process identity,
boot/time namespace and nondecreasing original BOOTTIME bounds are retained and
rechecked. There is one admission/binding/bootstrap attempt per process and no
retry/reset path.

## Closed policy

There are exactly eight top-level fields:

- `apiVersion`: `serverware.nativePilotSupervisorCommissioningPolicy/v1`.
- `purpose`: `initial-driver-bootstrap-and-endpoint-precreation`.
- `source`: the existing exact five runtime source fields: `revision`,
  `source_tree_digest`, `source_manifest_digest`, `source_archive_digest`,
  `source_date_epoch`.
- `conductorInventorySha256` and `authorityInventorySha256`: independently
  approved pins for the two distinct existing runtime inventories.
- `bootstrapOriginals`: exact `control`, `configuration`, `window`, and
  `deliveryConfiguration` literal canonical ASCII originals.
- `keyBindings`: exactly the 42 source-owned `KEY_PURPOSES`, each mapped to
  SHA256 of the actual raw 32-byte Ed25519 public key. This is a capability
  inventory, not approval of all 42 purposes or all sixty jobs.
- `precreation`: the separate closed
  `serverware.nativePilotSupervisorPrecreationPolicy/v1` fragment.

The precreation fragment contains only its exact API, C9 authority, endpoint
and cohort executable pins, existing cleanup authority/journal/genesis binding,
ten native cold originals, five ordinary cold originals and five ordinary
executable pins. Its composer validates these static choices independently of
any later request. It is not a JSON template or future-signature placeholder.

The bootstrap originals preserve configuration v4 / lifecycle v3 and the
existing signed Window/v1. Their hashes, signature, cold delivery UID/GID,
authority separation, fixed transport and original <=30-second startup window
are checked using the existing issuer/receiver helpers. The bootstrap and
constructed key selectors must match the selected constructed-admission public
key, the scope selector the phase-two key, and both cohort selectors the
approved C9 authority. That authority must also match the driver cold original.
Other key selectors remain independently pinned capabilities whose later
purpose decisions are not implemented by this owner.

`bind()` accepts only the actual `AuthorityCoordinatorProcess`, before start.
Its checked `policy_bindings()` must equal the two approved runtime hashes,
complete source identity and actual retained-key public bindings. The process
owner, not JSON, validates installed runtime files, capabilities and process
resources. The four actual retained bootstrap originals must equal the policy's
literal originals. This comparison first occurs in `bind()`,
after `prepare_bootstrap()` and before any child is spawned, with a fresh check
of the unchanged original startup window. The first pending request rechecks
the same four literal originals.

## First real decision

`bootstrap()` accepts only the real owner's current opaque `JobRequest` and
checks that ownership before and after composition. The job must be the exact
first `bootstrap-admission / driver-bootstrap` request, with the original
startup deadline, no preceding result and the complete correctly hash-bound
conductor request. Both observation and prepared admission payload are copied
literally from that authenticated request.

Existing driver authority validators check the configuration/window/image and
descriptor associations, original process-data grammar, authority binding and
unrenewed 30-second admission interval. The policy trusts observations only
through the authenticated process chain executing the approved installed
runtime. It does not independently resample kernel descriptors, reconstruct a
DriverBootstrap, or replace the native receiving owner's actual live checks.

The resulting complete input uses the existing driver-authority input schema.
The resulting approval is the existing exact eight-field
`serverware.nativePilotAuthorityJobApproval/v1`, bound to that complete input
hash, phase, job, conductor request and original deadline. No signature or
approval file is produced by this module: the separate spine owns the actual
protected installer and reply. A later observed signature must still be
verified and joined to the exact installed input, not merely trusted because a
previous-result object appeared on the pipe.

`precreation()`, `bootstrap_originals()`, and `bootstrap_input_original()` expose
checked copies/literal public bytes for those fixed later composers. They are
not generic approval capabilities. Unknown cleanup retains the policy owner;
`close()` requires the exact bound process's genuine closed/not-started or
terminal-and-reaped state. No caller-authored status object releases it.

No signing, approval installation, process launch, build, hardware execution or
complete-pilot verification was performed as part of authoring this source.
