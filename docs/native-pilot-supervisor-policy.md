# Initial independent commissioning policy

`serverware.native_pilot_supervisor_policy.SupervisorPolicy` admits one complete
independently selected policy and implements the first `driver-bootstrap`
decision. The separate precreation composer implements the next two jobs. This
is not a complete decision service, a runnable pilot supervisor, or
approval of unimplemented future jobs. Current v5 source composes 37 of 85 jobs;
the decision spine refuses startup while the remaining 48 are unimplemented.
Production acceptance remains 0/6.

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

## Legacy closed policy

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
- `keyBindings`: exactly the 42 legacy source-owned selectors, each mapped to
  SHA256 of the actual raw 32-byte Ed25519 public key. This is a capability
  inventory, not approval of all purposes or jobs.
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

## Initial-history successor: v4

Policy/v4 has the eleven v3 fields plus `ordinaryInitialHistories`. Its purpose
is `initial-driver-bootstrap-precreation-endpoints-and-ordinary-initial-history`.
The expanded coordinator requires 57 exact key selectors; v1–v3 keep their old
42-selector shape and therefore cannot bind it. No legacy policy is silently
upgraded or given new signing authority.

The new fragment is `serverware.nativePilotSupervisorOrdinaryInitialPolicy/v1`
with exactly `apiVersion` and five-role `services`. Each role selects three
separate public authorities, a protocol endpoint role, four positive generation
counters, deployment digest, revocation generation/root and the closed validity
rule `observed-initial-resources-through-original-lifetime`. It does not carry
predicted process identities, initial-state bytes or future signatures. The
composer derives those public inputs only from actual retained observations and
verified results under the unchanged startup window.

Only these four generation counters and the revocation high-water counter in
each v4 role entry accept positive u64 values. All other integers, older policy
versions and the original byte/depth/node limits keep their existing grammar.

`ordinary_initial_policy(process=..., request=...)` accepts only the bound actual
process and pending request under v4 or its explicit v5 successor. The fixed
composers verify every prior signature against its literal approved input. The next job observes the
actual output; receiving an approval reply alone is not success. The complete
wrapper is published to one fixed root-owned path per role. Downstream delivery
requires an independently installed service-owned copy at its separate fixed
slot, with the same retained bytes, digest and length; later grant inputs use
the same wrapper. V5 connects that fixed public copy installer without changing
v4's authorization. See
[the full connection](native-pilot-ordinary-initial-history.md#supervisor-connection).

## Ordinary-delivery successor: v5

Policy/v5 has the twelve v4 fields plus `ordinaryDeliveriesOriginal`, with purpose
`initial-driver-bootstrap-precreation-endpoints-and-ordinary-deliveries`.
The added value is the complete canonical ASCII original of
`serverware.nativePilotOrdinaryRuntimePolicy/v1`, not a template or an arbitrary
runtime document. The outer policy retains its 4 MiB limit and the exact 57-key
inventory. Each ordinary-delivery selector must equal the selected cold C9
authority. Earlier versions keep their exact fields and scopes; v4 does not
implicitly gain delivery or installation permission.

The runtime policy has exactly `apiVersion` and five-role `services`, whose rows
are exactly `runtimeHeader`, `service` and `credentials`. It selects static
limits, independent root/public-key bindings, explicit fresh-profile service
choices and metadata for existing credentials. It excludes predicted live
identities, directory observations and generated public-file destinations.
Reserved names and all fifteen source-owned public paths cannot be supplied as
static credentials. No private credential is generated or opened by this policy.

`ordinary_delivery_policy(process=..., request=...)` returns a checked copy only
for v5 and the actual pending owner. The composer joins its recipes to the five
verified initial wrappers and actual peer/preparation/directory observations.
The retained installer writes only its fifteen fixed public files from that
composer's actual prepared originals; it is not a general root writer. Five
existing C9 signing jobs consume the resulting complete inputs. The subsequent
first-generation boundary is read-only and verifies the final delivery result;
it supplies no generation approval. See
[ordinary-service deliveries](native-pilot-ordinary-deliveries.md) for the paths,
ownership, failure retention and unchanged native admission boundary.
