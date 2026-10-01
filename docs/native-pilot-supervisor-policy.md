# Initial independent commissioning policy

`serverware.native_pilot_supervisor_policy.SupervisorPolicy` admits one complete
independently selected policy and implements the first `driver-bootstrap`
decision. The separate precreation composer implements the next two jobs. This
is not a complete decision service, a runnable pilot supervisor, or
approval of unimplemented future jobs. Current v12 source composes 126 of 136 jobs;
the decision spine refuses startup while the remaining 10 are unimplemented.
Production acceptance remains 0/6.

## External approval boundary

The independent commissioning authority supplies the literal policy on a
protected FD and its independently authenticated SHA256. Computing the digest
locally, owning a root pipe, or passing validation is not that approval. Runtime
inventories, approved image/source identities, existing keys, original cold
configurations and the already signed driver window remain externally
provisioned. No key, timestamp, invocation, permission or historical receipt is
generated here. V9's explicitly approved fresh-store genesis is unsigned
initialization data, not a claim of prior state or observed empty storage.

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
At v4 the coordinator expanded to 57 exact key selectors; v1–v3 kept their old
42-selector shape. V4–v7 still keep 57; v8–v10 retain 77. None can bind the
current v11/v12 inventory of 108 selectors. No legacy policy is silently
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
process and pending request under v4 or its explicit v5/v6/v7/v8 successors. The fixed
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
for v5/v6/v7/v8 and the actual pending owner. The composer joins its recipes to the five
verified initial wrappers and actual peer/preparation/directory observations.
The retained installer writes only its fifteen fixed public files from that
composer's actual prepared originals; it is not a general root writer. Five
existing C9 signing jobs consume the resulting complete inputs. The subsequent
first-generation boundary is read-only and verifies the final delivery result;
it supplies no generation approval. See
[ordinary-service deliveries](native-pilot-ordinary-deliveries.md) for the paths,
ownership, failure retention and unchanged native admission boundary.

## Ordinary-generation successor: v6

Policy/v6 retains v5's thirteen fields and adds exactly
`ordinaryGenerationsOriginal`, with purpose
`initial-driver-bootstrap-precreation-endpoints-and-ordinary-generations`.
The literal canonical ASCII original is an exact three-field
`serverware.nativePilotOrdinaryGenerationPolicy/v1`: API version and positive
i64 `installationIssuedAtUnixNanos` / `installationExpiresAtUnixNanos`, in order.
It selects no future receipt, driver, descriptor, runtime or signature facts.

All eighteen scope fields are assembled from the admitted interval and genuine
authenticated originals under the retained process. The interval must fit the
assignment/trust/key/checkpoint validity and maximum evidence age. Each of the
five existing `ordinary-generation-*` capabilities must match the independently
approved role history-root key. The total 57 selectors and outer 4 MiB bound
remain unchanged; the literal field does not widen legacy outer integer rules.

`ordinary_generation_policy(process=..., request=...)` is available only to
explicit v6–v12 with the actual pending owner. Jobs 31–35 form existing complete
generation inputs, verify each preceding root-signed result and retain exact
originals. The next job's handoff is read-only. Native callers use the same
original installation interval without renewal; no running-service acceptance
is inferred. See [generation inputs and native time binding](native-pilot-ordinary-generations.md).

## Remaining-native-delivery successor: v7

Policy/v7 retains v6's fourteen fields and adds exactly
`nativeDeliveriesOriginal`, with purpose
`initial-driver-bootstrap-precreation-endpoints-ordinary-generations-and-native-deliveries`.
The literal canonical ASCII object has exactly seven role entries, each with
`runtimeOriginal`, `runtimeConfig` and nonempty `credentials`. Role markers,
fixed public paths, complete byte pins and cold-authority key bindings are
checked during policy admission. No private credential is opened or created.

The existing 57 selectors and 4 MiB outer bound remain unchanged. The original
three-role `endpointDeliveries` contract remains separate; no old policy is
widened. `native_delivery_policy(process=..., request=...)` returns a checked
copy only under v7–v12 with the actual pending owner. Jobs 36–42 use the same
independently authenticated measured recipe and signed role-specific closure
leaves, genuine cohort observations and unchanged windows. Job 43 only obtains
a verified read-only handoff. V8 separately authorizes the new key decisions
that now precede the native-service grants.
See [native delivery composition](native-pilot-native-deliveries.md).

## Native-key-authorization successor: v8

Policy/v8 retains v7's fifteen fields and adds `nativeKeyAuthorizationsOriginal`,
with purpose
`initial-driver-bootstrap-precreation-endpoints-generations-and-native-key-authorizations`.
Its literal canonical ASCII object has exactly ten endpoint-role entries. Each
contains `localRoles`, `challengeBase64url`, `issuedAtUnixNanos` and
`expiresAtUnixNanos`. Roles are ordered and unique, with each endpoint's required
local role included; the challenge and interval are supplied by the independent
authority, not generated from a request or current clock.

There are twenty new fixed purpose selectors, for 77 total; they select an
already provisioned supervisor capability, not twenty generated keys. Before
returning `native_key_authorization_policy(process=..., request=...)`, the owner
resolves the supervisor public key through the actual retained recipe's signed
assignment and pinned trust and matches every new selector to its raw public
material. This post-bootstrap check is separate from the initial admission of
the independently selected capability pins. The signer also checks the actual
private capability against that resolved public authority.

Service jobs 43–62 execute role-major pairs. Admission consumes the genuine
preceding signed role-key original, not a predicted digest. Job 63 provides a
verified read-only handoff. No verifier configuration, Nitro result, key seed,
launch or service grant is fabricated. The outer 4 MiB policy limit and original
legacy integer rules remain unchanged. See [full contracts](native-pilot-key-authorizations.md).

## Native-operational-service successor: v9

Policy/v9 retains v8's sixteen fields and adds only `nativeServicesOriginal`,
with purpose
`initial-driver-bootstrap-precreation-endpoints-generations-and-native-services`.
The literal closed eight-field native-service policy selects verifier settings,
original operation intervals, spool/origin policy, an independently trusted
startup runtime receipt and explicit fresh persistence/coordinator/time settings.
The outer 4 MiB bound and exact 77 selectors remain unchanged.

`native_service_policy(process=..., request=...)` resolves all eleven native
service/generation-install purpose keys through the actual retained assignment
and independent trust. It returns a copied admitted fragment only for v9–v12 and
the real pending owner. No older policy gains these grant decisions.
Jobs 63–73 revalidate the actual authorization pairs and complete predecessor
inputs/results. Job 74 is only a read-only verified handoff; earlier installer
entry points are not reopened by extending completed-owner rechecks.

Fresh genesis/journal projections are explicitly approved unsigned inputs.
Actual receiving owners still enforce empty directories, retained identities
and exclusive creation. The verifier configuration is not a Nitro verdict,
and the runtime-receipt verifier is not the independent receipt producer.
See [contracts and remaining acceptance](native-pilot-native-services.md).

## Ordinary-transition successor: v10

Policy/v10 retains v9's seventeen fields and adds only
`ordinaryTransitionsOriginal`, with purpose
`initial-driver-bootstrap-precreation-endpoints-generations-and-ordinary-transitions`.
Its literal canonical fragment selects two dispatch starting heads, three
spool starting heads and an append capacity of 1–32. These are approved initial
chain values, not proof of previous actions, receipts or empty storage. The
outer 4 MiB bound and 77 selectors remain unchanged; v1–v9 gain no new decisions.

The two dispatch selectors and `ordinary-head`, `ordinary-cleanup` and
`ordinary-current` must match each role's independently approved history-root
key. `ordinary_transition_policy(process=..., request=...)` requires v10–v12 and
returns a checked copy to the genuine pending owner. Service jobs 74–78 use
actual ordinary and native input/grant originals; Cleanup requires the actual
signed Head and Current requires the actual signed Head and Cleanup. Completed
predecessor rechecks extend only to the read-only job79 handoff; no installer
or launch entry is reopened. See [contracts and limits](native-pilot-ordinary-transitions.md).

## Late-launch-authorization successor: v11

Policy/v11 adds only `nativeLaunchAuthorizationsOriginal` to the eighteen v10
fields, with purpose
`initial-driver-bootstrap-precreation-endpoints-generations-and-native-launch-authorizations`.
The literal `serverware.nativePilotLaunchAuthorizationPolicy/v1` has exactly
`apiVersion` and ten `endpoints` rows. Each row selects a closure interval,
encrypted-delivery transport original and interval, and verifier port/interval.
CommitRequest additionally selects its provisioner's public secret descriptor
and original HMAC-authorization interval. No private bytes or guest identity are
accepted in this policy. Transport commitments do not prove ciphertext exists
or that KMS will release it; actual provisioners and receivers retain those duties.

The 31 new jobs have separate purpose selectors, for 108 total, all pinned to
the independently authenticated assignment's supervisor key. Old v1–v3 retain
42, v4–v7 retain 57 and v8–v10 retain 77. `launch_authorization_policy` requires v11/v12
and resolves the actual trusted signing authority before returning a checked
copy. The outer 4 MiB bound is unchanged; the fragment is bounded to 256 KiB.

Jobs 79–109 retain genuine prior inputs/results, produce one signature each,
and do not publish launch components. CommitRequest's encrypted delivery
requires the actual preceding signed request-commitment original, with its
descriptor and interval still equal to the independent policy. The first launch
job110 receives only a verified read-only handoff; remaining launch composition
is not authorized implicitly. See [full contracts](native-pilot-launch-authorizations.md).

## Endpoint-launch successor: v12

Policy/v12 adds only `endpointLaunchesOriginal` to v11's nineteen fields. Its
purpose is `initial-driver-bootstrap-precreation-endpoints-generations-and-endpoint-launches`.
The same 108 signing selectors remain; no new key or signer is introduced.
The outer 4 MiB bound remains. The 16 KiB fragment
`serverware.nativePilotEndpointLaunchPolicy/v1` has exactly `apiVersion` and
`endpoints`, with ten closed role rows selecting `parentPort`,
`maximumBracketNanos`, `timestampErrorNanos` and `maximumClockRateErrorPpm`.
These are unsigned time-bootstrap settings, not observations or trusted time.
The TrustedTime row must equal the already selected native-service settings;
its launch consumes the exact bootstrap original bound by that prior grant.

`endpoint_launch_policy` returns a copied fragment only for v12 and the actual
pending owner. Jobs110–119 derive complete bundles from authenticated literal
predecessors and call the existing exclusive installer. The supervisor verifies
actual results and only exposes a read-only handoff at service-material120.
It does not authorize bridge, release, origin, shutdown or resource provisioning.
See [contracts and evidence](native-pilot-endpoint-launches.md).
