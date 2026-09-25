# Supported-version historical replay

Source checkpoint `.118`; implementation only, unbuilt and unexecuted.
This authorizes verification of retained WebAuthn evidence and transition plans,
not activation of an old generation, renewed credentials, or business execution.

## Two trust decisions

The current configuration and verifier key authorize a fresh, bounded lookup.
The configuration, cohort and keys that originally authorized a plan verify its
retained originals. A stored plan, returned context, database row or successful
verification object cannot enroll those historical keys.

```text
Current root-signed configuration and measured launch
                 |
                 v
Current signed cohort + current-root-signed historical archive
                 |
       cold signature and package admission
                 |
                 v
       immutable historical snapshot inventory
                 |
Current signed lookup -> authenticate complete original history bytes
                 |
       select an already admitted snapshot
                 |
       original plan signature/proof/semantic replay
                 |
       retained originals, not execution permission
```

## Startup material

The existing sealed runtime-evidence descriptor now carries canonical
`serverware.authorityRuntimeEvidence/v1`, with exactly `schema`, `currentCohort`
and `historicalArchive`. Its aggregate limit remains 4 MiB. The current cohort
keeps its independent signature and five original role receipts. There is no
bare-cohort compatibility fallback or unsigned empty-archive exception.

The archive envelope has exactly `schema`, `payload` and `signature`, using
`serverware.signedAuthorityHistoricalArchive/v1`. Its payload has eight fields:

| Field | Meaning |
| --- | --- |
| `schema` | The archive schema above |
| `purpose` | Exactly `verify-retained-authority-plans` |
| `sourceRevision` | The supported source contract |
| `configurationDigest` | The independently admitted current configuration |
| `generationDigest` | The independently admitted current generation |
| `issuedAtEpochNs` | Beginning of current archive authorization |
| `expiresAtEpochNs` | End of current archive authorization, exclusive |
| `entries` | Zero to sixteen explicitly authorized historical snapshots |

The current configuration root verifies the archive signature. That signature
explicitly authorizes each historical configuration root and exact artifact
trust-state snapshot; roots are not selected from the retrieved plan. The
archive interval must fit inside the admitted current cohort and generation
interval. Startup repeats live time and local launch/custody checks after cold
admission. An empty signed archive supports only the independently admitted
current snapshot.

Each historical entry contains exactly `configurationEnvelope`, `artifactPackage`,
`artifactTrustState`, `configurationRootPublicKeyBase64Url`, `attestationCohort`,
`configurationDigest`, `validFromEpochNs` and `validUntilEpochNs`. Entries are
ordered and unique by configuration digest and planner receipt digest. A repeated
current selector is rejected rather than silently overriding its trust.

Admission verifies the actual historical configuration signature and its raw
file/payload membership, the actual signed artifact package, key authorizations,
revocations and witness checkpoint against the explicitly authorized historical
trust state. The package must be the exact already-accepted generation, not a
successor; no current high-water state is changed or synthesized from package
claims. Package verification covers both endpoints of the authorized replay
interval. Historical cohort signatures and full generation/role/configuration
joins use the original evaluation interval without consulting the current
launch guard as a substitute for historical evidence.

Historical package versions are declarations in the signed configuration,
joined to the signed cohort's runtime-closure claims. The artifact's SBOM is
digest-pinned but is not parsed for distribution versions. This is not an
independent measurement of the historical runtime's installed packages.

The inventory retains originals and freezes snapshot data transitively before
serving. A lookup holds immutable inventory references before callbacks and
copies only the selected snapshot on the existing measured work allowance.
It does not reverify whole artifact packages or copy every archive graph for
each request.

## Lookup and replay

Both evidence and transition lookup controls retain their current signature,
configuration, generation, operation, peer topology and complete original-history
commitment. Authentication precedes decoding the committed history or selecting
a historical snapshot. The selector uses the historical configuration digest,
planner receipt digest and original evaluation time—not fields learned from the
returned plan. Unknown selectors or times outside an admitted interval fail.

Historical configuration/cohort mapping then performs the existing bounded
configuration and runtime-identity joins, builds the actual historical public
keys, and checks the independently authenticated history. The writer uses its
current protected database connection settings with historical replay pins;
clients also replay the original response with historical keys and policy.
Original plan issuance, expiry, evidence, invocation, roots and retention times
are never refreshed to the lookup clock.

The producer clips the fresh lookup deadline to the archive authorization
expiry. Every receiving hop requires the signed lookup interval to be wholly
inside the same archive interval. Existing live lookup-window checks remain in
force through database/transport/replay and final return. An archive valid only
at startup is not an indefinite grant to use retired keys.

## Explicit caller reconciliation

Source `.118` adds a separate private, lookup-only path from the caller journal
through the runtime relay to the verifier. It carries the exact retained
evidence raw-six or transition raw-seven originals under the independently
admitted current configuration scope. It does not forward a custody write or
clear the journal's durable attempt marker.

The original intent's configuration, generation and issue time are initially
untrusted lookup locators. They can select only a snapshot already admitted by
the current-root-signed archive, solely to obtain its static signature key.
Where several eligible cohorts share that configuration/generation, the first
eligible snapshot can bootstrap signature verification; it cannot supply the
final historical identity. After authenticating the original controls and their
complete byte commitments, the verifier resolves the actual planner receipt and
authenticated historical expectations, joins the control intervals to that
snapshot, and performs genuine original-plan replay. Received headers and stored
context never enroll keys or establish independent history.

Only then does the existing current signed lookup retrieve the retained record.
Its fresh window remains bounded by current archive authorization; it renews no
original intent, relay, plan, evidence or invocation lifetime. The dedicated
response carries original plan bodies and unsigned record/time metadata. Errors,
missing records and uncertain responses grant neither absence proof nor retry,
write, signed-receipt or business execution authority.

## Limits and remaining work

This supports configuration, cohort and key changes only under the currently
supported source contract and schemas. It deliberately does not reinterpret
plans from arbitrary old binaries or relax exact source/schema pins. Cross-source
replay needs an explicitly versioned replay implementation.

No SQL mutation, new database grant, automatic retry, old-generation activation
or execution capability is added. Missing data and late/failed responses remain
uncertain observations, not proof of absence or rollback. Durable caller
retention and explicit private reconciliation now have source implementations;
deployed caller provisioning, public preparation/orchestration, successor
execution, independent evidence production and production infrastructure remain
separate work.
Broad fixture adaptation and all build/runtime verification remain deferred.
