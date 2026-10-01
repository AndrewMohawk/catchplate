# Bridge assembly: next source connections

This is a source-supported plan, not implemented bridge composition or runtime
evidence. Service-material publication is a separate prerequisite. No bridge
coverage, new authority, service availability or successful launch follows from
this document.

## Existing phase and installer

After service-material, the actual [operator](../serverware/native_pilot_operator.py)
admits the ordinary grants and endpoint transfers. Its `bridge-runtime` request
then carries exactly `ordinaryGenerationGrants`, `endpointLaunches`,
`nativeGrantSha256s`, `bridgeJournal`, `cohortObservationOriginal` and
`ordinaryParked`. The last contains parked PID/start/PIDFD-inode and retained
target-executable facts, not final-role cgroup, security label or readiness.

[Bridge installation](../serverware/native_pilot_bridge_install.py) already
accepts a closed `nativePilotBridgeRuntimeBundle/v1`: `apiVersion`,
`driverControlSha256`, `driverObservationOriginal`, `runtimeOriginal` and
`outgoingOriginal`. It retains the real bootstrap control/configuration/window
and cold original, then exclusively publishes runtime followed by outgoing
configuration. Runtime is fixed `policyCustodyProductionRpcRuntime/v9`, at
`/etc/serverware/native-pilot-inputs/bridge-runtime.json`; outgoing configuration
is `/etc/serverware/native-shadow-driver-outgoing.json`. Bounds remain 64 KiB
and 8 KiB respectively, with a 512 KiB complete bundle. Large embedded prior
grants may exceed these existing limits; no limit increase is implied.

The outgoing original is completely derivable: configuration/window/observation
hashes, original invocation, actual cold pin, runtime pin and fixed
`nativeProofBridgeLaunch/v5`. The exact driver observation is the retained
bootstrap original, not a new sample or a renewed window.

## Runtime sources, not a literal template

The complete field inventory is `_RUNTIME_FIELDS` in
[driver outgoing](../serverware/native_shadow_driver_outgoing.py), plus
`commitRequest` and `spool`. Its families need these sources:

| Runtime fields | Required source or independent selection |
| --- | --- |
| `journalDirectoryIdentity`, `generationAdmission.grants` | Actual bridge-phase journal observation and all five retained signed generation results; the phase executor already compares these. |
| `commitRequest.serviceGrantOriginals`; `spool.headGrantOriginal`, `cleanupGrantOriginal`, `currentGrantOriginal` | Literal actual two dispatch and three spool results, not reconstructed payloads. |
| `expectedServiceConfigurationSha256`, signing-credential, restart/readiness and history maps; dispatch protocol and durability limits | Exact approved ordinary runtimes, C9 credential metadata and authenticated histories; match the real service-report recipes. Private credentials are not read to derive these. |
| `histories` | Five role/credential-name/semantic-manifest/root-key records. The bridge needs its own accessible, independently provisioned credential originals; ordinary service-owned files are not automatically bridge-readable. |
| `serviceSessions` | Five fixed service roles, activation names, socket paths, full expected peers and complete handshake requests. See the missing current-head and peer joins below. |
| `parentSignerEndpoints`, `proofEndpoints` | Ten signer and four proof bindings, with exact authority credential names, key IDs/SPKI, paths, activation names and peer contracts. Six signers and four proofs map to existing native endpoints; four signers remain external. |
| `expectedFacadePeer`, driver identity/configuration, operation/shared configuration and helper-role expectations | Actual retained driver/gate observations plus the independently approved ordinary operation/configuration selections. Derive using the receiver's exact identity recipe, never a PID-only or target-executable substitute. |
| Startup timeout, handshake request IDs/nonces and original deadlines, external endpoint/credential selections | Closed independent policy decisions, cross-checked against retained originals and original startup limits; no generated authority, replacement deadline or default endpoint. |

The existing phase executor binds only part of this runtime. A new retained
composer must cover the remaining joins, not treat the existing installation
shape check as full runtime admission.

## Handshakes need a genuine current-head producer

`serviceSessions[].handshakes` are embedded public request objects, **not**
preprovisioned credential-file contents. The receiver is
[ServiceHandshakeRequestV3](../data-plane/decision-gate-rs/src/policy_custody/services/common.rs):
API/service role, request ID, nonce, client process/configuration identities,
deadline, `expectedCurrentHead`, request/reply rights counts and request digest.
The digest commits the complete request using the existing domain recipe.

`expectedCurrentHead` contains the full `signedCurrentHead` and its exact
canonical-original digest. The signed object is
`SignedTrustedHostNoTeeCurrentHeadWire` in
[protocol.rs](../data-plane/decision-gate-rs/src/policy_custody/protocol.rs),
not the initial key-authorization checkpoint. Its statement binds endpoint role,
request nonce/request digest, checkpoint sequence/digest, endpoint generation,
revocation generation/root, actual issue BOOTTIME and the exact deadline.
[HandshakeCurrentHeadPin](../data-plane/decision-gate-rs/src/policy_custody/services/mod.rs)
verifies the checkpoint-authority signature and matches the configured current
checkpoint, generation, revocation and deadline.

The existing Python initial-history and ordinary-key issuers do not produce
this signed current-head wire. Reusing their signatures under this domain is
invalid. The next issuer needs the actual authenticated checkpoint, its
independently selected checkpoint authority, and the genuine original prior
`TrustedHostNoTeeTrustRequestWire`. A retained signed checkpoint alone is not
evidence that no newer checkpoint exists. Currentness and the original request's
issue/deadline bounds need explicit authority and live checks, not caller-chosen
digest placeholders. Real replies and readiness remain native runtime results.

The trust request and service handshake have **different digests**. The
[trust-exchange receiver](../data-plane/decision-gate-rs/src/policy_custody/endpoint_clients.rs)
matches the head statement's nonce/digest to the pending trust request, which
contains no head. The later handshake hashes its complete signed-head binding.
Equating the head's `requestSha256` with that final handshake digest would create
a hash/signature cycle; current handshake validators do not require that
equality. Preserve an explicit genuine prior-trust-request binding rather than
inventing a headless-handshake digest. This does not inherently require a
post-service handshake result, but still needs fixed producer/purpose wiring
and authenticated currentness before the unsigned handshake can be composed.

## Peer, history and external-service gaps

Full `ExpectedPeerCredentialV3` includes UID/GID, PID/start, executable
device/inode/length/hash, cgroup path hash/mount/inode, security-label hash,
configuration generation and the corresponding process-identity hash. The
parked observation and intended-exec identity do not provide that entire
transport identity. The native facade still compares its configured outgoing
expectations through real parent inspection; it does not replace them with
unchecked observations. Connect a genuine owner-derived measurement or an
explicit independently approved expected-final-state contract with the exact
receiver recipe. Do not invent cgroup/label facts or claim final exec happened.

There is also a concrete history receiver mismatch:
[`load_production_histories`](../data-plane/decision-gate-rs/src/policy_custody/services/production.rs)
directly decodes credential bytes as `AuthorityHistoryManifestV3`. Current fresh
history results are explicit initial-history wrappers. An authenticated bridge
adapter must retain their initial-state/checkpoint/three-authority semantics;
neither passing the wrapper as a raw manifest nor silently stripping it is a
connected repair. Existing [initial-history admission](../data-plane/decision-gate-rs/src/policy_custody/services/initial_history.rs)
and authenticated ordinary grant/history bundles are reusable sources.

The four non-native signers are `unavailable-ingress`, `spool-compaction`,
`publication-reconciliation` and `activation-publication`. Their endpoint and
authority-binding configuration can be independently approved without starting
them. Real listening services, exact socket ownership/peer identity, matching
credential bindings and request/response authority are nevertheless required
when the bridge connects. No source in this commissioning slice provisions or
proves those services.

## Later bridge C9 and launch

After runtime installation the real operator prepares outgoing connections and
reports the actual 41-entry bridge activation inventory. The existing C9 issuer
supports `bridge`; use that observation, original driver window/cold and actual
runtime bytes. Do not predict activation records in the runtime phase.

The existing closure issuer also supports the bridge leaf after actual C9.
However, the new endpoint key/admission, encrypted-delivery and verifier
producers select exactly ten endpoint roles. They cannot silently accept
`bridge`. A bridge-specific authorization path must preserve
`nativeShadowBridgeAdmissionAssignment/v1`, its production-binding field and
the original bootstrap `continuation.keyTransport`. Bridge launch also needs
its approved time-bootstrap settings and the actual TrustedTime service grant.
The existing bridge launch installer is not a producer for these signatures.

The `.383` [service-material owner](native-pilot-service-material.md) now provides
`require_material` at the genuine `bridge-runtime` / `install-bridge-runtime`
job1 request. This read-only handoff retains the approved material input/result,
checks the actual next phase and previous result, and preserves the original
lifetime. It supplies immutable public material; it does not compose or
authorize the bridge runtime.

Broader bridge assembly must still connect the authority, measurement and
receiver joins above to that actual pending request through the real
[coordinator process](../serverware/native_pilot_supervisor_process.py). The
material handoff is not permission to widen every predecessor to arbitrary
phases or to count an unsupported runtime template as bridge coverage.
