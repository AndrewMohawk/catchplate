# Publication commissioning tools

This slice connects static closure preparation and assignment signing to an
isolated packaged command, exposes the actual retained cold-result controller,
and reuses native cold-chain verification before an adoption can be signed.
These tools are not a provisioned pilot or the complete commissioning graph.

## Explicit profiles, unchanged assignment wire

The preparation command accepts the existing preparation/v1 input for exactly
eleven members. Preparation/v2 requires a separate `setApiVersion` selecting
either `nativePublicationGenesisClosureSet/v1` (three members) or
`nativeCustodyExecutionClosureSet/v2` (twelve members). Each profile uses its
own ordered roles and hash domains. Extra members never select a new profile.

Assignment authority Input/v2 likewise requires `setApiVersion`. Its signed
output remains `policyShadowAssignment/v2`: the exact domain-separated roots
already bind the selected set. The cold custody-authority anchor is the
`publicationGenesisCoordinator` manifest; the operational anchor is `bridge`.
Legacy input and binding callers remain eleven-member-only by default. The
issuer retains existing independent trust/key selection, original timestamps,
complete-input approval and size limits. Schema checks are not trust approval.

## Packaged pre-commissioning entrypoint

The supervisor package now includes the fixed entrypoint
`/supervisor/app/scripts/native_pilot_publication_runtime_entrypoint.py`.
Invoke it with the packaged `/runtime/python/bin/python3 -I -B` and exactly one
of `--prepare-closure-set` or `--sign-assignment`, followed in source order by:

1. `--supervisor-inventory-fd N --supervisor-inventory-sha256 SHA256`
2. `--input-fd N --input-sha256 SHA256`
3. Only for signing: `--authority-key-fd N`

The descriptors must be distinct and already provisioned. The complete public
input is independently approved, hash-pinned and protected; the private key is
an existing sealed 32-byte descriptor, never an argument or generated default.
The command verifies and retains the actual installed package before reading
key bytes, rechecks input/runtime identities around output, and emits one
canonical original to the supervisor's bounded pipe. Partial output or a
nonzero exit must be discarded. An external supervisor still bounds filesystem
and cryptographic stalls. This command does not launch a guest or install its
output, and it offers no adoption-signing mode.

## Actual cold-result controller

`serverware-native-publication-genesis-controller` uses the existing fixed
protected launch file and genuine C9 descriptors. It takes no arguments, runs
under the existing root/single-thread/empty-environment contract, and requires
an actual anonymous nonblocking write-only stdout pipe. There is no output
path, reconstructed owner or supplied success marker.

It starts the real `GenesisParent`, drives the independently checked handoff
and post-ACK inspection, and exports the exact Bundle bytes. Output retains
the original scope/lifetime bounds and child-reap reserve. Exit zero requires
actual successful bounded reap. Uncertain cleanup retains the owner and
original watchdog without retry. The caller must require the successful exit
as well as complete output, and independently retain the actual cold core file
for operational retrieval; a Bundle is not that file or a durable adoption.

## One native adoption validator

`serverware-native-publication-adoption-validator` is a public-data command,
not a signer. Invoke it with an empty environment as root and exactly
`--input-fd N --input-sha256 SHA256`; stdout must be an anonymous nonblocking
write-only pipe. Its purpose-fixed input pins complete originals. It reuses the
existing native cold configuration, root-signed grants, initial histories,
deterministic genesis, stored core, receipt and durable-witness checks. The
unsigned payload is checked without manufacturing an authorization signature;
signed consumers use the same semantic checks plus signature verification.

Current trust, signed assignment, proof scope, target histories and original
windows must agree. Authority-side wall-clock validation is not a substitute
for trusted guest time or a running native owner. The production configuration
binding is an independently approved digest joined to the exact proof, not an
admission of a constructed runtime configuration. The input is explicit
`nativePublicationAdoptionValidationInput/v1`, containing `payloadOriginal`,
the pinned current trust original, signed assignment, current closure set,
configuration binding, exact proof scope and two complete target-history
records. The canonical result binds the exact input/payload hashes, public
signing-key identity and unchanged original BOOTTIME/UNIX expiry. It does not
contain a signature. Connecting this validator's
exact output to an independently operated signer remains required; the Python
entrypoint deliberately has no unchecked adoption-signing shortcut.

Both native tools are registered in the existing release build, static-ELF and
size checks, and native-install inventory. Source registration does not prove
an artifact build, protected installation or actual ceremony execution.

## Remaining integration

Complete cold grants/closures and provisioning, the expanded commissioning
graph, validator-to-signer handoff, operational grant composition and retained
core delivery remain open. So do uncertain/restart recovery, later authority
transitions, other signer families and independent production acceptance.
The old graph's 164 jobs/113 selectors do not include these new ceremonies.
Source checkpoints remain 36/46; independent production acceptance remains 0/6.

See [cold genesis](native-pilot-genesis.md),
[operational adoption](native-pilot-adoption.md), and the
[full project goal](../goal.md) for the unchanged completion requirements.

## Verification

Source is being assembled for one frozen, focused Python/native check. No live
ceremony, signing key, provider, deployment, cloud resource or paid test has
been used for this slice. Results will be recorded after the actual check.
