# Cold authority inputs and retained caller

The next [cold ordinary-service slice](native-pilot-genesis-ordinary.md) adds
explicit two-service preparation, initial history and service authorization.
The original five modes below remain supported; the successor documents the
additional fixed purposes and their separate authority requirements.

This continues the [acyclic bootstrap](native-pilot-genesis-bootstrap.md).
It provides purpose-fixed issuer inputs and an actual retained controller caller;
it does not provision the authorities or complete the commissioning graph.
The complete protected inputs and executable/package hashes must be approved
independently. A hash or a valid schema alone is not that approval.

## Packaged commands

The fixed `native_pilot_publication_runtime_entrypoint.py` now has five modes:

| Mode | Output | Private key |
| --- | --- | --- |
| `--prepare-closure-set` | Existing static measured closure set | None |
| `--sign-assignment` | Existing signed assignment | Independently selected assignment key |
| `--prepare-genesis-binding` | Cold-only binding, proof scope and genesis scope | None |
| `--sign-genesis-precreation` | Original authorization to create the parked coordinator | Precreation key |
| `--sign-genesis-release` | Original authorization to release that exact observed child | Distinct release key |

All modes retain the separately approved installed supervisor package and exact
protected input bytes. Signing modes require the existing sealed key descriptor;
preparation modes reject one. Input purpose must match the fixed command before
private-key access. No mode selects a Python module, path or arbitrary command.
There is still no unchecked adoption-signing mode.

The argument order is the same as the [publication entrypoint](native-pilot-publication-commissioning.md#packaged-pre-commissioning-entrypoint):
inventory FD/pin, input FD/pin, and a key FD only for signing. Output is one
canonical original on the supervisor pipe. Discard partial output or nonzero
exit. Original BOOTTIME and applicable UNIX intervals survive package
reinspection and output; a slow check never renews an authorization.

## Separate cold binding

The cold binding uses its own API and hash domain over independently approved
assignment, closure/key roots, commissioning identity and original intervals.
The exact signed assignment is authenticated against pinned current public
trust. The resulting proof scope and genesis scope join that same binding.

This is not a `ProductionCustodyConfiguration`, a measured application driver,
or admission of a running service. The native cold scope explicitly consumes
an independently approved binding; it does not construct a hot configuration.
Its historical field name `production_configuration_binding_sha256` does not
change that boundary. Operational adoption separately verifies the actual
current hot binding and its originals. The hot recipe still requires the real
retained application driver; no numeric PID or made-up observation replaces it.

## Precreation, observation, release

The parent issuer preserves the native signature framing and separate
precreation/release keys. Release joins the exact precreation, actual observation,
launch and selected bootstrap image pins. A public-data issuer cannot prove
observation provenance by parsing it; the operator must approve the literal
observation received from the genuine retained controller.

`ParkedGenesisController` retains independently pinned protected controls and
the fixed installed native executable. It uses actual process/PIDFD ownership,
not a reconstructed owner or caller-supplied success marker. The controller
receives its root operator channel on FD3, publishes the actual parked-child
observation and retains its own result pair. One independently signed release
supplies the other eight activation descriptors. The caller must drain bounded
output and observe successful native exit and actual reap before returning a
complete Bundle. Original deadlines and cancellation remain terminal; no retry
or replacement child is authorized.

The Bundle is not the immutable cold core file. The actual core FD still must
be retained and handed to operational retrieval, independently of these bytes.

## Verification and remaining integration

Exact `e9711b168b33658f3f92951aa5f4fce5be774644` passes all 28 controls in four
focused suites (0.500 seconds), ten-file Python 3.11.15 grammar and exact
membership in both Make inventories. The run used one CPU, an empty environment
and an isolated network namespace. Eight issuer controls use deterministic
synthetic signatures, seven caller controls cover pure framing/ELF checks,
eight cold-binding controls cover authenticated synthetic assignment/scope and
schema joins, and five command controls cover fixed syntax/purpose selection.
No privileged entrypoint, actual process owner or production signing key ran.

This slice does not change native code, so the preceding corrected native
check is retained without rebuilding it. Pure controls do not prove protected
process launch, descriptor transfer, independent signature authority, a live
ceremony or cleanup. No image rebuild, cloud resource or paid test was used.
Source archive, exact harness, logs and checksums are retained at
`codex-offload/serverware/engineering-builds/e9711b16-genesis-authorities-GTtQV0/`.
Review corrected the valid-export EOF race: a controller exit observed after
a nonblocking read does not imply that EOF has already been consumed. The
caller must drain again under the same original deadline before acceptance.
The packaged issuer also resamples clocks after retained-input reads and final
runtime closure; time spent checking those originals cannot extend the expiry.

Complete cold C9/key/grant/closure composers, an expanded commissioning caller,
actual core-FD delivery, native-validator-to-signer ownership, operational
composition, provisioning and connected allow/deny/cleanup acceptance remain
required. In particular, existing ordinary issuers still select five hot
services with generation admission; cold DRS/CSA need their distinct v11
runtimes, v2 initial histories and actual genesis journals. The historical
164-job/113-selector graph excludes this ceremony; source checkpoints remain
36/46 and production acceptance remains 0/6.

The next connected source slice starts with the two ordinary cold services:
real retained DRS/CSA preparation and journal resources, independently signed
initial Wrapper/v2, runtime/v11, and exact cold C9/grant issuance. The current
[`native_pilot_ordinary_initial_authority.py`](../serverware/native_pilot_ordinary_initial_authority.py)
selects the hot driver/five-service profile, and
[`native_pilot_service_authority.py`](../serverware/native_pilot_service_authority.py)
requires generation admission. These cannot be relabeled as cold owners. The
later [`native_pilot_closure_authority.py`](../serverware/native_pilot_closure_authority.py)
also needs explicit cold roles/v6; its existing eleven-member selector is not
permission to issue those originals.
