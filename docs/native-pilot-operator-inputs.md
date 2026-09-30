# Native pilot operator inputs

The fixed conductor entrypoint is
`scripts/run_native_pilot.py --run-native-pilot`. It is an explicitly privileged
live operation, not an offline validation command. Its only operator transport
is the existing root-only pipe channel on stdin/stdout. Interactive terminals,
arbitrary configuration paths, executable arguments, callbacks and commands
are not supported. An external root-owned automation process must establish
the pipes and coordinate the independently operated input authorities within
the original deadlines. This CLI does not supply that authority automation.
The same-process assembly does not yet provide an external independent
authority coordinator.

The separate [authority commands and protected installers](native-pilot-authority-commands.md)
provide cohort precreation/release, driver admission/scope, native/bridge C9 and
ordinary-service grant production, plus fixed precreation-file installation.
They require independently approved complete originals and keys, not raw
unapproved requests from this channel. Remaining native service-grant/launch
inputs, bridge runtime installation and the coordinator's actual process/pipe
and authority-automation joins remain open.

The separate [runtime package](native-pilot-build.md#conductor-runtime-package)
provides an isolated Python entrypoint and portable filesystem bytes. Building
or extracting that package does not install its privileged execution environment,
provision the independent authorities or authorize this live command.

The conductor retains the actual driver, endpoint, ordinary-service and
resource owners in one process. Operator replies supply independently produced
public originals or pins; they cannot reconstruct those owners from JSON or
turn an observation into permission. No authority private key, signing action,
new network broker or descriptor passing over this operator channel is part
of the contract.

## Closed pipe protocol

Each frame is canonical ASCII JSON followed by exactly one LF (NDJSON).
Requests have exactly these fields:

```json
{"apiVersion":"serverware.nativePilotOperatorRequest/v1","deadlineBoottimeNs":"<original decimal deadline>","payload":{},"phase":"<fixed phase>","sequence":1}
```

Replies have exactly these fields:

```json
{"apiVersion":"serverware.nativePilotOperatorReply/v1","inputs":{},"phase":"<same fixed phase>","requestSha256":"sha256:<64 lowercase hex digits>","sequence":1}
```

These are shape examples, not usable requests or authority originals. Replies
must match the actual request's sequence and phase. `requestSha256` hashes the
entire exact canonical request **excluding its terminating LF**. `payload` and
`inputs` are objects with the fixed phase-specific fields selected by the
conductor; they are not arbitrary extension bags. The channel bounds each
frame to 32 MiB and aggregate traffic to 128 MiB. A pipe reply or matching hash
is transport binding, not a signature, service result or readiness proof.

The exact stage order is:

| Stage | Exact reply `inputs` | Boundary |
| --- | --- | --- |
| `bootstrap-admission` | `{"bootstrapAdmission": Pin}` | Independent approval binds the already measured live driver; no predicted process identity. |
| `endpoint-precreation` | `{}` | Sent after independent protected precreation files have been installed. Existing owners still authenticate those originals. |
| `endpoint-inputs` | The seven-field object below | Public endpoint inputs bind actual retained resources. |
| `service-originals` | The ten-field object below | Independently approved originals; no private signing key enters the conductor. |
| `bridge-runtime` | `{}` | Sent after independent protected runtime files have been installed; not a bypass of their existing owner checks. |
| `bridge-delivery` | `{"launch": Pin}` | Fixed bridge delivery inputs bind its real retained descriptors. |
| `release` | `{"endpointRelease": Pin, "phaseTwoScope": Pin, "phaseTwoPublic": Pin}` | Drives the existing one-attempt retained-owner release; sending is not an acceptance or readiness receipt. |
| `constructed-admission` | `{"constructedAdmission": Pin}` | Independent admission binds genuine exported constructed-driver originals, not a supplied success claim. |
| `generation-origin` | `{"action":"observe-installed-generation"}` | Invokes the existing genuine origin producer/consumer. Its handoff remains non-ready and does not prove a request succeeded. |
| `shutdown` | `{"action":"stop"}` | Real owners remain retained while the external operation runs within the remaining bounded lifetime, then perform their actual cleanup. |

`Pin` means the exact two-field protected public-file pin described below, not
a literal JSON string named `Pin`. All objects and role maps are closed: every
listed field/key is required, with no additional fields, defaults or arbitrary
role selection. The following role-map names are notation for this guide only;
they are not extra fields in the wire protocol. Every value in these maps is a
`Pin`:

| Map | Exact keys |
| --- | --- |
| `Ordinary5` | `durable-recovery-store`, `cleanup-authorization-consumer`, `recovery-target-provider`, `current-signature-authority`, `bounded-cleanup-helper` |
| `Dispatch2` | `durable-recovery-store`, `current-signature-authority` |
| `Spool3` | `durable-recovery-store`, `cleanup-authorization-consumer`, `current-signature-authority` |
| `NativeSpool7` | `ingress`, `ledger`, `retrieval`, `terminal`, `dispatchBarrier`, `activeEffectBarrier`, `activeEffectCommit` |
| `Endpoint3` | `retrieval`, `persistence`, `trustedTime` |
| `Endpoint10` | `retrieval`, `persistence`, `trustedTime`, `generationInstall`, `commitRequest`, `ingressAdmission`, `terminalAppend`, `dispatchBarrier`, `activeEffectBarrier`, `activeEffectCommit` |

The exact `endpoint-inputs` reply object is:

```text
{
  "coldOriginals": Endpoint3,
  "peer": Pin,
  "proofScope": Pin,
  "retrievalManifest": Pin,
  "objectDirectory": <absolute protected directory path string>,
  "assignment": Pin,
  "production": <the exact nine-field object below>
}
```

`objectDirectory` is not a public-file pin: the actual endpoint owner acquires
and checks the existing root-owned `0555` Retrieval object directory and its
independently populated fs-verity objects. The reply neither creates that
directory nor substitutes a manifest observation for its actual descriptors.

`production` is the existing object consumed by the driver's generation recipe
and operational-input owner. Its five digest fields are `signerBackendSha256`,
`persistenceBackendSha256`, `retrievalBackendSha256`,
`dispatcherProtocolSetSha256` and `expectedConfigurationBindingSha256`.
Its four integer fields are `maximumRpcNanos` (250,000,000–1,000,000,000),
`cleanupReserveNanos` (1–5,000,000,000), `maximumInFlightCalls` (1–64), and
`maximumAsyncDurabilityNanos` (positive and no greater than `maximumRpcNanos`).
These values must come from the existing independently selected configuration;
the conductor does not choose or approve defaults.

The exact `service-originals` reply object is:

```text
{
  "ordinaryDeliveries": Ordinary5,
  "ordinaryGrants": Ordinary5,
  "dispatchGrants": Dispatch2,
  "dispatchNativeGrant": Pin,
  "spoolGrants": Spool3,
  "nativeSpoolGrants": NativeSpool7,
  "endpointDeliveries": Endpoint3,
  "endpointLaunches": Endpoint10,
  "persistence": {"configuration": Pin, "genesis": Pin, "journal": Pin},
  "generationJournal": {"genesis": Pin, "records": [Pin, ...]}
}
```

`generationJournal.records` is a JSON array of zero through eight supplied
record pins in original sequence order, not a reconstructed history. Actual
receivers enforce their individual byte bounds and exact admitted journal/head
bindings. The service helper admits all five ordinary deliveries then grants,
the three actual endpoint deliveries, both dispatch grants, and spool grants
in Head → Cleanup → Current order before assembling the ten real transfers.
The `dispatchNativeGrant` is the CommitRequest companion original, not the
outer LedgerSpool grant selected by `nativeSpoolGrants.ledger`. The mandatory
later release join checks their actual pinned relationship and all seven
native transfer originals; this earlier phase does not replace that check.

The exact `deadlineBoottimeNs` is supplied by the retained owners, not chosen by
the operator reply. The original startup deadline applies through constructed
admission. The final two stages use the original lifetime with the required
cleanup reserve. Waiting, replying, reinstalling a file or preparing a new
signature never renews those limits. There is no automatic retry, claim reset,
or inference of noncommit from missing output. A final origin-handoff payload
and an explicit shutdown are not evidence of external test success.

After the shutdown exchange there are no further operator protocol messages;
only the fixed result on stderr is emitted. No test pass is inferred from
shutdown, cleanup, an origin handoff or that result. If cleanup is unknown,
the actual process and retained owners remain held rather than being silently
retired. There is no retry or renewed deadline. The external supervisor must
investigate the real retained state before any forced retirement; this is not
an invitation to restart the conductor or regenerate input authority.

## Protected public originals

`serverware.native_pilot_public_inputs.PublicInputs` reads reply-selected pins
only beneath `/etc/serverware/native-pilot-inputs/`. Each pin is exactly
`{"path":"/etc/serverware/native-pilot-inputs/<public-original>","sha256":"sha256:<digest>"}`.
The independent provisioner must create these public fixtures before the
corresponding phase needs them. The reader creates or installs nothing.

Files must be root:root regular files, mode `0400`, with one link. Every actual
ancestor is retained and checked as root:root without group/other write
permission; traversal is no-follow. The reader retains original bytes and
descriptor/name identities, enforces the caller's purpose-specific size bound
on every use, and refuses the same path with a different digest. Its aggregate
limit is 128 distinct paths and 32 MiB of public bytes. A smaller later bound
cannot be weakened by an earlier larger read. `document()` additionally checks
the existing canonical public JSON grammar; it does not verify authority.

Only public fixtures belong in this directory. Do not place private keys,
credentials or other secrets there or send them through the operator channel.
Literal signed originals must preserve the independently supplied bytes;
neither this reader nor the pipe can manufacture, repair or re-sign them.
The actual purpose-specific receivers still verify signatures, scopes,
currentness, resource identities and original lifetimes.

Fixed cold control files, protected launch files and their nested originals
remain at the paths selected by their existing owners. They are installed
independently at the required phase boundaries, not redirected through an
arbitrary path option in this reader. Retrieval object-directory ownership is
also a separate actual descriptor owner, not a public-file pin.

The conductor must keep `PublicInputs` and all dependent live owners on an
unknown cleanup outcome. Only genuine completion of the required cleanup
permits closing retained inputs. A clean pipe exchange alone establishes no
hardware admission, deployment acceptance, ordinary HTTPS success or release
readiness; those require their real independent producers and retained results.
