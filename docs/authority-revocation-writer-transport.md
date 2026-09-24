# Detached writer transfer

Source `.68` adds `serverware.policyAuthorityRevocationWriterTransfer/v1`: a
fixed binary transfer for the private planner-to-writer path. The writer-only
server branch passes five original byte strings to the existing measured
[writer composition](authority-revocation-writer-composition.md) and sends the
exact stored [ACK](authority-revocation-writer-acknowledgment.md) after normal
owner exits. This is unbuilt, unexecuted source, not a demonstrated socket,
launch, database, delivery or production-admission result.

## Fixed wire and bounds

The request begins with eight bytes `SWRW 00 00 00 01`, then five unsigned
big-endian 64-bit lengths, then the five raw bodies in this exact order:

| Body | Local byte ceiling |
| --- | ---: |
| Original verifier intent | 4 MiB |
| Original planner relay | 4 MiB |
| Original plan envelope | 64 MiB |
| Original evaluation context | 512 KiB |
| Original historical expectations | 64 MiB |

Every body is at least two bytes. All five lengths and their sum are checked
before body allocation; the sum may not exceed 64 MiB. This is an explicit
whole-transfer ceiling, not five independent opportunities to consume a full
allowance. It does not reduce the pure components' local bounds: a successful
existing receiver already spends at least each original's size on its one
64 MiB cumulative work allowance. Repeated decoding, copying, hashing and
proof work mean local maxima are not promises of successful composition.

There is no JSON wrapper, base64 expansion, body reference, caller path,
descriptor transfer, chunk-resume token or arbitrary part list. The client
validates all original byte objects and bounds before opening a socket. It
half-closes its write direction after sending the fixed request. The server
requires EOF after the fifth body, before invoking composition; trailing bytes
are a denial, not another request on the same connection.

The reply is eight bytes `SWRA 00 00 00 01`, one unsigned big-endian 64-bit
length, and the exact stored ACK bytes, bounded to 2 through 16,384 bytes. The
client requires EOF after that body before returning it. Neither side silently
retransmits. Framing returns opaque original bytes, not a success or admission
object; this batch adds no configured planner-side ACK authenticator and no
response-key candidate or enrollment field.

## Existing peers and a single deadline

```text
planner opens the existing writer socket and checks writer UID/GID
  -> fixed request + write-half-close
  -> writer checks planner UID/GID, lengths, bodies and EOF
  -> existing measured composition, two replays, request and ACK custody
  -> normal transaction and connection exits
  -> exact stored ACK + connection close
  -> client checks reply framing and EOF; returns untrusted ACK bytes
```

The same Unix stream carries the reply. There is no writer-to-planner callback
connection, new socket, broader peer rule or additional database credential.
The activated listener remains bound to the measured descriptor, inode,
owner/group and mode. Only the planner-writer process admits the new request
magic; another service role denies it. The public canonical handler and its legacy purposes are not
repurposed to accept parsed detached controls.

One absolute monotonic deadline covers each side's exchange. The client starts
it before connect; the server starts it immediately after accept, before a
worker-queue wait. The configured duration retains the actual service's
0.05-through-30-second range. Each blocking I/O receives only the remaining
time, with checks around actual progress and final EOF; one-byte progress
cannot renew the deadline. The server checks the same deadline before work and
before releasing the ACK. The source does not claim to preempt a synchronous
database or cryptographic operation at that deadline.

For this protocol, any failure closes the connection without a speculative
response. Legacy canonical requests retain their separate response/error
format within the remaining connection deadline. The older raw invocation
helpers remain whole-frame 4 MiB operations; the legacy mapping helpers retain
their 64 MiB frame ceiling. Neither existing limit is widened by this dedicated
transfer format.

## Authentication, custody and uncertainty

After the complete request and EOF, the writer creates one source-capped
top-level work object. The existing private process method captures measured
configuration, binds the dedicated response signer, authenticates both original
controls, joins historical policy, and invokes genuine retained-plan and
reservation replay with the actual database/registry gates. The same work pays
for those phases and request/ACK custody; framing is not a replacement proof
allowance or signature verdict.

The response comes only from the third value returned by that configured
composition, after normal common-savepoint, outer-transaction and database
connection exit. A deadline, socket error or disconnect after commit can leave
all seven custody sets stored without delivery. It cannot undo commit, prove
rollback or authorize the client to regenerate or automatically retry an ACK.
Even complete framing and EOF do not authenticate the ACK at the client.

The source revision and measured file closure must be regenerated and
reprovisioned together. This wire contract adds no configuration field,
credential descriptor, database schema/DDL structure, privilege, peer or work
limit. Existing native-suite identities and resource allowances remain fixed.

## Remaining work

The configured planner/verifier intent and relay producers still need their
full serving composition. Source `.69` adds a separate
[configured planner client](authority-revocation-writer-client.md) using
independently derived request bindings and the measured writer response key;
the raw transport still authenticates nothing and carries no key candidate.
Historical key resolution and
authenticated recovery after uncertain delivery remain separate contracts.
Current-action freshness and both replays cannot be bypassed to retrieve old
evidence. Public end-to-end execution, current-root/witness authority and the
unfinished WebAuthn kernels remain blocked; this server branch does not make
the transition registry importable or activate an incomplete operation.

The 27 newly authored controls comprise 18 socket-recording methods, six source
linkage methods and three gated component-chain methods. The socket recorders
model bounded bytes, peer observations, clocks and failures, not measured
service admission; the component chain constructs no admitted service process.
All 27 remain unexecuted under [goal.md](../goal.md).
