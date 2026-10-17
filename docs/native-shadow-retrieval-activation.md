# Prepare a real retrieval activation

`catchplate.native_shadow_retrieval_activation.RetrievalActivation` supplies the
actual listener/object-directory originals missing from the server launch path.
It is an operator/launcher API, not an HTTP endpoint or a running service.
No preparation, signing, socket operation or launch has been executed for this
source checkpoint.

## Same-process preparation

The independent operator supplies the pinned C9 guest configuration, pinned
expected-peer original, an already-open root:root0555 immutable-object directory,
and one explicit startup deadline. Prepare the fixed
`/run/catchplate-shadow-retrieval` directory as root:root0711 beforehand; all
ancestors must be protected. The API creates neither directories nor keys.

The owner checks its actual process/start/boot/time namespace and retains the
object-directory descriptor and protected path ancestors. It exclusively binds
one fresh AF_UNIX SOCK_SEQPACKET socket at
`/run/catchplate-shadow-retrieval/listener.sock`, with mandatory credential and
PIDFD support. The pathname becomes final guest UID / expected peer primary GID,
mode0660. It stays **bound but not listening**: the actual guest must call
`listen` after its permanent identity drop and real admission.

`activation()` returns the actual measured C9 entries for target FD6
`retrieval-listener` and FD7 `retrieval-objects`. These are data projections;
passing an independently invented list cannot construct the retained owner.
The socket descriptor's kernel stat identity and filesystem socket pathname
identity are different objects and are checked separately.

## Original approval and handoff

Have the independent delivery operator approve the complete existing C9 payload
with those exact activation entries, original boot, runtime/credential pins,
invocation and deadlines. `sign_delivery(payload_raw=..., signing_key=...)`
accepts only that approved original and an already provisioned delivery key.
It uses unchanged `policyCustodyGuestDelivery/v1` framing and rechecks the actual
retained activation before and after signing. The C9 delivery key is not the
separate retrieval operational-grant key. Existing response-v2 guest delivery
is also a different contract and remains unchanged.

`take_for_launch(signed_delivery_sha256=...)` is a one-shot transfer of duplicate
owned descriptors as `(target_slot, actual_fd)` pairs. The separately supervised
launcher must install those originals at6/7 and supply its genuine FD3 parent
lifetime channel and explicit retrieval launch. Returned descriptors stay
close-on-exec until that launcher installs them. No launch, listening socket,
child PID, native admission or readiness result is fabricated by this API.

Use the owner as a context manager and retain it through handoff. Preparation,
signing and transfer stay within the same original startup bound (at most30s
when preparation starts). Failed or uncertain signing/transfer cannot be
repeated on the owner. Closing releases descriptors but deliberately leaves the
socket path, including after failure; cleanup requires explicit reconciliation.
There is no unlink, replacement, automatic retry or deadline renewal.

This API needs an external watchdog; checks around synchronous kernel calls do
not claim hard cancellation. Native consumers still verify actual C9 and
operational originals, peer measurements, closure/key/trust and lifetime.
The client cohort must separately admit its own socket and retained peer
directory; this server owner grants no ambient descriptor access. Complete
outer launch orchestration, client/factory integration and remaining proof and
receipt services remain required. See [retrieval provisioning](native-shadow-retrieval-provisioning.md).
