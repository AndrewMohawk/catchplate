# External verifier transport entrypoint

`serverware-native-shadow-verifier-transport` is the explicitly selected,
one-shot external supervisor for the existing [public exchange](native-shadow-verifier-transport.md).
It is separate from the unchanged `serverware-native-shadow-verifier` FD4/FD5/FD1
interface. Neither a discovered FD6 nor incoming bytes select this mode.
The only public Rust entry is process-exiting `run_transport() -> !`; it accepts
no arguments, arbitrary descriptor, policy path, command or retry operation.

The source takes the genuine sealed seed at FD4 and connected TCP owner at FD6
before opening launch/policy originals; FD5 must be absent. Seed acquisition
does not open another descriptor or read the secret. The existing exchange
owner moves its actual connection above the child slots and pins its full
kernel identity against the separately protected transport configuration.
The process opens the real `RuntimeAdmission`, arms the same original absolute
BOOTTIME watchdog, and then receives the one framed evidence original.
Receive cannot supply a fresh deadline, key, configuration or authority.

The returned sealed evidence owner is consumed with the held seed into
`Inputs::from_transport`, then bound to the actual admission's final UID/GID.
Numeric FD5 can already contain an admission original and is never overwritten
or reused as evidence. Only the confined child's existing descriptor map places
that retained evidence at child FD5, alongside its original config3 and seed4.

Both public entrypoints use the same private execution operation. It returns
original result bytes only after bounded pipe EOF, actual child terminal
readiness, retained input/image/configuration/process checks, exact PIDFD reap,
successful root/mount retirement and `CLD_EXITED` with status zero. Every earlier
failure retains the existing same-child stop/retirement path and publishes no
result frame. Cleanup cannot renew the original interval; exit or timeout is
not proof that cleanup succeeded.

After those checks, the transport entry rechecks its input and exchange owners
and consumes the existing `Exchange::publish` once. It emits the original result
frame and closes without retry, a second connection, output-pipe fallback or
error details. Partial publication is possible on failure and is not success.
The guest must require the exact complete response and EOF and independently
verify its signature, quote association and current trust; transport framing
is never a verification verdict. This public channel provides no confidentiality
or availability guarantee, and does not carry the verifier seed.

`data-plane/decision-gate-rs/Dockerfile.production` adds a separate
`native-shadow-verifier-transport-artifact` target. It selects the fixed binary
in the existing static launcher build, with no interpreter or dynamic dependency
and the existing 64 MiB executable ceiling, then exports it as root:root 0555.
It does not install an external verifier into the claimant guest image, create
independent keys/configuration, open a listener, provision a seed or promote a
normal service into verifier authority.

The earlier exchange slice's external entry/Inputs/terminal-publication/packaging
gaps are connected by this source. Genuine guest startup selection, independent
socket/seed/configuration provisioning and the remaining custody endpoints and
lifetime settlement are separate work. No build, parser, test, kernel/network
execution, live attestation, provider request or cloud action was performed.
Actual launch, framing/EOF failures, deadline expiry, descriptor ownership,
terminal/reap/mount failures and end-to-end Nitro acceptance remain unverified.
