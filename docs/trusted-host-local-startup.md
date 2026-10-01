# Local authority startup

This is the non-TEE startup path for the synthetic development pilot. It uses
the actual authority services and PostgreSQL policy authority; it is not a
second demo authority. Host root remains trusted. Co-location does not establish
hardware-backed keys, native stage-zero execution or an independent witness.

Frozen source `a51562e0` passes 33 focused controls in 0.411 seconds, the fixed
CLI help check, 12 changed-file syntax checks and four test-inventory checks.
That is source/contract/descriptor/filesystem verification, not a successful
signed-package launch. No installed authority role or working pilot is claimed.

## What the implementation connects

The existing systemd listener and protected static credentials are retained.
The fixed parent starts the actual authority entrypoint, which enters the
isolated Python launcher in the same child PID. Before loading the final launch
manifest, the launcher reports its actual process, interpreter, argument and
descriptor observations through an authenticated local channel. The producer
can then supply signed originals bound to that process, rather than predicting
the next PID or placing a future launch certificate in startup credentials.

Only after the existing package, manifest, certificate and role checks succeed
does the child report admission and enter the existing role service. Admission
is not a health check or an accepted application flow. The original startup
deadline is not renewed while waiting for signed inputs.

Local bootstrap evidence explicitly binds the Python interpreter and retained
bootstrap source and declares `pathname-execve`. Its request, certificate and
signature domains are separate from the native static-ELF/`execveat` profile.
The latter's admission requirements are unchanged.

The local signed role selects one closed argument grammar; it cannot predict a
future invocation's setup digest. The late signed request binds the actual
literal argv and descriptors at the explicit post-local-admission boundary.
Temporary transport copies close before that boundary; setup and control
ownership remain through the post-guard acknowledgment and then close. Parent
supervision continues without extending the original admission window.

## Operator interface

The fixed [parent CLI](../scripts/authority/local_startup.py) takes protected
originals and public descriptor numbers, not private keys in arguments:

```text
python -I -B scripts/authority/local_startup.py \
  --plan-fd PLAN_FD --plan-sha256 sha256:PLAN_SHA256 --listener-fd 3
```

The closed plan names the role, original clock bounds, protected credential and
exchange directories, retained installed files/directories, existing mutable
witness state where required, and the selected generation/artifact/operation
digests. It is not an arbitrary command runner. Use the exact schema defined by
[the parent implementation](../serverware/authority_local_startup.py).

The root-only exchange contains the actual `observation.json`. Its independently
authorized producer supplies only the fixed `manifest.json`, `certificate.json`
and, for the five policy authority roles, `evidence.json`. Runtime and witness
roles have no evidence slot. Publish complete protected originals; partially
written files are not a retry protocol. No signer or installer is supplied by
this transport, and it must not manufacture missing authorization receipts.

The parent reserves descriptor 256 for the manifest, 257 for the launch
certificate and 258 for role evidence where required. These reservations are
zero-byte sealed objects, never placeholder authority documents. Static
credentials remain distinct protected descriptors. The launcher replaces only
its exact retained reservations with received originals and runs the existing
signature and custody checks. Ambient DSNs, arbitrary environment values and
raw credential bytes do not go into the observation.

The parent retains the real child identity and supervises it. Cancellation must
terminate and reap that child; failed or incomplete startup is not permission
to adopt a different PID, retry with a fresh deadline or regenerate authority.

## Still required before the pilot can run

1. Build and genuinely install the signed local authority package, including
   its complete closure and real immutable-installation evidence. The new
   [local signing/installation commands](trusted-host-local-installation.md)
   connect these effects; they have not performed a complete signed install.
   Genuine upstream evidence and a capable dedicated filesystem remain missing.
2. Provision actual scoped keys, database authentication, TLS and trust pins,
   then run the existing offline metadata bootstrap and local authority roles.
3. Invoke genuine policy-genesis preparation, obtain actual audit inclusion and
   finalize through the new foreground commissioning caller. Its independent
   audit/evidence and enrolled-WebAuthn inputs remain required. The offline development installer
   only materializes an already finalized policy; it cannot create that state.
4. Start the control plane, seed once, verify the CA, start the frozen Rust gate
   and prove credential replacement, denial and redaction.

Follow [pilot commissioning](pilot-commissioning.md) for that ordered workflow.
Source/descriptor tests do not establish an installed authority package,
successful genesis or a usable pilot. Production acceptance remains separate.
