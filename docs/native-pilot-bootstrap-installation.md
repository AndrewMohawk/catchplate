# Native pilot bootstrap installation

`scripts/install_native_pilot_bootstrap.py` connects an independently approved
driver configuration and signed startup window to the three fixed public files
read before `ConductorProcess.prepare` and `DriverBootstrap.start`. It does not
sign a window, install an executable, create directories, provision keys or
credentials, start a process, or supply the missing automated decision supervisor.

## Approved input and command

Use the separately protected supervisor/installer Python environment, not the
conductor's runtime entrypoint. Run as root on the admitted pilot host and time
namespace with isolated/no-bytecode Python:

```text
python3 -I -B scripts/install_native_pilot_bootstrap.py --input-fd 3 --input-sha256 sha256:INDEPENDENTLY_APPROVED_COMPLETE_INPUT_DIGEST
```

The placeholder is deliberately invalid. FD 3 must already contain the complete
independently approved canonical ASCII JSON, without LF: either a root:root
`0400` read-only single-link regular file or a root:root `0400` sealed memfd.
The supplied full-input SHA must be independently authenticated; a locally
computed hash or protected FD does not itself approve anything. The input is
bounded to 256 KiB and has exactly these four fields:

```text
apiVersion = catchplate.nativePilotBootstrapInstallationInput/v1
configurationOriginal
windowOriginal
controlOriginal
```

The three originals are literal canonical ASCII JSON strings, copied unchanged.
They are respectively the existing driver bootstrap configuration/v4 with
lifecycle/v3 (at most 65,536 bytes), signed bootstrap window/v1 (32,768 bytes),
and bootstrap control/v1 (4,096 bytes). No optional versions, inferred fields,
replacement deadline or caller-supplied destination is accepted. The separate
window authority produces the existing signature; this installer only verifies it.

## Existing protected prerequisites

The configuration's pinned C9 production-bridge cold file must already be
installed as a protected root:root `0400` single-link regular original. The
installer retains its exact FD and named ancestors, verifies its pin and the
configured driver UID/GID, and rechecks it throughout publication.

The fixed supervisor must already exist at
`/opt/catchplate/catchplate-native-shadow-guest-supervisor`, root:root `0555`,
single-link and at most 64 MiB. Its actual retained bytes must match the supplied
control pin and the existing driver's static Linux/amd64 ELF rules: supported
ELF type, bounded program table, and neither PT_DYNAMIC nor PT_INTERP. This is
not independent binary admission, execution or a hardware measurement. The
actual executable FD, path and protected ancestors remain checked throughout.

All destination parents must already exist under root ownership without
group/other write permission. The shared public publisher also requires the
pre-provisioned `/etc/catchplate/native-pilot-inputs/` directory; this installer
does not create it or write any files beneath it.

## Exclusive publication and result

Before any write, the installer verifies the complete input, all closed profiles,
the configured bootstrap public key's signature over the original window, exact
configuration/window hashes in the control, actual local boot/time namespace,
original issued/startup/lifetime bounds, and the original cleanup reserve.
The startup interval remains at most 30 seconds from its original issuance.

All three destinations must be absent. Publication uses the existing retained
public-file owner, with exclusive creation, root:root `0400` single-link files,
fsync and exact readback, in this fixed order:

1. `/etc/catchplate/native-shadow-driver-bootstrap.json`
2. `/etc/catchplate/native-shadow-driver-bootstrap-window.json`
3. `/etc/catchplate/native-shadow-driver-bootstrap-control.json`

Control is last, not an atomic transaction or launch trigger. An error, expired
deadline, partial write or incomplete output leaves all created files for
explicit reconciliation. There is no overwrite, existing-file adoption, rollback
or automatic retry. An independent supervisor must bound filesystem stalls.

Successful stdout is canonical `catchplate.nativePilotBootstrapInstallation/v1`
JSON without LF on a root-owned supervisor pipe. It records `bundleSha256`,
`configurationSha256`, `windowSha256`, `supervisorExecutableSha256`,
`invocationId`, the original startup/lifetime deadlines, and `pins` for the three
`driver-bootstrap-*` purposes. These are publication observations, not live-owner
or readiness claims. Output is clipped to the unchanged startup deadline.

Only a separately authorized caller may subsequently use the real coordinator
and driver owners; they reread and authenticate the fixed originals themselves.
The full automated independent supervisor and its decision authorization remain
separate missing work. No signing, installation invocation, launch, build or
runtime acceptance was performed while this source was authored.
