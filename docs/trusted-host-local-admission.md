# Trusted-host-local late admission

This connects existing local startup to real manifest/certificate issuance and
RuntimeTrust signing. It does not establish a launched authority, working pilot,
independent administration, native stage zero, hardware custody or production
acceptance. Test and deployment results are recorded separately.

## Signing principals and original inputs

The independently selected approval explicitly delegates the provisioned
configuration root to the existing local launch-manifest signing domain:
`configuration-root-also-signs-local-launch-manifest-v7`. The issuer verifies
that both the child's actual launch-root credential and its corresponding
configuration/runtime/witness-root credential contain that public key. This is
deliberate local co-location, not a new artifact-key purpose or an implicit grant
based on key type. The cohort consumer already uses the configuration root.

Launch certificates use the separate artifact key authorized for
`launch-certificate-issuer`, normally `local-launch-certificate-issuer-v1`.
The root, certificate issuer and actual child launch key must be distinct.
Private keys arrive only through protected, sealed raw32 descriptors; never put
them in arguments, logs or chat. Native and production profiles are unchanged.

## Actual admission sequence

1. Complete genuine package installation and protected role credentials first.
   Supply the existing [local startup parent](../scripts/authority/local_startup.py)
   with its exact protected plan and real systemd listener. It parks the real
   same-PID child and publishes `observation.json` in the pinned root0700 exchange.
2. Independently select the complete unsigned launch payload and its original
   approval bounds using that observation and authenticated package, current
   trust, verification and installation originals. The
   [launch issuer](../scripts/authority/local_launch_authorization.py) takes only
   `--approval-fd`, `--approval-sha256`, `--exchange-directory-fd`, `--root-key-fd`
   and `--certificate-key-fd`; see its `--help` for the closed interface.
3. The issuer retains the actual process PIDFD and measures its real descriptors,
   launch key, argv/environment, executable mappings and vDSO. It checks installed
   inode generations, hashes and fs-verity, actual root credentials, listener and
   parent-control peer. Approved assertions alone cannot supply these observations.
   It atomically publishes root0400 `certificate.json` first and `manifest.json`
   last, without replacing an existing file. The existing parent seals those
   literal originals; the child independently validates them before admission.
4. The five service roles—verifier, planner, planner-writer, issuer and executor—
   additionally require genuine `evidence.json`: the existing signed five-role
   attestation cohort. **Its connected producer remains missing.** It must bind
   all five actual observed launches and their signed manifests to the selected
   configuration; a launch certificate or caller-provided success JSON is not a
   substitute. Runtime and replay-witness launches have no cohort evidence slot.
5. The [RuntimeTrust issuer](../scripts/authority/local_runtime_trust.py) signs the
   existing `signedPolicyAuthorityRuntimeTrust/v1` only from an independently
   approved payload, authentic signed Service6 configuration and supplied signed
   verifier local-attestation original. It does not generate that attestation.
   Its configuration-root signature uses the existing RuntimeTrust domain.
   Complete pipe output **and exit0** are required before retaining the original.
6. Install that original into the app/relay's exact protected inherited FD roster.
   The runtime relay's startup credentials need it before that role is parked.
   RuntimeTrust FD numbers are prospective admission policy, not observations of
   this signing process. Existing app/relay consumers still verify actual handles,
   UID/GID, current evidence and authenticated same-kernel Unix peers.

All approval/startup BOOTTIME and UNIX limits are original, at most 300 seconds;
waiting or signing does not renew them. Original generation, certificate and
evidence intervals remain separately enforced. Partial publication is retained,
not rolled back, overwritten, adopted or automatically retried. Pair publication
is neither service readiness nor successful policy commissioning.

## Kernel, paths and intended topology

The observer needs actual `pidfd_getfd`/ptrace access to the parked process,
readable `map_files` and process memory, and the same PID, mount, user and time
namespaces. Boot with `vsyscall=none ima_appraise=off`; the issuer measures the
actual command line and vDSO. Kernel release/command pins hash literal proc-file
bytes. These observations make no IMA/TEE/native-execution assurance claim.

Runtime aliases are local-only: the signed package's native/bootstrap/interpreter
references, or exact signed Python module/kind/package/hash joins, resolve to
installed artifact paths. Every physical installation field remains checked.
There is no arbitrary `/runtime` rebasing; data/role files remain under the
generation root. Native profiles retain lexical generation containment.

The preferred pilot assembly is one guest with the control-plane app, seven
authority roles (runtime relay, five services, replay witness), the retained
measured Rust gate and shared app/gate data. This preserves the required actual
same-kernel Unix peer identities; a host container cannot impersonate a guest
peer. Connectivity to the scoped existing PostgreSQL/audit services and synthetic
upstream must be separately configured and tested. This document claims no
installed networking, listener reachability or accepted request. Continue with
[installation](trusted-host-local-installation.md) and
[policy commissioning](pilot-commissioning.md) only from actual completed effects.
