# Fixed endpoint-precreation composition

`native_pilot_supervisor_precreation.compose(policy, *, process, request)` returns
the complete existing input for exactly `cohort-precreation` or
`install-precreation`. It requires the actual admitted `SupervisorPolicy`, live
`AuthorityCoordinatorProcess`, and that process's opaque pending `JobRequest`.
It does not accept a replacement observation dictionary, sign, install or issue
an approval. The independent supervisor spine retains approval/publication duty.

The policy's mandatory `precreation` fragment has exactly eight fields:

| Field | Independently selected input |
| --- | --- |
| `apiVersion` | `catchplate.nativePilotSupervisorPrecreationPolicy/v1` |
| `authority` | Existing C9 authority; same authority as the retained bridge cold configuration |
| `endpointExecutableSha256` | Exact endpoint worker executable pin |
| `cohortExecutableSha256` | Exact cohort parent executable pin |
| `cleanup` | Existing cleanup authority, scope, actual provisioned journal identity and genesis pin |
| `nativeColdOriginals` | Exact ten endpoint-role map of complete canonical C9 cold originals |
| `ordinaryColdOriginals` | Exact five ordinary-service map of complete canonical cold originals |
| `ordinaryExecutableSha256` | Exact five ordinary-service map of executable pins |

`validate_policy(fragment, *, bootstrap_configuration)` checks the closed fragment
without file/process creation. It does not fabricate a cleanup journal, genesis,
history, policy grant or private key. Those prerequisites must exist and have
been independently admitted. The same policy explicitly delegates copying the
original driver's boot/time namespace, invocation and unextended window into
both cohort precreation and ordinary launch; no clock-derived defaults exist.

Before composition, the actual earlier bootstrap input retained by the policy
must match the input digest in the process's previously sent installer reply.
The prior actual bootstrap result is hash- and signature-verified against that
exact input, original configured admission authority and repeated conductor
observation. The gate notice must reference those same configuration/window/
observation bytes, the admitted gate executable/UID/GID, and the exact lifecycle
prepared-transcript hash derived from signed bootstrap parent fields. This is a
data association check, not a fabricated gate observation or new PIDFD owner.

The v7 cohort configuration derives only source-fixed cold-file pins and hashes
of the admitted driver configuration/window and actual observation. It keeps the
external driver distinct from ten owned endpoints. It does not contain a gate
identity field, and the gate notice supplies no new independent trust decision.
Later bridge runtime and trust/assignment decisions remain separate phases.

For the second job, the exact reconstructed precreation input must match the
previously sent approved input digest. Its real returned precreation signature
is reverified before constructing the existing installation bundle. The actual
installer's read-only preparation checks run over that bundle; publication is
still its own fixed cold-files-first, cohort-control-last operation.

Both jobs keep the original startup deadline, require the original bootstrap
signature still fresh, and consume an in-process attempt before composition.
Failure grants no retry, renewal, deletion or inferred successful installation.
This closes these two composition joins only, not the remaining fixed jobs,
independent provisioning, service execution or connected pilot acceptance.
