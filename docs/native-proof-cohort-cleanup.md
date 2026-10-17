# Parent-owned proof-cohort cleanup

This explicit source-selected successor terminates and observes the actual five-child proof cohort. It does not manufacture the existing per-operation five-service terminal settlement. The latter requires independent operation, result, persistence, cleanup and current-signature effects; killing this cohort cannot fill those fields. The coordinator's old `RequestTermination`/`Settle` route remains refused until that separate producer exists.

The original routing constraint is concrete: the bridge and generation coordinator are themselves children of this cohort. Once all five children have been reaped, neither can return or sign the terminal response. The existing privileged clone parent therefore supplies the lifecycle observation on its already retained root-control channel. Its independent public cleanup authority is a distinct purpose and key, not a native role-key alias or TEE attestation.

## Selected authority and actual call path

`catchplate.nativeShadowProofCohortConfiguration/v2` is closed9: the original eight fields plus required `cleanup`. Old configuration/v1 continues to forbid the extra field and any post-release control message. The original precreation and release signatures already bind the complete configuration SHA; their signatures, five roles, original boot/time namespace, startup and lifetime do not change. The old single-guest, retrieval-pair and ordinary five-service profiles do not select this feature.

`cleanup` is closed4: a separately provisioned public `authority`, `scopeId`, exact root directory `journal` identity5, and `genesisSha256`. Cleanup public material must differ from the C9 delivery key. Deployment must independently assign this dedicated lifecycle key; no key is created or supplied to the Rust parent. It verifies only the public key. The authority approves complete fixed-cohort shutdown, not arbitrary processes or operation results.

The actual retained caller is `native_shadow_proof_cohort_control.ParkedProofCohort`, not an object constructed from PIDs or observations. After its existing one-shot `release`, `request_termination(authorization_original=...)` verifies the actual retained configuration/precreation/observation/release, independently signed cleanup permission and all current child handles. It makes exactly one seqpacket send. Failure or a lost response never resends the command or renews its deadline. The returned Python value is not an acknowledgement.

`native_shadow_proof_cohort_cleanup.authorize` is the closed offline signing producer using an already provisioned independent cleanup key. It validates original C9 precreation/release signatures and full scope; its data parameters alone do not authenticate live kernel ownership. Both retained runtime owners separately perform that association. It performs no network, process, filesystem mutation or key creation.

The authorization is envelope2 `{payload,signatureBase64url}`. Payload11 binds the configuration, precreation, original actual five-child observation, exact release, invocation, operation ID, requested BOOTTIME and original deadline. The domain is ASCII `catchplate.nativeShadowProofCohortCleanup.signature/v1`, NUL, complete canonical ASCII payload. The issuer-approved requested time must lie within the original boot window and at or before actual current BOOTTIME. The exact deadline must be live, at most30s after that original requested time, and at most the unchanged original lifetime minus the existing 250ms reap reserve. Every controlled signal checks that same deadline. A new command or grant cannot reset the consumed attempt; unconditional fail-closed teardown after a failure yields no successful cleanup observation.

## Actual effects and retained originals

The Rust parent validates the same source-owned identities before writing the intent. It appends `intent.json` with O_EXCL, file fsync, root0400, readback and directory fsync before the first signal. It then signals all five retained clone PIDFDs before waiting for any one child. `Child::reap_observed` checks the original start/parent/PIDFD relationship, obtains terminal `waitid(P_PIDFD,WNOWAIT)` status and consumes exactly the same status with `waitid`. Only that source owner constructs the terminal child observation; there is no deserializer or public constructor for it.

Each of the five observations contains actual process/start, PIDFD device/inode, kernel terminal code/status, observation BOOTTIME and reap BOOTTIME. The terminal original binds all original scope digests and the actual completion time. There is no `processReaped:true` input, invented epoch correlation, timeout-as-terminal, guessed PID list, or success based only on SIGKILL acceptance.

The parent fsyncs/readbacks `terminal.json` before sending the exact cleanup result5. All image, original, activation and process resources remain retained through every child's real reap. It exits status0 only on this completed selected path, after the cohort's owned fields drop. This does not assert separate mount-retirement or storage-erasure effects. Every partial failure stays unknown and follows the existing fail-closed parent cleanup path; it cannot emit a terminal success.

`settle_cohort()` receives the actual result on the retained root parent channel, verifies SCM credentials and the same sender PIDFD, exact intent/terminal chain and all five retained child PIDFD terminal states. It additionally waits for that same parent to exit status0 and reaps it via the retained PIDFD before closing transfers or reporting the original. A packet or directory row alone is not sufficient.

`recover_cohort_cleanup()` is explicit read-only observation after uncertain delivery. It can run only on the same retained caller with the same original authorization, deadline and actual process handles. It reads only the exact complete journal and still demands all five child terminal states and successful same-parent exit/reap. It never contacts the coordinator, resends a command, kills a process, signs evidence, repairs partial records or changes a deadline. Missing intent/terminal, nonzero/unknown parent status, mismatched handles or expiry refuses. `cleanup_original()` returns only an already completed exact data original; it grants no effect or retry authority.

## Durable and size bounds

The fixed directory is `/var/lib/catchplate/native-shadow-proof-cohort-cleanup`, independently precreated root0700 with pinned device/inode/mode/UID/GID. Every named ancestor must remain protected root-owned. It must be a writable local ext4, XFS or Btrfs filesystem; volatile, overlay and network filesystems are refused. An existing root0600 zero-byte `cleanup.lock` is exclusively retained. Existing root0400 `genesis.json` contains exact `{apiVersion,scopeId,authorityKeyId}` matching the independent configuration pin. The runtime creates neither the directory, lock nor genesis and never repairs them.

At initial admission only the lock and genesis may exist. Exactly two append-only records are permitted, intent followed by terminal; complete directory population is checked. A reused, partial or changed journal refuses another start. This anti-replay boundary is the independently pinned configuration and retained same-scope owner, not a claim that chmod makes data cryptographically immutable. Each record is at most64KiB; configuration, command and complete result remain at most32KiB. No generic frame or inventory limit was raised.

The schema is `native-shadow-proof-cohort.v2.schema.json`, with configuration, authorization, terminal, record and result anchors. The existing five role order is Retrieval, Persistence, TrustedTime, GenerationInstallEnvelope, Bridge. The additional LedgerAppend endpoint is not a sixth parked child in this profile. A genuine separately selected sixth-owner release remains required; this cleanup cannot silently broaden its inventory or certify that endpoint.

## Source boundary

This source builds on the existing generation coordinator and preserves the
ordinary-service inspection and final-role listening path. The new cleanup
profile does not change older single-guest, pair or fixed-five launch behavior.

No builds, parsers, tests, runtime, provider, cloud, signing-key creation or provisioning actions were performed. This source connects genuine parent lifecycle effects and their retained caller. Per-operation business settlement, additional endpoint cohort ownership, deployment/key/journal provision and integrated build/runtime acceptance remain separate requirements.
