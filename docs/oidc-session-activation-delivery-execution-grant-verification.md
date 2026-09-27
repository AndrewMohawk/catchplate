# Independent consume-grant verification

`authority_oidc_session_activation_delivery_execution_grant_verification._verify_on_work`
accepts original signed grant/caller bytes, caller/current-root/consume-grant
enrollment originals, independent root/configuration/planner/operation pins, the
exact raw pair `(signed consume plan, encrypted execution bundle)`, closed
expectations, the independent before-vector and the actual receiving custody
owner. The original processing window, inherited deadline and cumulative work
are mandatory. No successful proof-result carrier is an input.

The receiver follows this fixed sequence:

1. Hold the bounded immutable grant original and include it in the common
   `extra_originals` accounting before any caller hashing or callbacks.
2. Genuinely admit caller, root enrollments and receiving custody. Verify the
   actual grant signature with the enrolled authorizer key; join source, cohort,
   caller, original-frame and live-control bindings **before decryption**.
3. Invoke the shared actual private-original replay once, then compare the
   authenticated grant claims to its genuinely derived plan, result and complete
   before/after vector commitments. No received snapshot or claimed capability
   replaces this replay.
4. Narrow the same original processing bracket to the signed grant expiry and
   actual replay ceiling. Copy the actual token-free result under the existing
   bounds and retain current guards through output creation.

The grant issue remains the authentic consume-plan original issue; a post-plan
caller control does not backdate a new clock or renew the plan. Original plan,
caller, enrollment, receiving launch and signed-grant expiry constraints remain
effective. A shorter grant expiry also narrows the returned monotonic bound;
there is no reopened work allowance, historical consume-plan mode or fallback
to generic successor grants.

The private `_VerifiedGrant` output contains `payload`, `grant_digest`, `result`,
`valid_until_epoch_ns`, `window`, `deadline_ns` and `live`. Its payload is ordinary
authenticated control data; its result is a bounded copy of the genuine replay
result, not executable mutations or an accepted proof token. The live guard
retains the actual replay/custody/caller checks and the shorter grant interval.
There is no separate successful-carrier admission API.

This is source-only and unexecuted. It verifies the dedicated consume-only grant
family; it does not install a cold authorizer service, admit a reservation,
execute one-use SQL, sign completion, release a token or establish public/user
permission. Generic consume-operation rejection is unchanged. Signature validity
alone remains weaker than this full original-based receiving verification.
