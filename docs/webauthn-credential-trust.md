# Explicit-context credential trust classification

Status: source implementation and authored fixtures only; unexecuted. This
does not resolve any of the four [authority-transition startup gaps](authority-transition-startup-blocker.md).

`serverware/webauthn_credential_trust.py` contains the classification shared by
the actual `webauthn.credential_trust_status` boundary and trust-withdrawal
enumeration. The pure core accepts immutable credential facts and one explicit
root/development-policy context. It performs no database, filesystem, cache,
clock, configuration, certificate or signature access. It retains only a boolean
for development-key presence; no private key or certificate enters the core.

## Preserved classification and capture

Branch order and result fields preserve the existing behavior:

- An enabled development credential with a stored development key takes the
  development exception first. Even when its enrollment was untrusted, this
  branch retains its enrolled bundle metadata and returns `not_attested`.
- Other untrusted enrollments return `not_attested`, without current bundle
  metadata. A trusted enrollment without a root digest returns
  `attestation_root_missing`; no matching root returns `trust_root_withdrawn`.
- The first matching certificate digest wins. Duplicate certificate identities
  are neither sorted nor deduplicated to find a more permissive later root.
  AAGUID restriction is checked before an authenticator-class change; either
  denial retains that root's current bundle digest and sequence.
- AAGUID comparison uses `str.lower`, not `casefold`. Root-digest and class
  comparisons remain literal and case-sensitive. Empty root AAGUID/class
  restrictions remain unconstrained. Only `trusted_by_current_root` adds the
  current root ID and certificate digest to the six common result fields.

The boundary preserves existing credential `bool`/`str` normalization, then
passes only validated facts. Calls without an explicit context retain lazy root
loading: an unattested credential, missing root, or applicable development
exception does not read trust files. Explicit roots and a captured context are
mutually exclusive. Classification/type/bound failures become
`WebAuthnTrustError`; authentication maps them to its existing denial type.

Credential-option enumeration captures the development flag and one context
for its whole loop. Its earlier eager-root-load condition remains unchanged:
any attested non-exempt credential requires the root load, even if that
credential has no stored root digest. A failed policy capture returns no options.

The trust-publication API captures one candidate context after verifying the
candidate roots. It reuses that context for both the preapproval withdrawal
enumeration and the enumeration under the exclusive trust lock. The helper
still visits every live credential returned by the existing database query,
preserves affected-row order and redaction, and applies no new row truncation.
Classification failures in either pass become HTTP 409 before publication.
Approval consumption, global registration invalidation, dependent revocations,
audits and publication staging remain in their existing single transaction.

## Explicit finite-input tightening

The core accepts at most 256 roots and 1024 AAGUID entries per root, with a
2 MiB combined input budget for facts and context. UTF-8 text contributes its
actual byte length, booleans one byte each and non-null sequence metadata eight
bytes each. Null metadata contributes no bytes. This is a primitive-input bound,
not a claim about JSON wire size or Python heap usage. The root projection
charges each validated descriptor before retaining it or projecting the next;
the core separately checks the combined facts/context budget before classifying.

Text must be exact, valid Unicode without NUL. Sequence metadata is null or an
exact signed-64 integer, including zero and negative historical values; booleans,
floats and numeric strings are not integers here. The existing signature/bundle
verifier remains responsible for bundle sequence policy. No new class enum,
digest spelling or UUID spelling requirement is imposed on classification facts.

Applying these type and size checks to formerly unbounded legacy descriptors is
an intentional fail-closed compatibility tightening, including for malformed
fields that an earlier branch might not have read. Oversized roots/facts are
rejected, never truncated. Results reserve 128 additional bytes only for fixed
classification labels; that does not enlarge the accepted input budget.

## Evidence boundary and pending verification

The context is a detached classification policy, not proof of independent root
currentness, enrollment, complete withdrawal enumeration or authorization to
mutate anything. Reusing it does not authenticate the database's credential
population. The same-database query and existing publication transaction still
need the root/predicate evidence and aggregate authority design in
[WebAuthn authority integration](webauthn-authority-integration.md).

`scripts/test_webauthn_credential_trust.py` authors independent branch-result
oracles, development/duplicate-root/precedence controls, immutability checks,
malformed-input rejection and finite-boundary cases against the actual core.
Supplemental AST checks cover source delegation, redacted descriptor capture,
one context per loop and the two publication calls. They are not executed live
wrapper, database, API, hardware or startup coverage. The fixture and both
revocation fixtures are listed in the frozen isolated Python inventory; adding
them does not bypass any prerequisite or native-test coverage gate.

All fixtures remain unrun pending the required clean source freeze, admitted
dependency/controller/coverage closure, one preparation and sequential no-build
verification. Full live classification and transactional regressions remain
required after the startup kernels and their authority dependencies are complete.
