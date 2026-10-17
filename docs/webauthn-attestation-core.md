# Explicit-context registration attestation core

`catchplate/webauthn_attestation_core.py` separates the existing attestation
computation from live database, configuration, file, cache and clock access.
The registration path and compatibility helpers in `webauthn.py` use it; this
is not a replacement enrollment API. The source is unverified until its frozen
commit completes the prescribed preparation and no-build checks.

## Inputs and result

The core takes original bounded client-data and attestation bytes, ceremony
scope, RP/origin, immutable trust-root snapshots and one explicit UTC
verification time. Scope includes the selected challenge identity/value,
user/label and bounded canonical authorization bytes. Supplying that scope
does not authenticate a database row or authorize enrollment: those remain
caller and transaction responsibilities.

Parsing retains original signature inputs. Verification reparses the retained
bytes, checks the derived fields and their exact types, and uses the newly
derived immutable values. A caller-created parsed object cannot replace a
counter, key, credential identifier, flag or buffer merely because Python
equality accepts a differently typed value.

Results contain immutable derived credential/key/counter/AAGUID/class and
attestation data, with original artifact and context commitments. These local
commitments are not authority signing domains. The result carries no signed
external-evidence receipt, independently authenticated time, verified database
snapshot, enrollment permission or physical-authenticator provenance.

Packed certificate attestation, FIDO U2F and packed self-attestation preserve
their original signature preimages. Supported untrusted classifications,
including `none`, unknown formats and self-attestation, remain untrusted.
Certificate validity checks use the supplied time with inclusive endpoints.
Legacy PEM roots can have no signed-bundle metadata; the core does not invent
bundle provenance for them.

## Live ownership and compatibility

The live layer retains trust-read locking, exact challenge/user/label and
authorization checks, credential-ID history lookup, current signed-bundle
verification/rollback handling, and atomic database finalization. It must
reject invalid supplied signatures and internal certificate chains before
stateful root loading, which can advance rollback state. Pure preflight and
root anchoring use the same explicit certificate-verification instant.
Untrusted formats that do not use x5c do not acquire a new trust-file dependency.

Recovery retains its existing six-argument attestation helper and additional
UV, currently trusted hardware, ceremony and exact trust-generation checks.
The new local verification timestamp must not enter recovery's stable candidate
identity. Assertion trust caching and final database freshness checks remain
separate from this computation.

The explicit core bounds include 256 roots, a 2 MiB aggregate root snapshot,
64 KiB authorization context, 1024 AAGUID entries per root and 16 transport
strings, alongside the existing raw-data/key/certificate limits. Oversized
inputs fail rather than being truncated. This is not a claim that every legacy
configuration size remains accepted, or that live trust-file loading and total
process memory are fully bounded by the core's snapshot budget.

## Verification and remaining work

`scripts/test_webauthn_attestation_core.py` is included in the isolated Python
test inventory. Its fixtures use real local certificate/signature checks with
explicit historical time; they import the core without importing the database
or replacing the transition registry. Source-wiring checks, where present, are
not executions of the live wrapper, recovery transaction or startup.

No tests in this source batch have run yet. The existing integration tests and
source-root startup failure remain visible. The four WebAuthn kernels, signed
evidence producer/admission protocol, authenticated complete-set/root authority
and full transactional integration are still required. See
[the integration design](webauthn-authority-integration.md); this extraction
does not activate those contracts or make the control plane start.
