"""Configured shared-work kernel for the two evidence-admission operations.

Construction holds independently admitted public-key and purpose-policy pins;
it performs no key callback and establishes no configuration or request
authority. Every transition invokes the genuine original-input computation,
including purpose semantics and signature verification, on the caller's work.
Selected-row/root, ceremony or installation provenance remains upstream.

The explicit metered interfaces are shared by live acquisition and retained
replay. There is no legacy unmetered transition, registry entry, SQL, clock,
signer, callback override or replacement allowance. Returned computation data
is never accepted as a successful-verification input.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_revocation_root_reader as reader
from serverware import authority_webauthn_evidence_computation as computation


evidence, authority, core = computation.evidence, computation.authority, computation.core
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


class WebAuthnEvidenceKernelError(ValueError):
    pass


def _adapter(operation):
    if type(operation) is not str or operation not in (
            computation.registration.OPERATION, computation.installation.OPERATION):
        raise WebAuthnEvidenceKernelError("evidence kernel operation is not source fixed")
    adapter = (computation.registration if operation == computation.registration.OPERATION
        else computation.installation)
    if authority.operation_spec(operation)["handler"] != adapter.HANDLER:
        raise WebAuthnEvidenceKernelError("evidence kernel handler differs from the source operation")
    return adapter


def _configuration(values):
    """Validate held immutable tuple9 without invoking a public key."""
    if type(values) is not tuple or len(values) != 9:
        raise WebAuthnEvidenceKernelError("evidence kernel configuration is not an exact nine-tuple")
    operation, public_key, identity, spki, age, skew, rp_id, origin, target = values
    _adapter(operation)
    if (not isinstance(public_key, evidence.keys.Ed25519PublicKey)
            or type(identity) is not tuple or len(identity) != 3):
        raise WebAuthnEvidenceKernelError("evidence kernel key or identity is not exact")
    shape = evidence.plan.contract
    for digest in (*identity, spki):
        shape._digest(digest)
    shape._integer(age, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if operation == computation.registration.OPERATION:
        reader._bounded_text(rp_id, 4096)
        reader._bounded_text(origin, 8192)
        if target is not None:
            raise WebAuthnEvidenceKernelError("registration evidence kernel cannot use an installation target")
    else:
        shape._digest(target)
        if rp_id is not None or origin is not None:
            raise WebAuthnEvidenceKernelError("installation evidence kernel cannot use a registration RP")
    return values


def _snapshot(kernel):
    if type(kernel) is not EvidenceAdmissionKernel:
        raise WebAuthnEvidenceKernelError("evidence admission kernel type changed")
    return _configuration(kernel._configured)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class EvidenceAdmissionKernel:
    """Hold one fixed operation's pins; accept originals, never proof results."""

    _configured: tuple

    def __init__(self, *, operation, public_key, expected_identity, expected_spki_digest,
            maximum_age_ns, maximum_clock_skew_ns, rp_id=None, origin=None,
            installation_target_digest=None):
        evidence._identity(expected_identity)
        configured = _configuration((operation, public_key,
            tuple(expected_identity[name] for name in _IDENTITY_FIELDS), expected_spki_digest,
            maximum_age_ns, maximum_clock_skew_ns, rp_id, origin, installation_target_digest))
        object.__setattr__(self, "_configured", configured)

    @property
    def operation(self):
        return _snapshot(self)[0]

    @property
    def handler(self):
        return _adapter(_snapshot(self)[0]).HANDLER

    @property
    def program_id(self):
        configured = _snapshot(self)
        return core.transition_program_id(configured[0], _adapter(configured[0]).HANDLER)

    @property
    def permits_empty_mutation(self):
        _snapshot(self)
        return True

    def queries_on_work(self, *, arguments, work):
        """Use the actual fixed operation's bounded query recipe."""
        configured = _snapshot(self)
        return _adapter(configured[0])._query_recipe_on_work(arguments=arguments, work=work)

    def transition_on_work(self, *, request, selected_rows, database_now, inputs_bytes,
            expected_inputs_digest, work):
        """Repeat real original-input computation with this invocation's work."""
        configured = _snapshot(self)
        operation, public_key, identity, spki, age, skew, rp_id, origin, target = configured
        return computation._compute_on_work(operation=operation, request=request,
            selected_rows=selected_rows, database_now=database_now, inputs_bytes=inputs_bytes,
            expected_inputs_digest=expected_inputs_digest, public_key=public_key,
            expected_identity=dict(zip(_IDENTITY_FIELDS, identity)), expected_spki_digest=spki,
            maximum_age_ns=age, maximum_clock_skew_ns=skew, rp_id=rp_id, origin=origin,
            installation_target_digest=target, work=work)
