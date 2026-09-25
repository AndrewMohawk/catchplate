"""Request once and genuinely verify independent registration evidence.

The caller must already admit its configuration/cohort, endpoint, enrollment
grant and complete original source exchange. This private composition owns
those inputs before socket callbacks and never treats the peer, a parsed
response or successful transport as evidence. The configured consumer replays
the originals and derives the evidence-admission invocation on the same work.
It does not return or authorize registration-finalization arguments.

No public route, source acquisition, signer provisioning, retry, business
execution or replacement work allowance is introduced here.
"""
from __future__ import annotations

from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_registration_signer_response as response
from serverware import authority_webauthn_registration_signer_transport as transport
from serverware import authority_webauthn_registration_signer_wire as wire


def _request_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, endpoint, request_originals, work, deadline_ns=None):
    """Return (original evidence, regenerated request, original verified inputs)."""
    ledger = configuration.capability.capture._SharedLedger(work)
    originals = wire._request_originals(request_originals)
    held_endpoint = transport._endpoint(endpoint)
    digest = configuration_digest
    configuration.capability.shape._digest(digest)
    configuration.capability.shape._bounded_object(generation, 24, "signer caller launch context")
    owned = configuration._ConfigurationCapture(ledger,
        maximum_bytes=configuration.authority.MAX_REQUEST_BYTES).visit(payload)
    launch = configuration.capability.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in configuration._GENERATION_FIELDS})
    runtime = configuration.capability.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    # Snapshot the complete caller graph before the first socket/native work.
    # Consistency/provenance and original signatures are independently enforced
    # in the actual fixed consumer; the endpoint is never learned from response.
    received = configuration.production._callback(work,
        lambda: transport._socket_request(held_endpoint, originals=originals,
            deadline_ns=deadline_ns))
    request, inputs = response._verify_on_configuration(payload=owned,
        configuration_digest=digest, generation=launch, runtime_role_identities=runtime,
        request_originals=originals, response_originals=received, work=work)
    if deadline_ns is not None:
        configuration.production._callback(work, lambda: transport._check_deadline(deadline_ns))
    return received[0], request, inputs
