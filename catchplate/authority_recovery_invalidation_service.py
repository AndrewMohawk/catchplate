"""Fixed measured planner-writer integration for live invalidation custody.

These private calls retain/read originals, not witness or execution authority.
They have no public dispatch route and do not change generic operation denial.
"""
from __future__ import annotations

import time

from catchplate import authority_recovery_invalidation_configuration as mapping
from catchplate import authority_recovery_invalidation_persistence as persistence
from catchplate import authority_webauthn_transition_service as measured

plan, proof = persistence.plan, persistence.proof


def _run(process, *, originals, retained_record_digest, expectations, live_window, check, work):
    from catchplate import authority_service as service

    plan._object(expectations, plan.EXPECTATION_FIELDS)
    owned = proof._own(expectations, work)
    if originals is not None:
        originals = persistence.store._raw4(originals)
    else:
        plan.shape._digest(retained_record_digest)
    window = plan.clock._validate(live_window)
    plan.shape._integer(owned["originalDeadlineNs"], minimum=1)
    deadline = min(window[4], owned["originalDeadlineNs"])
    epoch_deadline = min(window[3], window[0] + deadline - window[1])
    plan._require(callable(check) and type(process) is service.AuthorityProcess
        and process.role_name == "planner-writer" and process.process_mode == "policy-authority-planner-writer"
        and type(process.configuration) is service.MeasuredConfiguration)
    original_configuration = process.configuration
    digest = original_configuration.digest
    last = window[2]
    manifest = None

    def local():
        nonlocal last, manifest
        plan._require(process.configuration is original_configuration
            and original_configuration.digest == digest and process.role_name == "planner-writer"
            and process.process_mode == "policy-authority-planner-writer")
        now = plan.clock._check_on_work(window, work=work)
        mono = plan.evidence.production._callback(work, time.monotonic_ns)
        plan._require(type(mono) is int and last <= mono < deadline and now < epoch_deadline)
        last = mono
        actual = plan.evidence.production._callback(work,
            lambda: service.authority_launch_guard.require_active("planner-writer"))
        plan.shape._digest(actual)
        if manifest is None:
            manifest = actual
        else:
            plan._require(actual == manifest)

    def current():
        local()
        plan._require(plan.evidence.production._callback(work, check) is None)
        local()

    def signed_live(raw4):
        expected, request, context = plan._originals(raw4[1], raw4[2], owned, work)
        work.charge(input_bytes=len(context) + len(raw4[3]))
        plan._require(context == raw4[3])
        document = plan._decode(raw4[0], plan.MAX_PARENT_BYTES, work, nodes=2048, depth=8)
        plan._object(document, {"schema", "payload", "signatureBase64Url"})
        plan._require(document["schema"] == plan.ENVELOPE_SCHEMA)
        plan._bind(document["payload"], expected, request, *raw4[1:], work)
        return plan._Live(expected, document["payload"], window, current, work)

    current()
    # An unauthenticated original interval may only restrict early setup.
    # The actual store must still authenticate and replay every original.
    live = None if originals is None else signed_live(originals)
    if live is not None:
        live.checked()
    payload, selected_digest, generation, dsn, _private, runtime = measured._measured_context_on_work(
        process, role="planner-writer", signing=False,
        read_descriptor="CATCHPLATE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN", work=work)
    proof._same(selected_digest, digest, work)
    (current if live is None else live.checked)()
    owner = mapping._persistence_from_configuration_on_work(payload=payload,
        configuration_digest=selected_digest, generation=generation,
        runtime_role_identities=runtime, writer_dsn=dsn, work=work)
    (current if live is None else live.checked)()
    if originals is None:
        result = persistence.RecoveryInvalidationPlanPersistence.read(owner,
            retained_record_digest=retained_record_digest, expectations=owned,
            live_window=window, check=current, work=work)
    else:
        result = persistence.RecoveryInvalidationPlanPersistence.persist(owner,
            originals=originals, expectations=owned, live_window=window, check=current, work=work)
    if live is None:
        live = signed_live(result["originals"])
    live.checked()
    return result


def _persist_on_work(process, *, originals, expectations, live_window, check, work):
    return _run(process, originals=originals, retained_record_digest=None,
        expectations=expectations, live_window=live_window, check=check, work=work)


def _read_on_work(process, *, retained_record_digest, expectations, live_window, check, work):
    return _run(process, originals=None, retained_record_digest=retained_record_digest,
        expectations=expectations, live_window=live_window, check=check, work=work)
