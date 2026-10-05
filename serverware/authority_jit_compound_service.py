"""Measured planner caller for the original JIT acquisition/custody producer.

Only this process's actual admitted configuration, live generation, retained
planner signer and protected read descriptor configure the producer. Variable
request/root originals are owned before any measured descriptor/key callback.
The producer owns the sole native pass, writer-page retention and independent
readback replay; no caller supplies those callbacks or a successful result.

This private caller is not request authorization, root/witness admission, a
public operation route, or execution authority. Its upstream owner must retain
those original admissions through the neutral check(stage) callback. The JIT
assertion receipt operation remains distinct from the existing jit.decide API.
"""
from __future__ import annotations

from serverware import authority_jit_compound as compound
from serverware import authority_jit_compound_configuration as mapping
from serverware import authority_jit_compound_plan as plan
from serverware import authority_jit_original_service as pages
from serverware import authority_webauthn_transition_service as measured
from serverware.authority_query_read_work import _ValidationWork


OPERATION = "jit.assertion.issue"
_READ_DSN = "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"
source, evidence, clock = compound.source, pages.evidence, pages.clock


class JitCompoundServiceError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitCompoundServiceError("JIT production lost its original measured caller or inputs")


def _inputs_on_work(request, business, authorization, heads, work):
    """Own the complete variable graph before descriptor/key/clock callbacks."""
    _require(type(work) is _ValidationWork and type(request) is dict
        and type(business) is tuple and type(authorization) is tuple and type(heads) is tuple
        and len(business) == len(authorization) == 4 and len(heads) == 12)
    work.charge(input_bytes=16384, json_nodes=1024)
    owned = source.reads._CopyBudget(work).copy({"request": request,
        "business": business, "authorization": authorization, "heads": heads})
    source._request(owned["request"], work)
    contracts = source.primary_contract.primary_table_contracts(OPERATION)
    _require(len(contracts) == 8)
    # These are the same source-class scalar documents the actual native
    # planner later compares with all eight authenticated metadata roots.
    for name in ("business", "authorization"):
        values = owned[name]
        for value in values:
            plan._object(value, plan._ROOT_FIELDS)
            source.shape._digest(value["rootDigest"])
            source.shape._integer(value["rootRevision"])
            source.shape._integer(value["leafCount"])
        _require(tuple(value["table"] for value in values)
            == tuple(item.table for item in contracts if item.root_class == name))
    values = owned["heads"]
    for value in values:
        plan._object(value, plan._HEAD_FIELDS)
        source.shape._digest(value["rootDigest"])
        source.shape._integer(value["indexRevision"])
        source.shape._integer(value["leafCount"])
    _require(tuple(value["indexId"] for value in values) == source.heads._jit_receipt_ids())
    return owned["request"], tuple(owned["business"]), tuple(owned["authorization"]), tuple(values)


def _producer_on_work(process, *, live_window, work, processing_owner=None):
    """Bind the actual page signer and protected planner-read descriptor only."""
    caller = pages._caller_on_work(process, live_window=live_window, work=work,
        processing_owner=processing_owner)
    _require(caller._configured.local_role == "planner")
    pages._PageCaller._live(caller, work)
    owned, digest, generation, dsn, private, runtime = measured._measured_context_on_work(
        process, role="planner", signing=False, read_descriptor=_READ_DSN, work=work)
    _require(private is None)
    pages._PageCaller._live(caller, work)
    producer = mapping._producer_from_configuration_on_work(payload=owned,
        configuration_digest=digest, generation=generation, runtime_role_identities=runtime,
        read_dsn=dsn, page_caller=caller, work=work)
    pages._PageCaller._live(caller, work)
    return producer, caller


def _produce_on_work(process, *, request, business_before_roots, authorization_before_roots,
        expected_counted_heads, live_window, original_deadline_ns, check, work, processing_owner=None):
    """Call the genuine fixed producer with no request-selected I/O owner."""
    _require(type(work) is _ValidationWork and callable(check))
    owned_request, business, authorization, heads = _inputs_on_work(request,
        business_before_roots, authorization_before_roots, expected_counted_heads, work)
    window = clock._validate(live_window)
    source.shape._integer(original_deadline_ns, minimum=1)
    _require(window[2] < original_deadline_ns <= window[4])
    if processing_owner is not None:
        from serverware.authority_jit_compound_request_service import _page_bounds

        _page_bounds(processing_owner, original_window=window,
            original_deadline_ns=original_deadline_ns, work=work)
    producer, caller = _producer_on_work(process, live_window=window, work=work,
        processing_owner=processing_owner)
    from serverware import authority_jit_compound_production as production

    _require(type(producer) is production._JitCompoundProducer
        and type(caller) is pages._PageCaller and caller._window is window)

    def current(stage):
        # Native continuity supplies a source-owned observation over the
        # already supplied parent. Production/replay stages hold their actual
        # children. Their owner brackets this callback; never reenter check().
        _require(type(stage) in (production._ProductionStage, compound._Stage))
        active_work = stage.work
        _require(type(active_work) is _ValidationWork)
        pages._PageCaller._live(caller, active_work)
        _require(evidence.production._callback(active_work, lambda: check(stage)) is None)
        _require(stage.work is active_work)
        pages._PageCaller._live(caller, active_work)

    result = production._JitCompoundProducer.produce(producer,
        request=owned_request, business_before_roots=business, authorization_before_roots=authorization,
        expected_counted_heads=heads, live_window=window, original_deadline_ns=original_deadline_ns,
        check=current, work=work)
    pages._PageCaller._live(caller, work)
    _require(type(result) is production.ProducedJitCompoundPlan)
    # The page caller may own a wider window than this original invocation.
    # Recheck the unchanged original bound after all producer output/metric
    # construction and owner callbacks, never derive a fresh relative bound.
    expires = window[0] + original_deadline_ns - window[1]
    _require(pages._original_interval_on_work(window, window[0], expires,
        original_deadline_ns, work) == original_deadline_ns)
    return result
