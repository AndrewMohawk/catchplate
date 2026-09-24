"""Exact query and private mutation adapter for v2 installation evidence.

This unregistered operation proposes only an INSERT into evidence custody, or
no mutation for an identical unused verified row. It does not consume evidence,
publish trust, write an audit outbox/capacity row, sign, install files or execute
SQL. Existing framework audit remains the executor's separate responsibility.

Request authorization, the selected primary proofs/current roots, committed
stage, physical installation provenance, target, installer pins and both time
observations remain independently admitted caller inputs. A KernelContext or
an ordinary output is not an authority token. The real purpose-specific
composer recomputes installation semantics and verifies the original signature
on every invocation before this adapter renders the fixed INSERT template.
All source-visible work uses the supplied allowance; no registry is activated.
"""
from __future__ import annotations

from serverware import authority_webauthn_installation_admission as admission


completion, evidence = admission.completion, admission.evidence
authority, core, trust = completion.authority, completion.core, completion.trust
OPERATION = "webauthn.trust.installation.admit"
HANDLER = "admit_webauthn_trust_installation_evidence"
_ARGUMENT_FIELDS = frozenset({"evidence_digest", "publication_id", "businessIntent"})
_MAX_ROWS, _MAX_MUTATIONS, _MAX_WORK = 3, 1, 128


class WebAuthnInstallationAdmissionTransitionError(ValueError):
    pass


def _arguments(arguments, work):
    completion._object(arguments, _ARGUMENT_FIELDS, "installation admission arguments")
    core.require_digest(arguments["evidence_digest"], "installation admission evidence digest")
    completion._text(arguments["publication_id"], "installation admission publication ID")
    work.prepare_copy(arguments)
    semantic = {name: arguments[name] for name in _ARGUMENT_FIELDS - {"businessIntent"}}
    completion._same(arguments["businessIntent"],
        authority._synthesize_business_intent(OPERATION, semantic, work=work), work,
        "installation admission business intent changed")


def _query_recipe_on_work(*, arguments, work):
    """Return three real exact-PK queries without reading or proving any row."""
    ledger = evidence.capture._SharedLedger(work)
    owned = evidence.capture._JSONCapture(ledger).visit(arguments)
    _arguments(owned, work)
    targets = (("evidence", evidence.EVIDENCE_TABLE, "evidence_digest", owned["evidence_digest"]),
        ("publication", trust.PUBLICATION_TABLE, "id", owned["publication_id"]),
        ("high_water", trust.HIGH_WATER_TABLE, "authority_scope", trust.AUTHORITY_SCOPE))
    queries = tuple(core.BoundedQuery(query_id=core.query_program_id(OPERATION, name, table),
        table=table, predicates=(core.QueryPredicate(column, "eq", value),),
        order_by=(core.QueryOrder(column),), maximum_rows=1, absent_key={column: value})
        for name, table, column, value in targets)
    if (len(queries) != _MAX_ROWS or sum(query.maximum_rows for query in queries) > _MAX_ROWS
            or sum(query.work_units for query in queries) > _MAX_WORK):
        raise WebAuthnInstallationAdmissionTransitionError("installation admission query bounds changed")
    return core.close_queries(OPERATION, queries)


def _kernel_transition_on_work(context, *, installation_envelope_bytes,
        installed_bundle_bytes, installed_state_bytes, installation_target_digest,
        expected_committed_stage, observed_at, installer_public_key,
        expected_installer_identity, expected_installer_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Genuinely verify custody material, then propose its single INSERT or none."""
    ledger = evidence.capture._SharedLedger(work)
    if (type(context) is not core.KernelContext or type(context.operation) is not str
            or context.operation != OPERATION or type(context.selected_rows) is not tuple
            or len(context.selected_rows) > _MAX_ROWS
            or any(type(selected) is not dict for selected in context.selected_rows)):
        raise WebAuthnInstallationAdmissionTransitionError("installation admission context is not exact and bounded")
    spec = authority.operation_spec(OPERATION)
    if len(context.selected_rows) > spec["maximumQueryRows"]:
        raise WebAuthnInstallationAdmissionTransitionError("installation admission rows exceed the actual manifest")
    database_now, request_digest = context.database_now, context.request_digest
    now_ns = completion._now(database_now)
    completion._now(observed_at)
    core.require_digest(request_digest, "installation admission request digest")
    for raw, maximum in (
            (installation_envelope_bytes, evidence.MAX_EVIDENCE_BYTES),
            (installed_bundle_bytes, completion.bundle_core.MAX_INSTALLATION_BYTES),
            (installed_state_bytes, completion.bundle_core.MAX_STATE_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnInstallationAdmissionTransitionError("installation admission requires bounded original bytes")
    # Own every caller graph before native decoding or installer-key callbacks.
    # Exact datetimes and raw bytes are retained outside the JSON-only capture.
    work.prepare_copy(context.selected_rows)
    selected_input = list(context.selected_rows)
    owned = evidence.capture._JSONCapture(ledger).visit({
        "arguments": context.arguments, "selected": selected_input,
        "stage": expected_committed_stage, "identity": expected_installer_identity,
        "target": installation_target_digest, "installerSpkiDigest": expected_installer_spki_digest,
        "maximumAgeNs": maximum_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns})
    arguments = owned["arguments"]
    _arguments(arguments, work)
    for selected in owned["selected"]:
        completion._object(selected, evidence.capture._SELECTED_FIELDS, "installation admission selected row")
        core.require_digest(selected["keyDigest"], "installation admission selected key digest")
        if (type(selected["table"]) is not str or type(selected["key"]) is not dict
                or type(selected["present"]) is not bool or selected["contractSelector"] is not None
                or (selected["present"] and type(selected["row"]) is not dict)
                or (not selected["present"] and selected["row"] is not None)):
            raise WebAuthnInstallationAdmissionTransitionError("installation admission selection is not an exact PK row")
    work.prepare_copy(owned["selected"])
    selected_rows = tuple(owned["selected"])
    held = core.KernelContext(OPERATION, arguments, selected_rows, database_now, request_digest)
    selected_evidence = held._exact(evidence.EVIDENCE_TABLE,
        {"evidence_digest": arguments["evidence_digest"]}, work=work)
    selected_publication = held._exact(trust.PUBLICATION_TABLE,
        {"id": arguments["publication_id"]}, work=work)
    selected_high = held._exact(trust.HIGH_WATER_TABLE,
        {"authority_scope": trust.AUTHORITY_SCOPE}, work=work)
    if selected_publication["present"] is not True or selected_high["present"] is not True:
        raise WebAuthnInstallationAdmissionTransitionError("installation admission requires current publication and high-water rows")
    completion._same(selected_publication["row"].get("id"), arguments["publication_id"], work,
        "installation admission publication row differs from the request")
    actual_digest = evidence._evidence_digest_on_work(installation_envelope_bytes, work)
    completion._same(actual_digest, arguments["evidence_digest"], work,
        "installation admission original evidence differs from the request")
    selected, proposed = admission._admit_on_work(
        installation_envelope_bytes=installation_envelope_bytes,
        installed_bundle_bytes=installed_bundle_bytes, installed_state_bytes=installed_state_bytes,
        publication_row=selected_publication["row"], high_water_row=selected_high["row"],
        expected_committed_stage=owned["stage"], installation_target_digest=owned["target"],
        observed_at=observed_at, now_epoch_ns=now_ns, selected_evidence=selected_evidence,
        installer_public_key=installer_public_key, expected_installer_identity=owned["identity"],
        expected_installer_spki_digest=owned["installerSpkiDigest"],
        maximum_age_ns=owned["maximumAgeNs"], maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=work)
    mutations = []
    if proposed is not None:
        work.prepare_copy(selected["key"])
        work.prepare_copy(proposed)
        mutations.append(core.mutation(operation=OPERATION, selected=selected, row=proposed))
    work.prepare_copy(mutations)
    planned = tuple(mutations)
    work_units = 8 + len(selected_rows) + 4 * len(planned)
    if (len(planned) > _MAX_MUTATIONS or len(planned) > spec["maximumMutations"]
            or work_units > _MAX_WORK or work_units > spec["maximumWorkUnits"]):
        raise WebAuthnInstallationAdmissionTransitionError("installation admission effects exceed source bounds")
    result = {"evidence_digest": actual_digest,
        "admission": "already-retained" if proposed is None else "proposed-insert"}
    work.prepare_encoding(result)
    return core.KernelTransition(mutations=planned, result=result, work_units=work_units)
