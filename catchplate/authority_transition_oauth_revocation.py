"""Current-grant cleanup metadata transitions; never provider success proof."""
from dataclasses import dataclass
from catchplate import authority_oauth_retirement_succession_current as succession
from types import MappingProxyType

from catchplate import authority_oauth_revocation as profile
from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate.authority_transition_oauth_exchange import _iso

_HANDLERS = {operation: "catchplate_policy_authority_" + operation.replace(".", "_") for operation in profile.OPERATIONS}


def _values(operation, arguments):
    try:
        return profile.arguments(operation, arguments, typed=True)
    except (TypeError, ValueError, KeyError) as exc:
        raise core.TransitionKernelError("OAuth cleanup request is not exact") from exc


def _grant(values):
    return profile.grant_document(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))["payload"]


def _journal_public(row):
    return {"workId": row["id"], "status": row["status"], "rowSha256": profile.sha256(profile.journal_original(row)),
        "authorizationSha256": row["authorization_sha256"], "expiresAt": row["expires_at"]}


def _attempt_public(row):
    if row is None:
        return None
    return {"id": row["id"], "tokenPurpose": row["token_purpose"], "status": row["status"],
        "rowSha256": profile.sha256(profile.attempt_original(row)), "transportSha256": row["transport_sha256"]}


def _originals(context, values, grant):
    exchange = shared._row(context.exact(profile.exchange.TABLE, {"id": values["work_id"]}), "retained OAuth exchange")
    if (exchange["status"] != "retained" or profile.sha256(profile.exchange.row_original(exchange)) != grant["exchangeRowSha256"]
            or exchange["enrollment_original"] != values["enrollment_original"] or exchange["provider_id"] != grant["providerId"]
            or exchange["token_secret_sha256"] != grant["tokenSecretSha256"] or exchange["token_envelope_json"] is None
            or exchange["raw_response_envelope_json"] is None):
        raise core.TransitionKernelError("cleanup does not select the exact retained issued-token original")
    historical = enrollment.enrollment_document(profile.exchange.enrollment_bytes(values["enrollment_original"]))["payload"]
    created_ns = shared._database_epoch_ns(profile.exchange.timestamp(exchange["created_at"]))
    if not historical["issuedAtEpochNs"] <= created_ns < historical["expiresAtEpochNs"]:
        raise core.TransitionKernelError("retained exchange creation is outside its historical enrollment")
    token = shared._canonical_stored_mapping(exchange["token_envelope_json"], "retained OAuth envelope")
    profile.exchange.envelope(token)
    if profile.sha256(profile.canonical(token)) != grant["tokenEnvelopeSha256"]:
        raise core.TransitionKernelError("cleanup token envelope differs from independent grant")
    work_selected = context.exact("oauth_revocation_work", {"id": values["work_id"]})
    work = shared._row(work_selected, "retained OAuth work")
    profile.work_original(work)
    if (work["id"] != exchange["id"] or work["provider_id"] != exchange["provider_id"]
            or work["actor_id"] != exchange["requester_id"] or work["source"] != "enrolled-oauth-exchange/v1"
            or any(work[name] != token[name] or type(work[name]) is not type(token[name]) for name in profile.exchange.ENVELOPE_FIELDS)
            or work["created_at"] != exchange["created_at"]
            or any(work[name] is not None for name in ("last_error", "lease_owner", "lease_until"))):
        raise core.TransitionKernelError("cleanup work/material association changed")
    return exchange, work_selected, work


@dataclass(frozen=True, slots=True)
class OAuthRevocationKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return _HANDLERS[self.operation]

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        values = _values(self.operation, arguments)
        grant, item_id = _grant(values), values["work_id"]
        queries = [shared._query(operation=self.operation, name="exchange", table=profile.exchange.TABLE, key={"id": item_id}),
            shared._query(operation=self.operation, name="work", table="oauth_revocation_work", key={"id": item_id}),
            shared._query(operation=self.operation, name="journal", table=profile.JOURNAL_TABLE, key={"id": item_id}, require_absence=self.operation == profile.OP_CLAIM)]
        if self.operation in succession.GUARDED_OPERATIONS:
            queries.append(succession.query(self.operation, grant["providerId"]))
        for purpose in grant["tokenPurposes"]:
            queries.append(shared._query(operation=self.operation, name="attempt_" + purpose, table=profile.ATTEMPT_TABLE,
                key={"id": profile.attempt_id(item_id, purpose)}, require_absence=self.operation == profile.OP_CLAIM))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = _values(self.operation, context.arguments)
        grant, request = _grant(values), values["request"]
        if self.operation in succession.GUARDED_OPERATIONS:
            succession.require_unassigned(context, grant["providerId"])
        now_ns = shared._database_epoch_ns(context.database_now)
        if not grant["issuedAtEpochNs"] <= now_ns < grant["expiresAtEpochNs"]:
            raise core.TransitionKernelError("original cleanup grant deadline expired")
        exchange, work_selected, work = _originals(context, values, grant)
        journal_selected = context.exact(profile.JOURNAL_TABLE, {"id": values["work_id"]})
        attempts = {purpose: context.exact(profile.ATTEMPT_TABLE, {"id": profile.attempt_id(values["work_id"], purpose)}) for purpose in grant["tokenPurposes"]}
        now_s, mutations, attempt = context.database_now.isoformat(), [], None
        if self.operation == profile.OP_CLAIM:
            if (journal_selected["present"] or any(item["present"] for item in attempts.values())
                    or profile.sha256(profile.work_original(work)) != grant["workRowSha256"]
                    or work["status"] != "held" or work["attempts"] != 0):
                raise core.TransitionKernelError("cleanup work was already consumed, changed or requires another source profile")
            journal = {"id": values["work_id"], "authorization_original": values["authorization_original"],
                "authorization_sha256": profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES)),
                "exchange_row_sha256": grant["exchangeRowSha256"], "original_work_json": profile.work_original(work).decode("ascii"),
                "owner_nonce_sha256": request["ownerNonceSha256"], "status": "claimed", "created_at": now_s,
                "expires_at": _iso(grant["expiresAtEpochNs"]), "updated_at": now_s}
            # This actual write conflicts with .267 stage's held-work predicate;
            # no token may be activated concurrently with cleanup admission.
            work = {**work, "status": "revocation_reserved", "updated_at": now_s}
        else:
            journal = shared._row(journal_selected, "cleanup journal")
            original_work = profile.document(journal["original_work_json"].encode("ascii"), 512 * 1024)
            if (profile.sha256(profile.journal_original(journal)) != request["journalRowSha256"]
                    or journal["authorization_original"] != values["authorization_original"]
                    or journal["authorization_sha256"] != profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))
                    or journal["exchange_row_sha256"] != grant["exchangeRowSha256"]
                    or profile.sha256(profile.work_original(original_work)) != grant["workRowSha256"]
                    or journal["owner_nonce_sha256"] != profile.sha256(profile.unb64(request["ownerNonce"], 32))
                    or journal["expires_at"] != _iso(grant["expiresAtEpochNs"]) or journal["status"] != "claimed"
                    or work["status"] != "revocation_reserved"
                    or any(work[name] != original_work[name] for name in profile.WORK_FIELDS - {"status", "attempts", "updated_at"})):
                raise core.TransitionKernelError("cleanup owner, grant, retained work or original journal changed")
            purpose = request["tokenPurpose"]
            selected = attempts[purpose]
            used = [item for item in attempts.values() if item["present"]]
            if work["attempts"] != len(used):
                raise core.TransitionKernelError("cleanup attempt inventory differs from actual work counter")
            if self.operation == profile.OP_CONTACT:
                ordinal = grant["tokenPurposes"].index(purpose)
                previous = [attempts[name] for name in grant["tokenPurposes"][:ordinal]]
                following = [attempts[name] for name in grant["tokenPurposes"][ordinal + 1:]]
                if (selected["present"] or any(item["present"] for item in following)
                        or any(not item["present"] or shared._row(item, "cleanup attempt")["status"] not in {"accepted", "rejected"} for item in previous)
                        or any(shared._row(item, "cleanup attempt")["status"] in {"contact-claimed", "unknown"} for item in used)):
                    raise core.TransitionKernelError("cleanup contact already claimed or an earlier outcome is unknown")
                attempt = {"id": profile.attempt_id(work["id"], purpose), "work_id": work["id"], "token_purpose": purpose,
                    "contact_request_sha256": request["contactRequestSha256"], "status": "contact-claimed",
                    "transport_original": None, "transport_sha256": None, "created_at": now_s, "updated_at": now_s}
                work = {**work, "attempts": work["attempts"] + 1, "updated_at": now_s}
            else:
                attempt = shared._row(selected, "cleanup contact original")
                if (profile.sha256(profile.attempt_original(attempt)) != request["attemptRowSha256"]
                        or attempt["work_id"] != work["id"] or attempt["token_purpose"] != purpose
                        or attempt["status"] != "contact-claimed" or attempt["transport_original"] is not None
                        or attempt["transport_sha256"] is not None):
                    raise core.TransitionKernelError("cleanup contact observation was already consumed or changed")
                raw = profile.unb64(request["transportOriginal"], profile.MAX_TRANSPORT_BYTES)
                outcome = profile.transport(raw, attempt["contact_request_sha256"])
                attempt = {**attempt, "status": outcome, "transport_original": raw.decode("ascii"),
                    "transport_sha256": profile.sha256(raw), "updated_at": now_s}
                states = [outcome if name == purpose else shared._row(item, "cleanup attempt")["status"] if item["present"] else None
                    for name, item in attempts.items()]
                if "unknown" in states:
                    journal = {**journal, "status": "unknown"}
                elif all(state in {"accepted", "rejected"} for state in states):
                    journal = {**journal, "status": "observed-rejected" if "rejected" in states else "observed-accepted"}
                if journal["status"] != "claimed":
                    work = {**work, "status": "revocation_" + journal["status"].replace("-", "_"), "updated_at": now_s}
            mutations.append(core.mutation(operation=self.operation, selected=selected, row=attempt))
            journal = {**journal, "updated_at": now_s}
        profile.journal_original(journal)
        if attempt is not None:
            profile.attempt_original(attempt)
        mutations.extend((core.mutation(operation=self.operation, selected=journal_selected, row=journal),
            core.mutation(operation=self.operation, selected=work_selected, row=work)))
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation,
            actor_type="cleanup_authority", actor_id=grant["authorizationId"],
            event={"schema": "catchplate.oauthRevocationAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "workId": work["id"], "authorizationSha256": journal["authorization_sha256"],
                "journalRowSha256": profile.sha256(profile.journal_original(journal)), "status": journal["status"],
                "attempt": _attempt_public(attempt)})
        if replay:
            raise core.TransitionKernelError("cleanup audit original already used")
        return core.KernelTransition(mutations=tuple(mutations) + audit, work_units=256,
            result={"ok": True, "journal": _journal_public(journal), "attempt": _attempt_public(attempt), "operation": self.operation,
                "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False})


KERNELS = MappingProxyType({operation: OAuthRevocationKernel(operation) for operation in profile.OPERATIONS})
