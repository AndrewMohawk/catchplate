"""Atomic never-issued roots, measured membership and all-holder drain barriers.

No timeout removes a holder. A barrier authorizes no provider contact by itself;
the separate effect kernel consumes it with its own current permission.
"""
from dataclasses import dataclass
from types import MappingProxyType

from serverware import authority_credential_currentness as profile
from serverware import authority_oauth_refresh as refresh
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared


def _values(operation, arguments):
    try:
        return profile.arguments(operation, arguments, typed=True)
    except (TypeError, ValueError, KeyError) as exc:
        raise core.TransitionKernelError("currentness originals are not exact") from exc


def _query(operation, name, table, key, *, absent=False):
    return shared._query(operation=operation, name=name, table=table, key=key, require_absence=absent)


def root_query(operation, credential_id, version, *, absent=False, name="currentness_root"):
    return _query(operation, name, profile.ROOT_TABLE, {"id": profile.root_id(credential_id, version)}, absent=absent)


def effect_queries(operation, credential_id, version, *, next_root=False):
    key = {"id": profile.root_id(credential_id, version)}
    result = [root_query(operation, credential_id, version),
        _query(operation, "currentness_barrier", profile.BARRIER_TABLE,
            {"id": core.SelectedRowFieldReference(profile.ROOT_TABLE, key, "barrier_id")})]
    if next_root:
        profile.require(version < 2**63 - 1)
        result.append(root_query(operation, credential_id, version + 1, absent=True, name="next_currentness_root"))
    return tuple(result)


def require_root(context, credential_id, version):
    selected = context.exact(profile.ROOT_TABLE, {"id": profile.root_id(credential_id, version)})
    row = shared._row(selected, "strict currentness root")
    profile.root_original(row)
    profile.require(row["id"] == profile.root_id(credential_id, version) and row["credential_id"] == credential_id
        and row["credential_version"] == version and row["epoch"] == version and row["profile"] == profile.ROOT_SCHEMA
        and row["status"] in {"open", "quiescing", "admitted", "consumed"})
    profile.digest(row["origin_request_digest"])
    return selected, row


def _barrier(context, root, barrier_id, digest=None):
    profile.identifier(barrier_id)
    selected = context.exact(profile.BARRIER_TABLE, {"id": barrier_id})
    row = shared._row(selected, "currentness barrier")
    profile.require(set(row) == profile.BARRIER_FIELDS and row["root_id"] == root["id"]
        and row["credential_id"] == root["credential_id"] and row["credential_version"] == root["credential_version"]
        and row["epoch"] == root["epoch"] and row["id"] == root["barrier_id"])
    public = profile.public_barrier(row)
    original = public["original"]
    profile.require(original["barrierId"] == row["id"] and original["credentialId"] == root["credential_id"]
        and original["credentialVersion"] == root["credential_version"] and original["epoch"] == root["epoch"]
        and (digest is None or public["sha256"] == digest))
    return selected, row, original


def consume_barrier(context, credential_id, version, digest):
    """Return mutations only to the actual effect kernel, never a permit DTO."""
    profile.digest(digest)
    root_selected, root = require_root(context, credential_id, version)
    barrier_selected, barrier, original = _barrier(context, root, root["barrier_id"], digest)
    now = shared._database_epoch_ns(context.database_now)
    profile.require(root["status"] == "admitted" and barrier["status"] == "admitted"
        and barrier["admit_request_digest"] is not None and barrier["consume_request_digest"] is None
        and original["issuedAtEpochNs"] <= now < original["expiresAtEpochNs"])
    profile.digest(barrier["admit_request_digest"])
    stamp = context.database_now.isoformat()
    return (core.mutation(operation=context.operation, selected=root_selected, row={**root, "status": "consumed", "updated_at": stamp}),
        core.mutation(operation=context.operation, selected=barrier_selected,
            row={**barrier, "status": "consumed", "consume_request_digest": context.request_digest, "updated_at": stamp}))


def require_consumed_refresh_barrier(context, credential_id, version, barrier_sha256, *, claim_request_digest):
    """Historical drain association only; no renewed contact window or effect."""
    _, root = require_root(context, credential_id, version)
    _, barrier, _ = _barrier(context, root, root["barrier_id"], barrier_sha256)
    profile.require(root["status"] == "consumed" and barrier["status"] == "consumed"
        and barrier["consume_request_digest"] == claim_request_digest)
    profile.digest(claim_request_digest)


def require_consumed_pending_retirement_barrier(context, credential_id, version, barrier_sha256, *, claim_request_digest):
    """Exact retained pending claim association, without expiry renewal."""
    from serverware import authority_oauth_measured_pending_retirement as pending
    profile.require(context.operation in {pending.OP_CONTACT, pending.OP_FINISH, pending.OP_RECOVER})
    _, root = require_root(context, credential_id, version)
    _, barrier, _ = _barrier(context, root, root["barrier_id"], barrier_sha256)
    profile.require(root["status"] == "consumed" and barrier["status"] == "consumed"
        and barrier["consume_request_digest"] == claim_request_digest)
    profile.digest(claim_request_digest)


def require_consumed_capture_retirement_barrier(context, credential_id, version, barrier_sha256, *, claim_request_digest):
    """Exact retained provider-capture claim only; no contact/expiry renewal."""
    from serverware import authority_oauth_measured_capture_retirement as capture
    profile.require(context.operation in {capture.OP_CONTACT, capture.OP_FINISH, capture.OP_RECOVER})
    _, root = require_root(context, credential_id, version)
    _, barrier, _ = _barrier(context, root, root["barrier_id"], barrier_sha256)
    profile.require(root["status"] == "consumed" and barrier["status"] == "consumed"
        and barrier["consume_request_digest"] == claim_request_digest)
    profile.digest(claim_request_digest)


def _holder(context, root, holder_id):
    selected = context.exact(profile.HOLDER_TABLE, {"id": profile.holder_record_id(root["id"], holder_id)})
    if selected["present"] is False:
        return selected, None
    row = shared._row(selected, "measured currentness holder")
    profile.registration_evidence(row)
    profile.require(row["id"] == profile.holder_record_id(root["id"], holder_id) and row["root_id"] == root["id"]
        and row["credential_id"] == root["credential_id"] and row["credential_version"] == root["credential_version"]
        and row["epoch"] == root["epoch"] and row["holder_id"] == holder_id)
    return selected, row


def _frozen(row):
    profile.registration_evidence(row)
    return {"holderId": row["holder_id"], "bootId": row["boot_id"], "keyId": row["key_id"],
        "controlPlaneResponseSigningKeyId": row["control_plane_response_signing_key_id"], "registrationSha256": row["registration_sha256"]}


def _members(context, root):
    result = []
    for selected in context.present_rows(profile.HOLDER_TABLE):
        row = shared._row(selected, "complete currentness holder inventory")
        if row["root_id"] == root["id"]:
            _, row = _holder(context, root, row["holder_id"])
            result.append(row)
    profile.require(len(result) <= profile.MAX_ROWS)
    return sorted(result, key=lambda item: item["holder_id"])


@dataclass(frozen=True, slots=True)
class CurrentnessKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        del database_now
        values = _values(self.operation, arguments)
        credential, version, request = values["credential_id"], values["credential_version"], values["request"]
        root = profile.root_id(credential, version)
        queries = [_query(self.operation, "credential", "credentials", {"id": credential}),
            _query(self.operation, "generation", "credential_generations", {"credential_id": credential}),
            root_query(self.operation, credential, version)]
        if "static_creation_provenance_original" in values:
            from serverware import authority_static_credential_provenance as provenance
            queries.append(_query(self.operation, "static_creation_audit", "metadata_audit_outbox",
                {"id": provenance.outbox_id(values["static_creation_provenance_original"])}))
        if "static_generation_provenance_original" in values:
            from serverware import authority_static_credential_provenance as provenance
            queries.append(_query(self.operation, "static_rotation_audit", "metadata_audit_outbox",
                {"id": provenance.generation_outbox_id(values["static_generation_provenance_original"])}))
        item = request["evidence"]["statement"] if self.operation in {profile.OP_REGISTER, profile.OP_ACK} else request
        if self.operation in {profile.OP_CHALLENGE, profile.OP_REGISTER, profile.OP_ACK}:
            queries.extend((_query(self.operation, "challenge", profile.CHALLENGE_TABLE, {"id": item["challengeId"]}, absent=self.operation == profile.OP_CHALLENGE),
                _query(self.operation, "holder", profile.HOLDER_TABLE, {"id": profile.holder_record_id(root, item["holderId"])})))
        if item.get("barrierId") is not None:
            queries.append(_query(self.operation, "barrier", profile.BARRIER_TABLE, {"id": item["barrierId"]}, absent=self.operation == profile.OP_QUIESCE))
        tables = ((profile.CHALLENGE_TABLE,) if self.operation == profile.OP_CHALLENGE else
            (profile.HOLDER_TABLE,) if self.operation in {profile.OP_REGISTER, profile.OP_QUIESCE, profile.OP_ADMIT} else ())
        queries.extend(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table), table=table,
            predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=profile.MAX_ROWS + 1,
            proof_primitive="bounded-limit-plus-one", work_units=profile.MAX_ROWS + 1, page_size=profile.MAX_ROWS) for table in tables)
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = _values(self.operation, context.arguments)
        credential, version, request = values["credential_id"], values["credential_version"], values["request"]
        now, stamp = shared._database_epoch_ns(context.database_now), context.database_now.isoformat()
        current = shared._row(context.exact("credentials", {"id": credential}), "current credential")
        generation = shared._row(context.exact("credential_generations", {"credential_id": credential}), "current generation")
        profile.require(current["id"] == credential and type(current["credential_version"]) is int and current["credential_version"] == version
            and current["lifecycle_status"] == "active"
            and generation["credential_id"] == credential and type(generation["last_version"]) is int and generation["last_version"] == version
            and current["revocation_error"] is None and current["revocation_requested_at"] is None)
        root_selected, root = require_root(context, credential, version)
        static_deployment = None
        if "static_creation_provenance_original" in values:
            from serverware import authority_static_credential_provenance as provenance
            original = values["static_creation_provenance_original"]
            outbox = shared._row(context.exact("metadata_audit_outbox", {"id": provenance.outbox_id(original)}),
                "authenticated completed static creation audit")
            static_deployment = provenance.verify_rows(original, credential=current, generation=generation,
                root=root, outbox=outbox, configuration_digest=values["control_plane_configuration_digest"],
                now_epoch_ns=now)
        elif "static_generation_provenance_original" in values:
            from serverware import authority_static_credential_provenance as provenance
            original = values["static_generation_provenance_original"]
            outbox = shared._row(context.exact("metadata_audit_outbox", {"id": provenance.generation_outbox_id(original)}),
                "authenticated completed static rotation audit")
            static_deployment = provenance.verify_generation_rows(original, credential=current, generation=generation,
                root=root, outbox=outbox, configuration_digest=values["control_plane_configuration_digest"], now_epoch_ns=now)
        else:
            profile.require(current["kind"] == "oauth2")
        mutations, challenge_public, holder_public, barrier_public = [], None, None, None
        if self.operation in {profile.OP_CHALLENGE, profile.OP_REGISTER, profile.OP_ACK}:
            item = request["evidence"]["statement"] if self.operation != profile.OP_CHALLENGE else request
            if self.operation != profile.OP_CHALLENGE:
                if static_deployment is not None:
                    profile.require(static_deployment == item["deploymentId"],
                        "measured holder deployment differs from authenticated static creation")
                else:
                    metadata = shared._canonical_stored_mapping(current["metadata"], "current enrolled credential metadata")
                    association = metadata.get("oauth_application_owner")
                    profile.require(type(association) is dict and association.get("deploymentId") == item["deploymentId"],
                        "measured holder deployment differs from the actual credential association")
            holder_selected, holder = _holder(context, root, item["holderId"])
            if holder is not None:
                profile.require(holder["control_plane_configuration_digest"] == values["control_plane_configuration_digest"],
                    "retained holder cannot cross a control-plane configuration replacement")
            challenge_selected = context.exact(profile.CHALLENGE_TABLE, {"id": item["challengeId"]})
            profile.require(item["issuedAtEpochNs"] <= now < item["expiresAtEpochNs"])
            if item["phase"] == "register":
                profile.require(root["status"] == "open" and root["barrier_id"] is None and holder is None)
            else:
                _, barrier, original = _barrier(context, root, item["barrierId"], item["barrierSha256"])
                profile.require(root["status"] == "quiescing" and barrier["status"] == "quiescing" and holder is not None
                    and holder["status"] == "registered" and holder["acknowledgement_sha256"] is None
                    and holder["acknowledgement_original_json"] is None
                    and original["issuedAtEpochNs"] <= item["issuedAtEpochNs"] < item["expiresAtEpochNs"] <= original["expiresAtEpochNs"]
                    and _frozen(holder) in original["holders"])
                barrier_public = profile.public_barrier(barrier)
            if self.operation == profile.OP_CHALLENGE:
                profile.require(challenge_selected["present"] is False and len(context.present_rows(profile.CHALLENGE_TABLE)) < profile.MAX_ROWS)
                challenge = {"id": item["challengeId"], "root_id": root["id"], "credential_id": credential,
                    "credential_version": version, "epoch": version, "holder_id": item["holderId"], "phase": item["phase"],
                    "challenge": item["challenge"], "barrier_id": item["barrierId"], "barrier_sha256": item["barrierSha256"],
                    "issued_at_epoch_ns": item["issuedAtEpochNs"], "expires_at_epoch_ns": item["expiresAtEpochNs"], "status": "open",
                    "request_digest": context.request_digest, "consumed_request_digest": None, "created_at": stamp, "updated_at": stamp}
            else:
                challenge = shared._row(challenge_selected, "original currentness challenge")
                profile.require(set(challenge) == profile.CHALLENGE_FIELDS and challenge["status"] == "open"
                    and challenge["consumed_request_digest"] is None and challenge["root_id"] == root["id"]
                    and challenge["credential_id"] == credential and challenge["credential_version"] == version and challenge["epoch"] == version)
                original_challenge = {"phase": challenge["phase"], "holderId": challenge["holder_id"], "challengeId": challenge["id"],
                    "challenge": challenge["challenge"], "barrierId": challenge["barrier_id"], "barrierSha256": challenge["barrier_sha256"],
                    "issuedAtEpochNs": challenge["issued_at_epoch_ns"], "expiresAtEpochNs": challenge["expires_at_epoch_ns"]}
                profile.require(profile.canonical(original_challenge) == profile.canonical({name: item[name] for name in profile.CHALLENGE_REQUEST_FIELDS}))
                original = profile.canonical(request["evidence"]).decode("ascii")
                original_sha = profile.sha256(original.encode("ascii"))
                if self.operation == profile.OP_REGISTER:
                    profile.require(len(context.present_rows(profile.HOLDER_TABLE)) < profile.MAX_ROWS)
                    holder = {"id": profile.holder_record_id(root["id"], item["holderId"]), "root_id": root["id"], "credential_id": credential,
                        "credential_version": version, "epoch": version, "holder_id": item["holderId"], "boot_id": item["bootId"], "key_id": item["keyId"],
                        "control_plane_response_signing_key_id": item["controlPlaneResponseSigningKeyId"], "registration_sha256": original_sha,
                        "control_plane_configuration_digest": values["control_plane_configuration_digest"],
                        "registration_original_json": original, "acknowledgement_sha256": None, "acknowledgement_original_json": None,
                        "status": "registered", "created_at": stamp, "updated_at": stamp}
                else:
                    profile.require(item["bootId"] == holder["boot_id"] and item["keyId"] == holder["key_id"]
                        and item["controlPlaneResponseSigningKeyId"] == holder["control_plane_response_signing_key_id"])
                    holder = {**holder, "acknowledgement_sha256": original_sha, "acknowledgement_original_json": original,
                        "status": "acked", "updated_at": stamp}
                mutations.append(core.mutation(operation=self.operation, selected=holder_selected, row=holder))
                holder_public = profile.public_holder(holder)
                challenge = {**challenge, "status": "consumed", "consumed_request_digest": context.request_digest, "updated_at": stamp}
            mutations.append(core.mutation(operation=self.operation, selected=challenge_selected, row=challenge))
            challenge_public = {name: item[name] for name in profile.CHALLENGE_REQUEST_FIELDS}
        elif self.operation == profile.OP_QUIESCE:
            selected = context.exact(profile.BARRIER_TABLE, {"id": request["barrierId"]})
            profile.require(root["status"] == "open" and root["barrier_id"] is None and selected["present"] is False
                and request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"])
            members = _members(context, root)
            profile.require(all(member["control_plane_configuration_digest"] == values["control_plane_configuration_digest"] for member in members),
                "quiesce cannot reinterpret old-configuration registrations")
            profile.require(all(member["status"] == "registered" and member["acknowledgement_sha256"] is None
                and member["acknowledgement_original_json"] is None for member in members))
            original = {"apiVersion": profile.BARRIER_SCHEMA, "barrierId": request["barrierId"], "credentialId": credential,
                "credentialVersion": version, "epoch": version, "holders": [_frozen(member) for member in members],
                "issuedAtEpochNs": request["issuedAtEpochNs"], "expiresAtEpochNs": request["expiresAtEpochNs"]}
            barrier = {"id": request["barrierId"], "root_id": root["id"], "credential_id": credential, "credential_version": version,
                "epoch": version, "original_json": profile.barrier_original(original).decode("ascii"), "original_sha256": profile.barrier_digest(original),
                "status": "quiescing", "quiesce_request_digest": context.request_digest, "admit_request_digest": None,
                "consume_request_digest": None, "created_at": stamp, "updated_at": stamp}
            root = {**root, "status": "quiescing", "barrier_id": barrier["id"], "updated_at": stamp}
            mutations.extend((core.mutation(operation=self.operation, selected=selected, row=barrier),
                core.mutation(operation=self.operation, selected=root_selected, row=root)))
            barrier_public = profile.public_barrier(barrier)
        else:
            selected, barrier, original = _barrier(context, root, request["barrierId"], request["barrierSha256"])
            profile.require(root["status"] == "quiescing" and barrier["status"] == "quiescing"
                and barrier["admit_request_digest"] is None and barrier["consume_request_digest"] is None
                and original["issuedAtEpochNs"] <= now < original["expiresAtEpochNs"])
            members = _members(context, root)
            profile.require(all(member["control_plane_configuration_digest"] == values["control_plane_configuration_digest"] for member in members),
                "admit cannot reinterpret old-configuration registrations")
            profile.require(profile.canonical([_frozen(member) for member in members]) == profile.canonical(original["holders"]))
            for member in members:
                profile.require(member["status"] == "acked" and member["acknowledgement_original_json"] is not None)
                ack = profile.evidence(refresh.document(member["acknowledgement_original_json"].encode("ascii"), 32 * 1024))
                statement = ack["statement"]
                profile.require(profile.sha256(profile.canonical(ack)) == member["acknowledgement_sha256"]
                    and statement["phase"] == "ack" and statement["holderId"] == member["holder_id"]
                    and statement["credentialId"] == credential and statement["credentialVersion"] == version
                    and statement["barrierId"] == barrier["id"] and statement["barrierSha256"] == barrier["original_sha256"])
            root = {**root, "status": "admitted", "updated_at": stamp}
            barrier = {**barrier, "status": "admitted", "admit_request_digest": context.request_digest, "updated_at": stamp}
            mutations.extend((core.mutation(operation=self.operation, selected=root_selected, row=root),
                core.mutation(operation=self.operation, selected=selected, row=barrier)))
            barrier_public = profile.public_barrier(barrier)
        public = {"root": profile.public_root(root), "challenge": challenge_public, "holder": holder_public, "barrier": barrier_public}
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation,
            actor_type="measured_holder_policy", actor_id="credential-currentness", event={"schema": "serverware.credentialCurrentnessAudit/v1",
                "operation": self.operation, "requestDigest": context.request_digest, "currentness": public})
        profile.require(not replay, "currentness original operation is not replayable")
        return core.KernelTransition(mutations=tuple(mutations) + audit, result={"ok": True, "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False, "currentness": public}, work_units=1024)


KERNELS = MappingProxyType({operation: CurrentnessKernel(operation) for operation in profile.OPERATIONS})
