#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ACTIVE_ROUTE_DIGEST = "sha256:" + "a" * 64
OTHER_ROUTE_DIGEST = "sha256:" + "b" * 64
VERIFY_NONCE = "setup-session-api-verifier-nonce-0123456789"


def expect_http_error(
    http_exception: type[BaseException],
    status_code: int,
    callback: Callable[[], Any],
    *,
    detail_contains: str | None = None,
) -> BaseException:
    try:
        callback()
    except http_exception as exc:
        if getattr(exc, "status_code", None) != status_code:
            raise AssertionError(
                f"expected HTTP {status_code}, received {getattr(exc, 'status_code', None)}: {exc}"
            ) from exc
        if detail_contains is not None and detail_contains not in str(
            getattr(exc, "detail", "")
        ):
            raise AssertionError(
                f"HTTP {status_code} detail did not contain {detail_contains!r}: "
                f"{getattr(exc, 'detail', None)!r}"
            ) from exc
        return exc
    raise AssertionError(f"expected HTTP {status_code}")


def expect_validation_error(
    validation_error: type[BaseException],
    callback: Callable[[], Any],
    *,
    message: str,
) -> None:
    try:
        callback()
    except validation_error:
        return
    raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="catchplate-setup-session-api-") as tmp:
        os.environ["CATCHPLATE_DATA_DIR"] = tmp
        os.environ["CATCHPLATE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
        os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "0"
        for name in (
            "CATCHPLATE_METADATA_STORE_POSTGRES_DSN",
            "CATCHPLATE_AUDIT_STORE_POSTGRES_DSN",
            "CATCHPLATE_GRANT_STORE_POSTGRES_DSN",
        ):
            os.environ.pop(name, None)

        from fastapi import HTTPException
        from pydantic import ValidationError

        from catchplate import app as app_module
        from catchplate import db
        from catchplate.auth import AdminIdentity

        db.init_db()

        owner = AdminIdentity(
            "user:setup-owner",
            frozenset({"credential_owner", "policy_author"}),
            "test",
        )
        assignee = AdminIdentity(
            "user:setup-assignee",
            frozenset({"policy_author"}),
            "test",
        )
        outsider = AdminIdentity(
            "user:setup-outsider",
            frozenset({"credential_owner"}),
            "test",
        )
        auditor = AdminIdentity("user:setup-auditor", frozenset({"auditor"}), "test")
        admin = AdminIdentity("user:setup-admin", frozenset({"admin"}), "test")

        original_get_policy_snapshot = app_module.get_policy_snapshot
        original_setup_active_route = app_module._setup_active_route
        app_module.get_policy_snapshot = lambda: object()
        initial_route_digests = {
            "gmail.messages.list": ACTIVE_ROUTE_DIGEST,
            "x.search.recent": OTHER_ROUTE_DIGEST,
            "api.read": ACTIVE_ROUTE_DIGEST,
        }
        app_module._setup_active_route = lambda _snapshot, route_id: (
            object(),
            {"id": route_id},
            initial_route_digests.get(route_id, ACTIVE_ROUTE_DIGEST),
        )

        try:
            # OAuth setup bindings are atomic: neither half can be accepted alone.
            setup_id = str(uuid.uuid4())
            for model, base in (
                (app_module.OAuthStartRequest, {"provider": "google"}),
                (app_module.OAuthPendingActivateRequest, {}),
            ):
                model.model_validate(base)
                paired = model.model_validate(
                    {**base, "setupSessionId": setup_id, "setupRevision": 0}
                )
                if paired.setup_session_id != setup_id or paired.setup_revision != 0:
                    raise AssertionError(
                        f"{model.__name__} lost its setup session binding"
                    )
                snake_case = model.model_validate(
                    {**base, "setup_session_id": setup_id, "setup_revision": 7}
                )
                serialized = snake_case.model_dump(by_alias=True, exclude_none=True)
                if (
                    serialized.get("setupSessionId") != setup_id
                    or serialized.get("setupRevision") != 7
                    or "setup_session_id" in serialized
                    or "setup_revision" in serialized
                ):
                    raise AssertionError(
                        f"{model.__name__} serialized an unstable setup binding"
                    )
                expect_validation_error(
                    ValidationError,
                    lambda model=model, base=base: model.model_validate(
                        {**base, "setupSessionId": setup_id}
                    ),
                    message=f"{model.__name__} accepted setupSessionId without setupRevision",
                )
                expect_validation_error(
                    ValidationError,
                    lambda model=model, base=base: model.model_validate(
                        {**base, "setupRevision": 0}
                    ),
                    message=f"{model.__name__} accepted setupRevision without setupSessionId",
                )
                expect_validation_error(
                    ValidationError,
                    lambda model=model, base=base: model.model_validate(
                        {**base, "setupSessionId": setup_id, "setupRevision": None}
                    ),
                    message=f"{model.__name__} accepted a null setupRevision with setupSessionId",
                )
                expect_validation_error(
                    ValidationError,
                    lambda model=model, base=base: model.model_validate(
                        {**base, "setupSessionId": setup_id.upper(), "setupRevision": 0}
                    ),
                    message=f"{model.__name__} accepted a non-canonical setup session ID",
                )
                expect_validation_error(
                    ValidationError,
                    lambda model=model, base=base: model.model_validate(
                        {**base, "setupSessionId": setup_id, "setupRevision": -1}
                    ),
                    message=f"{model.__name__} accepted a negative setup revision",
                )
                expect_validation_error(
                    ValidationError,
                    lambda model=model, base=base: model.model_validate(
                        {**base, "setupSessionID": setup_id, "setupRevision": 0}
                    ),
                    message=f"{model.__name__} accepted an unknown setup binding field",
                )

            expect_validation_error(
                ValidationError,
                lambda: app_module.SetupSessionCreateRequest.model_validate(
                    {"routePolicyDigest": ACTIVE_ROUTE_DIGEST}
                ),
                message="Setup creation accepted a route digest without a route ID",
            )
            draft_route_request = app_module.SetupSessionCreateRequest.model_validate(
                {"routeId": "route:planned-before-activation"}
            )
            if (
                draft_route_request.route_id != "route:planned-before-activation"
                or draft_route_request.route_policy_digest is not None
            ):
                raise AssertionError("Setup creation lost its draft route binding")
            expect_validation_error(
                ValidationError,
                lambda: app_module.SetupSessionRevisionRequest.model_validate(
                    {"expectedRevision": 0, "transition": "complete"}
                ),
                message="Setup revision input accepted a caller-selected transition",
            )

            setup_routes = {
                (route.path, method)
                for route in app_module.app.routes
                if route.path.startswith("/api/setup/sessions")
                for method in getattr(route, "methods", set())
            }
            if any(
                method == "PATCH" or path.endswith("/transition")
                for path, method in setup_routes
            ):
                raise AssertionError(
                    "Setup API exposed a generic client-selected transition endpoint"
                )

            first = app_module.setup_session_create(
                app_module.SetupSessionCreateRequest(
                    templateId="template:gmail-read",
                    principalId="agent:mail-reader",
                    routeId="gmail.messages.list",
                    routePolicyDigest=ACTIVE_ROUTE_DIGEST,
                ),
                identity=owner,
            )
            first_session = first["session"]
            if (
                first_session["ownerId"] != owner.user_id
                or first_session["currentAssigneeId"] != owner.user_id
                or first_session["phase"] != "created"
                or first_session["revision"] != 0
                or first_session["routePolicyDigest"] != ACTIVE_ROUTE_DIGEST
            ):
                raise AssertionError(
                    f"Setup creation returned an invalid public session: {first_session}"
                )
            if first["audit"] != {"claimed": 1, "audited": 1, "failed": 0}:
                raise AssertionError(
                    f"Setup creation did not synchronously drain its outbox: {first}"
                )

            second = app_module.setup_session_create(
                app_module.SetupSessionCreateRequest(
                    templateId="template:x-read",
                    principalId="agent:social-reader",
                    routeId="x.search.recent",
                    routePolicyDigest=OTHER_ROUTE_DIGEST,
                ),
                identity=assignee,
            )["session"]

            owner_list = app_module.setup_sessions(
                status=None, limit=100, identity=owner
            )["sessions"]
            outsider_list = app_module.setup_sessions(
                status=None, limit=100, identity=outsider
            )["sessions"]
            auditor_list = app_module.setup_sessions(
                status=None, limit=100, identity=auditor
            )["sessions"]
            if {item["id"] for item in owner_list} != {first_session["id"]}:
                raise AssertionError(
                    f"owner list leaked or omitted Setup sessions: {owner_list}"
                )
            if outsider_list:
                raise AssertionError(
                    f"outsider list leaked Setup sessions: {outsider_list}"
                )
            if {item["id"] for item in auditor_list} != {
                first_session["id"],
                second["id"],
            }:
                raise AssertionError(
                    f"auditor did not receive the complete Setup list: {auditor_list}"
                )

            expect_http_error(
                HTTPException,
                403,
                lambda: app_module.setup_session_get(
                    first_session["id"], identity=outsider
                ),
                detail_contains="another operator",
            )
            audited_read = app_module.setup_session_get(
                first_session["id"], identity=auditor
            )["session"]
            if (
                not audited_read.get("events")
                or audited_read["events"][0]["audit_status"] != "audited"
            ):
                raise AssertionError(
                    f"auditor read did not expose audited transition history: {audited_read}"
                )

            handed_off = app_module.setup_session_handoff(
                first_session["id"],
                app_module.SetupSessionHandoffRequest(
                    expectedRevision=first_session["revision"],
                    assigneeId=assignee.user_id,
                ),
                identity=owner,
            )["session"]
            if (
                handed_off["currentAssigneeId"] != assignee.user_id
                or handed_off["revision"] != 1
            ):
                raise AssertionError(
                    f"owner handoff did not advance the Setup session: {handed_off}"
                )
            if (
                app_module.setup_session_get(first_session["id"], identity=assignee)[
                    "session"
                ]["id"]
                != first_session["id"]
            ):
                raise AssertionError(
                    "the current assignee could not read the handed-off Setup session"
                )
            expect_http_error(
                HTTPException,
                403,
                lambda: app_module.setup_session_handoff(
                    first_session["id"],
                    app_module.SetupSessionHandoffRequest(
                        expectedRevision=handed_off["revision"],
                        assigneeId=outsider.user_id,
                    ),
                    identity=assignee,
                ),
                detail_contains="only the setup owner or an admin",
            )
            admin_handoff = app_module.setup_session_handoff(
                first_session["id"],
                app_module.SetupSessionHandoffRequest(
                    expectedRevision=handed_off["revision"],
                    assigneeId=outsider.user_id,
                ),
                identity=admin,
            )["session"]
            if (
                admin_handoff["currentAssigneeId"] != outsider.user_id
                or admin_handoff["revision"] != 2
            ):
                raise AssertionError(
                    f"admin handoff did not advance the Setup session: {admin_handoff}"
                )
            expect_http_error(
                HTTPException,
                403,
                lambda: app_module.setup_session_get(
                    first_session["id"], identity=assignee
                ),
                detail_contains="another operator",
            )

            credential = db.create_credential(
                "Setup session API bearer",
                "bearer",
                "setup-session-api-secret",
                {"injection": {"header": "Authorization", "scheme": "Bearer"}},
            )
            stale = expect_http_error(
                HTTPException,
                409,
                lambda: app_module.setup_session_bind_credential(
                    first_session["id"],
                    app_module.SetupSessionCredentialRequest(
                        expectedRevision=first_session["revision"],
                        credentialId=credential["id"],
                    ),
                    identity=owner,
                ),
                detail_contains="setup_session_stale_revision",
            )
            stale_detail = getattr(stale, "detail", {})
            if (
                not isinstance(stale_detail, dict)
                or stale_detail.get("currentRevision") != 2
            ):
                raise AssertionError(
                    f"stale Setup error omitted the authoritative revision: {stale_detail}"
                )

            credential_setup = app_module.setup_session_create(
                app_module.SetupSessionCreateRequest(
                    principalId="agent:credential-test",
                    routeId="api.read",
                    routePolicyDigest=ACTIVE_ROUTE_DIGEST,
                ),
                identity=owner,
            )["session"]
            expect_http_error(
                HTTPException,
                403,
                lambda: app_module.setup_session_bind_credential(
                    credential_setup["id"],
                    app_module.SetupSessionCredentialRequest(
                        expectedRevision=credential_setup["revision"],
                        credentialId=credential["id"],
                    ),
                    identity=outsider,
                ),
                detail_contains="another operator",
            )
            bound = app_module.setup_session_bind_credential(
                credential_setup["id"],
                app_module.SetupSessionCredentialRequest(
                    expectedRevision=credential_setup["revision"],
                    credentialId=credential["id"],
                ),
                identity=owner,
            )
            bound_session = bound["session"]
            if (
                bound_session["phase"] != "credential_activated"
                or bound_session["credentialId"] != credential["id"]
                or bound_session["credentialVersion"] != 1
                or bound_session["revision"] != 1
            ):
                raise AssertionError(
                    f"credential binding was incomplete: {bound_session}"
                )
            if bound["audit"] != {"claimed": 1, "audited": 1, "failed": 0}:
                raise AssertionError(
                    f"credential binding did not synchronously drain its outbox: {bound}"
                )

            replacement = db.create_credential(
                "Setup session API replacement",
                "bearer",
                "setup-session-api-replacement-secret",
                {},
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.setup_session_bind_credential(
                    credential_setup["id"],
                    app_module.SetupSessionCredentialRequest(
                        expectedRevision=bound_session["revision"],
                        credentialId=replacement["id"],
                    ),
                    identity=owner,
                ),
                detail_contains="cannot be rebound",
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.setup_session_verify(
                    credential_setup["id"],
                    app_module.SetupSessionVerifyRequest(
                        expectedRevision=bound_session["revision"],
                        nonce=VERIFY_NONCE,
                    ),
                    identity=owner,
                ),
                detail_contains="complete active assignment",
            )

            generation_credential = db.create_credential(
                "Setup generation recheck",
                "bearer",
                "setup-generation-recheck-secret",
                {},
            )
            generation_setup = app_module.setup_session_create(
                app_module.SetupSessionCreateRequest(
                    principalId="agent:generation-recheck",
                    routeId="api.generation",
                    routePolicyDigest=ACTIVE_ROUTE_DIGEST,
                ),
                identity=owner,
            )["session"]
            generation_setup = app_module.setup_session_bind_credential(
                generation_setup["id"],
                app_module.SetupSessionCredentialRequest(
                    expectedRevision=generation_setup["revision"],
                    credentialId=generation_credential["id"],
                ),
                identity=owner,
            )["session"]
            generation_policy_hash = "sha256:" + "c" * 64
            generation_assignment, generation_assignment_digest = (
                app_module._setup_assignment(
                    principal_id=generation_setup["principalId"],
                    route_id=generation_setup["routeId"],
                    credential_id=generation_setup["credentialId"],
                    credential_version=generation_setup["credentialVersion"],
                    policy_hash=generation_policy_hash,
                    route_policy_digest=ACTIVE_ROUTE_DIGEST,
                )
            )
            staged_generation = db.transition_setup_session(
                generation_setup["id"],
                expected_revision=generation_setup["revision"],
                transition="bind_candidate",
                actor_id=owner.user_id,
                updates={
                    "canary_id": "canary:generation-recheck",
                    "policy_hash": generation_policy_hash,
                    "route_policy_digest": ACTIVE_ROUTE_DIGEST,
                    "assignment_digest": generation_assignment_digest,
                },
                event={"assignment": generation_assignment},
            )
            rotated_generation = db.update_credential(
                generation_credential["id"],
                {"secret": "setup-generation-recheck-rotated"},
            )
            if not rotated_generation or rotated_generation["credential_version"] != 2:
                raise AssertionError("active credential generation fixture did not rotate")
            app_module.get_policy_snapshot = lambda: SimpleNamespace(
                hash=generation_policy_hash
            )
            app_module._setup_active_route = lambda _snapshot, route_id: (
                SimpleNamespace(credential_ref=generation_credential["id"]),
                {"id": route_id, "credentialRef": generation_credential["id"]},
                ACTIVE_ROUTE_DIGEST,
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.setup_session_bind_active_policy(
                    staged_generation["id"],
                    app_module.SetupSessionRevisionRequest(
                        expectedRevision=staged_generation["revision"]
                    ),
                    identity=owner,
                ),
                detail_contains="active credential generation no longer matches",
            )
            generation_after_rejection = db.get_setup_session(staged_generation["id"])
            if not generation_after_rejection or generation_after_rejection[
                "phase"
            ] != "policy_staged":
                raise AssertionError(
                    "credential generation drift advanced policy confirmation"
                )
            app_module.get_policy_snapshot = lambda: object()
            app_module._setup_active_route = lambda _snapshot, route_id: (
                object(),
                {"id": route_id},
                initial_route_digests.get(route_id, ACTIVE_ROUTE_DIGEST),
            )

            # A reviewed route digest is checked against live policy state at creation.
            app_module.get_policy_snapshot = lambda: None
            draft_route = app_module.setup_session_create(
                app_module.SetupSessionCreateRequest(
                    templateId="template:draft-route",
                    principalId="agent:draft-route",
                    routeId="route:planned-before-activation",
                ),
                identity=owner,
            )["session"]
            if (
                draft_route["routeId"] != "route:planned-before-activation"
                or draft_route["routePolicyDigest"] is not None
            ):
                raise AssertionError(
                    f"draft Setup route was incorrectly treated as authoritative: {draft_route}"
                )
            expect_http_error(
                HTTPException,
                503,
                lambda: app_module.setup_session_create(
                    app_module.SetupSessionCreateRequest(
                        principalId="agent:route-unavailable",
                        routeId="route:stable-id",
                        routePolicyDigest=ACTIVE_ROUTE_DIGEST,
                    ),
                    identity=owner,
                ),
                detail_contains="active signed policy is unavailable",
            )
            app_module.get_policy_snapshot = lambda: object()
            app_module._setup_active_route = lambda _snapshot, _route_id: (
                None,
                None,
                None,
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.setup_session_create(
                    app_module.SetupSessionCreateRequest(
                        principalId="agent:route-missing",
                        routeId="route:stable-id",
                        routePolicyDigest=ACTIVE_ROUTE_DIGEST,
                    ),
                    identity=owner,
                ),
                detail_contains="authoritative active setup route is unavailable",
            )
            app_module._setup_active_route = lambda _snapshot, route_id: (
                object(),
                {"id": route_id},
                ACTIVE_ROUTE_DIGEST,
            )
            before_mismatch = len(db.list_setup_sessions(limit=100))
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.setup_session_create(
                    app_module.SetupSessionCreateRequest(
                        principalId="agent:route-mismatch",
                        routeId="route:stable-id",
                        routePolicyDigest=OTHER_ROUTE_DIGEST,
                    ),
                    identity=owner,
                ),
                detail_contains="does not match the active route",
            )
            if len(db.list_setup_sessions(limit=100)) != before_mismatch:
                raise AssertionError(
                    "route digest mismatch created a durable Setup session"
                )
            route_bound = app_module.setup_session_create(
                app_module.SetupSessionCreateRequest(
                    principalId="agent:route-match",
                    routeId="route:stable-id",
                    routePolicyDigest=ACTIVE_ROUTE_DIGEST,
                ),
                identity=owner,
            )["session"]
            if route_bound["routePolicyDigest"] != ACTIVE_ROUTE_DIGEST:
                raise AssertionError(
                    f"active route digest was not bound at creation: {route_bound}"
                )

            # Route authority is re-checked immediately before OAuth consent.
            unbound_route = app_module.setup_session_create(
                app_module.SetupSessionCreateRequest(
                    principalId="agent:route-unbound",
                ),
                identity=owner,
            )["session"]
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.oauth_start(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialName="Unbound route OAuth",
                        setupSessionId=unbound_route["id"],
                        setupRevision=unbound_route["revision"],
                    ),
                    response=app_module.Response(),
                    identity=owner,
                ),
                detail_contains="requires an intended route ID",
            )
            app_module.get_policy_snapshot = lambda: None
            expect_http_error(
                HTTPException,
                503,
                lambda: app_module.oauth_start(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialName="Unavailable route OAuth",
                        setupSessionId=route_bound["id"],
                        setupRevision=route_bound["revision"],
                    ),
                    response=app_module.Response(),
                    identity=owner,
                ),
                detail_contains="active signed policy is unavailable",
            )
            app_module.get_policy_snapshot = lambda: object()
            app_module._setup_active_route = lambda _snapshot, _route_id: (
                object(),
                {"id": "route:stable-id"},
                OTHER_ROUTE_DIGEST,
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.oauth_start(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialName="Mismatched route OAuth",
                        setupSessionId=route_bound["id"],
                        setupRevision=route_bound["revision"],
                    ),
                    response=app_module.Response(),
                    identity=owner,
                ),
                detail_contains="does not match the active route",
            )
            route_after_rejection = db.get_setup_session(route_bound["id"])
            if not route_after_rejection or route_after_rejection["phase"] != "created":
                raise AssertionError(
                    "rejected route authority check started durable OAuth consent"
                )
            app_module._setup_active_route = lambda _snapshot, route_id: (
                object(),
                {"id": route_id},
                ACTIVE_ROUTE_DIGEST,
            )

            # Setup-bound OAuth consent remains owner-only even after an operator handoff.
            expect_http_error(
                HTTPException,
                403,
                lambda: app_module.oauth_start(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialName="Owner-bound OAuth",
                        setupSessionId=first_session["id"],
                        setupRevision=admin_handoff["revision"],
                    ),
                    response=app_module.Response(),
                    identity=outsider,
                ),
                detail_contains="only the setup owner",
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.oauth_start(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialName="Stale owner OAuth",
                        setupSessionId=first_session["id"],
                        setupRevision=0,
                    ),
                    response=app_module.Response(),
                    identity=owner,
                ),
                detail_contains="setup_session_stale_revision",
            )
            expect_http_error(
                HTTPException,
                409,
                lambda: app_module.oauth_start(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialId=credential["id"],
                        setupSessionId=first_session["id"],
                        setupRevision=admin_handoff["revision"],
                    ),
                    response=app_module.Response(),
                    identity=owner,
                ),
                detail_contains="cannot reconnect an existing grant",
            )

            final_read = app_module.setup_session_get(
                credential_setup["id"], identity=auditor
            )["session"]
            if any(
                event["audit_status"] != "audited"
                for event in final_read.get("events", [])
            ):
                raise AssertionError(
                    f"Setup transition outbox was not fully audited: {final_read}"
                )
            setup_audit = [
                event
                for event in db.list_audit_events(limit=500)
                if event["event_type"].startswith("setup.")
            ]
            if not setup_audit or not all(
                event["event"].get("setup_event_id")
                and event["event"]
                .get("setup_event_payload_digest", "")
                .startswith("sha256:")
                for event in setup_audit
            ):
                raise AssertionError(
                    f"Setup outbox audit records are missing stable bindings: {setup_audit}"
                )
            audit_count = len(setup_audit)
            if app_module._drain_setup_session_audit_outbox() != {
                "claimed": 0,
                "audited": 0,
                "failed": 0,
            }:
                raise AssertionError(
                    "an already-drained Setup outbox was not idempotent"
                )
            if (
                len(
                    [
                        event
                        for event in db.list_audit_events(limit=500)
                        if event["event_type"].startswith("setup.")
                    ]
                )
                != audit_count
            ):
                raise AssertionError(
                    "idempotent Setup outbox drain duplicated audit events"
                )
        finally:
            app_module.get_policy_snapshot = original_get_policy_snapshot
            app_module._setup_active_route = original_setup_active_route

    print(
        json.dumps(
            {
                "auth_isolation": "pass",
                "oauth_setup_binding": "pass",
                "ok": True,
                "outbox_audit": "pass",
                "setup_session_api": "pass",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
