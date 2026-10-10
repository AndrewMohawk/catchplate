"""Bounded administrator API for the operator-development resource catalog.

Transport admission stays here; catalog persistence and policy publication stay
with their existing owners. No request, credential, token or exception body is
logged. This module grants no native or production authority.
"""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from serverware import auth, config, operator_demo
from serverware import operator_catalog_timing as _catalog_timing
from serverware.setup_receipts import JsonLimits, parse_strict_json_object


PREFIX = "/api/operator-demo"
CATALOG_PATH = PREFIX + "/catalog"
MUTATION_PATHS = frozenset(PREFIX + path for path in (
    "/credentials", "/credentials/revoke", "/credentials/replace-key", "/credentials/github-token", "/credentials/npm-token", "/applications", "/applications/revoke",
    "/applications/rotate-token", "/applications/proxy-authentication",
    "/access-rules", "/access-rules/revoke", "/access-rules/gmail-read", "/access-rules/github", "/access-rules/npm-metadata", "/access-rules/npm-publish",
    "/oauth/google/disconnect", "/oauth/google/reauthorize", "/oauth/google/reauthorization-storage",
    "/oauth/google/setup", "/oauth/google/setup/cancel",
    "/proxy/upstreams", "/proxy/upstreams/cancel",
    "/notifications/settings", "/notifications/test",
))
router = APIRouter(prefix=PREFIX)
_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
_ADMIN_ROLE = auth.require_role("admin")
_WORKER_SLOTS = asyncio.BoundedSemaphore(4)


def _reject(status: int, detail: str) -> None:
    raise HTTPException(status_code=status, detail=detail, headers=_HEADERS)


def _profile() -> None:
    try:
        enabled = operator_demo.active()
    except Exception:
        _reject(503, "operator workspace unavailable")
    if not enabled:
        _reject(404, "not found")


def _admin_identity(request: Request) -> auth.AdminIdentity:
    _profile()
    if any(len(request.headers.getlist(name)) > 1 for name in ("authorization", "x-serverware-admin-token")):
        _reject(401, "administrator authentication required")
    try:
        identity = auth.require_admin(request, request.headers.get("x-serverware-admin-token"))
        return _ADMIN_ROLE(identity)
    except HTTPException as exc:
        status = exc.status_code if exc.status_code in {401, 403, 503} else 503
        details = {401: "administrator authentication required", 403: "administrator access required",
            503: "administrator authentication unavailable"}
        _reject(status, details[status])
    except Exception:
        _reject(503, "administrator authentication unavailable")


async def _blocking(function, *args, observation=None):
    from serverware import app as application

    # The existing helper retains its slot until the worker exits, including
    # when an HTTP caller disconnects. A cancelled request never retries work.
    return await application._run_bounded_blocking(
        _WORKER_SLOTS, function, *args,
        _catalog_observation=observation, _catalog_phase="mutation",
    )


def legacy_catalog_refusal() -> JSONResponse:
    return JSONResponse(status_code=409, headers=_HEADERS, content={
        "code": "operator_demo_resource_model_changed",
        "detail": "This workspace uses separate credentials, applications and access rules. Reload the workspace before continuing.",
        "catalog_path": CATALOG_PATH,
    })


def legacy_catalog_guard() -> JSONResponse | None:
    from serverware import operator_catalog_schema

    try:
        migrated = operator_catalog_schema.active()
    except Exception:
        _reject(503, "operator workspace status unavailable")
    return legacy_catalog_refusal() if migrated else None


def _admit(request: Request, *, mutation: bool) -> None:
    _profile()
    if request.query_params:
        _reject(422, "operator catalog requests do not accept query parameters")
    if mutation and request.headers.getlist("origin") != [config.PUBLIC_URL.rstrip("/")]:
        _reject(403, "same-origin operator session required")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


async def _payload(request: Request, model, maximum: int):
    content_types = request.headers.getlist("content-type")
    if (len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
            or request.headers.getlist("content-encoding")):
        _reject(415, "operator catalog requires unencoded application/json")
    lengths = request.headers.getlist("content-length")
    transfers = request.headers.getlist("transfer-encoding")
    if len(lengths) > 1 or len(transfers) > 1 or lengths and transfers:
        _reject(400, "ambiguous operator catalog request framing")
    if transfers and transfers[0].strip().lower() != "chunked":
        _reject(400, "unsupported operator catalog transfer encoding")
    declared = None
    if lengths:
        if not lengths[0].isascii() or not lengths[0].isdecimal() or len(lengths[0]) > 10:
            _reject(400, "invalid operator catalog content length")
        declared = int(lengths[0])
        if declared > maximum:
            _reject(413, "operator catalog input exceeds size limit")
    body = bytearray()
    try:
        async with asyncio.timeout(30):
            async for chunk in request.stream():
                if len(chunk) > maximum - len(body):
                    _reject(413, "operator catalog input exceeds size limit")
                body.extend(chunk)
    except HTTPException:
        raise
    except TimeoutError:
        _reject(408, "operator catalog request body timed out")
    except Exception:
        _reject(400, "operator catalog request body unavailable")
    if declared is not None and declared != len(body):
        _reject(400, "operator catalog content length mismatch")
    try:
        value = parse_strict_json_object(bytes(body), limits=JsonLimits(
            max_bytes=maximum, max_depth=4, max_object_keys=24, max_total_keys=32,
            max_array_items=64, max_total_nodes=512, max_string_bytes=8192,
        ))
        return model.model_validate(_plain(value))
    except (ValueError, TypeError, RecursionError):
        # Pydantic and parser exceptions can contain submitted secret material.
        _reject(422, "invalid operator catalog input")


async def _mutate(request: Request, identity: auth.AdminIdentity, model_name: str,
        operation_name: str, maximum: int, *, created: bool = False) -> JSONResponse:
    from serverware import operator_catalog_inputs as inputs
    from serverware import operator_catalog_mutations as mutations
    from serverware import operator_catalog_schema

    _admit(request, mutation=True)
    # _admit and the route's admin dependency own admission. The tracker is
    # private until input validation succeeds and never grants authority.
    observation = _catalog_timing.create(operation_name, operator_development=True)
    request.scope["serverware.operator_catalog_timing"] = observation
    _catalog_timing.mark(observation, "api_admitted")
    payload = await _payload(request, getattr(inputs, model_name), maximum)
    _catalog_timing.mark(observation, "payload_validated")
    _catalog_timing.activate(observation)
    try:
        result = await _blocking(getattr(mutations, operation_name), payload, identity.user_id,
            observation=observation)
    except mutations.CatalogNotFound:
        _reject(404, "operator catalog resource not found")
    except operator_catalog_schema.CatalogConflict:
        _reject(409, "operator catalog or policy changed; refresh before trying again")
    except mutations.CatalogLimitReached:
        _reject(409, "operator catalog capacity reached; inspect workspace limits before trying again")
    except ValueError:
        _reject(422, "invalid operator catalog input or unsupported policy")
    except Exception:
        _reject(503, "operator catalog storage unavailable; inspect saved status before retrying")
    try:
        return JSONResponse(result, status_code=201 if created else 200, headers=_HEADERS)
    except Exception:
        _reject(503, "operator catalog result unavailable; inspect saved status before retrying")


@router.get("/catalog")
async def catalog(request: Request, _: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_catalog_mutations as mutations

    _admit(request, mutation=False)
    if request.headers.getlist("transfer-encoding") or request.headers.getlist("content-length") not in ([], ["0"]):
        _reject(400, "operator catalog status accepts no body")
    try:
        result = await _blocking(mutations.catalog_status)
        return JSONResponse(result, headers=_HEADERS)
    except Exception:
        _reject(503, "operator catalog status unavailable")


@router.post("/credentials")
async def create_credential(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "CredentialInput", "create_credential", 16384, created=True)


@router.post("/credentials/revoke")
async def revoke_credential(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "TargetInput", "revoke_credential", 1024)


@router.post("/credentials/github-token")
async def create_github_credential(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "GithubTokenInput", "create_github_credential", 16384, created=True)


@router.post("/credentials/replace-key")
async def replace_credential_key(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "ReplaceCredentialKeyInput", "replace_credential_key", 16384)


@router.post("/credentials/npm-token")
async def create_npm_credential(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "NpmTokenInput", "create_npm_credential", 16384, created=True)


@router.post("/applications")
async def create_application(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "ApplicationInput", "create_application", 2048, created=True)


@router.post("/applications/revoke")
async def revoke_application(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "TargetInput", "revoke_application", 1024)


@router.post("/applications/rotate-token")
async def rotate_application_token(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "RotateApplicationInput", "rotate_application_token", 2048)


@router.post("/applications/proxy-authentication")
async def set_application_proxy_authentication(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "ApplicationProxyAuthenticationInput", "set_application_proxy_authentication", 2048)


@router.post("/access-rules")
async def create_rule(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "RuleInput", "create_rule", 32768, created=True)


@router.post("/access-rules/revoke")
async def revoke_rule(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "TargetInput", "revoke_rule", 1024)


@router.post("/access-rules/gmail-read")
async def create_gmail_rule(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "GmailReadRuleInput", "create_gmail_rule", 4096, created=True)


@router.post("/access-rules/github")
async def create_github_rule(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "GithubRuleInput", "create_github_rule", 4096, created=True)


@router.post("/access-rules/npm-metadata")
async def create_npm_rule(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "NpmMetadataRuleInput", "create_npm_rule", 16384, created=True)


@router.post("/access-rules/npm-publish")
async def create_npm_publish_rule(request: Request, identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    return await _mutate(request, identity, "NpmPublishRuleInput", "create_npm_publish_rule", 4096, created=True)


async def _google_disconnect_result(function, *args, accepted: bool = False) -> JSONResponse:
    """A transport failure is not a disconnect rollback or permission to retry."""
    from serverware import operator_google_disconnect as lifecycle
    from serverware.operator_catalog_mutations import CatalogNotFound
    from serverware.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

    try:
        result = await _blocking(function, *args)
    except CatalogNotFound:
        _reject(404, "Google account or disconnect operation not found")
    except CatalogConflict:
        _reject(409, "Google account or affected access changed; inspect saved status before continuing")
    except (lifecycle.DisconnectUnavailable, CatalogIntegrityError):
        _reject(503, "Google disconnect status unavailable; inspect saved status before continuing")
    except ValueError:
        _reject(422, "invalid Google disconnect input")
    except Exception:
        _reject(503, "Google disconnect outcome unavailable; do not repeat the action automatically")
    if result is None:
        # Absence is deliberately not a successful rollback/retirement receipt.
        _reject(404, "Google disconnect operation not found; absence does not authorize retry")
    try:
        status_code = 503 if result.get("outcome") == "unknown" else 202 if accepted else 200
        return JSONResponse(result, status_code=status_code, headers=_HEADERS)
    except Exception:
        _reject(503, "Google disconnect result unavailable; inspect saved status before continuing")


@router.post("/oauth/google/disconnect")
async def disconnect_google_account(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_disconnect as lifecycle
    from serverware.operator_catalog_inputs import GoogleDisconnectInput

    _admit(request, mutation=True)
    payload = await _payload(request, GoogleDisconnectInput, 8192)
    return await _google_disconnect_result(lifecycle.disconnect, payload, identity.user_id, accepted=True)


@router.get("/oauth/google/disconnect/{credential_id}")
async def google_disconnect_status(credential_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_disconnect as lifecycle
    from serverware.operator_catalog_inputs import _identifier

    _admit(request, mutation=False)
    if request.headers.getlist("transfer-encoding") or request.headers.getlist("content-length") not in ([], ["0"]):
        _reject(400, "Google disconnect status accepts no body")
    try:
        _identifier(credential_id)
    except (ValueError, TypeError, AttributeError):
        _reject(422, "invalid Google account identifier")
    return await _google_disconnect_result(lifecycle.status_for_credential, credential_id, identity.user_id)


async def _google_reauthorization_result(function, *args):
    """Never translate an unavailable receipt into rollback or a retry grant."""
    from serverware.operator_catalog_schema import CatalogConflict

    try:
        result = await _blocking(function, *args)
    except CatalogConflict:
        _reject(409, "Google account or reviewed access changed; check saved reauthorization status")
    except Exception:
        _reject(503, "Google reauthorization outcome unavailable; check saved status without repeating the action")
    if result is None:
        _reject(404, "Google reauthorization record not found; absence does not authorize retry")
    return result


def _google_reauthorization_read(request: Request, identifier: str) -> None:
    from serverware.operator_catalog_inputs import _identifier

    _admit(request, mutation=False)
    if request.headers.getlist("transfer-encoding") or request.headers.getlist("content-length") not in ([], ["0"]):
        _reject(400, "Google reauthorization status accepts no body")
    try:
        _identifier(identifier)
    except (ValueError, TypeError, AttributeError):
        _reject(422, "invalid Google reauthorization identifier")


@router.get("/oauth/google/reauthorize/{credential_id}/review")
async def review_google_reauthorization(credential_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_reauthorization as lifecycle

    _google_reauthorization_read(request, credential_id)
    result = await _google_reauthorization_result(lifecycle.review, credential_id, identity.user_id)
    return JSONResponse(result, headers=_HEADERS)


@router.get("/oauth/google/reauthorize/{operation_id}")
async def google_reauthorization_status(operation_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_reauthorization as lifecycle

    _google_reauthorization_read(request, operation_id)
    result = await _google_reauthorization_result(lifecycle.status, operation_id, identity.user_id)
    return JSONResponse(result, headers=_HEADERS)


@router.post("/oauth/google/reauthorize")
async def reauthorize_google_account(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    import secrets
    import time
    from serverware import oauth, operator_google_reauthorization as lifecycle

    _admit(request, mutation=True)
    payload = await _payload(request, lifecycle.ReauthorizeInput, 8192)
    browser_nonce = secrets.token_urlsafe(32)
    result = await _google_reauthorization_result(lifecycle.start, payload, identity.user_id, browser_nonce)
    # Only a durably bound start may hand out a browser cookie. If constructing
    # the response fails, the caller still owns its exact public operation ID.
    try:
        response = JSONResponse(result, headers=_HEADERS)
        response.set_cookie(oauth.browser_cookie_name(result["state"]), browser_nonce,
            max_age=max(1, result["expiresAtEpoch"] - int(time.time())),
            path="/", secure=True, httponly=True, samesite="lax")
        return response
    except Exception:
        _reject(503, "Google reauthorization start response unavailable; check saved status without repeating the action")


@router.get("/oauth/google/reauthorization-storage")
async def google_reauthorization_storage_status(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_reauthorization_setup as setup

    _admit(request, mutation=False)
    if request.headers.getlist("transfer-encoding") or request.headers.getlist("content-length") not in ([], ["0"]):
        _reject(400, "Google reauthorization setup status accepts no body")
    result = await _google_reauthorization_result(setup.status, identity.user_id)
    return JSONResponse(result, headers=_HEADERS)


@router.post("/oauth/google/reauthorization-storage")
async def enable_google_reauthorization_storage(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_reauthorization_setup as setup

    _admit(request, mutation=True)
    payload = await _payload(request, setup.SetupInput, 2048)
    result = await _google_reauthorization_result(setup.enable, payload, identity.user_id)
    return JSONResponse(result, headers=_HEADERS)


async def _google_setup_result(function, *args):
    from serverware import operator_google_setup as setup
    from serverware.operator_catalog_schema import CatalogConflict

    try:
        return await _blocking(function, *args)
    except setup.SetupNotFound:
        _reject(404, "Google setup operation not found")
    except CatalogConflict:
        _reject(409, "Google setup review changed; inspect saved status before preparing again")
    except setup.SetupUnavailable:
        _reject(409, "Google setup unavailable for this deployment state")
    except ValueError:
        _reject(422, "invalid Google setup input")
    except Exception:
        _reject(503, "Google setup status unavailable; inspect the operation without repeating the action")


def _google_setup_read_admission(request: Request) -> None:
    _admit(request, mutation=False)
    if request.headers.getlist("transfer-encoding") or request.headers.getlist("content-length") not in ([], ["0"]):
        _reject(400, "Google setup status accepts no body")


@router.get("/oauth/google/setup")
async def google_setup_review(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_setup as setup

    _google_setup_read_admission(request)
    result = await _google_setup_result(setup.review, identity.user_id)
    return JSONResponse(result, headers=_HEADERS)


@router.post("/oauth/google/setup")
async def prepare_google_setup(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_setup as setup

    _admit(request, mutation=True)
    payload = await _payload(request, setup.SetupInput, 4096)
    result = await _google_setup_result(setup.prepare, payload, identity.user_id)
    return JSONResponse(result, status_code=201, headers=_HEADERS)


@router.get("/oauth/google/setup/{operation_id}")
async def google_setup_status(operation_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_setup as setup

    _google_setup_read_admission(request)
    result = await _google_setup_result(setup.status, operation_id, identity.user_id)
    return JSONResponse(result, headers=_HEADERS)


@router.post("/oauth/google/setup/cancel")
async def cancel_google_setup(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_google_setup as setup

    _admit(request, mutation=True)
    payload = await _payload(request, setup.CancelInput, 2048)
    result = await _google_setup_result(setup.cancel, payload, identity.user_id)
    return JSONResponse(result, headers=_HEADERS)


async def _upstream_setup_result(function, *args, created: bool = False) -> JSONResponse:
    """A missing response never authorizes replay or applies pending settings."""
    from serverware import operator_upstream_setup as setup
    from serverware.operator_catalog_schema import CatalogConflict

    try:
        result = await _blocking(function, *args)
    except setup.SetupNotFound:
        _reject(404, "upstream setup operation not found")
    except CatalogConflict:
        _reject(409, "upstream setup review changed; inspect saved status before preparing again")
    except setup.SetupUnavailable:
        _reject(503, "upstream setup status unavailable; inspect the operation without repeating the action")
    except ValueError:
        _reject(422, "invalid upstream setup input")
    except Exception:
        _reject(503, "upstream setup outcome unavailable; inspect the operation without repeating the action")
    try:
        return JSONResponse(result, status_code=201 if created else 200, headers=_HEADERS)
    except Exception:
        _reject(503, "upstream setup result unavailable; inspect the operation without repeating the action")


def _upstream_setup_read_admission(request: Request) -> None:
    _admit(request, mutation=False)
    if request.headers.getlist("transfer-encoding") or request.headers.getlist("content-length") not in ([], ["0"]):
        _reject(400, "upstream setup status accepts no body")


@router.get("/proxy/upstreams")
async def upstream_setup_review(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_upstream_setup as setup

    _upstream_setup_read_admission(request)
    return await _upstream_setup_result(setup.review, identity.user_id)


@router.post("/proxy/upstreams")
async def prepare_upstream_setup(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_upstream_setup as setup

    _admit(request, mutation=True)
    payload = await _payload(request, setup.PrepareInput, 8192)
    return await _upstream_setup_result(setup.prepare, payload, identity.user_id, created=True)


@router.get("/proxy/upstreams/{operation_id}")
async def upstream_setup_status(operation_id: str, request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_upstream_setup as setup
    from serverware.operator_catalog_inputs import _identifier

    _upstream_setup_read_admission(request)
    try:
        _identifier(operation_id)
    except (ValueError, TypeError, AttributeError):
        _reject(422, "invalid upstream setup operation identifier")
    return await _upstream_setup_result(setup.status, operation_id, identity.user_id)


@router.post("/proxy/upstreams/cancel")
async def cancel_upstream_setup(request: Request,
        identity: auth.AdminIdentity = Depends(_admin_identity)) -> JSONResponse:
    from serverware import operator_upstream_setup as setup

    _admit(request, mutation=True)
    payload = await _payload(request, setup.CancelInput, 2048)
    return await _upstream_setup_result(setup.cancel, payload, identity.user_id)
