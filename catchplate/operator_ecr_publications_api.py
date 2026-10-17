"""Separate client staging and operator review for exact ECR publications.

The public proxy authenticates a workload and injects its current token digest
and policy identity. These internal routes authenticate the gate before reading
any body, then rejoin that identity against the catalog. Human review remains
on the existing same-origin administrator surface. Neither surface sends AWS
requests; only the separate signing/ACK path advances an activated publication.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from catchplate import auth, config, operator_catalog_api as admission
from catchplate import operator_ecr_artifacts as artifacts
from catchplate import operator_ecr_publications as owner
from catchplate.setup_receipts import JsonLimits, parse_strict_json_object

router = APIRouter()
CLIENT = "/api/data-plane/ecr-publications/client"
ADMIN = "/api/operator-demo/ecr-publications"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CLIENT_MUTATION = re.compile(re.escape(CLIENT) + "/" + _UUID
    + r"/(?:manifest|submit|activate|blobs/[0-9a-f]{64}/parts/(?:0|[1-9][0-9]{0,9}))\Z")
_ADMIN_MUTATION = re.compile(re.escape(ADMIN) + "/" + _UUID + r"/(?:review|decision|retire)\Z")
_SLOTS = asyncio.BoundedSemaphore(2)
_CREATE_FIELDS = {"application_id", "access_rule_id", "expected_policy_hash", "manifest_digest", "artifact_sha256"}


def owns_post(path):
    return type(path) is str and (path == CLIENT or _CLIENT_MUTATION.fullmatch(path) is not None
        or _ADMIN_MUTATION.fullmatch(path) is not None)


def _identifier(value):
    if type(value) is not str or re.fullmatch(_UUID, value) is None:
        admission._reject(404, "ECR publication not found")
    return value


def _exact(request, path, *, bodyless=False, query=b""):
    if (request.scope.get("raw_path") != path.encode("ascii") or request.scope.get("query_string", b"") != query
            or bodyless and (request.headers.getlist("content-length") not in ([], ["0"])
                or request.headers.getlist("transfer-encoding"))):
        admission._reject(400, "ECR publication transport refused")


def _machine(request):
    from catchplate import app
    admission._profile()
    names = [key.lower() for key, _ in request.scope.get("headers", [])]
    if len(names) != len(set(names)):
        admission._reject(400, "ECR publication headers refused")
    if any(request.headers.getlist(key) for key in (
            "authorization", "proxy-authorization", "cookie", "origin", "x-catchplate-admin-token",
            "x-catchplate-bootstrap-token", "remote-user", "remote-groups", "remote-email", "remote-name")):
        admission._reject(401, "ECR publication machine authentication required")
    tokens = request.headers.getlist("x-catchplate-data-plane-token")
    if len(tokens) != 1:
        admission._reject(401, "ECR publication machine authentication required")
    app._require_data_plane_token(tokens[0], app.DATA_PLANE_CREDENTIAL_LEASE_TOKEN)
    values = []
    for key in ("x-catchplate-principal-id", "x-catchplate-client-token-sha256", "x-catchplate-policy-hash"):
        entries = request.headers.getlist(key)
        if len(entries) != 1:
            admission._reject(401, "ECR publication client identity required")
        values.append(entries[0])
    principal, token_hash, policy_hash = values
    if (not 1 <= len(principal) <= 256 or not all("!" <= c <= "~" for c in principal)
            or _SHA.fullmatch(token_hash) is None or _SHA.fullmatch(policy_hash) is None):
        admission._reject(401, "ECR publication client identity refused")
    return principal, token_hash, policy_hash


async def _body(request, maximum, *, binary=False):
    expected = "application/octet-stream" if binary else "application/json"
    if (request.headers.getlist("content-type") != [expected]
            or request.headers.getlist("content-encoding") or request.headers.getlist("transfer-encoding")):
        admission._reject(415, "ECR publication content framing refused")
    lengths = request.headers.getlist("content-length")
    if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal()
            or len(lengths[0]) > 10 or str(int(lengths[0])) != lengths[0]):
        admission._reject(400, "ECR publication content length required")
    length = int(lengths[0])
    if not 0 < length <= maximum:
        admission._reject(413, "ECR publication body exceeds its limit")
    raw = bytearray()
    try:
        async with asyncio.timeout(15):
            async for chunk in request.stream():
                if len(chunk) > length - len(raw):
                    admission._reject(400, "ECR publication content length differs")
                raw.extend(chunk)
    except TimeoutError:
        admission._reject(408, "ECR publication body timed out")
    if len(raw) != length:
        admission._reject(400, "ECR publication content length differs")
    if binary:
        return bytes(raw)
    try:
        return admission._plain(parse_strict_json_object(bytes(raw), limits=JsonLimits(
            max_bytes=maximum, max_depth=4, max_object_keys=32, max_total_keys=64,
            max_array_items=16, max_total_nodes=128, max_string_bytes=4096)))
    except (ValueError, TypeError, RecursionError):
        admission._reject(422, "ECR publication JSON refused")


def _current_client(identity):
    from catchplate import db, operator_catalog_schema as catalog, operator_publication
    principal, token_hash, policy_hash = identity
    with operator_publication.exclusive(), db.metadata_connection() as conn:
        conn.execute("BEGIN")
        retained = catalog.read_catalog(conn)
        policy = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
        clients = [row for row in retained["applications"] if row["principal_id"] == principal]
        if len(clients) != 1 or policy is None or policy[0] != policy_hash:
            raise owner.PublicationConflict()
        client = clients[0]
        if (client["status"] != "active" or not hmac.compare_digest(client["token_sha256"], token_hash)
                or type(client["token_expires_at_epoch_ms"]) is not int
                or client["token_expires_at_epoch_ms"] <= time.time_ns() // 1_000_000):
            raise owner.PublicationConflict()
        return client


def _create(identity, value):
    if type(value) is not dict or set(value) != _CREATE_FIELDS:
        raise ValueError()
    for key in ("application_id", "access_rule_id"):
        if type(value[key]) is not str or str(uuid.UUID(value[key])) != value[key]:
            raise ValueError()
    if any(type(value[key]) is not str or _SHA.fullmatch(value[key]) is None
            for key in ("expected_policy_hash", "manifest_digest", "artifact_sha256")):
        raise ValueError()
    client = _current_client(identity)
    if value["application_id"] != client["id"] or value["expected_policy_hash"] != identity[2]:
        raise owner.PublicationConflict()
    stage = artifacts.configured_store()
    result = owner.create(**value, principal_id=identity[0])
    try:
        stage.begin(result["id"])
    except Exception:
        # A refused disk slot must not leave a phantom active publication until
        # expiry. There has been no provider dispatch or signing reservation.
        owner.fail_staging(result["id"], identity[0])
        raise
    return result


def _client_operation(identity, identifier, action, raw=None, digest=None, offset=None):
    _current_client(identity)
    stage = artifacts.configured_store()
    if action == "status":
        return owner.status(identifier, identity[0])
    owner.require_client(identity[0], identifier, staging=action in {"manifest", "part", "submit"})
    if action == "manifest":
        stage.write_manifest(identifier, raw)
        return owner.status(identifier, identity[0])
    if action == "part":
        stage.append_part(identifier, "sha256:" + digest, offset, raw)
        return owner.status(identifier, identity[0])
    if action == "submit":
        with stage.finalize(identifier) as sealed:
            return owner.finalize_stage(identifier, sealed)
    if action == "activate":
        sealed = stage.recapture(identifier)
        try:
            return owner.activate(identifier, sealed, principal_id=identity[0])
        except BaseException:
            sealed.close()
            raise
    raise ValueError()


async def _result(function, *args, status_code=200, maximum=65536):
    from catchplate import app
    try:
        result = await app._run_bounded_blocking(_SLOTS, function, *args)
        if len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii")) > maximum:
            raise ValueError()
        return JSONResponse(result, status_code=status_code, headers=admission._HEADERS)
    except owner.PublicationNotFound:
        admission._reject(404, "ECR publication not found")
    except (owner.PublicationConflict, artifacts.ArtifactStoreError):
        admission._reject(409, "ECR publication changed or is unavailable; inspect current status")
    except ValueError:
        admission._reject(422, "ECR publication input refused")
    except Exception:
        admission._reject(503, "ECR publication outcome unavailable; inspect status before continuing")


@router.post(CLIENT)
async def create(request: Request):
    identity = _machine(request)
    _exact(request, CLIENT)
    return await _result(_create, identity, await _body(request, 16384), status_code=201)


@router.get(CLIENT + "/{identifier}")
async def status(identifier: str, request: Request):
    identity = _machine(request)
    _exact(request, CLIENT + "/" + _identifier(identifier), bodyless=True)
    return await _result(_client_operation, identity, identifier, "status")


@router.post(CLIENT + "/{identifier}/blobs/{digest}/parts/{offset}")
async def blob_part(identifier: str, digest: str, offset: str, request: Request):
    identity = _machine(request)
    _identifier(identifier)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None or re.fullmatch(r"0|[1-9][0-9]{0,9}", offset) is None:
        admission._reject(400, "ECR publication blob target refused")
    _exact(request, CLIENT + "/" + identifier + "/blobs/" + digest + "/parts/" + offset)
    raw = await _body(request, artifacts.MAX_PART_BYTES, binary=True)
    return await _result(_client_operation, identity, identifier, "part", raw, digest, int(offset))


@router.post(CLIENT + "/{identifier}/{action}")
async def client_action(identifier: str, action: str, request: Request):
    identity = _machine(request)
    _identifier(identifier)
    if action not in {"manifest", "submit", "activate"}:
        admission._reject(404, "ECR publication operation not found")
    _exact(request, CLIENT + "/" + identifier + "/" + action)
    raw = await _body(request, artifacts.MAX_PART_BYTES if action == "manifest" else 1024,
        binary=action == "manifest")
    if action != "manifest" and raw != {}:
        admission._reject(422, "ECR publication operation requires an empty object")
    return await _result(_client_operation, identity, identifier, action, raw)


def _administrator(request, identity, *, mutation):
    # This surface owns its exact query grammar (the history cursor only).
    # Mutations retain the catalog's no-query and same-origin admission.
    admission._profile()
    if mutation:
        admission._admit(request, mutation=True)
    if (identity.user_id != config.ADMIN_USER_ID or not identity.has_any_role({"admin"})
            or mutation and identity.auth_method != "admin-token-header"):
        admission._reject(403, "configured operator administrator required")


@router.get(ADMIN)
async def publications(request: Request, identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    _administrator(request, identity, mutation=False)
    query = request.scope.get("query_string", b"")
    before = None
    if query:
        if re.fullmatch(("before=" + _UUID).encode("ascii"), query) is None:
            admission._reject(400, "ECR publication cursor refused")
        before = query[len(b"before="):].decode("ascii")
    _exact(request, ADMIN, bodyless=True, query=query)
    # A complete verified artifact can approach the single-record response
    # bound. Page history rather than serializing every retained image at once.
    return await _result(lambda: owner.list_publications_page(identity.user_id, before=before),
        maximum=1048576)


@router.get(ADMIN + "/{identifier}")
async def publication(identifier: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    _administrator(request, identity, mutation=False)
    _exact(request, ADMIN + "/" + _identifier(identifier), bodyless=True)
    return await _result(owner.status, identifier, identity.user_id)


@router.post(ADMIN + "/{identifier}/{action}")
async def decision(identifier: str, action: str, request: Request,
        identity: auth.AdminIdentity = Depends(admission._admin_identity)):
    _administrator(request, identity, mutation=True)
    _identifier(identifier)
    if action not in {"review", "decision", "retire"}:
        admission._reject(404, "ECR publication operation not found")
    _exact(request, ADMIN + "/" + identifier + "/" + action)
    value = await _body(request, 2048)
    if action in {"review", "retire"}:
        if value != {}:
            admission._reject(422, "ECR publication operation requires an empty object")
        operation = owner.review if action == "review" else owner.retire_artifacts
        return await _result(operation, identifier, identity.user_id)
    return await _result(owner.decide, identifier, identity.user_id, value)
