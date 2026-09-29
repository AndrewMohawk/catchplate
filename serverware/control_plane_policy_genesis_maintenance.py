"""Sealed cold maintenance owner and closed HTTP gate, never an effect grant."""
from __future__ import annotations

import json
import os
import re
import threading
import time

from serverware import control_plane_policy_genesis_bootstrap as profile
from serverware.control_plane_policy_file_authority import CurrentPolicyAuthority
from serverware.control_plane_policy_file_genesis import GenesisPolicyAuthority, read_original

_OWNER = None
_STATE = "new"
_TOKEN = object()
_APPROVE = re.compile(r"/api/control-plane/approvals/([0-9a-f-]{36})/approve\Z")
_MATCH = ("genesisPreparationDigest", "genesisFinalizationDigest", "policyId", "sequence", "rollbackEpoch", "policyHash")


class GenesisAdmissionRead(CurrentPolicyAuthority):
    SQL, DSN_PATH, DSN_SHA = GenesisPolicyAuthority.SQL, GenesisPolicyAuthority.DSN_PATH, GenesisPolicyAuthority.DSN_SHA

    def check(self):
        self._check_held_connection()
        actual = read_original(self)
        if self.original is None:
            self.original = actual
        else:
            profile.require(self.original == actual)
        self._configure()
        self._contract()
        self.publication.check()


class MaintenanceOwner:
    def __init__(self, token):
        profile.require(token is _TOKEN and _STATE == "admitting")
        from serverware import control_plane_custody_startup as custody
        from serverware import control_plane_custody_client as client
        from serverware import control_plane_enrollment_startup as enrollment
        from serverware import control_plane_rbac_currentness as rbac
        from serverware import policy_bundle
        self.pid, self.lock = os.getpid(), threading.RLock()
        self.custody, self.enrollment = custody.require_started(), enrollment.require_started()
        self.rbac = rbac.require_started()
        profile.require(self.custody is not None and self.enrollment is not None and self.rbac is not None)
        self.binding = client._snapshot(self.custody)
        self.scope = custody.genesis_maintenance_configuration()
        profile.require(self.scope is not None)
        self.original_scope = profile.canonical(self.scope)
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.expires = min(self.scope["expiresAtEpochNs"], self.binding.attestation_interval[1])
        profile.require(self.scope["issuedAtEpochNs"] <= self.epoch < self.expires)
        self.outer_deadline = self.mono + self.expires - self.epoch
        # This separate opening read never extends any later effect window.
        self.deadline = min(self.outer_deadline, self.mono + 30_000_000_000)
        self.dsn = (os.environ.get(GenesisPolicyAuthority.DSN_PATH), os.environ.get(GenesisPolicyAuthority.DSN_SHA))
        profile.require(self.dsn[1] == self.scope["genesisDsnSha256"])
        self.material_binding = {key: self.scope[key] for key in _MATCH}
        self.path, self.pins = policy_bundle.POLICY_BUNDLE_PATH, []
        self.closed = False
        self.startup_original = None

    def check(self):
        profile.require(os.getpid() == self.pid)
        with self.lock:
            from serverware import control_plane_custody_startup as custody
            from serverware import control_plane_custody_client as client
            from serverware import control_plane_enrollment_startup as enrollment
            from serverware import control_plane_rbac_currentness as rbac
            now, mono = time.time_ns(), time.monotonic_ns()
            profile.require(_OWNER is self and _STATE in {"admitting", "ready"} and not self.closed
                and self.epoch <= now < self.expires and self.mono <= mono < self.outer_deadline
                and custody.require_started() is self.custody and client._snapshot(self.custody) is self.binding
                and enrollment.require_started() is self.enrollment
                and rbac.require_started() is self.rbac
                and profile.canonical(custody.genesis_maintenance_configuration()) == self.original_scope
                and self.dsn == (os.environ.get(GenesisPolicyAuthority.DSN_PATH), os.environ.get(GenesisPolicyAuthority.DSN_SHA)))
            closing_epoch, closing_mono = time.time_ns(), time.monotonic_ns()
            profile.require(now <= closing_epoch < self.expires and mono <= closing_mono < self.outer_deadline)
            self.epoch, self.mono = closing_epoch, closing_mono

    def matches(self, bound, *, publication=None):
        self.check()
        from serverware import authority_policy_file_approval as approval
        from serverware import control_plane_policy_file_publication as files
        bound = approval.request_binding(bound)
        if bound["kind"] == "resolve":
            if type(publication) is files.PolicyFilePublication and hasattr(publication, "material_binding"):
                profile.require(publication.bound == bound)
                material = publication.material_binding
            else:
                observed = files.inspect_publication()
                matches = [item for item in observed["attempts"] if item["publicationId"] == bound["publicationId"]
                    and item["intentSha256"] == bound["intentSha256"]]
                profile.require(len(matches) == 1)
                material = matches[0]["binding"]
        else:
            material = bound
        profile.require(material["kind"] == "genesis-materialize"
            and all(material[key] == self.scope[key] for key in _MATCH))
        self.check()

    def require_approval(self, identifier):
        from serverware.control_plane_publication_authorization import _approval
        row = _approval(identifier, "policy-file")
        self.matches(json.loads(row["request_json"]))


def initialize_from_started():
    global _OWNER, _STATE
    profile.require(_STATE == "new")
    _STATE = "admitting"
    reader = None
    try:
        _OWNER = MaintenanceOwner(_TOKEN)
        _OWNER.check()
        reader = GenesisAdmissionRead._connect(_OWNER)
        reader.check()
        _OWNER.startup_original = reader.original
        reader.close()
        reader = None
        _OWNER.check()
        _STATE = "ready"
        return _OWNER
    except BaseException:
        _STATE = "failed"
        if _OWNER is not None:
            _OWNER.closed = True
        if reader is not None:
            reader.close()
        raise


def clip_window(deadline_ns, expires_epoch_ns):
    from serverware import control_plane_custody_startup as custody
    if custody.genesis_maintenance_configuration() is None:
        return deadline_ns, expires_epoch_ns
    profile.require(type(_OWNER) is MaintenanceOwner and _STATE == "ready")
    _OWNER.check()
    return min(deadline_ns, _OWNER.outer_deadline), min(expires_epoch_ns, _OWNER.expires)


def require_binding(bound, *, publication=None):
    from serverware import control_plane_custody_startup as custody
    if custody.genesis_maintenance_configuration() is None:
        # Ordinary startup must not expose this cold-selected first-effect
        # purpose even if its previously loaded policy file is later removed.
        profile.require(bound.get("kind") != "genesis-materialize")
        if publication is not None and hasattr(publication, "material_binding"):
            profile.require(publication.material_binding["kind"] != "genesis-materialize")
        return
    profile.require(type(_OWNER) is MaintenanceOwner and _STATE == "ready")
    _OWNER.matches(bound, publication=publication)


def visible_approval(row):
    from serverware import control_plane_custody_startup as custody
    if custody.genesis_maintenance_configuration() is None:
        return True
    profile.require(type(_OWNER) is MaintenanceOwner and _STATE == "ready")
    _OWNER.check()
    if row.get("action") not in {"policy.file.genesis.materialize", "policy.file.resolve"}:
        return False
    try:
        _OWNER.require_approval(row["id"])
        return True
    except (ValueError, KeyError, OSError):
        return False


def close():
    global _STATE
    if _OWNER is not None:
        profile.require(os.getpid() == _OWNER.pid)
        _OWNER.closed = True
    _STATE = "closed"


class MaintenanceApplication:
    def __init__(self, owner):
        profile.require(type(owner) is MaintenanceOwner and owner is _OWNER and _STATE == "ready")
        owner.check()
        from serverware.app import app
        from serverware import control_plane_oidc_session_activation_routes as activation
        from serverware import control_plane_oidc_session_activation_recovery_routes as recovery
        from serverware import portal_session_activation_confirmation_routes as confirmation
        from serverware import control_plane_oidc_session_activation_permission_routes as permission
        from serverware import portal_policy_genesis as portal
        self.owner, self.app = owner, app
        self.gets = frozenset({"/", "/api/auth/status", "/api/auth/oidc/start", "/api/auth/oidc/callback", "/api/csrf",
            "/api/control-plane/approvals", "/api/policy/file-publication"})
        self.posts = frozenset({"/api/auth/session/webauthn/options", "/api/auth/session/webauthn/verify", "/api/auth/logout",
            "/api/policy/file-publication/webauthn/options", "/api/policy/file-publication/genesis-materialize",
            "/api/policy/file-publication/resolve", activation.POST_PATH, confirmation.POST_PATH}) | recovery.PATHS | permission.PATHS | portal.POSTS

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # Never forward to the broad application's startup/shutdown hooks.
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    self.owner.check()
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        try:
            self.owner.check()
            method, path = scope["method"], scope["path"]
            approval = _APPROVE.fullmatch(path) if method == "POST" else None
            profile.require(method == "GET" and path in self.gets or method == "POST" and (path in self.posts or approval is not None))
            if approval is not None:
                self.owner.require_approval(approval[1])
        except Exception:
            from starlette.responses import JSONResponse
            await JSONResponse({"detail": "genesis maintenance route or original authority unavailable"},
                status_code=403, headers={"Cache-Control": "no-store"})(scope, receive, send)
            return
        from serverware import portal_policy_genesis as portal
        if method == "GET" and path == "/" or method == "POST" and path in portal.POSTS:
            # The broad dashboard is never served in this cold profile.
            await portal.dispatch(self.owner, scope, receive, send)
            return
        await self.app(scope, receive, send)
