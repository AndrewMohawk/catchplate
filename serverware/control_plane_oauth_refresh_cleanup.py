"""Fixed cold cleanup authority and one-attempt retained-token reconciliation.

This is not the OAuth application owner: expired enrollment authenticates
history only. A separately current grant authorizes each exact retained work.
No HTTP caller supplies a result, root, token, endpoint or retry instruction.
"""
from __future__ import annotations

import base64
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_contract, crypto, db
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_refresh_cleanup as profile
from serverware import authority_oauth_refresh_cleanup_policy as policy
from serverware import oauth_application_owner as originals
from serverware.http_client import HttpDeadline, request_bytes

STARTUP_SCHEMA = "serverware.oauthRefreshCleanupStartup/v1"
CONFIG_ENVIRONMENT = "SERVERWARE_OAUTH_REFRESH_CLEANUP_CONFIG_FD"
MAX_CONFIG_BYTES = 2 * 1024 * 1024
_PREFIX = "SERVERWARE_OAUTH_REFRESH_CLEANUP_"
_PID = os.getpid()
_LOCK = threading.RLock()
_RUN = threading.Lock()
_state, _owner, _namespace = "new", None, None


def _environment():
    return (os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower(),
        tuple(sorted((key, value) for key, value in os.environ.items() if key.startswith(_PREFIX))))


def _read(table, identifier):
    profile.identifier(identifier)
    # Closed source names only; no caller-selected relation or mutation.
    profile.require(table in {profile.refresh.TABLE, "credentials", "credential_generations", "oauth_revocation_work", profile.JOURNAL_TABLE, profile.ATTEMPT_TABLE})
    with db.connect() as connection:
        key = "credential_id" if table == "credential_generations" else "id"
        row = connection.execute("SELECT * FROM " + table + " WHERE " + key + " = ?", (identifier,)).fetchone()
    return None if row is None else dict(row)


def _journal_public(row):
    return {"workId": row["id"], "status": row["status"], "rowSha256": profile.sha256(profile.journal_original(row)),
        "authorizationSha256": row["authorization_sha256"], "expiresAt": row["expires_at"]}


def _attempt_public(row):
    return None if row is None else {"id": row["id"], "tokenPurpose": row["token_purpose"], "status": row["status"],
        "rowSha256": profile.sha256(profile.attempt_original(row)), "transportSha256": row["transport_sha256"]}


class _Cold:
    def __init__(self):
        raise ValueError("cleanup owner requires fixed cold admission")

    def __copy__(self):
        raise ValueError("cleanup owner cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("cleanup owner cannot be copied")

    def check(self):
        with _LOCK:
            try:
                from serverware import control_plane_custody_client as client
                from serverware import control_plane_custody_startup as custody
                profile.require(self is _owner and _state == "started" and not self.poisoned
                    and os.getpid() == _PID and (os.geteuid(), os.getegid()) == self.identity
                    and _environment() == _namespace and custody.require_started() is self.custody
                    and client._snapshot(self.custody) is self.binding)
                now, mono = client._receipt_now(self.binding), time.monotonic_ns()
                profile.require(self.epoch <= now < self.expires and self.mono <= mono < self.deadline)
                for original in self.originals:
                    original.check()
                closing, closing_mono = client._receipt_now(self.binding), time.monotonic_ns()
                profile.require(now <= closing < self.expires and mono <= closing_mono < self.deadline)
                self.epoch, self.mono = closing, closing_mono
                return closing
            except BaseException:
                self.poisoned = True
                raise


def initialize_from_environment():
    """Exactly once after genuine custody startup, before the worker starts."""
    global _state, _owner, _namespace
    with _LOCK:
        profile.require(os.getpid() == _PID and _state == "new")
        _namespace = _environment()
        if _namespace[0] in originals._DEVELOPMENT and not _namespace[1]:
            _state = "disabled"
            return
        _state = "admitting"
        try:
            from serverware import control_plane_custody_client as client
            from serverware import control_plane_custody_startup as custody
            profile.require(set(dict(_namespace[1])) == {CONFIG_ENVIRONMENT})
            descriptor_text = os.environ[CONFIG_ENVIRONMENT]
            profile.require(descriptor_text.isascii() and descriptor_text.isdecimal() and str(int(descriptor_text)) == descriptor_text)
            descriptor = originals._fd(int(descriptor_text))
            actual = custody.require_started()
            binding = client._snapshot(actual)
            opening_epoch, opening_mono = client._receipt_now(binding), time.monotonic_ns()
            admission_deadline = opening_mono + min(30_000_000_000, binding.maximum_deadline_ns,
                binding.attestation_interval[1] - opening_epoch)
            profile.require(descriptor in binding.inherited_descriptors)
            original = originals._Original(descriptor, MAX_CONFIG_BYTES)
            value = profile.document(original.raw, MAX_CONFIG_BYTES)
            profile.require(set(value) == {"schema", "sourceRevision", "configurationDigest", "authorityRootFd", "authorityRootSha256", "authorizations"}
                and value["schema"] == STARTUP_SCHEMA and value["sourceRevision"] == authority_contract.SOURCE_REVISION
                and value["configurationDigest"] == binding.configuration_digest
                and type(value["authorizations"]) is list and len(value["authorizations"]) <= 16)
            held, entries, root, descriptors, works = [original], [], None, {descriptor}, set()
            if not value["authorizations"]:
                profile.require(value["authorityRootFd"] is None and value["authorityRootSha256"] is None)
            else:
                root_fd = originals._fd(value["authorityRootFd"])
                profile.require(root_fd not in descriptors and root_fd in binding.inherited_descriptors)
                descriptors.add(root_fd)
                root_original = originals._Original(root_fd, 4096)
                held.append(root_original)
                profile.require(profile.sha256(root_original.raw) == value["authorityRootSha256"])
                root = serialization.load_pem_public_key(root_original.raw)
                profile.require(isinstance(root, Ed25519PublicKey)
                    and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == root_original.raw
                    and enrollment._spki(root) != enrollment._spki(binding.runtime_root_public_key))
            for entry in value["authorizations"]:
                profile.require(type(entry) is dict and set(entry) == {"authorization", "clientMaterialFd", "historicalEnrollmentRootFd"})
                raw = profile.canonical(entry["authorization"])
                signed = profile.grant_document(raw)
                grant = signed["payload"]
                profile.require(grant["sourceRevision"] == authority_contract.SOURCE_REVISION
                    and grant["configurationDigest"] == binding.configuration_digest and grant["workId"] not in works)
                works.add(grant["workId"])
                root.verify(profile.unb64(signed["signatureBase64Url"], 64), profile.GRANT_SCHEMA.encode("ascii") + b"\0" + profile.canonical(grant))
                pair = []
                for name, maximum, private in (("clientMaterialFd", 32 * 1024, True), ("historicalEnrollmentRootFd", 4096, False)):
                    fd = originals._fd(entry[name])
                    profile.require(fd not in descriptors and fd in binding.inherited_descriptors)
                    descriptors.add(fd)
                    item = originals._Original(fd, maximum, private=private)
                    held.append(item)
                    pair.append(item)
                material, historical = pair
                profile.require(profile.sha256(material.raw) == grant["clientMaterialSha256"])
                historical_key = serialization.load_pem_public_key(historical.raw)
                profile.require(isinstance(historical_key, Ed25519PublicKey)
                    and historical_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) == historical.raw
                    and enrollment._spki(historical_key) == grant["historicalEnrollmentRootSpkiSha256"]
                    and enrollment._spki(historical_key) != enrollment._spki(root))
                entries.append((raw, material, historical))
            owner = object.__new__(_Cold)
            owner.custody, owner.binding, owner.root = actual, binding, root
            owner.originals, owner.entries, owner.used = tuple(held), tuple(entries), set()
            owner.identity, owner.poisoned = (os.geteuid(), os.getegid()), False
            owner.epoch, owner.mono = client._receipt_now(binding), time.monotonic_ns()
            profile.require(opening_epoch <= owner.epoch < binding.attestation_interval[1]
                and opening_mono <= owner.mono < admission_deadline)
            owner.expires = binding.attestation_interval[1]
            owner.deadline = opening_mono + owner.expires - opening_epoch
            _owner, _state = owner, "started"
            owner.check()
        except BaseException:
            _state = "poisoned"
            raise


def selected():
    with _LOCK:
        profile.require(os.getpid() == _PID)
        current = _environment()
        if _state == "new" and current[0] in originals._DEVELOPMENT and not current[1]:
            # Same explicit unconfigured-development predicate as admission;
            # no FD access, state transition, lazy owner or borrowed authority.
            return False
        profile.require(current == _namespace)
        if _state == "disabled":
            return False
        profile.require(_state == "started" and _owner is not None)
        _owner.check()
        # An explicitly empty production profile stays selected: no DML fallback.
        return True


def close():
    """Permanently stop this selection; borrowed custody descriptors stay owned.

    Safe after partial admission and on repeated shutdown. This does not erase
    immutable Python bytes, settle an attempt, or release a retry permission.
    """
    global _state
    with _LOCK:
        if _owner is not None:
            _owner.poisoned = True
        _state = "closed"


def _request(grant, material, token, purpose):
    provider = grant["providerConfiguration"]
    profile.require(type(token) is str and 1 <= len(token.encode("utf-8")) <= 64 * 1024)
    body = {"token": token, "token_type_hint": purpose}
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if provider["tokenAuth"] == "basic":
        credentials = (material["clientId"] + ":" + material["clientSecret"]).encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode("ascii")
    elif grant["providerId"] == "x":
        body["client_id"] = material["clientId"]
    request = urllib.request.Request(provider["revocationUrl"], data=urllib.parse.urlencode(body).encode("utf-8"), headers=headers, method="POST")
    return request, _request_digest(request)


def _request_digest(request):
    profile.require(type(request) is urllib.request.Request and request.get_method() == "POST" and type(request.data) is bytes)
    return profile.sha256(profile.canonical({"schema": "serverware.oauthRevocationContact/v1", "url": request.full_url,
        "method": "POST", "bodySha256": profile.sha256(request.data),
        "headersSha256": profile.sha256(profile.canonical(dict(request.header_items())))}))


class _Operation:
    def __init__(self, owner, entry):
        self.owner, self.entry = owner, entry
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.epoch, self.mono = owner.check(), time.monotonic_ns()
        self.grant = profile.grant_document(entry[0])["payload"]
        lifetime = min(30_000_000_000, owner.binding.maximum_deadline_ns,
            owner.expires - self.epoch, owner.deadline - self.mono, self.grant["expiresAtEpochNs"] - self.epoch)
        profile.require(lifetime > 0 and self.grant["issuedAtEpochNs"] <= self.epoch)
        self.deadline, self.expires = self.mono + lifetime, self.epoch + lifetime
        self.nonce, self.journal, self.attempt = secrets.token_bytes(32), None, None
        self.attempts, self.contacts, self.finished, self.poisoned = set(), set(), set(), False
        self.enrollment, self.work = None, None
        self.credential, self.generation, self.refresh = None, None, None
        self.historical_barrier_sha256, self.barrier_sha256 = None, None
        self.check()

    def __copy__(self):
        raise ValueError("cleanup operation cannot be copied")

    def __deepcopy__(self, memo):
        raise ValueError("cleanup operation cannot be copied")

    def check(self):
        try:
            profile.require(not self.poisoned and (os.getpid(), threading.get_ident()) == (self.pid, self.thread))
            epoch, mono = self.owner.check(), time.monotonic_ns()
            profile.require(self.epoch <= epoch < self.expires and self.mono <= mono < self.deadline
                and profile.canonical(self.grant) == profile.canonical(profile.grant_document(self.entry[0])["payload"]))
            self.epoch, self.mono = epoch, mono
        except BaseException:
            self.poisoned = True
            raise

    def prepare(self):
        self.check()
        grant = self.grant
        self.refresh = _read(profile.refresh.TABLE, grant["refreshId"])
        work = _read("oauth_revocation_work", grant["workId"])
        self.credential = _read("credentials", grant["credentialId"])
        self.generation = _read("credential_generations", grant["credentialId"])
        profile.require(all(item is not None for item in (self.refresh, work, self.credential, self.generation))
            and _read(profile.JOURNAL_TABLE, grant["workId"]) is None
            and profile.refresh.row_digest(self.refresh) == grant["refreshRowSha256"]
            and profile.sha256(profile.work_original(work)) == grant["workRowSha256"]
            and profile.sha256(profile.refresh.credential_original(self.credential)) == grant["credentialRowSha256"]
            and profile.sha256(profile.refresh.generation_original(self.generation)) == grant["generationRowSha256"]
            and self.credential["lifecycle_status"] == "active" and work["status"] == "held" and work["attempts"] == 0
            and self.credential["credential_version"] == self.generation["last_version"] == grant["credentialVersion"]
            and self.refresh["credential_id"] == grant["credentialId"] and self.refresh["credential_version"] == grant["refreshVersion"]
            and self.refresh["id"] == profile.refresh.refresh_id(grant["credentialId"], grant["refreshVersion"])
            and self.refresh["raw_response_envelope_json"] is not None)
        self.enrollment = self.refresh["enrollment_original"]
        self.historical_barrier_sha256 = grant["historicalBarrierSha256"]
        # Signature/historical provider identity before any barrier or effect.
        policy.verify_originals(self.arguments({}), grant_root=self.owner.root,
            configuration_digest=self.owner.binding.configuration_digest, source_revision=authority_contract.SOURCE_REVISION,
            deployment_id=grant["deploymentId"], now_epoch_ns=self.epoch)
        envelope = {name: work[name] for name in profile.refresh.ENVELOPE_FIELDS}
        profile.refresh.envelope(envelope, 1)
        profile.require(profile.sha256(profile.canonical(envelope)) == grant["tokenEnvelopeSha256"])
        raw = crypto.decrypt_secret_envelope(work).encode("utf-8")
        purpose = "issued" if grant["workSource"] == profile.refresh.ISSUED_SOURCE else "superseded"
        profile.require(work["source"] == grant["workSource"] and work["actor_id"] == "oauth-refresh"
            and work["provider_id"] == grant["providerId"] and work["created_at"] == self.refresh["created_at"]
            and self.refresh["status"] == ("retained" if purpose == "issued" else "committed")
            and self.refresh[purpose + "_work_id"] == grant["workId"]
            and grant["workId"] == profile.refresh.artifact_id(grant["refreshId"], purpose)
            and profile.sha256(raw) == grant["tokenSecretSha256"] == self.refresh[purpose + "_material_sha256"])
        token = profile.document(raw, 190 * 1024)
        old_row = profile.document(self.refresh["credential_original_json"].encode("ascii"), 512 * 1024)
        profile.refresh.credential_original(old_row)
        old = profile.document(crypto.decrypt_secret_envelope(old_row).encode("utf-8"), 190 * 1024)
        current_raw = crypto.decrypt_secret_envelope(self.credential).encode("utf-8")
        current = profile.document(current_raw, 190 * 1024)
        if purpose == "issued":
            profile.require(self.credential == old_row and self.refresh["issued_material_envelope_json"] == profile.canonical(envelope).decode("ascii"))
        else:
            profile.require(profile.sha256(current_raw) == self.refresh["replacement_secret_sha256"]
                and grant["credentialRowSha256"] == self.refresh["replacement_credential_sha256"])
        original_enrollment = profile.refresh.enrollment_bytes(self.enrollment)
        payload = enrollment.enrollment_document(original_enrollment)["payload"]
        created = profile.refresh.timestamp(self.refresh["created_at"])
        from serverware import authority_transition_quota as shared
        profile.require(payload["issuedAtEpochNs"] <= shared._database_epoch_ns(created) < payload["expiresAtEpochNs"])
        association = originals._association(payload, original_enrollment)
        metadata = profile.document(self.credential["metadata"].encode("ascii"), 32 * 1024)
        profile.require(all(value.get("oauth_application_owner") == association for value in (token, old, current, metadata))
            and metadata.get("provider_identity_verified") is True and metadata.get("provider_id") == grant["providerId"]
            and metadata.get("provider_subject") == grant["familyScope"]["providerSubject"]
            and metadata.get("provider_account") == grant["familyScope"]["providerAccount"])
        purposes = [name for name in ("access_token", "refresh_token") if type(token.get(name)) is str and token[name]]
        # No unchanged shared refresh token is ever a retirement target.
        purposes = [name for name in purposes if name != "refresh_token" or token[name] != old.get(name)]
        if purpose == "superseded":
            purposes = [name for name in ("access_token", "refresh_token") if type(token.get(name)) is str and token[name]]
            profile.require(all(token[name] == old.get(name) and token[name] != current.get(name) for name in purposes))
        if grant["providerId"] == "google":
            purposes = ["refresh_token"] if "refresh_token" in purposes else ["access_token"] if "access_token" in purposes else []
        profile.require(purposes == grant["tokenPurposes"])
        material = profile.document(self.entry[1].raw, 32 * 1024)
        profile.require(set(material) == {"schema", "providerId", "clientId", "clientSecret", "redirectUri"}
            and material["schema"] == originals.CLIENT_SCHEMA and material["providerId"] == grant["providerId"]
            and material["clientId"] == grant["clientId"] and material["redirectUri"] == payload["redirectUri"]
            and type(material["clientSecret"]) is str and len(material["clientSecret"].encode("utf-8")) <= 8192
            and (material["clientSecret"] or grant["providerConfiguration"]["tokenAuth"] == "none"))
        requests = [(name, *_request(grant, material, token[name], name)) for name in purposes]
        self.work = profile.work_original(work)
        self.check()
        # Actual type-checked coordinator, not a caller result/callback.
        from serverware import control_plane_credential_currentness as coordinator
        self.barrier_sha256 = coordinator.admit_cleanup_barrier(self)
        profile.digest(self.barrier_sha256)
        self.check()
        return requests

    def arguments(self, request):
        return {"work_id": self.grant["workId"], "authorization_original": profile.b64(self.entry[0]),
            "enrollment_original": self.enrollment, "historical_root_original": profile.b64(self.entry[2].raw), "request": request}

    def dispatch(self, operation, request):
        self.check()
        key = (operation, request.get("tokenPurpose"))
        profile.require(key not in self.attempts)
        arguments = profile.arguments(operation, self.arguments(request))
        expected = profile.request_digest(operation, arguments)
        self.attempts.add(key)  # An uncertain controlled call is never replayed.
        from serverware.control_plane_custody_client import ControlPlaneCustodyClient
        result = ControlPlaneCustodyClient._request_authority(self.owner.custody, operation=operation,
            input_value={"schema": "serverware.policyAuthorityControlledWriterInput/v1",
                "handler": authority_contract.operation_spec(operation)["handler"],
                "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST, "arguments": arguments}, deadline_ns=self.deadline)
        self.check()
        profile.require(type(result) is dict and set(result) == {"ok", "journal", "attempt", "operation", "requestDigest", "auditEventDigest", "idempotentReplay"}
            and result["ok"] is True and result["operation"] == operation and result["requestDigest"] == expected and result["idempotentReplay"] is False)
        profile.digest(result["auditEventDigest"])
        journal = _read(profile.JOURNAL_TABLE, self.grant["workId"])
        profile.require(journal is not None and _journal_public(journal) == result["journal"]
            and journal["authorization_original"] == profile.b64(self.entry[0]) and journal["owner_nonce_sha256"] == profile.sha256(self.nonce)
            and journal["original_work_json"].encode("ascii") == self.work)
        attempt = None if operation == profile.OP_CLAIM else _read(profile.ATTEMPT_TABLE, profile.attempt_id(self.grant["workId"], request["tokenPurpose"]))
        profile.require(_attempt_public(attempt) == result["attempt"])
        if operation == profile.OP_CLAIM:
            profile.require(journal["status"] == "claimed")
        elif operation == profile.OP_CONTACT:
            profile.require(journal["status"] == "claimed" and attempt["status"] == "contact-claimed"
                and attempt["contact_request_sha256"] == request["contactRequestSha256"])
        else:
            raw = profile.unb64(request["transportOriginal"], profile.MAX_TRANSPORT_BYTES)
            profile.require(attempt["transport_original"] == raw.decode("ascii") and attempt["transport_sha256"] == profile.sha256(raw)
                and attempt["status"] == profile.transport(raw, attempt["contact_request_sha256"]))
            self.finished.add(request["tokenPurpose"])
        profile.require(journal["original_credential_json"] == profile.refresh.credential_original(self.credential).decode("ascii")
            and journal["original_generation_json"] == profile.refresh.generation_original(self.generation).decode("ascii")
            and journal["currentness_barrier_sha256"] == self.barrier_sha256)
        self._fenced(journal)
        self.journal, self.attempt = profile.journal_original(journal), None if attempt is None else profile.attempt_original(attempt)
        self.check()
        return result

    def _fenced(self, journal):
        profile.require(_read("credentials", self.grant["credentialId"]) == {
            **self.credential, "lifecycle_status": "revocation_pending",
            "revocation_requested_at": journal["created_at"], "updated_at": journal["created_at"]}
            and _read("credential_generations", self.grant["credentialId"]) == self.generation)

    def contact(self, purpose, request, request_digest):
        self.check()
        profile.require(purpose not in self.contacts and self.journal is not None and self.attempt is not None
            and _request_digest(request) == request_digest
            and profile.journal_original(_read(profile.JOURNAL_TABLE, self.grant["workId"])) == self.journal
            and profile.attempt_original(_read(profile.ATTEMPT_TABLE, profile.attempt_id(self.grant["workId"], purpose))) == self.attempt)
        self._fenced(profile.document(self.journal, 2 * 1024 * 1024))
        attempt = profile.document(self.attempt, 256 * 1024)
        profile.require(attempt["status"] == "contact-claimed" and attempt["contact_request_sha256"] == request_digest)
        self.check()
        self.contacts.add(purpose)
        try:
            response = request_bytes(request, timeout=min(20.0, (self.deadline - time.monotonic_ns()) / 1_000_000_000),
                max_bytes=64 * 1024, require_https=True, expected_statuses=tuple(range(200, 600)),
                deadline=HttpDeadline(self.deadline / 1_000_000_000))
            value = {"schema": profile.TRANSPORT_SCHEMA, "contactRequestSha256": request_digest,
                "status": response.status, "rawHeaders": [list(pair) for pair in response.raw_headers],
                "bodyBase64url": base64.urlsafe_b64encode(response.body).rstrip(b"=").decode("ascii"), "errorCode": None}
            raw = profile.canonical(value)
            profile.transport(raw, request_digest)
            return raw
        except Exception:
            # This records local transport uncertainty, never synthetic HTTP
            # bytes or proof that the provider was (or was not) contacted.
            return profile.canonical({"schema": profile.TRANSPORT_SCHEMA, "contactRequestSha256": request_digest,
                "status": None, "rawHeaders": None, "bodyBase64url": None, "errorCode": "transport-unknown"})


def reconcile(limit=16):
    """Process cold-selected work once; counts are observations, not revocations."""
    profile.require(type(limit) is int and 1 <= limit <= 16 and selected())
    counts = {"claimed": 0, "accepted": 0, "rejected": 0, "unknown": 0, "notContacted": 0, "blocked": 0}
    if not _RUN.acquire(blocking=False):
        counts["blocked"] = 1
        return counts
    try:
        owner = _owner
        owner.check()
        processed = 0
        for entry in owner.entries:
            item_id = profile.grant_document(entry[0])["payload"]["workId"]
            if item_id in owner.used or processed == limit:
                continue
            owner.used.add(item_id)
            processed += 1
            operation = None
            try:
                operation = _Operation(owner, entry)
                requests = operation.prepare()
                operation.dispatch(profile.OP_CLAIM, {"ownerNonceSha256": profile.sha256(operation.nonce),
                    "currentnessBarrierSha256": operation.barrier_sha256})
                counts["claimed"] += 1
                for purpose, request, digest in requests:
                    operation.dispatch(profile.OP_CONTACT, {"journalRowSha256": profile.sha256(operation.journal),
                        "ownerNonce": profile.b64(operation.nonce), "tokenPurpose": purpose, "contactRequestSha256": digest})
                    raw = operation.contact(purpose, request, digest)
                    result = operation.dispatch(profile.OP_FINISH, {"journalRowSha256": profile.sha256(operation.journal),
                        "ownerNonce": profile.b64(operation.nonce), "attemptRowSha256": profile.sha256(operation.attempt),
                        "tokenPurpose": purpose, "transportOriginal": profile.b64(raw)})
                    outcome = result["attempt"]["status"]
                    counts[outcome] += 1
                    if outcome == "unknown":
                        break
            except Exception:
                if operation is not None and operation.contacts - operation.finished:
                    counts["unknown"] += 1
                elif operation is not None and operation.attempts:
                    counts["notContacted"] += 1
                else:
                    counts["blocked"] += 1
                # No retry, legacy mutation, inline revoke, deletion or renewal.
        return counts
    finally:
        _RUN.release()
