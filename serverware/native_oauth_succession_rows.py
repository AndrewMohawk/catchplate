"""Exact immutable succession originals, consumed only after signed receipts.

Rows report the protected writer's committed transaction. Their hashes are
never independent drain, provider acceptance, or permission evidence.
"""
import uuid
from serverware import native_oauth_refresh as m
from serverware import native_oauth_exchange as provider
from serverware import native_oauth_succession as material
from serverware.native_oauth_reconnect_rows import stored, epoch, EXCHANGE, CUSTODY, CREDENTIAL

JOURNAL = frozenset({"id", "provider_id", "authorization_original", "authorization_sha256", "enrollment_original", "actor_id",
    "credential_policy_json", "authorize_arguments_json", "authorize_request_digest", "approval_id", "requester_credential_id",
    "requester_evidence_expires_at", "fence_arguments_json", "fence_request_digest", "scope_original_json", "status", "created_at",
    "admission_expires_at", "expires_at", "updated_at"})
SCOPE = frozenset({"id", "provider_id", "sequence", "authorization_sha256", "previous_head_json", "predecessors_json",
    "affected_originals_json", "inventory_original_json", "currentness_barriers_json", "fence_request_digest", "created_at", "expires_at"})
HEAD = frozenset({"id", "provider_id", "scope_kind", "provider_subject", "sequence", "scope_id", "scope_sha256", "created_at", "updated_at"})
CLAIM = frozenset({"id", "material_id", "scope_id", "provider_id", "scope_json", "authorization_sha256", "material_original_json",
    "claim_arguments_json", "claim_request_digest", "owner_nonce_sha256", "status", "created_at", "updated_at"})
ATTEMPT = frozenset({"id", "material_id", "material_claim_id", "scope_id", "token_purpose", "contact_request_sha256", "contact_arguments_json",
    "contact_request_digest", "finish_arguments_json", "finish_request_digest", "transport_original", "prior_contact_json", "status", "created_at", "updated_at"})
MATERIAL = frozenset({"apiVersion", "pin", "providerId", "enrollmentOriginal", "tokenEnvelope", "aadCredentialId", "aadCredentialVersion", "sourceOriginals"})
CANDIDATE = frozenset({"apiVersion", "authorizationSha256", "credentialId", "previousVersion", "exchangeId", "tokenSecretSha256",
    "tokenEnvelope", "metadata", "review", "payloadDigest", "createdAtEpochNs", "expiresAtEpochNs", "scopeSha256", "materialClosureSha256"})
ORIGINALS = frozenset({"journalOriginal", "scopeOriginal", "headOriginal", "materialOriginals", "attemptOriginals", "exchangeOriginal",
    "custodyOriginal", "candidateOriginal", "associationOriginal"})
OBSERVATION = frozenset({"status", "approval", "snapshotOriginal", "materialOriginal", "contactDisposition", "closureSha256"})


def record(original, fields, *, maximum=4 * 1024 * 1024, integers=(), nullable=()):
    value = stored(original, maximum)
    m.require(set(value) == fields)
    for name, item in value.items():
        if name in integers:
            m.integer(item)
        else:
            m.require(type(item) is str or name in nullable and item is None)
    if "id" in value:
        provider.identifier(value["id"])
    return value


def envelope(value, version):
    m.require(type(value) is dict and set(value) == m.ENVELOPE_FIELDS
        and type(value["credential_version"]) is int and value["credential_version"] == version
        and value["encrypted_secret"] == "envelope:v2")
    m.integer(version)
    for name in m.ENVELOPE_FIELDS - {"credential_version"}:
        m.text(value[name], 512 * 1024)
    m.require(value["secret_kek_id"].startswith("attested-memory-kek:") and len(value["secret_kek_id"]) == 44
        and all(char in "0123456789abcdef" for char in value["secret_kek_id"][-24:]))
    return value


def human(arguments, grant, journal):
    m.require(type(arguments) is dict and set(arguments) == material.HUMAN_FIELDS
        and arguments["action"] == "credential.oauth.retirement-succession" and arguments["resource_id"] == grant["authorizationId"]
        and arguments["actor_id"] == grant["requesterId"] and arguments["approval_id"] == journal["approval_id"]
        and arguments["authorization_original"] == m.encoded(journal["authorization_original"].encode("ascii"))
        and arguments["enrollment_original"] == m.encoded(journal["enrollment_original"].encode("ascii"))
        and m.canonical(arguments["credential_policy"]).decode("ascii") == journal["credential_policy_json"]
        and arguments["payload_digest"] == m.sha(m.canonical(arguments["request"])))


def transport(original, request_sha256):
    value = stored(original, 384 * 1024)
    m.require(set(value) == {"schema", "requestSha256", "status", "receivedAtEpochNs", "rawResponseSha256", "rawResponseEnvelope"}
        and value["schema"] == material.TRANSPORT and value["requestSha256"] == request_sha256)
    m.integer(value["receivedAtEpochNs"]); m.digest(value["rawResponseSha256"]); envelope(value["rawResponseEnvelope"], 1)
    status = value["status"]
    m.require(status is None or type(status) is int and 200 <= status <= 599)
    return "unknown" if status is None else "accepted" if 200 <= status < 300 else "rejected"


class Originals:
    def __init__(self):
        self.journal_original = self.scope_original = self.head_original = None
        self.target = self.inventory = self.exchange = self.custody = None
        self.claims, self.attempts = {}, {}

    def pin_scope(self, originals, grant, enrollment_original, *, historical=False):
        m.require(type(originals) is dict and set(originals) == ORIGINALS)
        journal = record(originals["journalOriginal"], JOURNAL)
        scope = record(originals["scopeOriginal"], SCOPE, integers={"sequence"}, nullable={"previous_head_json"})
        head = record(originals["headOriginal"], HEAD, maximum=8192, integers={"sequence"}, nullable={"provider_subject"})
        m.require(journal["status"] in ({"fenced", "committed"} if historical else {"fenced"})
            and journal["id"] == scope["id"] == head["scope_id"] == grant["authorizationId"]
            and journal["provider_id"] == scope["provider_id"] == head["provider_id"] == grant["providerId"]
            and journal["actor_id"] == grant["requesterId"] and journal["enrollment_original"].encode("ascii") == enrollment_original
            and material.grant(journal["authorization_original"].encode("ascii"))["payload"] == grant
            and journal["authorization_sha256"] == scope["authorization_sha256"] == m.sha(journal["authorization_original"].encode("ascii"))
            and journal["fence_request_digest"] == scope["fence_request_digest"]
            and journal["scope_original_json"] == originals["scopeOriginal"]
            and head["scope_sha256"] == m.sha(originals["scopeOriginal"].encode("ascii"))
            and head["sequence"] == scope["sequence"] and head["scope_kind"] == grant["scope"]["kind"]
            and head["provider_subject"] == grant["scope"]["providerSubject"]
            and head["id"] == str(uuid.uuid5(uuid.NAMESPACE_URL, "serverware.oauthRetiredScopeHead/v1:" + grant["providerId"])))
        provider.identifier(journal["approval_id"]); m.text(journal["requester_credential_id"], 1024)
        for name in ("authorize_request_digest", "fence_request_digest"):
            m.digest(journal[name])
        m.require(epoch(journal["admission_expires_at"]) == grant["admissionExpiresAtEpochNs"] // 1000 * 1000
            and epoch(scope["expires_at"]) == epoch(journal["expires_at"]) == grant["expiresAtEpochNs"] // 1000 * 1000
            and grant["issuedAtEpochNs"] <= epoch(journal["created_at"]) <= epoch(scope["created_at"])
            < epoch(journal["admission_expires_at"]) and epoch(scope["created_at"]) < epoch(journal["requester_evidence_expires_at"]))
        fenced = stored(journal["fence_arguments_json"], material.MAX_ARGUMENT)
        human(fenced, grant, journal)
        request = fenced["request"]
        m.require(type(request) is dict and set(request) == {"authorizationRowSha256", "currentnessBarriers", "issuedAtEpochNs", "expiresAtEpochNs"}
            and grant["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= epoch(scope["created_at"]) < request["expiresAtEpochNs"] <= grant["admissionExpiresAtEpochNs"])
        m.digest(request["authorizationRowSha256"])
        if scope["previous_head_json"] is None:
            m.require(grant["previousHeadSha256"] is None and scope["sequence"] == 1)
        else:
            previous = record(scope["previous_head_json"], HEAD, maximum=8192, integers={"sequence"}, nullable={"provider_subject"})
            m.require(m.sha(scope["previous_head_json"].encode("ascii")) == grant["previousHeadSha256"]
                and previous["sequence"] + 1 == scope["sequence"] and previous["provider_id"] == grant["providerId"])
        predecessors = material.array(scope["predecessors_json"].encode("ascii"), 4 * 1024 * 1024)
        m.require(len(predecessors) == len(grant["predecessors"]))
        for actual, pin in zip(predecessors, grant["predecessors"]):
            m.require(type(actual) is dict and set(actual) == {"kind", "rowOriginal", "journalOriginal"} and actual["kind"] == pin["kind"]
                and m.sha(actual["rowOriginal"].encode("ascii")) == pin["rowSha256"]
                and m.sha(actual["journalOriginal"].encode("ascii")) == pin["journalSha256"]
                and stored(actual["rowOriginal"])["id"] == pin["id"])
        pairs = material.array(scope["affected_originals_json"].encode("ascii"), 4 * 1024 * 1024)
        drains = material.array(scope["currentness_barriers_json"].encode("ascii"), 65536)
        m.require(len(pairs) == len(drains) == len(grant["affectedLineages"]))
        target, active = None, []
        for pair, drain, pin in zip(pairs, drains, grant["affectedLineages"]):
            m.require(type(pair) is dict and set(pair) == {"credentialOriginal", "generationOriginal"}
                and type(drain) is dict and set(drain) == {"credentialId", "credentialVersion", "barrierSha256", "consumeRequestDigest"})
            credential, generation = stored(pair["credentialOriginal"], 512 * 1024), stored(pair["generationOriginal"], 8192)
            m.require(set(credential) == CREDENTIAL and set(generation) == {"credential_id", "last_version", "updated_at"}
                and m.sha(pair["credentialOriginal"].encode("ascii")) == pin["credentialRowSha256"]
                and m.sha(pair["generationOriginal"].encode("ascii")) == pin["generationRowSha256"]
                and credential["id"] == generation["credential_id"] == drain["credentialId"] == pin["credentialId"]
                and credential["credential_version"] == generation["last_version"] == drain["credentialVersion"] == pin["credentialVersion"]
                and credential["kind"] == "oauth2")
            m.digest(drain["barrierSha256"]); m.digest(drain["consumeRequestDigest"])
            if pin["predecessorKind"] == "active":
                m.require(credential["lifecycle_status"] == "active" and drain["consumeRequestDigest"] == scope["fence_request_digest"])
                active.append({name: drain[name] for name in ("credentialId", "credentialVersion", "barrierSha256")})
            metadata = stored(credential["metadata"], 32768)
            m.require(metadata.get("provider_id") == grant["providerId"] and metadata.get("provider_identity_verified") is True
                and (grant["scope"]["kind"] == "provider" or metadata.get("provider_subject") == grant["providerSubject"]))
            if credential["id"] == grant["credentialId"]:
                m.require(m.sha(m.canonical(metadata)) == grant["metadataSha256"]
                    and metadata.get("provider_subject") == grant["providerSubject"] and metadata.get("provider_account") == grant["providerAccount"])
                target = credential
        m.require(target is not None and request["currentnessBarriers"] == active)
        inventory = stored(scope["inventory_original_json"])
        m.require(set(inventory) == {"snapshotBindings", "materialOriginals", "priorContacts", "analysisSha256"})
        m.digest(inventory["analysisSha256"])
        snapshots = inventory["snapshotBindings"]
        m.require(type(snapshots) is list and len(snapshots) == len(grant["inventoryRoots"]))
        for actual, root in zip(snapshots, grant["inventoryRoots"]):
            m.require(type(actual) is dict and set(actual) == {"snapshotId", "snapshotSha256"}
                and actual["snapshotId"] == str(uuid.uuid5(uuid.UUID(grant["authorizationId"]), "serverware.oauthRetiredScopeSnapshot/v1:" + root["part"])))
            m.digest(actual["snapshotSha256"])
        materials = inventory["materialOriginals"]
        m.require(type(materials) is list and len(materials) == len(grant["materials"]))
        for item, pin in zip(materials, grant["materials"]):
            m.require(type(item) is dict and set(item) == MATERIAL and item["apiVersion"] == "serverware.oauthRetiredScopeMaterial/v1"
                and item["pin"] == pin and item["providerId"] == grant["providerId"]
                and item["aadCredentialVersion"] == pin["sourceVersion"] and m.sha(m.canonical(item["tokenEnvelope"])) == pin["tokenEnvelopeSha256"]
                and type(item["sourceOriginals"]) is dict)
            envelope(item["tokenEnvelope"], pin["sourceVersion"])
            if pin["sourceKind"] in {"reconnect-candidate", "succession-candidate"}:
                # Candidate identity is the originating exchange, whereas its
                # actual encrypted envelope targets credential/N+1. Preserve
                # the producer's distinct AAD, never substitute exchange ID.
                candidate = stored(item["sourceOriginals"]["candidateOriginal"], 512 * 1024)
                m.require(m.sha(m.canonical(candidate)) == pin["sourceRowSha256"]
                    and candidate["exchangeId"] == pin["sourceId"] and candidate["previousVersion"] + 1 == pin["sourceVersion"]
                    and candidate["credentialId"] == item["aadCredentialId"] and candidate["tokenEnvelope"] == item["tokenEnvelope"])
                provider.identifier(item["aadCredentialId"])
            else:
                m.require(item["aadCredentialId"] == pin["sourceId"])
            if item["enrollmentOriginal"] is not None:
                m.require(m.sha(item["enrollmentOriginal"].encode("ascii")) == pin["enrollmentSha256"])
        m.require(type(inventory["priorContacts"]) is list and len(inventory["priorContacts"]) <= 64)
        if self.scope_original is not None:
            m.require(originals["scopeOriginal"] == self.scope_original and originals["headOriginal"] == self.head_original)
            old = stored(self.journal_original)
            m.require(journal == old or historical and journal == {**old, "status": "committed", "updated_at": journal["updated_at"]})
        self.journal_original, self.scope_original, self.head_original = (originals[name] for name in ("journalOriginal", "scopeOriginal", "headOriginal"))
        self.target, self.inventory = target, inventory
        return journal, scope, target

    def effects(self, originals, grant):
        claims, attempts = {}, {}
        m.require(type(originals["materialOriginals"]) is list and len(originals["materialOriginals"]) <= len(grant["materials"])
            and type(originals["attemptOriginals"]) is list and len(originals["attemptOriginals"]) <= 32)
        for original in originals["materialOriginals"]:
            row = record(original, CLAIM)
            pin = next((item for item in grant["materials"] if item["materialId"] == row["material_id"]), None)
            m.require(pin is not None and row["id"] == material.claim_id(grant["authorizationId"], pin["materialId"])
                and row["id"] not in claims and row["scope_id"] == grant["authorizationId"] and row["status"] == "claimed"
                and row["authorization_sha256"] == m.sha(stored(self.journal_original)["authorization_original"].encode("ascii"))
                and row["provider_id"] == grant["providerId"] and stored(row["scope_json"], 8192) == grant["scope"])
            expected = next(item for item in self.inventory["materialOriginals"] if item["pin"] == pin)
            m.require(row["material_original_json"] == m.canonical(expected).decode("ascii"))
            m.digest(row["claim_request_digest"]); m.digest(row["owner_nonce_sha256"])
            if row["id"] in self.claims:
                m.require(row == self.claims[row["id"]])
            claims[row["id"]] = row
        for original in originals["attemptOriginals"]:
            row = record(original, ATTEMPT, maximum=512 * 1024,
                nullable={"finish_arguments_json", "finish_request_digest", "transport_original", "prior_contact_json"})
            claim = claims.get(row["material_claim_id"])
            m.require(claim is not None and row["id"] == material.attempt_id(claim["id"], row["token_purpose"])
                and row["id"] not in attempts and row["material_id"] == claim["material_id"] and row["scope_id"] == grant["authorizationId"]
                and row["token_purpose"] in stored(claim["material_original_json"])["pin"]["tokenPurposes"]
                and row["status"] in {"contact-claimed", "accepted", "accepted-existing", "rejected", "unknown"})
            m.digest(row["contact_request_sha256"]); m.digest(row["contact_request_digest"])
            contact = stored(row["contact_arguments_json"], material.MAX_ARGUMENT)
            m.require(contact["request"]["contactRequestSha256"] == row["contact_request_sha256"]
                and contact["request"]["materialRowSha256"] == m.sha(m.canonical(claim)))
            if row["status"] in {"contact-claimed", "accepted-existing"}:
                m.require(all(row[name] is None for name in ("finish_arguments_json", "finish_request_digest", "transport_original")))
            else:
                m.digest(row["finish_request_digest"])
                m.require(row["status"] == transport(row["transport_original"], row["contact_request_sha256"]))
            m.require((row["prior_contact_json"] is not None) == (row["status"] == "accepted-existing"))
            if row["status"] == "accepted-existing":
                prior = stored(row["prior_contact_json"], 512 * 1024)
                m.require(set(prior) == {"profile", "attemptOriginal", "sourceOriginal"}
                    and prior["profile"] in {"exchange", "refresh", "measured-refresh", "pending", "capture", "succession"})
                before = stored(prior["attemptOriginal"], 512 * 1024)
                m.require(before["status"] == "accepted" and before["contact_request_sha256"] == row["contact_request_sha256"]
                    and before["transport_original"] is not None)
                report = stored(before["transport_original"], 384 * 1024)
                m.require(report["requestSha256"] == row["contact_request_sha256"] and type(report["status"]) is int and 200 <= report["status"] < 300)
                stored(prior["sourceOriginal"])
            old = self.attempts.get(row["id"])
            if old is not None:
                m.require(row == old or old["status"] == "contact-claimed" and row == {**old, **{name: row[name]
                    for name in ("status", "finish_arguments_json", "finish_request_digest", "transport_original", "updated_at")}})
            attempts[row["id"]] = row
        m.require(self.claims.keys() <= claims.keys() and self.attempts.keys() <= attempts.keys())
        self.claims, self.attempts = claims, attempts
        return claims, attempts

    def closure(self, grant):
        expected = {material.attempt_id(material.claim_id(grant["authorizationId"], pin["materialId"]), purpose)
            for pin in grant["materials"] for purpose in pin["tokenPurposes"]}
        m.require(set(self.attempts) == expected and all(row["status"] in {"accepted", "accepted-existing"} for row in self.attempts.values()))
        return m.sha(m.canonical(sorted(self.attempts.values(), key=lambda row: row["id"])))

    def fresh(self, result, arguments, grant, phase):
        original = result["originals"]
        row, custody = stored(original["exchangeOriginal"], 1024 * 1024), stored(original["custodyOriginal"])
        journal = stored(self.journal_original)
        m.require(set(row) == EXCHANGE and set(custody) == CUSTODY and row["id"] == custody["id"] == grant["authorizationId"]
            and row["provider_id"] == grant["providerId"] and row["requester_id"] == grant["requesterId"]
            and row["enrollment_original"] == arguments["enrollment_original"]
            and row["credential_policy_json"] == journal["credential_policy_json"]
            and custody["recovery_request_digest"] is None and custody["recovery_arguments_json"] is None
            and custody["recovery_expires_at_epoch_ns"] is None and custody["recovery_owner_nonce_sha256"] is None)
        prepared = stored(custody["preparation_arguments_json"], material.MAX_ARGUMENT)
        consent = stored(row["consent_json"], material.MAX_ARGUMENT)
        m.require(set(prepared) == material.ARGUMENT_FIELDS and prepared["request"] == consent
            and all(prepared[name] == arguments[name] for name in ("authorization_original", "enrollment_original", "credential_policy", "assignment_original"))
            and consent["metadata"] == stored(self.target["metadata"], 32768) and consent["credentialName"] == self.target["name"]
            and consent["exchangeId"] == grant["authorizationId"] and consent["providerId"] == grant["providerId"]
            and consent["enrollmentSha256"] == grant["enrollmentSha256"] and consent["scopeRowSha256"] == arguments["request"]["scopeRowSha256"]
            and all(consent[name] == grant[name] for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")))
        closure = self.closure(grant)
        m.require(result["observation"]["closureSha256"] == closure)
        if phase == "prepare":
            m.require(self.custody is None and custody["status"] == row["status"] == "prepared"
                and prepared == arguments and custody["prepare_request_digest"] == result["requestDigest"])
        else:
            m.require(self.custody is not None and arguments["request"]["exchangeRowSha256"] == m.sha(m.canonical(self.exchange)))
            slot = {"claim": "claim_arguments_json", "capture": "capture_arguments_json", "stage": "stage_arguments_json", "cancel": "cancel_arguments_json"}[phase]
            desired = {"claim": "claimed", "capture": "captured", "stage": "staged", "cancel": "cancelled"}[phase]
            m.require(stored(custody[slot], material.MAX_ARGUMENT) == arguments and custody["status"] == desired)
            if phase == "claim":
                m.require(self.custody["status"] == "prepared" and row["status"] == "claimed"
                    and row["claim_request_digest"] == result["requestDigest"] and custody["owner_nonce_sha256"] == arguments["request"]["ownerNonceSha256"]
                    and row["code_sha256"] == arguments["request"]["codeSha256"] and row["contact_request_sha256"] == arguments["request"]["contactRequestSha256"])
            elif phase == "capture":
                request = arguments["request"]
                m.require(self.custody["status"] == "claimed" and row["status"] == "retained"
                    and row["raw_response_sha256"] == request["rawResponseSha256"]
                    and stored(row["raw_response_envelope_json"]) == request["rawResponseEnvelope"]
                    and row["token_secret_sha256"] == request["issuedMaterialSha256"]
                    and (None if row["token_envelope_json"] is None else stored(row["token_envelope_json"])) == request["issuedMaterialEnvelope"]
                    and custody["received_at_epoch_ns"] == request["receivedAtEpochNs"])
            elif phase == "stage":
                m.require(self.custody["status"] == "captured" and row == {**self.exchange, "status": "staged", "updated_at": row["updated_at"]})
            else:
                m.require(self.custody["status"] == "prepared" and row == self.exchange)
            for name in ("prepare_request_digest", "preparation_arguments_json", "created_at"):
                m.require(custody[name] == self.custody[name])
            for name in ("claim_arguments_json", "capture_arguments_json", "owner_nonce_sha256", "received_at_epoch_ns"):
                if self.custody[name] is not None:
                    m.require(custody[name] == self.custody[name])
        m.require(original["associationOriginal"] is None and original["candidateOriginal"] == custody["candidate_original_json"]
            and result["observation"]["status"] == custody["status"])
        candidate = None
        if phase == "stage":
            candidate = stored(original["candidateOriginal"], 512 * 1024)
            request = arguments["request"]
            m.require(set(candidate) == CANDIDATE and candidate["apiVersion"] == "serverware.oauthRetiredScopeSuccessionCandidate/v1"
                and candidate["credentialId"] == grant["credentialId"] and candidate["previousVersion"] == grant["credentialVersion"]
                and candidate["exchangeId"] == grant["authorizationId"] and candidate["authorizationSha256"] == journal["authorization_sha256"]
                and candidate["scopeSha256"] == m.sha(self.scope_original.encode("ascii")) and candidate["materialClosureSha256"] == closure
                and all(candidate[name] == request[name] for name in ("tokenEnvelope", "tokenSecretSha256", "metadata", "review", "payloadDigest"))
                and 0 < candidate["createdAtEpochNs"] < candidate["expiresAtEpochNs"] == grant["pendingExpiresAtEpochNs"])
            envelope(candidate["tokenEnvelope"], grant["credentialVersion"] + 1)
        else:
            m.require(original["candidateOriginal"] is None)
        self.exchange, self.custody = row, custody
        return row, custody, candidate
