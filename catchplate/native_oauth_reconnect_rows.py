"""Exact retained reconnect originals, checked only inside receipt admission."""
from datetime import datetime, timezone
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_reconnect as material

JOURNAL = frozenset({"id", "authorization_original", "authorization_sha256", "enrollment_original", "actor_id",
    "credential_policy_json", "original_affected_json", "authorize_arguments_json", "authorize_request_digest",
    "currentness_barriers_json", "fence_arguments_json", "fence_request_digest", "status", "created_at",
    "admission_expires_at", "expires_at", "updated_at"})
CUSTODY = frozenset({"id", "prepare_request_digest", "preparation_arguments_json", "claim_arguments_json",
    "capture_arguments_json", "stage_arguments_json", "cancel_arguments_json", "owner_nonce_sha256", "received_at_epoch_ns",
    "recovery_request_digest", "recovery_expires_at_epoch_ns", "recovery_arguments_json", "recovery_owner_nonce_sha256",
    "candidate_original_json", "commit_request_digest", "committed_credential_json", "predecessor_original_json", "status", "created_at", "updated_at"})
EXCHANGE = frozenset({"id", "provider_id", "requester_id", "enrollment_original", "credential_policy_json", "consent_json", "status",
    "claim_request_digest", "code_sha256", "contact_request_sha256", "raw_response_sha256", "raw_response_envelope_json",
    "token_secret_sha256", "token_envelope_json", "created_at", "updated_at"})
CREDENTIAL = frozenset({"id", "name", "kind", "encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id",
    "credential_version", "secret_updated_at", "metadata", "lifecycle_status", "revocation_error", "revocation_requested_at", "created_at", "updated_at"})
CANDIDATE = frozenset({"apiVersion", "authorizationSha256", "credentialId", "previousVersion", "exchangeId", "tokenSecretSha256",
    "tokenEnvelope", "metadata", "review", "payloadDigest", "createdAtEpochNs", "expiresAtEpochNs"})
ORIGINALS = frozenset({"journalOriginal", "exchangeOriginal", "custodyOriginal", "candidateOriginal"})


def stored(value, maximum=4 * 1024 * 1024):
    m.require(type(value) is str and len(value) <= maximum)
    return m.document(value.encode("ascii"), maximum)


def epoch(value):
    m.require(type(value) is str)
    stamp = datetime.fromisoformat(value)
    m.require(stamp.tzinfo is not None and stamp.utcoffset() == timezone.utc.utcoffset(stamp))
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return m.integer((delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000)


def human(arguments, grant, journal):
    m.require(type(arguments) is dict and set(arguments) == material.HUMAN_FIELDS
        and arguments["action"] == "credential.oauth.reconnect" and arguments["resource_id"] == grant["authorizationId"]
        and arguments["actor_id"] == grant["requesterId"] and arguments["approval_id"] is None
        and arguments["authorization_original"] == m.encoded(journal["authorization_original"].encode("ascii"))
        and arguments["enrollment_original"] == m.encoded(journal["enrollment_original"].encode("ascii"))
        and m.canonical(arguments["credential_policy"]).decode("ascii") == journal["credential_policy_json"]
        and arguments["payload_digest"] == m.sha(m.canonical(arguments["request"])))


def journal(original, grant, application_original):
    value = stored(original)
    m.require(set(value) == JOURNAL and all(type(item) is str for item in value.values())
        and value["status"] == "fenced" and value["id"] == grant["authorizationId"]
        and value["actor_id"] == grant["requesterId"] and value["enrollment_original"].encode("ascii") == application_original
        and value["authorization_sha256"] == m.sha(value["authorization_original"].encode("ascii"))
        and material.grant(value["authorization_original"].encode("ascii"))["payload"] == grant)
    authorized, fenced = stored(value["authorize_arguments_json"], 2 * 1024 * 1024), stored(value["fence_arguments_json"], 2 * 1024 * 1024)
    human(authorized, grant, value); human(fenced, grant, value)
    m.require(authorized["request"] == {"credentialId": grant["credentialId"], "credentialVersion": grant["credentialVersion"],
        "authorizationSha256": value["authorization_sha256"]})
    before = {**value, "status": "authorized", "currentness_barriers_json": None, "fence_arguments_json": None,
        "fence_request_digest": None, "updated_at": value["created_at"]}
    barriers = material.array(value["currentness_barriers_json"].encode("ascii"), 16384)
    m.require(len(barriers) == len(grant["affectedLineages"]))
    for barrier, pin in zip(barriers, grant["affectedLineages"]):
        m.require(type(barrier) is dict and set(barrier) == {"credentialId", "credentialVersion", "barrierSha256"}
            and barrier["credentialId"] == pin["credentialId"] and barrier["credentialVersion"] == pin["credentialVersion"])
        m.integer(barrier["credentialVersion"])
        m.digest(barrier["barrierSha256"])
    m.require(fenced["request"] == {"authorizationRowSha256": m.sha(m.canonical(before)), "currentnessBarriers": barriers,
        "issuedAtEpochNs": epoch(value["created_at"]), "expiresAtEpochNs": epoch(value["admission_expires_at"])}
        and grant["issuedAtEpochNs"] <= epoch(value["created_at"]) <= epoch(value["updated_at"])
        < epoch(value["admission_expires_at"]) <= grant["contactExpiresAtEpochNs"]
        and epoch(value["admission_expires_at"]) - epoch(value["created_at"]) <= 30_000_000_000
        and epoch(value["expires_at"]) == grant["expiresAtEpochNs"] // 1000 * 1000)
    m.digest(value["authorize_request_digest"]); m.digest(value["fence_request_digest"])
    pairs = material.array(value["original_affected_json"].encode("ascii"), 4 * 1024 * 1024)
    m.require(len(pairs) == len(grant["affectedLineages"]))
    target = None
    for pair, pin in zip(pairs, grant["affectedLineages"]):
        m.require(type(pair) is dict and set(pair) == {"credentialOriginal", "generationOriginal"})
        credential, head = stored(pair["credentialOriginal"], 512 * 1024), stored(pair["generationOriginal"], 8192)
        m.require(set(credential) == CREDENTIAL and set(head) == {"credential_id", "last_version", "updated_at"}
            and m.sha(pair["credentialOriginal"].encode("ascii")) == pin["credentialRowSha256"]
            and m.sha(pair["generationOriginal"].encode("ascii")) == pin["generationRowSha256"]
            and credential["id"] == head["credential_id"] == pin["credentialId"]
            and credential["credential_version"] == head["last_version"] == pin["credentialVersion"]
            and credential["kind"] == "oauth2" and credential["lifecycle_status"] == "active"
            and credential["revocation_error"] is None and credential["revocation_requested_at"] is None)
        metadata = stored(credential["metadata"], 512 * 1024)
        m.require(metadata.get("oauth") is True and metadata.get("provider_identity_verified") is True
            and metadata.get("provider_id") == grant["providerId"] and metadata.get("provider_subject") == grant["providerSubject"]
            and metadata.get("provider_account") == grant["providerAccount"])
        if credential["id"] == grant["credentialId"]:
            m.require(m.sha(m.canonical(metadata)) == grant["metadataSha256"])
            target = credential
    m.require(target is not None)
    return value, target


class Originals:
    def __init__(self):
        self.journal_original = self.exchange = self.custody = None

    def pin_journal(self, original, grant, application_original):
        value, target = journal(original, grant, application_original)
        if self.journal_original is None:
            self.journal_original = original
        m.require(original == self.journal_original)
        return value, target

    def verify(self, originals, arguments, result, grant, application_original):
        m.require(type(originals) is dict and set(originals) == ORIGINALS)
        retained, target = self.pin_journal(originals["journalOriginal"], grant, application_original)
        m.require(arguments["request"]["fencedRowSha256"] == m.sha(originals["journalOriginal"].encode("ascii")))
        row, custody = stored(originals["exchangeOriginal"], 1024 * 1024), stored(originals["custodyOriginal"])
        m.require(set(row) == EXCHANGE and set(custody) == CUSTODY and row["id"] == custody["id"] == grant["authorizationId"]
            and row["provider_id"] == grant["providerId"] and row["requester_id"] == grant["requesterId"]
            and row["enrollment_original"] == m.encoded(application_original)
            and row["credential_policy_json"] == retained["credential_policy_json"]
            and custody["status"] in {"prepared", "claimed", "captured", "staged", "cancelled", "committed"})
        preparation = stored(custody["preparation_arguments_json"], 2 * 1024 * 1024)
        consent = stored(row["consent_json"], 1024 * 1024)
        m.require(set(preparation) == material.ARGUMENT_FIELDS and preparation["request"] == consent
            and preparation["authorization_original"] == arguments["authorization_original"]
            and preparation["enrollment_original"] == arguments["enrollment_original"]
            and preparation["credential_policy"] == arguments["credential_policy"]
            and consent["metadata"] == stored(target["metadata"], 512 * 1024) and consent["credentialName"] == target["name"]
            and consent["exchangeId"] == grant["authorizationId"] and consent["providerId"] == grant["providerId"]
            and consent["enrollmentSha256"] == grant["enrollmentSha256"]
            and consent["fencedRowSha256"] == arguments["request"]["fencedRowSha256"]
            and all(consent[name] == grant[name] for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")))
        phase = result["operation"].rsplit(".", 1)[1]
        if phase == "prepare":
            m.require(self.custody is None and custody["status"] == row["status"] == "prepared"
                and preparation == arguments and custody["prepare_request_digest"] == result["requestDigest"])
        elif phase == "recover":
            m.require(custody["status"] in {"captured", "staged", "committed"}
                and m.sha(custody["capture_arguments_json"].encode("ascii")) == arguments["request"]["captureInputSha256"])
            if custody["status"] == "captured":
                m.require(custody["recovery_request_digest"] == result["requestDigest"]
                    and stored(custody["recovery_arguments_json"], 2 * 1024 * 1024) == arguments
                    and custody["recovery_owner_nonce_sha256"] == arguments["request"]["ownerNonceSha256"]
                    and custody["recovery_expires_at_epoch_ns"] == arguments["request"]["expiresAtEpochNs"])
        else:
            m.require(self.custody is not None and arguments["request"]["exchangeRowSha256"] == m.sha(m.canonical(self.exchange)))
            slot = {"claim": "claim_arguments_json", "capture": "capture_arguments_json", "stage": "stage_arguments_json", "cancel": "cancel_arguments_json"}[phase]
            m.require(stored(custody[slot], 2 * 1024 * 1024) == arguments
                and custody["status"] == {"claim": "claimed", "capture": "captured", "stage": "staged", "cancel": "cancelled"}[phase])
            if phase == "claim":
                m.require(self.custody["status"] == "prepared" and row["claim_request_digest"] == result["requestDigest"]
                    and custody["owner_nonce_sha256"] == arguments["request"]["ownerNonceSha256"])
            elif phase == "capture":
                request = arguments["request"]
                m.require(self.custody["status"] == "claimed" and row["raw_response_sha256"] == request["rawResponseSha256"]
                    and stored(row["raw_response_envelope_json"]) == request["rawResponseEnvelope"]
                    and row["token_secret_sha256"] == request["issuedMaterialSha256"]
                    and (None if row["token_envelope_json"] is None else stored(row["token_envelope_json"])) == request["issuedMaterialEnvelope"]
                    and custody["received_at_epoch_ns"] == request["receivedAtEpochNs"])
            elif phase == "stage":
                m.require(self.custody["status"] == "captured")
            else:
                m.require(self.custody["status"] == "prepared" and row == self.exchange)
            for field in ("prepare_request_digest", "preparation_arguments_json", "created_at"):
                m.require(custody[field] == self.custody[field])
            for field in ("claim_arguments_json", "capture_arguments_json", "recovery_request_digest", "recovery_arguments_json",
                    "recovery_expires_at_epoch_ns", "recovery_owner_nonce_sha256"):
                if self.custody[field] is not None:
                    m.require(custody[field] == self.custody[field])
        candidate = None
        m.require(originals["candidateOriginal"] == custody["candidate_original_json"])
        if custody["status"] in {"staged", "committed"}:
            candidate = stored(originals["candidateOriginal"], 512 * 1024)
            staged = stored(custody["stage_arguments_json"], 2 * 1024 * 1024)["request"]
            m.require(set(candidate) == CANDIDATE and candidate["apiVersion"] == "catchplate.oauthReconnectCandidate/v1"
                and candidate["credentialId"] == grant["credentialId"] and candidate["previousVersion"] == grant["credentialVersion"]
                and candidate["exchangeId"] == grant["authorizationId"] and candidate["authorizationSha256"] == retained["authorization_sha256"]
                and candidate["tokenEnvelope"]["credential_version"] == grant["credentialVersion"] + 1
                and all(candidate[name] == staged[name] for name in ("tokenEnvelope", "tokenSecretSha256", "metadata", "review", "payloadDigest"))
                and 0 < candidate["createdAtEpochNs"] < candidate["expiresAtEpochNs"] <= grant["pendingExpiresAtEpochNs"])
        else:
            m.require(originals["candidateOriginal"] is None)
        self.exchange, self.custody = row, custody
        return retained, row, custody, candidate, target
