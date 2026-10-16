"""Reviewed first Google preparation on a retained operator store.

Legacy preparation stays public-only. Internal managed preparation also retains
an encrypted application secret in the same setup/audit transaction; it neither
edits effective settings nor contacts a provider. The separately versioned v2
configuration path selects one exact operation and uses its dedicated app key;
the v1 foundation remains unselected. No managed HTTP API is exposed here.
Cold activation consumes the exact pending review in the caller's publication
transaction; it preserves resource rows and signed policy, not stale reviews.
Import and retained-row decoding are configuration-independent. API/runtime
functions import configured database access only when called; this module does
not itself implement managed cold configuration or early-startup admission.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import sqlite3
import uuid

from pydantic import ConfigDict, Field, field_validator

from serverware import operator_catalog_schema as catalog
from serverware import operator_catalog_oauth_profile as profiles
from serverware import operator_provider_custody as custody
from serverware.db_common import audit_hash
from serverware.operator_catalog_inputs import RevisionInput, _identifier
from serverware.operator_publication import exclusive, assert_held

TABLE = "operator_google_setups"
MAX_OPERATIONS = 1024
_PREFIX = "operator_catalog.google_setup."
_KEYS = {"operation_id", "actor_id", "client_id", "old_settings", "target_settings",
    "expected_settings_digest", "public_url", "redirect_uri", "profile_binding", "profile_binding_digest",
    "reviewed_revision", "staged_revision", "policy_hash", "created_at"}
MANAGED_BINDING = "serverware.operatorGoogleManagedSetupBinding/v1"
MANAGED_PUBLIC = "serverware.operatorGoogleManagedSetup/v1"
MANAGED_BINDING_V2 = "serverware.operatorGoogleManagedSetupBinding/v2"
MANAGED_PUBLIC_V2 = "serverware.operatorGoogleManagedSetup/v2"
MANAGED_KEY_SOURCE = "operator-provider-key-v1"
_MANAGED_KEYS = _KEYS | {"setup_contract", "custody_ref"}
_SQL = """CREATE TABLE operator_google_setups (
    operation_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, status TEXT NOT NULL,
    binding_json TEXT NOT NULL, terminal_revision INTEGER, terminal_policy_hash TEXT, completed_at TEXT) WITHOUT ROWID"""
_IMMUTABLE = """CREATE TRIGGER operator_google_setups_immutable BEFORE UPDATE ON operator_google_setups
    WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.actor_id IS NOT OLD.actor_id
      OR NEW.binding_json IS NOT OLD.binding_json OR OLD.status IS NOT 'pending'
      OR NEW.status NOT IN ('cancelled','activated')
    BEGIN SELECT RAISE(ABORT,'operator Google setup binding is immutable'); END"""
_RETAINED = """CREATE TRIGGER operator_google_setups_retained BEFORE DELETE ON operator_google_setups
    BEGIN SELECT RAISE(ABORT,'operator Google setup history must be retained'); END"""
_INSERT = """CREATE TRIGGER operator_google_setups_insert_guard BEFORE INSERT ON operator_google_setups
    WHEN EXISTS (SELECT 1 FROM operator_google_setups WHERE operation_id=NEW.operation_id)
      OR (NEW.status='pending' AND EXISTS (SELECT 1 FROM operator_google_setups WHERE status='pending'))
    BEGIN SELECT RAISE(ABORT,'operator Google setup already exists'); END"""
_PENDING = "CREATE UNIQUE INDEX operator_google_setups_one_pending ON operator_google_setups(status) WHERE status='pending'"
_DEFINITIONS = ((TABLE, "table", _SQL), (TABLE + "_immutable", "trigger", _IMMUTABLE),
    (TABLE + "_retained", "trigger", _RETAINED), (TABLE + "_insert_guard", "trigger", _INSERT),
    (TABLE + "_one_pending", "index", _PENDING))


class SetupUnavailable(RuntimeError):
    """Fixed, non-secret setup admission failure."""


class SetupNotFound(LookupError):
    """No operation belongs to this exact actor and locator."""


class SetupInput(RevisionInput):
    operation_id: str = Field(min_length=36, max_length=36)
    client_id: str = Field(min_length=1, max_length=240)
    expected_settings_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71)
    _uuid = field_validator("operation_id")(_identifier)

    @field_validator("client_id")
    @classmethod
    def google_client(cls, value):
        if profiles._CLIENT_ID.fullmatch(value) is None:
            raise ValueError("Google public client ID refused")
        return value


class CancelInput(RevisionInput):
    operation_id: str = Field(min_length=36, max_length=36)
    _uuid = field_validator("operation_id")(_identifier)


class ManagedSetupInput(SetupInput):
    """Write-only managed setup input; secrets are excluded from public receipts."""
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    client_secret: str = Field(min_length=1, max_length=custody.MAX_SECRET_BYTES, repr=False, exclude=True)

    @field_validator("client_secret")
    @classmethod
    def application_secret(cls, value):
        try:
            custody._secret(value)
        except custody.CustodyError:
            raise ValueError("operator Google application secret refused") from None
        return value


def _require(value):
    if not value:
        raise SetupUnavailable("operator Google setup unavailable")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _settings(raw):
    from serverware import operator_demo
    _require(isinstance(raw, str) and len(raw.encode("utf-8")) <= 16384)
    value = json.loads(raw)
    _require(isinstance(value, dict) and set(value) == {"allowed_upstreams", "fixture_cidrs"}
        and isinstance(value["allowed_upstreams"], list) and 1 <= len(value["allowed_upstreams"]) <= operator_demo.MAX_ALLOWED_UPSTREAMS
        and all(isinstance(item, str) and operator_demo.origin(item)[0] == item for item in value["allowed_upstreams"])
        and len(set(value["allowed_upstreams"])) == len(value["allowed_upstreams"])
        and isinstance(value["fixture_cidrs"], list) and len(value["fixture_cidrs"]) <= 16
        and all(isinstance(item, str) for item in value["fixture_cidrs"])
        and raw == json.dumps(value, sort_keys=True))
    return value


def _target(old):
    from serverware.operator_demo import MAX_ALLOWED_UPSTREAMS
    origins = list(old["allowed_upstreams"])
    if "https://gmail.googleapis.com" not in origins:
        origins.append("https://gmail.googleapis.com")
    _require(len(origins) <= MAX_ALLOWED_UPSTREAMS)
    return {"allowed_upstreams": origins, "fixture_cidrs": list(old["fixture_cidrs"])}


def _public_origin():
    from serverware import config, operator_demo
    origin, _ = operator_demo.origin(config.PUBLIC_URL)
    _require(config.PUBLIC_URL == origin and origin != "https://demo-upstream:8443")
    return origin, origin + profiles.CALLBACK_PATH


def _actor(actor_id):
    _require(isinstance(actor_id, str) and 1 <= len(actor_id) <= 512)


def _audit(conn, operation_id, action, expected):
    row = conn.execute("SELECT * FROM audit_events WHERE id=?", ("operator-google-setup:" + operation_id + ":" + action,)).fetchone()
    _require(row is not None and row["event_type"] == _PREFIX + action and row["actor_type"] == "admin"
        and row["actor_id"] == expected["actor_id"] and json.loads(row["event_json"]) == expected
        and row["event_hash"] == audit_hash(event_id=row["id"], event_type=row["event_type"],
            actor_type=row["actor_type"], actor_id=row["actor_id"], event_json=row["event_json"],
            prev_event_hash=row["prev_event_hash"], created_at=row["created_at"]))


def _terminal(item):
    return {"operation_id": item["operation_id"], "actor_id": item["actor_id"], "status": item["status"],
        "revision": item["terminal_revision"], "policy_hash": item["terminal_policy_hash"],
        "profile_binding_digest": item["binding"]["profile_binding_digest"], "completed_at": item["completed_at"]}


def _managed(item):
    return item["binding"].get("setup_contract") in {MANAGED_BINDING, MANAGED_BINDING_V2}


def _managed_configuration(item):
    return item["binding"].get("setup_contract") == MANAGED_BINDING_V2


def _custody_present(conn):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE lower(name) GLOB 'operator_provider_custody*' "
        "OR lower(tbl_name) GLOB 'operator_provider_custody*' LIMIT 1").fetchone() is not None


def _structural_owner_reference(owner_id):
    # This is only a local, process-bound reference for public schema inspection,
    # NOT development-profile admission or readiness. The internal custody type
    # is not an unforgeable capability. No key read/decrypt is reachable here.
    # Writers and cold secret consumers must separately admit actual ownership.
    return custody.DevelopmentOwner(owner_id, os.geteuid(), os.getpid())


def _inspect_custody(conn, items):
    managed = [item for item in items if _managed(item)]
    if not managed:
        _require(not _custody_present(conn))
        return
    _require(len(managed) <= custody.MAX_VERSIONS)
    _require(len({item["binding"]["setup_contract"] for item in managed}) == 1)
    references = [item["binding"]["custody_ref"] for item in managed]
    owner_id = references[0]["owner_id"]
    _require(all(ref["owner_id"] == owner_id for ref in references)
        and {ref["config_version"] for ref in references} == set(range(1, len(managed) + 1)))
    owner = _structural_owner_reference(owner_id)
    for item in managed:
        binding = item["binding"]
        exact = custody.bind_google(owner, config_version=binding["custody_ref"]["config_version"],
            public_profile=binding["profile_binding"])
        custody.inspect_public_binding(conn, owner, exact)
    # Inspection above validates the full custody grammar and bounded envelopes.
    # Require a bijection: no retained row is an orphan or an implicit candidate.
    versions = conn.execute("SELECT config_version FROM " + custody.TABLE + " ORDER BY config_version LIMIT ?",
        (custody.MAX_VERSIONS + 1,)).fetchall()
    _require([row[0] for row in versions] == list(range(1, len(managed) + 1)))


def _managed_binding(binding, status):
    reference = binding["custody_ref"]
    version_two = binding["setup_contract"] == MANAGED_BINDING_V2
    _require((version_two and status in {"pending", "cancelled", "activated"}
            or binding["setup_contract"] == MANAGED_BINDING and status in {"pending", "cancelled"})
        and type(reference) is dict
        and set(reference) == ({"owner_id", "config_version", "key_source"} if version_two else {"owner_id", "config_version"})
        and (not version_two or reference["key_source"] == MANAGED_KEY_SOURCE)
        and _identifier(reference["owner_id"]) == reference["owner_id"]
        and type(reference["config_version"]) is int and 1 <= reference["config_version"] <= custody.MAX_VERSIONS)
    # The managed contract is separately versioned and closed. It uses the
    # existing settings/profile grammars, not a second configuration authority.
    _settings(json.dumps(binding["old_settings"], sort_keys=True))
    _settings(json.dumps(binding["target_settings"], sort_keys=True))
    from serverware.operator_demo import origin
    _require(origin(binding["public_url"])[0] == binding["public_url"]
        and binding["redirect_uri"] == binding["public_url"] + profiles.CALLBACK_PATH
        and type(binding["staged_revision"]) is int
        and type(binding["policy_hash"]) is str and catalog._SHA.fullmatch(binding["policy_hash"])
        and type(binding["created_at"]) is str and 1 <= len(binding["created_at"]) <= 128)
    _actor(binding["actor_id"])


def _managed_activation(conn, item):
    """Join the exact existing terminal receipt to the retained public profile.

    This is structural committed-state decoding, not provisional authorization.
    _decode_rows already verifies the prepared and activated audit records; the
    selection join below additionally retains this same operation UUID.
    """
    binding = item["binding"]
    _require(_managed_configuration(item) and item["status"] == "activated"
        and item["terminal_revision"] == binding["staged_revision"] + 1
        and item["terminal_policy_hash"] == binding["policy_hash"])
    expected_sql = ("CREATE TABLE operator_catalog_oauth_profile (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
        "binding_json TEXT NOT NULL,binding_digest TEXT NOT NULL)")
    objects = conn.execute("SELECT name,type,tbl_name,sql FROM sqlite_master "
        "WHERE lower(name)='operator_catalog_oauth_profile' OR lower(tbl_name)='operator_catalog_oauth_profile' LIMIT 3").fetchall()
    _require(len(objects) == 1 and tuple(objects[0][:3]) == (
        "operator_catalog_oauth_profile", "table", "operator_catalog_oauth_profile")
        and type(objects[0][3]) is str and len(objects[0][3]) <= 4096
        and " ".join(objects[0][3].split()) == " ".join(expected_sql.split()))
    rows = conn.execute("SELECT singleton,binding_json,binding_digest FROM operator_catalog_oauth_profile LIMIT 2").fetchall()
    _require(len(rows) == 1 and type(rows[0][0]) is int and rows[0][0] == 1
        and rows[0][1] == _canonical(binding["profile_binding"])
        and rows[0][2] == binding["profile_binding_digest"])


def _rows(conn):
    """Decode retained state and structural custody joins, never load a secret."""
    try:
        return _decode_rows(conn)
    except (sqlite3.Error, custody.CustodyError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError,
            RuntimeError):
        raise SetupUnavailable("operator Google setup unavailable") from None


def _decode_rows(conn):
    from serverware import operator_google_managed_selection as selection
    objects = {row["name"]: row for row in conn.execute("SELECT name,type,tbl_name,sql FROM sqlite_master "
        "WHERE name IN (" + ",".join("?" for _ in _DEFINITIONS) + ") OR (type='trigger' AND tbl_name=?)",
        (*[item[0] for item in _DEFINITIONS], TABLE))}
    audits = conn.execute("SELECT id FROM audit_events WHERE event_type IN (?,?,?) LIMIT ?",
        (*[_PREFIX + action for action in ("prepared", "cancelled", "activated")], 2 * MAX_OPERATIONS + 1)).fetchall()
    _require(len(audits) <= 2 * MAX_OPERATIONS)
    if not objects:
        _require(not audits and not _custody_present(conn))
        selection._validate_items(conn, [])
        return []
    _require(set(objects) == {item[0] for item in _DEFINITIONS})
    for name, kind, sql in _DEFINITIONS:
        _require(objects[name]["type"] == kind and objects[name]["tbl_name"] == TABLE
            and " ".join(objects[name]["sql"].split()) == " ".join(sql.split()))
    records = conn.execute("SELECT * FROM " + TABLE + " ORDER BY operation_id LIMIT ?", (MAX_OPERATIONS + 1,)).fetchall()
    _require(len(records) <= MAX_OPERATIONS and {row["id"] for row in audits}
        == {"operator-google-setup:" + row["operation_id"] + ":" + action for row in records
            for action in (["prepared"] if row["status"] == "pending" else ["prepared", row["status"]])})
    result = []
    for row in records:
        _require(isinstance(row["binding_json"], str) and len(row["binding_json"].encode("utf-8")) <= 32768)
        binding = json.loads(row["binding_json"])
        _require(isinstance(binding, dict) and set(binding) in (_KEYS, _MANAGED_KEYS)
            and row["binding_json"] == _canonical(binding)
            and _identifier(row["operation_id"]) == binding["operation_id"] and row["actor_id"] == binding["actor_id"]
            and row["status"] in {"pending", "cancelled", "activated"}
            and profiles._CLIENT_ID.fullmatch(binding["client_id"]) is not None
            and binding["target_settings"] == _target(binding["old_settings"])
            and binding["expected_settings_digest"] == _digest(binding["old_settings"])
            and binding["profile_binding"] == profiles._record(binding["client_id"], binding["redirect_uri"])
            and binding["profile_binding_digest"] == _digest(binding["profile_binding"])
            and type(binding["reviewed_revision"]) is int and binding["reviewed_revision"] >= 1
            and binding["staged_revision"] == binding["reviewed_revision"] + 1
            and ((row["status"] == "pending" and row["terminal_revision"] is None
                    and row["terminal_policy_hash"] is None and row["completed_at"] is None)
                or (row["status"] != "pending" and type(row["terminal_revision"]) is int
                    and row["terminal_revision"] > binding["staged_revision"] and isinstance(row["completed_at"], str)
                    and isinstance(row["terminal_policy_hash"], str) and catalog._SHA.fullmatch(row["terminal_policy_hash"]))))
        if set(binding) == _MANAGED_KEYS:
            _managed_binding(binding, row["status"])
        item = {**dict(row), "binding": binding}
        _audit(conn, row["operation_id"], "prepared", binding)
        if row["status"] != "pending":
            _audit(conn, row["operation_id"], row["status"], _terminal(item))
        if _managed_configuration(item) and item["status"] == "activated":
            _managed_activation(conn, item)
        result.append(item)
    _require(sum(item["status"] == "pending" for item in result) <= 1)
    _inspect_custody(conn, result)
    selection._validate_items(conn, result)
    return result


def _public(item):
    binding = item["binding"]
    receipt = None
    if item["status"] == "activated":
        receipt = {"schema": "serverware.operatorGoogleSetupActivation/v1", "operation_id": item["operation_id"],
            "activated_revision": item["terminal_revision"], "policy_hash": binding["policy_hash"],
            "profile_binding_digest": binding["profile_binding_digest"],
            "settings_digest": _digest(binding["target_settings"]), "activated_at": item["completed_at"]}
    return {"schema": (MANAGED_PUBLIC_V2 if _managed_configuration(item) else MANAGED_PUBLIC)
            if _managed(item) else "serverware.operatorGoogleSetup/v1",
        **{key: value for key, value in binding.items() if key != "actor_id"},
        **({"secret_present": True} if _managed(item) else {}),
        "status": item["status"], "revision": item["terminal_revision"] or binding["staged_revision"],
        "completed_at": item["completed_at"], "activation_receipt": receipt}


def read_managed_pending(conn, operation_id):
    """Inspect only the exact pending managed operation in an existing snapshot.

    Internal cold-reader primitive, not HTTP lookup or activation authority. The
    caller must already admit the complete development profile and publication
    read snapshot. Returned secret_present is structural only; it never reads a
    key, authenticates ciphertext, chooses latest, or establishes readiness.
    """
    try:
        _identifier(operation_id)
        _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
        matches = [item for item in _rows(conn) if item["operation_id"] == operation_id]
        _require(len(matches) == 1 and _managed(matches[0]) and matches[0]["status"] == "pending")
        return _public(matches[0])
    except (sqlite3.Error, ValueError, TypeError, AttributeError):
        raise SetupUnavailable("operator Google setup unavailable") from None


def _snapshot(conn, *, disabled):
    from serverware import operator_demo, operator_catalog_policy as policy
    _require(catalog.active(conn))
    if disabled:
        _require(not profiles.selected())
        catalog.validate_bindings(conn)
    _require(conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone() is None)
    value = catalog.read_catalog(conn)
    _require(not any(row.get("auth_type") == "google_oauth" for row in value["credentials"]))
    policy.verify_retained_policy(conn, value)
    row = conn.execute("SELECT settings_json FROM operator_demo_settings WHERE singleton=1").fetchone()
    _require(row is not None)
    old = _settings(row[0])
    if disabled:
        actual = operator_demo.settings()
        _require(old == {key: actual[key] for key in old})
    retained = dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone())
    return value, retained, row[0], old


def review(actor_id):
    return _review(actor_id, configuration=False)


def review_configuration(actor_id):
    """Internal v2 review; cancelled v2 history can prepare its next version."""
    try:
        _require(os.getenv("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED", "") == "1")
        return _review(actor_id, configuration=True)
    except (sqlite3.Error, OSError, ValueError, TypeError, RuntimeError):
        raise SetupUnavailable("operator Google setup unavailable") from None


def _review(actor_id, *, configuration):
    from serverware import db, operator_demo_store, operator_upstream_setup
    operator_demo_store._require()
    _actor(actor_id)
    with db.connect() as conn:
        conn.execute("BEGIN")
        value, policy, _, old = _snapshot(conn, disabled=True)
        rows = _rows(conn)
        origin, redirect = _public_origin()
        managed = [row for row in rows if _managed(row)]
        eligible = (not any(row["status"] == "pending" or _managed(row) for row in rows)
            if not configuration else not any(row["status"] != "cancelled" for row in rows)
                and all(_managed_configuration(row) for row in managed) and len(managed) < custody.MAX_VERSIONS)
        return {"schema": "serverware.operatorGoogleManagedSetupReview/v2" if configuration else "serverware.operatorGoogleSetupReview/v1",
            "expected_revision": value["revision"],
            "expected_policy_hash": policy["policy_hash"], "expected_settings_digest": _digest(old),
            "old_settings": old, "target_settings": _target(old), "public_url": origin, "redirect_uri": redirect,
            "provider_id": "google", "permission_preset": profiles.PERMISSION_PRESET, "scopes": list(profiles.SCOPES),
            "eligible": eligible and len(rows) < MAX_OPERATIONS and not operator_upstream_setup.pending(conn)}


def _get(conn, operation_id, actor_id):
    _identifier(operation_id)
    _actor(actor_id)
    matches = [item for item in _rows(conn) if item["operation_id"] == operation_id and item["actor_id"] == actor_id]
    if not matches:
        raise SetupNotFound("operator Google setup not found")
    return matches[0]


def status(operation_id, actor_id):
    from serverware import db, operator_demo_store
    operator_demo_store._require()
    with db.connect() as conn:
        conn.execute("BEGIN")
        return _public(_get(conn, operation_id, actor_id))


def _append(conn, identifier, actor_id, action, event):
    from serverware import db
    db.append_audit_event(conn, event_type=_PREFIX + action, actor_type="admin", actor_id=actor_id,
        event=event, idempotency_key="operator-google-setup:" + identifier + ":" + action)


def prepare(payload, actor_id):
    _require(not isinstance(payload, ManagedSetupInput))
    payload = SetupInput.model_validate(payload.model_dump() if isinstance(payload, SetupInput) else payload)
    return _prepare(payload, actor_id, managed=False)


def prepare_managed(payload, actor_id):
    """Internal atomic encrypted preparation, not activation or a public API."""
    try:
        if isinstance(payload, ManagedSetupInput):
            payload = {**payload.model_dump(), "client_secret": payload.client_secret}
        return _prepare(ManagedSetupInput.model_validate(payload), actor_id, managed=True)
    except (sqlite3.Error, ValueError, TypeError, RuntimeError):
        # Never echo validation input, filesystem failures, SQL or crypto detail.
        raise SetupUnavailable("operator Google setup unavailable") from None


def prepare_configuration(payload, actor_id):
    """Internal v2 self-service preparation; never restart, activate or send."""
    try:
        _require(os.getenv("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED", "") == "1")
        if isinstance(payload, ManagedSetupInput):
            payload = {**payload.model_dump(), "client_secret": payload.client_secret}
        return _prepare(ManagedSetupInput.model_validate(payload), actor_id, managed=True, configuration=True)
    except (sqlite3.Error, OSError, ValueError, TypeError, RuntimeError):
        raise SetupUnavailable("operator Google setup unavailable") from None


def _admit_managed_owner(owner_id):
    from serverware import config, operator_demo, oauth_application_owner
    _require(not profiles.selected() and not config.GOOGLE_OAUTH_CLIENT_ID
        and not config.GOOGLE_OAUTH_CLIENT_SECRET and config.GOOGLE_OAUTH_CLIENT_SECRET_FILE is None
        and config.GOOGLE_OAUTH_REDIRECT_URI == config.PUBLIC_URL + profiles.CALLBACK_PATH)
    return custody.admit_development_owner(owner_id, operator_development=operator_demo.active(),
        release_channel=config.RELEASE_CHANNEL, production_image=config.PRODUCTION_IMAGE,
        native_or_enrolled=(config.TEE_PLATFORM != "none-dev" or config.TEE_QUOTE_PROVIDER != "dev-signed-quote"
            or config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED or config.KEY_RELEASE_REQUIRED
            or oauth_application_owner.require_started() is not None))


@contextmanager
def _configuration_key(conn, retained):
    from serverware import config, operator_provider_key
    _require(os.getenv("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED", "") == "1")
    # Admit the actual development ownership profile before any key creation.
    # On first use the key owner itself is generated by the durable key writer.
    prior_owner = retained[0]["binding"]["custody_ref"]["owner_id"] if retained else None
    _admit_managed_owner(prior_owner or str(uuid.uuid4()))
    admission = operator_provider_key.admit_directory(
        os.environ.get("SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR", ""), data_directory=config.DATA_DIR)
    key = None
    try:
        if retained:
            key = operator_provider_key.read_existing_pinned(admission, prior_owner)
        else:
            # _rows proved no managed setup/audit or custody rows. An orphan
            # durable key may be retried, never overwritten or silently rotated.
            key = operator_provider_key.initialize_first(admission, conn, no_retained_provider_state=True)
        owner = _admit_managed_owner(key.owner_id)
        yield owner, key
    finally:
        if key is not None:
            operator_provider_key.close_pin(key)


def _prepare(payload, actor_id, *, managed, configuration=False):
    from serverware import db, operator_demo_store, operator_upstream_setup
    operator_demo_store._require()
    _actor(actor_id)
    with exclusive(), db.connect() as conn, ExitStack() as pins:
        conn.execute("BEGIN IMMEDIATE")
        value, policy, _, old = _snapshot(conn, disabled=True)
        if (value["revision"] != payload.expected_revision or policy["policy_hash"] != payload.expected_policy_hash
                or _digest(old) != payload.expected_settings_digest):
            raise catalog.CatalogConflict()
        rows = _rows(conn)
        if (len(rows) >= MAX_OPERATIONS or any(item["status"] == "pending" or item["operation_id"] == payload.operation_id for item in rows)
                or operator_upstream_setup.pending(conn)):
            raise catalog.CatalogConflict()
        retained_managed = [item for item in rows if _managed(item)]
        if not managed:
            _require(not retained_managed)
        elif len(retained_managed) >= custody.MAX_VERSIONS:
            raise catalog.CatalogConflict()
        else:
            contract = MANAGED_BINDING_V2 if configuration else MANAGED_BINDING
            _require(all(item["binding"]["setup_contract"] == contract for item in retained_managed))
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone() is None:
            for _, _, sql in _DEFINITIONS:
                conn.execute(sql)
        origin, redirect = _public_origin()
        public_binding = profiles._record(payload.client_id, redirect)
        reference = None
        key_pin = None
        if managed:
            from serverware import config
            # _rows proved exact custody/setup joins, including one stable owner
            # and all retained versions. Allocation is not activation selection.
            if configuration:
                from serverware import operator_google_managed_selection as selection
                owner, key_pin = pins.enter_context(_configuration_key(conn, retained_managed))
                key = key_pin.material
                if not retained_managed:
                    selection.install_empty(conn)
            else:
                owner_id = (retained_managed[0]["binding"]["custody_ref"]["owner_id"]
                    if retained_managed else str(uuid.uuid4()))
                owner = _admit_managed_owner(owner_id)
                key = custody.read_existing_master_key(config.DATA_DIR, owner)
            exact = custody.bind_google(owner, config_version=len(retained_managed) + 1, public_profile=public_binding)
            if not retained_managed:
                custody.install_empty_store(conn, owner)
            custody.insert_secret(conn, owner, exact, key=key, secret=payload.client_secret)
            reference = {"owner_id": owner.owner_id, "config_version": exact.config_version}
            if configuration:
                reference["key_source"] = MANAGED_KEY_SOURCE
        staged = catalog.advance_revision(conn, payload.expected_revision)
        binding = {"operation_id": payload.operation_id, "actor_id": actor_id, "client_id": payload.client_id,
            "old_settings": old, "target_settings": _target(old), "expected_settings_digest": _digest(old),
            "public_url": origin, "redirect_uri": redirect, "profile_binding": public_binding,
            "profile_binding_digest": _digest(public_binding), "reviewed_revision": payload.expected_revision,
            "staged_revision": staged, "policy_hash": policy["policy_hash"], "created_at": db.iso_now()}
        if managed:
            binding.update(setup_contract=MANAGED_BINDING_V2 if configuration else MANAGED_BINDING, custody_ref=reference)
        conn.execute("INSERT INTO " + TABLE + " VALUES (?,?,'pending',?,NULL,NULL,NULL)",
            (payload.operation_id, actor_id, _canonical(binding)))
        _append(conn, payload.operation_id, actor_id, "prepared", binding)
        if configuration:
            selection.select_pending(conn, payload.operation_id)
        result = _public(_get(conn, payload.operation_id, actor_id))
        # Check the original directory/key pin before the SQL commit and keep
        # its descriptor until the transaction exits. Never adopt a replacement.
        if key_pin is not None:
            from serverware import operator_provider_key
            operator_provider_key.check_pin(key_pin)
        conn.commit()
    return result


def cancel(payload, actor_id):
    from serverware import db, operator_demo_store
    operator_demo_store._require()
    payload = CancelInput.model_validate(payload.model_dump() if isinstance(payload, CancelInput) else payload)
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        value, policy, _, _ = _snapshot(conn, disabled=True)
        item = _get(conn, payload.operation_id, actor_id)
        if (item["status"] != "pending" or value["revision"] != payload.expected_revision
                or policy["policy_hash"] != payload.expected_policy_hash):
            raise catalog.CatalogConflict()
        item.update(status="cancelled", terminal_revision=catalog.advance_revision(conn, payload.expected_revision),
            terminal_policy_hash=policy["policy_hash"], completed_at=db.iso_now())
        conn.execute("UPDATE " + TABLE + " SET status=?,terminal_revision=?,terminal_policy_hash=?,completed_at=? WHERE operation_id=?",
            (item["status"], item["terminal_revision"], item["terminal_policy_hash"], item["completed_at"], payload.operation_id))
        _append(conn, payload.operation_id, actor_id, "cancelled", _terminal(item))
        if _managed_configuration(item):
            from serverware import operator_google_managed_selection as selection
            selection.clear_cancelled(conn, payload.operation_id)
        result = _public(_get(conn, payload.operation_id, actor_id))
        conn.commit()
    return result


def validate_startup(conn, previous_settings_raw, target_settings_raw, *, retained_authority=None):
    """Pure reads; preflight and the activation transaction use the same gates."""
    if not profiles.selected():
        return None
    managed_operation = None
    if os.getenv("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED", "") == "1":
        from serverware import operator_google_managed_config
        # This read joins the current snapshot to the exact cold bootstrap pin.
        # It does not grant a serving capability or provisional write authority.
        managed_operation = operator_google_managed_config.validate_selection(conn)
        _require(managed_operation is not None and managed_operation["schema"] == MANAGED_PUBLIC_V2)
    else:
        # External env/file ownership cannot claim a managed application
        # namespace, including after cancelled preparations.
        _require(not _custody_present(conn))
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone():
        _require(managed_operation is None or managed_operation["status"] == "activated")
        return None
    from serverware import operator_upstream_setup
    _require(not operator_upstream_setup.pending(conn))
    if not catalog.active(conn):
        if retained_authority is None:
            retained_authority = conn.execute("SELECT 1 FROM sqlite_master WHERE lower(name) GLOB 'operator_demo_*' "
                "OR lower(name) GLOB 'operator_catalog_*' OR lower(name) GLOB 'operator_google_*' "
                "OR lower(name) GLOB 'operator_upstream_*' LIMIT 1").fetchone() is not None
        _require(retained_authority is False and previous_settings_raw is None)
        return None
    _require(isinstance(conn, sqlite3.Connection) and previous_settings_raw is not None)
    value, policy, actual_raw, old = _snapshot(conn, disabled=False)
    target = _settings(target_settings_raw)
    rows = [item for item in _rows(conn) if item["status"] == "pending"]
    _require(len(rows) == 1)
    item, = rows
    binding = item["binding"]
    _require((_managed_configuration(item) and _public(item) == managed_operation)
        if managed_operation is not None else not _managed(item))
    from serverware import config
    profile = profiles.validate_imported_configuration(config)
    origin, redirect = _public_origin()
    _require(actual_raw == previous_settings_raw and old == binding["old_settings"]
        and target == binding["target_settings"] == _target(old)
        and _digest(old) == binding["expected_settings_digest"]
        and value["revision"] == binding["staged_revision"] and policy["policy_hash"] == binding["policy_hash"]
        and origin == binding["public_url"] and redirect == binding["redirect_uri"] == profile.redirect_uri
        and profiles._record(profile.client_id, profile.redirect_uri) == binding["profile_binding"]
        and profile.binding_digest == binding["profile_binding_digest"])
    return item


def startup(conn, previous_settings_raw, target_settings_raw, *, retained_authority=None):
    from serverware import db
    assert_held()
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
    item = validate_startup(conn, previous_settings_raw, target_settings_raw, retained_authority=retained_authority)
    if item is None:
        return False
    if _managed_configuration(item):
        from serverware import operator_google_managed_config
        operator_google_managed_config.assert_startup_transaction(conn)
    from serverware import operator_catalog_policy as policy
    before = catalog.read_catalog(conn)
    retained = dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone())
    conn.execute("UPDATE operator_demo_settings SET settings_json=? WHERE singleton=1", (target_settings_raw,))
    catalog.initialize(conn)
    catalog.validate_bindings(conn)
    policy.verify_retained_policy(conn, catalog.read_catalog(conn))
    _require(catalog.read_catalog(conn) == before
        and dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()) == retained)
    item.update(status="activated", terminal_revision=catalog.advance_revision(conn, item["binding"]["staged_revision"]),
        terminal_policy_hash=retained["policy_hash"], completed_at=db.iso_now())
    conn.execute("UPDATE " + TABLE + " SET status=?,terminal_revision=?,terminal_policy_hash=?,completed_at=? WHERE operation_id=?",
        (item["status"], item["terminal_revision"], item["terminal_policy_hash"], item["completed_at"], item["operation_id"]))
    _append(conn, item["operation_id"], item["actor_id"], "activated", _terminal(item))
    _require(_get(conn, item["operation_id"], item["actor_id"])["status"] == "activated")
    return True
