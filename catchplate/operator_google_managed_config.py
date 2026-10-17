"""Cold, app-only Google configuration from one explicitly selected operation.

Bootstrap borrows the existing publication SH snapshot before configured imports.
It never initializes a key, database, marker or environment variable. The sole
provisional capability is scoped to the real startup writer's connection/thread;
normal serving becomes available only after its committed activation is re-read.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import threading

from catchplate import operator_catalog_oauth_profile as profiles

_FLAG = "CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED"
_DIRECTORY = "CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR"
_DYNAMIC = {"status", "revision", "completed_at", "activation_receipt"}
_admission = None
_ready = False
_startup = threading.local()


@dataclass(frozen=True)
class _Admission:
    environment: tuple = field(repr=False)
    process: tuple
    directory: object = field(repr=False)
    publication: object = field(repr=False)
    selected_json: str | None
    raw_settings_json: str
    retained_settings_json: str | None
    effective_settings_json: str
    profile: profiles.Profile | None
    key: object = field(repr=False)
    secret: str | None = field(repr=False)
    custody_digest: bytes | None = field(repr=False)


def _require(value):
    if not value:
        profiles._refuse()


def _safe(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            raise profiles.OperatorGoogleProfileError(profiles._ERROR) from None
    return guarded


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _process():
    return os.getpid(), os.geteuid(), os.getegid()


@_safe
def enabled() -> bool:
    value = os.getenv(_FLAG, "0")
    _require(value in {"0", "1"} and (_admission is None or value == "1"))
    return value == "1"


def _empty(path):
    from catchplate.operator_provider_key import _open_directory
    with _open_directory(path) as descriptor, os.scandir(descriptor) as entries:
        return next(entries, None) is None


def _settings(value):
    from catchplate.operator_google_setup import _settings as decode
    return decode(json.dumps(value, sort_keys=True, allow_nan=False))


def _raw_settings():
    from catchplate.operator_demo import _destinations, origin
    value = _settings({"allowed_upstreams": json.loads(os.environ["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"]),
        "fixture_cidrs": json.loads(os.getenv("CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS", "[]"))})
    _destinations(value["allowed_upstreams"], value["fixture_cidrs"])
    origin(os.environ["CATCHPLATE_OPERATOR_DEMO_PROXY_URL"])
    return value


def _retained_settings(conn, *, absent=False):
    rows = conn.execute("SELECT singleton,settings_json FROM operator_demo_settings LIMIT 2").fetchall()
    if not rows and absent:
        return None
    _require(len(rows) == 1 and type(rows[0][0]) is int and rows[0][0] == 1)
    from catchplate.operator_google_setup import _settings as decode
    return decode(rows[0][1])


def _connection(conn, value):
    _require(isinstance(conn, sqlite3.Connection))
    databases = conn.execute("PRAGMA database_list").fetchall()
    _require(len(databases) == 1 and tuple(databases[0]) == (
        0, "main", str(value.directory.data_directory / "catchplate.sqlite3"))
        and conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)


def _unconfigured(conn):
    # Selection absence alone must not adopt a legacy or partially lost OAuth
    # capability. Its public profile/intents namespace has never been installed.
    _require(conn.execute("SELECT 1 FROM sqlite_master WHERE lower(name) GLOB 'operator_catalog_oauth_*' "
        "OR lower(tbl_name) GLOB 'operator_catalog_oauth_*' "
        "OR lower(name) GLOB 'operator_google_cleanup*' OR lower(tbl_name) GLOB 'operator_google_cleanup*' "
        "OR lower(name) GLOB 'operator_google_reauthorization*' "
        "OR lower(tbl_name) GLOB 'operator_google_reauthorization*' LIMIT 1").fetchone() is None)
    from catchplate import operator_catalog_schema as catalog
    if catalog.active(conn):
        _require(not any(item.get("auth_type") == "google_oauth"
            for item in catalog.read_catalog(conn)["credentials"]))


def _public_origin():
    from catchplate.operator_demo import origin
    value = os.environ["CATCHPLATE_PUBLIC_URL"]
    _require(origin(value)[0] == value and value != "https://demo-upstream:8443")
    return value


def _identity(operation):
    return None if operation is None else _canonical({key: value for key, value in operation.items()
        if key not in _DYNAMIC})


def _custody(conn, operation, key):
    from catchplate import operator_provider_custody as custody
    reference = operation["custody_ref"]
    _require(key is not None and key.owner_id == reference["owner_id"])
    owner = custody.admit_development_owner(reference["owner_id"], operator_development=True,
        release_channel="dev", production_image=False, native_or_enrolled=False)
    binding = custody.bind_google(owner, config_version=reference["config_version"],
        public_profile=operation["profile_binding"])
    envelope = custody._matching_envelope(conn, owner, binding)
    return owner, binding, hashlib.sha256(envelope.nonce + envelope.ciphertext).digest()


def _current_pin():
    from catchplate import operator_provider_key as keys
    value = _admission
    _require(enabled() and value is not None and value.process == _process()
        and value.environment == profiles._environment())
    _require(profiles._raw_development_directory(managed=True) == value.directory.data_directory)
    _require(keys.admit_directory(value.directory.path,
        data_directory=value.directory.data_directory) == value.directory)
    if value.key is not None:
        keys.check_pin(value.key)
    if value.publication is not None:
        from catchplate import operator_publication as publication
        from catchplate.development_sandbox import _open_directory
        pin = value.publication
        with publication.closing_fd(_open_directory(pin.directory)) as descriptor:
            _require(publication._bootstrap_identities(descriptor) == (pin.directory_identity,
                pin.marker_identity, pin.lock_identity, pin.database_identity))
    return value


def _derive_settings(conn, operation, retained, raw):
    from catchplate import operator_upstream_setup as upstream
    pending = [item["binding"] for item in upstream._rows(conn) if item["status"] == "pending"]
    if operation is not None and operation["status"] == "pending":
        _require(not pending and retained == operation["old_settings"] and raw == retained)
        revision = conn.execute("SELECT revision FROM operator_catalog_state WHERE singleton=1").fetchone()
        policy = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
        _require(revision is not None and type(revision[0]) is int
            and revision[0] == operation["staged_revision"] and policy is not None
            and policy[0] == operation["policy_hash"])
        return operation["target_settings"]
    if raw == retained:
        return retained
    if pending:
        _require(len(pending) == 1 and pending[0]["old_settings"] == retained
            and pending[0]["target_settings"] == raw)
        return raw  # Existing startup repeats the complete reviewed-CAS check.
    # Managed activation may have added Gmail without changing the cold base
    # environment. The base is not authority to remove that retained origin.
    _require(operation is not None and operation["status"] == "activated"
        and raw in (operation["old_settings"], operation["target_settings"]))
    return retained


@_safe
def bootstrap() -> None:
    """Pin one cold selection, or prove a genuinely unconfigured first boot."""
    global _admission
    if not enabled():
        return
    if _admission is not None:
        _current_pin()
        return
    _require("catchplate.config" not in sys.modules)
    data_directory = profiles._raw_development_directory(managed=True)
    _require(os.getenv("CATCHPLATE_CONTROL_PLANE_STARTUP_VALIDATED_PID") is None)
    from catchplate import operator_provider_key as keys, operator_publication as publication
    from catchplate import operator_google_managed_selection as selection, operator_google_setup as setup
    environment, process = profiles._environment(), _process()
    directory = keys.admit_directory(os.environ[_DIRECTORY], data_directory=data_directory)
    raw, public_url = _raw_settings(), _public_origin()
    pin = key = operation = profile = secret = retained = custody_digest = None
    effective = raw
    try:
        if _empty(data_directory):
            _require(_empty(directory.path))
        else:
            # Never turn an absent/corrupt marker, lock or database into a fresh
            # start. Only the literally empty, separately pinned directory above
            # can be initialized later by the ordinary operator owner.
            pin = publication.admit_bootstrap_reader(data_directory, operator_development=True,
                release_channel="dev", production_image=False, native_or_enrolled=False)
            with publication.bootstrap_read(pin) as conn:
                operation = selection.read_selection(conn)
                history = setup._rows(conn)
                _require(all(setup._managed_configuration(item) for item in history))
                retained = _retained_settings(conn)
                if operation is None or operation["status"] == "pending":
                    _unconfigured(conn)
                effective = _derive_settings(conn, operation, retained, raw)
                from catchplate.operator_demo import _destinations
                _destinations(effective["allowed_upstreams"], effective["fixture_cidrs"])
                if history:
                    key = keys.read_existing_pinned(directory, history[0]["binding"]["custody_ref"]["owner_id"])
                if operation is not None:
                    _require(operation["public_url"] == public_url
                        and operation["redirect_uri"] == public_url + profiles.CALLBACK_PATH
                        and set(profiles.API_ORIGINS) <= set(effective["allowed_upstreams"]))
                    from catchplate import operator_provider_custody as custody
                    owner, binding, custody_digest = _custody(conn, operation, key)
                    secret = custody.read_secret(conn, owner, binding, key=key.material).secret
                    profile = profiles.Profile(profiles.PROFILE, "google", operation["client_id"],
                        operation["redirect_uri"], profiles.PERMISSION_PRESET, profiles.SCOPES,
                        profiles.API_ORIGINS, operation["profile_binding_digest"])
        _require(environment == profiles._environment() and process == _process())
        _admission = _Admission(environment, process, directory, pin,
            None if operation is None else _canonical(operation), _canonical(raw),
            None if retained is None else _canonical(retained), _canonical(effective), profile, key, secret, custody_digest)
        _current_pin()
    except BaseException:
        _admission = None
        if key is not None:
            keys.close_pin(key)
        raise


@_safe
def selected() -> bool:
    return _current_pin().profile is not None


@_safe
def effective_settings(base_settings: dict) -> dict:
    if not enabled():
        return base_settings
    value = _current_pin()
    _require(_canonical(_settings(base_settings)) == value.raw_settings_json)
    return json.loads(value.effective_settings_json)


@_safe
def load_configuration(*, production_image: bool, release_channel: str):
    value = _current_pin()
    _require(production_image is False and release_channel == "dev" and value.profile is not None)
    return value.profile.client_id, value.secret, None, value.profile.redirect_uri


def _configuration(config, value):
    _require(not config.PRODUCTION_IMAGE and config.RELEASE_CHANNEL == "dev"
        and config.DATA_DIR == value.directory.data_directory
        and config.METADATA_STORE_BACKEND == config.AUDIT_STORE_BACKEND == config.GRANT_STORE_BACKEND == "sqlite"
        and not config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED and not config.KEY_RELEASE_REQUIRED
        and not any(getattr(config, key) for key in profiles._PROTECTED_FLAGS)
        and not config.CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES
        and not config.DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
        and config.TEE_QUOTE_PROVIDER == "dev-signed-quote" and config.TEE_PLATFORM == "none-dev"
        and config.PUBLIC_URL == _public_origin())
    if value.profile is None:
        _require(not config.GOOGLE_OAUTH_CLIENT_ID and not config.GOOGLE_OAUTH_CLIENT_SECRET
            and config.GOOGLE_OAUTH_REDIRECT_URI == config.PUBLIC_URL + profiles.CALLBACK_PATH
            and config.GOOGLE_OAUTH_CLIENT_SECRET_FILE is None)
    else:
        _require(config.GOOGLE_OAUTH_CLIENT_ID == value.profile.client_id
            and config.GOOGLE_OAUTH_REDIRECT_URI == value.profile.redirect_uri
            and config.GOOGLE_OAUTH_CLIENT_SECRET_FILE is None
            and hmac.compare_digest(config.GOOGLE_OAUTH_CLIENT_SECRET.encode("utf-8"), value.secret.encode("utf-8")))


@_safe
def validate_imported_configuration(config):
    value = _current_pin()
    _configuration(config, value)
    _require(value.profile is not None)
    return value.profile


@_safe
def validate_selection(conn):
    """Join a real read snapshot to the cold identity; no readiness is granted."""
    value = _current_pin()
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
    _connection(conn, value)
    from catchplate.operator_google_managed_selection import read_selection
    current = read_selection(conn)
    original = None if value.selected_json is None else json.loads(value.selected_json)
    _require(_identity(current) == _identity(original))
    if current is not None:
        _, _, custody_digest = _custody(conn, current, value.key)
        _require(hmac.compare_digest(custody_digest, value.custody_digest))
    if original is None:
        _unconfigured(conn)
    elif original["status"] == "activated":
        _require(current == original)
    elif current["status"] == "activated":
        _require(_ready or getattr(_startup, "connection", None) is conn)
    else:
        _require(current == original)
        if getattr(_startup, "connection", None) is not conn:
            _unconfigured(conn)
    return current


def _startup_connection(conn, *, transaction):
    from catchplate.operator_publication import assert_held
    _require(isinstance(conn, sqlite3.Connection) and getattr(_startup, "connection", None) is conn)
    assert_held()
    _require(conn.in_transaction is transaction)
    _connection(conn, _admission)
    _require(conn.execute("PRAGMA query_only").fetchone()[0] == 0)


@_safe
def assert_startup_transaction(conn) -> None:
    _current_pin()
    _startup_connection(conn, transaction=True)


@contextmanager
def startup_transaction(conn):
    """Only the actual startup writer may use an uncommitted profile."""
    global _ready
    if not enabled():
        yield
        return
    try:
        value = _current_pin()
        _require(not _ready and getattr(_startup, "connection", None) is None
            and isinstance(conn, sqlite3.Connection) and conn.in_transaction)
        from catchplate import config
        from catchplate.operator_publication import assert_held
        assert_held()
        _configuration(config, value)
        validate_selection(conn)
        retained = _retained_settings(conn, absent=value.retained_settings_json is None)
        _require((None if retained is None else _canonical(retained)) == value.retained_settings_json)
        _startup.connection = conn
        yield
        _require(_ready and not conn.in_transaction)
    except Exception:
        _ready = False
        raise profiles.OperatorGoogleProfileError(profiles._ERROR) from None
    finally:
        _startup.connection = None


@_safe
def committed(conn) -> None:
    """Promote only after a real commit, re-reading its exact retained result."""
    global _ready
    if not enabled():
        return
    value = _current_pin()
    _require(not _ready)
    _startup_connection(conn, transaction=False)
    conn.execute("BEGIN")
    try:
        operation = validate_selection(conn)
        _require(operation is None if value.profile is None else operation is not None and operation["status"] == "activated")
        _require(_canonical(_retained_settings(conn)) == value.effective_settings_json)
    finally:
        conn.rollback()
    _ready = True


@_safe
def require_profile():
    value = _current_pin()
    from catchplate import config, operator_demo, oauth_application_owner
    profile = validate_imported_configuration(config)
    if not _ready:
        assert_startup_transaction(getattr(_startup, "connection", None))
    _require(operator_demo.active() and oauth_application_owner.require_started() is None)
    return profile


@_safe
def committed_identity():
    """Public process identity only; the publication owner reads retained state."""
    if not enabled():
        return None
    value = _current_pin()
    _require(_ready)
    if value.profile is None:
        return None
    operation = json.loads(value.selected_json)
    return {"operation_id": operation["operation_id"], "owner_id": operation["custody_ref"]["owner_id"],
        "config_version": operation["custody_ref"]["config_version"],
        "profile_binding_digest": value.profile.binding_digest}
