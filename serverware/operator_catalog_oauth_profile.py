"""Cold, opt-in Google capability for the non-production operator workspace.

This module does not open a database, contact a provider, or adopt an enrolled
OAuth application. Public bindings are persisted by the catalog transaction.
The secret stays in the existing OAuth configuration, never in that binding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat


PROFILE = "operator-google-v1"
PERMISSION_PRESET = "gmail_readonly"
SCOPES = ("email", "https://www.googleapis.com/auth/gmail.readonly", "openid")
API_ORIGINS = ("https://gmail.googleapis.com",)
CALLBACK_PATH = "/api/oauth/callback/google"
GOOGLE_CONFIGURATION_KEYS = frozenset({
    "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID", "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
    "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI",
})
_SELECTION = "SERVERWARE_OPERATOR_GOOGLE_PROFILE"
_MAX_SECRET_BYTES = 4096
_ERROR = "operator Google profile refused"
_CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,199}\.apps\.googleusercontent\.com\Z")
_PROTECTED_FLAGS = (
    "CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED",
    "CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION",
    "CONTROL_PLANE_TWO_PERSON_REQUIRED",
)


class OperatorGoogleProfileError(RuntimeError):
    """A fixed, non-secret-bearing admission failure."""


@dataclass(frozen=True)
class Profile:
    profile: str
    provider_id: str
    client_id: str
    redirect_uri: str
    permission_preset: str
    scopes: tuple[str, ...]
    api_origins: tuple[str, ...]
    binding_digest: str


@dataclass(frozen=True)
class _Admission:
    profile: Profile
    environment: tuple[tuple[str, str], ...]
    process: tuple[int, int, int]
    secret_path: Path
    secret_identity: tuple[int, ...]
    descriptor: int = field(repr=False)
    secret: str = field(repr=False)
    secret_digest: bytes = field(repr=False)


_admission: _Admission | None = None
_managed_seen = False


def _refuse() -> None:
    raise OperatorGoogleProfileError(_ERROR)


def selected() -> bool:
    """Only an unconfigured capability is disabled; invalid/drifted input fails."""
    if _managed_mode():
        from serverware import operator_google_managed_config
        return operator_google_managed_config.selected()
    value = os.getenv(_SELECTION, "")
    if value not in {"", PROFILE} or (_admission is not None and value != PROFILE):
        _refuse()
    return value == PROFILE


def _managed_mode() -> bool:
    global _managed_seen
    value = os.getenv("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED", "0")
    if value not in {"0", "1"} or (_managed_seen and value != "1"):
        _refuse()
    if value == "1":
        if _admission is not None:
            _refuse()
        _managed_seen = True
    return value == "1"


def _environment() -> tuple[tuple[str, str], ...]:
    return tuple(sorted((key, value) for key, value in os.environ.items()
        if key.startswith("SERVERWARE_")
        and key != "SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID"))


def _record(client_id: str, redirect_uri: str) -> dict:
    # Keep this closed public shape identical to the Rust cold capability.
    return {
        "schema": "serverware.operatorGoogleProfile/v1", "profile": PROFILE,
        "provider_id": "google", "client_id": client_id, "redirect_uri": redirect_uri,
        "permission_preset": PERMISSION_PRESET, "scopes": list(SCOPES),
        "api_origins": list(API_ORIGINS),
        "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "revocation_url": "https://oauth2.googleapis.com/revoke",
        "identity_url": "https://openidconnect.googleapis.com/v1/userinfo",
    }


def _raw_development_directory(*, managed: bool = False) -> Path:
    """Configuration-independent ownership guard shared by both cold profiles."""
    expected = {
        "SERVERWARE_OPERATOR_DEMO": "1", "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite", "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0", "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
    }
    if managed:
        expected.update(SERVERWARE_DEV_AUTHENTICATOR="0", SERVERWARE_DEV_DEMO_SEED="0",
            SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED="1")
        if (os.getenv("SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED") != "1"
                or _SELECTION in os.environ
                or any(key.startswith("SERVERWARE_GOOGLE_") for key in os.environ)
                or os.getenv("SERVERWARE_TEE_PLATFORM", "none-dev") != "none-dev"
                or os.getenv("SERVERWARE_TEE_QUOTE_PROVIDER", "dev-signed-quote") != "dev-signed-quote"):
            _refuse()
    if (any(os.getenv(key) != value for key, value in expected.items())
            or os.getenv("SERVERWARE_PRODUCTION_IMAGE", "0") != "0"
            or os.getenv("SERVERWARE_DEVELOPMENT_SANDBOX", "0") != "0"):
        _refuse()
    directory = Path(os.getenv("SERVERWARE_DATA_DIR", ""))
    if not directory.is_absolute() or directory == Path("/") or ".." in directory.parts:
        _refuse()
    forbidden = ("SERVERWARE_OAUTH_APPLICATION_", "SERVERWARE_AUTHORITY_",
        "SERVERWARE_POLICY_AUTHORITY_", "SERVERWARE_NATIVE_", "SERVERWARE_NITRO_",
        "SERVERWARE_AWS_", "SERVERWARE_CONTROL_PLANE_CUSTODY_",
        "SERVERWARE_CONTROL_PLANE_ENROLLMENT_", "SERVERWARE_WORKLOAD_IDENTITY_",
        "SERVERWARE_X_OAUTH_", "SERVERWARE_TWITTER_OAUTH_", "SERVERWARE_SETUP_",
        "SERVERWARE_OIDC_", "SERVERWARE_WEBAUTHN_RECOVERY_")
    from serverware.development_sandbox import _FIXED_PATHS, _TOKEN_FILES
    disabled = {"SERVERWARE_OIDC_ENABLED", "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED",
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED", "SERVERWARE_WEBAUTHN_RECOVERY_ENABLED"}
    for key, value in _environment():
        if not value or key in disabled and value == "0" or key in GOOGLE_CONFIGURATION_KEYS:
            continue
        if key in _FIXED_PATHS:
            if Path(value) != directory / _FIXED_PATHS[key]:
                _refuse()
            continue
        if key in _TOKEN_FILES:
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts or not path.is_relative_to("/run"):
                _refuse()
            continue
        if (key.startswith(forbidden) or key.startswith("SERVERWARE_GOOGLE_")
                or key.endswith(("_FD", "_DSN", "_COMMAND", "_FILE", "_PATH"))
                or "_FD_" in key or "_COMMAND_" in key
                or key in {"SERVERWARE_MASTER_KEY", "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY",
                    "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", "SERVERWARE_SCHEMA_DIR"}):
            _refuse()
    if (any(os.getenv("SERVERWARE_" + key, "0") != "0" for key in _PROTECTED_FLAGS)
            or os.getenv("SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES", "")):
        _refuse()
    return directory


def _raw_profile() -> tuple[Profile, Path]:
    # This runs before config's existing client-secret reader. In particular,
    # selecting a native/enrolled owner must not read this development secret.
    if not selected():
        _refuse()
    _raw_development_directory()
    client_id = os.getenv("SERVERWARE_GOOGLE_OAUTH_CLIENT_ID", "")
    if _CLIENT_ID.fullmatch(client_id) is None:
        _refuse()
    from serverware.operator_demo import MAX_ALLOWED_UPSTREAMS, origin
    public_url = os.getenv("SERVERWARE_PUBLIC_URL", "")
    try:
        public_origin, _ = origin(public_url)
        raw_origins = json.loads(os.getenv("SERVERWARE_OPERATOR_DEMO_UPSTREAMS", "null"))
        if not isinstance(raw_origins, list) or not 1 <= len(raw_origins) <= MAX_ALLOWED_UPSTREAMS:
            _refuse()
        origins = tuple(origin(value)[0] for value in raw_origins)
    except (ValueError, TypeError, AttributeError):
        _refuse()
    redirect_uri = os.getenv("SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI", "")
    if (public_url != public_origin or public_origin == "https://demo-upstream:8443"
            or redirect_uri != public_url + CALLBACK_PATH
            or len(set(origins)) != len(origins) or not set(API_ORIGINS) <= set(origins)):
        _refuse()
    raw_path = os.getenv("SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE", "")
    secret_path = Path(raw_path)
    if (not secret_path.is_absolute() or secret_path == Path("/") or ".." in secret_path.parts
            or str(secret_path) != raw_path or any(ord(char) < 33 for char in raw_path)):
        _refuse()
    record = _record(client_id, redirect_uri)
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")
    return Profile(PROFILE, "google", client_id, redirect_uri, PERMISSION_PRESET,
        SCOPES, API_ORIGINS, "sha256:" + hashlib.sha256(encoded).hexdigest()), secret_path


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_secret(path: Path) -> int:
    # Open each ancestor relative to its descriptor. A final O_NOFOLLOW alone
    # would still traverse an attacker-replaced symlink in a parent directory.
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory = os.open("/", flags | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(path.name, flags, dir_fd=directory)
    finally:
        os.close(directory)


def _read_secret(descriptor: int) -> tuple[tuple[int, ...], bytes, str]:
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or not 1 <= before.st_size <= _MAX_SECRET_BYTES):
        _refuse()
    payload = os.pread(descriptor, _MAX_SECRET_BYTES + 1, 0)
    if len(payload) != before.st_size or _identity(before) != _identity(os.fstat(descriptor)):
        _refuse()
    secret = payload.decode("utf-8")
    if secret.endswith("\r\n"):
        secret = secret[:-2]
    elif secret.endswith("\n"):
        secret = secret[:-1]
    if not secret or secret != secret.strip() or any(char in secret for char in ("\x00", "\r", "\n")):
        _refuse()
    return _identity(before), hashlib.sha256(payload).digest(), secret


def _check_pin(admission: _Admission) -> None:
    if (not selected() or admission.process != (os.getpid(), os.geteuid(), os.getegid())
            or admission.environment != _environment()):
        _refuse()
    current = _open_secret(admission.secret_path)
    try:
        identity, digest, _ = _read_secret(current)
        pinned_identity, pinned_digest, _ = _read_secret(admission.descriptor)
        if (identity != admission.secret_identity or pinned_identity != identity
                or not hmac.compare_digest(digest, admission.secret_digest)
                or not hmac.compare_digest(pinned_digest, digest)):
            _refuse()
    finally:
        os.close(current)


def load_configuration(*, production_image: bool, release_channel: str) -> tuple[str, str, Path | None, str]:
    """Config-import preflight; never used by the unchanged disabled profile."""
    if _managed_mode():
        from serverware import operator_google_managed_config
        return operator_google_managed_config.load_configuration(
            production_image=production_image, release_channel=release_channel)
    global _admission
    descriptor = None
    try:
        if production_image or release_channel != "dev":
            _refuse()
        if _admission is None:
            environment = _environment()
            profile, secret_path = _raw_profile()
            descriptor = _open_secret(secret_path)
            identity, digest, secret = _read_secret(descriptor)
            candidate = _Admission(profile, environment, (os.getpid(), os.geteuid(), os.getegid()),
                secret_path, identity, descriptor, secret, digest)
            _check_pin(candidate)
            _admission = candidate
            descriptor = None  # Lifetime pin: do not reopen/adopt a replacement.
        else:
            _check_pin(_admission)
        value = _admission
        return value.profile.client_id, value.secret, value.secret_path, value.profile.redirect_uri
    except (OSError, ValueError, TypeError, RuntimeError):
        raise OperatorGoogleProfileError(_ERROR) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_imported_configuration(config) -> Profile:
    """No database/owner side effects; usable before the operator marker is pinned."""
    if _managed_mode():
        from serverware import operator_google_managed_config
        return operator_google_managed_config.validate_imported_configuration(config)
    try:
        value = _admission
        if value is None:
            _refuse()
        _check_pin(value)
        if (config.PRODUCTION_IMAGE or config.RELEASE_CHANNEL != "dev"
                or config.GOOGLE_OAUTH_CLIENT_ID != value.profile.client_id
                or config.GOOGLE_OAUTH_REDIRECT_URI != value.profile.redirect_uri
                or config.GOOGLE_OAUTH_CLIENT_SECRET_FILE != value.secret_path
                or not hmac.compare_digest(config.GOOGLE_OAUTH_CLIENT_SECRET.encode("utf-8"),
                    value.secret.encode("utf-8"))
                or config.PUBLIC_URL + CALLBACK_PATH != value.profile.redirect_uri
                or any(getattr(config, key) for key in _PROTECTED_FLAGS)
                or config.CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES
                or config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED or config.KEY_RELEASE_REQUIRED
                or config.DATA_DIR != Path(os.environ["SERVERWARE_DATA_DIR"])
                or config.METADATA_STORE_BACKEND != "sqlite" or config.AUDIT_STORE_BACKEND != "sqlite"
                or config.GRANT_STORE_BACKEND != "sqlite"
                or config.DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
                or config.TEE_QUOTE_PROVIDER != "dev-signed-quote" or config.TEE_PLATFORM != "none-dev"):
            _refuse()
        return value.profile
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError):
        raise OperatorGoogleProfileError(_ERROR) from None


def require_profile() -> Profile:
    """Return the immutable admitted capability, including on an existing DB tx."""
    if _managed_mode():
        from serverware import operator_google_managed_config
        return operator_google_managed_config.require_profile()
    if not selected() or _admission is None:
        _refuse()
    from serverware import config, operator_demo, oauth_application_owner
    value = validate_imported_configuration(config)
    try:
        if not operator_demo.active() or oauth_application_owner.require_started() is not None:
            _refuse()
    except (RuntimeError, ValueError):
        raise OperatorGoogleProfileError(_ERROR) from None
    return value


def require_lease_reconciliation_profile() -> Profile:
    # The caller separately binds the actual catalog/core credential, active
    # policy and uncontrolled pre-envelope attempt. This grants none of those.
    return require_profile()


def binding_record() -> dict:
    value = require_profile()
    return _record(value.client_id, value.redirect_uri)
