from __future__ import annotations

import os
import stat
import unicodedata
from pathlib import Path

from serverware.rbac import RBACRoleValidationError, normalize_rbac_roles


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RELEASE_CHANNEL = os.getenv("SERVERWARE_RELEASE_CHANNEL", "dev")
_PRODUCTION_IMAGE_MARKER = PROJECT_ROOT / ".serverware-production-image"
try:
    _PRODUCTION_IMAGE_MARKER_PRESENT = (
        _PRODUCTION_IMAGE_MARKER.is_file()
        and _PRODUCTION_IMAGE_MARKER.read_text(encoding="ascii")
        == "serverware.productionImage/v1\n"
    )
except OSError:
    _PRODUCTION_IMAGE_MARKER_PRESENT = False
PRODUCTION_IMAGE = _PRODUCTION_IMAGE_MARKER_PRESENT or os.getenv(
    "SERVERWARE_PRODUCTION_IMAGE", "0"
) == "1"
_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}
MAX_OAUTH_CLIENT_SECRET_FILE_BYTES = 4096
MAX_SERVICE_CREDENTIAL_FILE_BYTES = 4096
_SERVICE_CREDENTIAL_FILE_MODES = {0o400, 0o440, 0o600, 0o640}


def _production_release() -> bool:
    return RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS


def _read_oauth_client_secret_file(path: Path, *, setting_name: str) -> str:
    if not path.is_absolute():
        raise RuntimeError(f"{setting_name} must be an absolute path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{setting_name} must reference a readable, non-symlink secret file") from exc
    try:
        file_stat = os.fstat(descriptor)
        mode = stat.S_IMODE(file_stat.st_mode)
        if not stat.S_ISREG(file_stat.st_mode):
            raise RuntimeError(f"{setting_name} must reference a regular file")
        if mode not in {0o400, 0o600}:
            raise RuntimeError(f"{setting_name} must use owner-readable mode 0400 or 0600")
        if not 1 <= file_stat.st_size <= MAX_OAUTH_CLIENT_SECRET_FILE_BYTES:
            raise RuntimeError(
                f"{setting_name} must contain between 1 and {MAX_OAUTH_CLIENT_SECRET_FILE_BYTES} bytes"
            )
        chunks: list[bytes] = []
        remaining = MAX_OAUTH_CLIENT_SECRET_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != file_stat.st_size:
            raise RuntimeError(f"{setting_name} changed while it was being read")
    finally:
        os.close(descriptor)
    try:
        secret = payload.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{setting_name} must contain UTF-8 text") from exc
    if not secret or secret != secret.strip() or any(character in secret for character in ("\x00", "\r", "\n")):
        raise RuntimeError(f"{setting_name} must contain one non-empty secret without surrounding whitespace")
    return secret


def _oauth_client_secret(*, value_name: str, file_name: str) -> tuple[str, Path | None]:
    direct_value = os.getenv(value_name, "").strip()
    raw_path = os.getenv(file_name, "").strip()
    secret_path = Path(raw_path) if raw_path else None
    if _production_release() and direct_value and secret_path is not None:
        raise RuntimeError(f"production must not set both {value_name} and {file_name}")
    if direct_value:
        return direct_value, secret_path
    if secret_path is None:
        return "", None
    return _read_oauth_client_secret_file(secret_path, setting_name=file_name), secret_path


def _service_credential_file_identity(file_stat: os.stat_result) -> tuple[int, ...]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _read_service_credential_file(path: Path, *, setting_name: str) -> str:
    if not path.is_absolute():
        raise RuntimeError(f"{setting_name} must be an absolute path")
    try:
        path_stat_before = path.lstat()
    except OSError as exc:
        raise RuntimeError(
            f"{setting_name} must reference a readable, non-symlink credential file"
        ) from exc
    if stat.S_ISLNK(path_stat_before.st_mode):
        raise RuntimeError(f"{setting_name} must not reference a symlink")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(
            f"{setting_name} must reference a readable, non-symlink credential file"
        ) from exc
    try:
        file_stat_before = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat_before.st_mode):
            raise RuntimeError(f"{setting_name} must reference a regular file")
        if (
            path_stat_before.st_dev != file_stat_before.st_dev
            or path_stat_before.st_ino != file_stat_before.st_ino
        ):
            raise RuntimeError(f"{setting_name} changed while it was being opened")
        mode = stat.S_IMODE(file_stat_before.st_mode)
        if mode not in _SERVICE_CREDENTIAL_FILE_MODES:
            raise RuntimeError(
                f"{setting_name} must use mode 0400, 0440, 0600, or 0640"
            )
        if not 1 <= file_stat_before.st_size <= MAX_SERVICE_CREDENTIAL_FILE_BYTES:
            raise RuntimeError(
                f"{setting_name} must contain between 1 and "
                f"{MAX_SERVICE_CREDENTIAL_FILE_BYTES} bytes"
            )

        chunks: list[bytes] = []
        remaining = MAX_SERVICE_CREDENTIAL_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        file_stat_after = os.fstat(descriptor)
        try:
            path_stat_after = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"{setting_name} changed while it was being read") from exc
        if (
            len(payload) != file_stat_before.st_size
            or _service_credential_file_identity(file_stat_after)
            != _service_credential_file_identity(file_stat_before)
            or _service_credential_file_identity(path_stat_after)
            != _service_credential_file_identity(file_stat_before)
        ):
            raise RuntimeError(f"{setting_name} changed while it was being read")
    finally:
        os.close(descriptor)

    try:
        credential = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{setting_name} must contain UTF-8 text") from exc
    if not credential:
        raise RuntimeError(f"{setting_name} must contain one non-empty credential")
    if credential != credential.strip():
        raise RuntimeError(
            f"{setting_name} must not contain surrounding whitespace or newlines"
        )
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in credential
    ):
        raise RuntimeError(f"{setting_name} must not contain whitespace or control characters")
    return credential


def _service_credential(
    *,
    value_name: str,
    file_name: str,
    strip_direct_value: bool = False,
) -> tuple[str, Path | None]:
    value_present = value_name in os.environ
    file_present = file_name in os.environ
    if value_present and file_present:
        raise RuntimeError(f"must not set both {value_name} and {file_name}")
    if value_present:
        direct_value = os.environ[value_name]
        return (
            direct_value.strip() if strip_direct_value else direct_value,
            None,
        )
    if not file_present:
        return "", None
    raw_path = os.environ[file_name]
    if not raw_path or raw_path != raw_path.strip():
        raise RuntimeError(f"{file_name} must be a non-empty absolute path")
    credential_path = Path(raw_path)
    return (
        _read_service_credential_file(credential_path, setting_name=file_name),
        credential_path,
    )


DATA_DIR = Path(os.getenv("SERVERWARE_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "serverware.sqlite3"
MITMPROXY_CONF_DIR = DATA_DIR / "mitmproxy"
CA_INSTALL_SESSIONS_PATH = Path(os.getenv("SERVERWARE_CA_INSTALL_SESSIONS", str(DATA_DIR / "ca-install-sessions.json")))
MASTER_KEY_PATH = DATA_DIR / "master.key"
KEY_RELEASE_STATE_PATH = Path(os.getenv("SERVERWARE_KEY_RELEASE_STATE", str(DATA_DIR / "key-release-state.json")))
TEE_QUOTE_SIGNING_KEY_PATH = Path(os.getenv("SERVERWARE_TEE_QUOTE_SIGNING_KEY", str(DATA_DIR / "dev-tee-quote-ed25519.pem")))
RESPONSE_SIGNING_KEY_PATH = Path(os.getenv("SERVERWARE_RESPONSE_SIGNING_KEY", str(DATA_DIR / "response-signing-ed25519.pem")))
_RESPONSE_SIGNING_PUBLIC_KEY = os.getenv(
    "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY", ""
).strip()
_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = os.getenv(
    "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", ""
).strip()
if bool(_RESPONSE_SIGNING_PUBLIC_KEY) != bool(_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH):
    raise RuntimeError(
        "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY and "
        "SERVERWARE_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH must be configured together"
    )
RESPONSE_SIGNING_PUBLIC_KEY_PATH = (
    Path(_RESPONSE_SIGNING_PUBLIC_KEY) if _RESPONSE_SIGNING_PUBLIC_KEY else None
)
RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH = (
    Path(_RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH)
    if _RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH
    else None
)
TEE_QUOTE_PROVIDER = os.getenv("SERVERWARE_TEE_QUOTE_PROVIDER", "dev-signed-quote").strip()
TEE_QUOTE_COMMAND = os.getenv("SERVERWARE_TEE_QUOTE_COMMAND", "").strip()
TEE_QUOTE_VERIFY_COMMAND = os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND", "").strip()
TEE_PLATFORM = os.getenv("SERVERWARE_TEE_PLATFORM", "none-dev").strip()
POLICY_BUNDLE_PATH = Path(os.getenv("SERVERWARE_POLICY_BUNDLE", str(DATA_DIR / "policy-bundle.json")))
POLICY_CANARY_STATE_PATH = Path(os.getenv("SERVERWARE_POLICY_CANARY_STATE", str(DATA_DIR / "policy-canary-state.json")))
POLICY_CANARY_BUNDLE_PATH = Path(os.getenv("SERVERWARE_POLICY_CANARY_BUNDLE", str(DATA_DIR / "policy-canary-bundle.json")))
POLICY_SIGNING_KEY_PATH = Path(os.getenv("SERVERWARE_POLICY_SIGNING_KEY", str(DATA_DIR / "policy-signing-ed25519.pem")))
POLICY_SIGNING_PUBLIC_KEY_PATH = Path(os.getenv("SERVERWARE_POLICY_SIGNING_PUBLIC_KEY", str(DATA_DIR / "policy-signing-ed25519.pub.pem")))
ADMIN_TOKEN, _ADMIN_TOKEN_FILE_PATH = _service_credential(
    value_name="SERVERWARE_ADMIN_TOKEN",
    file_name="SERVERWARE_ADMIN_TOKEN_FILE",
)
ADMIN_TOKEN_FILE_PATH = _ADMIN_TOKEN_FILE_PATH
ADMIN_TOKEN_EXTERNALLY_CONFIGURED = (
    "SERVERWARE_ADMIN_TOKEN" in os.environ or ADMIN_TOKEN_FILE_PATH is not None
)
ADMIN_TOKEN_SOURCE = (
    "env"
    if "SERVERWARE_ADMIN_TOKEN" in os.environ
    else "file"
    if ADMIN_TOKEN_FILE_PATH is not None
    else "generated-file"
)
ADMIN_TOKEN_PATH = ADMIN_TOKEN_FILE_PATH or DATA_DIR / "admin.token"
RBAC_BINDINGS_PATH = Path(os.getenv("SERVERWARE_RBAC_BINDINGS", str(DATA_DIR / "rbac-bindings.json")))
RELEASE_PROVENANCE_PATH = Path(os.getenv("SERVERWARE_RELEASE_PROVENANCE", str(DATA_DIR / "release-provenance.json")))
IMAGE_SIGNATURES_PATH = Path(os.getenv("SERVERWARE_IMAGE_SIGNATURES", str(DATA_DIR / "image-signatures.json")))
DECISION_GATE_CA_CERT_PATH = Path(os.getenv("SERVERWARE_DECISION_GATE_CA_CERT", str(DATA_DIR / "decision-gate-ca-cert.pem")))
DECISION_GATE_CA_KEY_PATH = Path(os.getenv("SERVERWARE_DECISION_GATE_CA_KEY", str(DATA_DIR / "decision-gate-ca-key.pem")))
SCHEMA_DIR = Path(os.getenv("SERVERWARE_SCHEMA_DIR", str(PROJECT_ROOT / "schemas")))
OAUTH_STATE_PATH = Path(os.getenv("SERVERWARE_OAUTH_STATE_PATH", str(DATA_DIR / "oauth-states.json")))
OAUTH_STATE_TTL_SECONDS = int(os.getenv("SERVERWARE_OAUTH_STATE_TTL_SECONDS", "600"))
if OAUTH_STATE_TTL_SECONDS <= 0:
    raise RuntimeError("SERVERWARE_OAUTH_STATE_TTL_SECONDS must be positive")
if _production_release() and not 60 <= OAUTH_STATE_TTL_SECONDS <= 900:
    raise RuntimeError("production SERVERWARE_OAUTH_STATE_TTL_SECONDS must be between 60 and 900 seconds")
OAUTH_PENDING_CREDENTIAL_TTL_SECONDS = int(
    os.getenv("SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS", "900")
)
if not 60 <= OAUTH_PENDING_CREDENTIAL_TTL_SECONDS <= 3600:
    raise RuntimeError("SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS must be between 60 and 3600 seconds")
OAUTH_PENDING_CREDENTIAL_MAX_COUNT = int(
    os.getenv("SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT", "1000")
)
if not 1 <= OAUTH_PENDING_CREDENTIAL_MAX_COUNT <= 10_000:
    raise RuntimeError("SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT must be between 1 and 10000")

SETUP_SESSION_TTL_SECONDS = int(os.getenv("SERVERWARE_SETUP_SESSION_TTL_SECONDS", "86400"))
if not 300 <= SETUP_SESSION_TTL_SECONDS <= 604_800:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_TTL_SECONDS must be between 300 and 604800")
SETUP_SESSION_MAX_ACTIVE = int(os.getenv("SERVERWARE_SETUP_SESSION_MAX_ACTIVE", "1000"))
if not 1 <= SETUP_SESSION_MAX_ACTIVE <= 100_000:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_MAX_ACTIVE must be between 1 and 100000")
SETUP_SESSION_MAX_RETAINED = int(os.getenv("SERVERWARE_SETUP_SESSION_MAX_RETAINED", "10000"))
if not SETUP_SESSION_MAX_ACTIVE <= SETUP_SESSION_MAX_RETAINED <= 1_000_000:
    raise RuntimeError(
        "SERVERWARE_SETUP_SESSION_MAX_RETAINED must be between "
        "SERVERWARE_SETUP_SESSION_MAX_ACTIVE and 1000000"
    )
SETUP_SESSION_RETENTION_SECONDS = int(
    os.getenv("SERVERWARE_SETUP_SESSION_RETENTION_SECONDS", "604800")
)
if not 300 <= SETUP_SESSION_RETENTION_SECONDS <= 7_776_000:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_RETENTION_SECONDS must be between 300 and 7776000")
SETUP_SESSION_EVIDENCE_MAX_BYTES = int(
    os.getenv("SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_BYTES", "1048576")
)
if not 1024 <= SETUP_SESSION_EVIDENCE_MAX_BYTES <= 1_048_576:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_BYTES must be between 1024 and 1048576")
SETUP_SESSION_EVIDENCE_MAX_COUNT = int(
    os.getenv("SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_COUNT", "64")
)
if not 1 <= SETUP_SESSION_EVIDENCE_MAX_COUNT <= 1024:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_EVIDENCE_MAX_COUNT must be between 1 and 1024")
SETUP_SESSION_EVENT_MAX_BYTES = int(
    os.getenv("SERVERWARE_SETUP_SESSION_EVENT_MAX_BYTES", "16384")
)
if not 1024 <= SETUP_SESSION_EVENT_MAX_BYTES <= 262_144:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_EVENT_MAX_BYTES must be between 1024 and 262144")
SETUP_SESSION_EVENT_MAX_COUNT = int(
    os.getenv("SERVERWARE_SETUP_SESSION_EVENT_MAX_COUNT", "128")
)
if not 4 <= SETUP_SESSION_EVENT_MAX_COUNT <= 4096:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_EVENT_MAX_COUNT must be between 4 and 4096")
SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING = int(
    os.getenv("SERVERWARE_SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING", "10000")
)
if not 100 <= SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING <= 1_000_000:
    raise RuntimeError(
        "SERVERWARE_SETUP_SESSION_AUDIT_OUTBOX_MAX_PENDING must be between 100 and 1000000"
    )
SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS = int(
    os.getenv("SERVERWARE_SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS", "60")
)
if not 5 <= SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS <= 3600:
    raise RuntimeError("SERVERWARE_SETUP_SESSION_AUDIT_CLAIM_TTL_SECONDS must be between 5 and 3600")

_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY = os.getenv(
    "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY", ""
).strip()
SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY_PATH = (
    Path(_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY)
    if _SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY
    else None
)
SETUP_ENROLLMENT_VERIFIER_KEY_ID = os.getenv(
    "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_KEY_ID", ""
).strip()
SETUP_ENROLLMENT_VERIFIER_PROVIDER = os.getenv(
    "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PROVIDER", ""
).strip()
_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY = os.getenv(
    "SERVERWARE_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY", ""
).strip()
SETUP_HARDWARE_VERIFIER_PUBLIC_KEY_PATH = (
    Path(_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY)
    if _SETUP_HARDWARE_VERIFIER_PUBLIC_KEY
    else None
)
SETUP_HARDWARE_VERIFIER_KEY_ID = os.getenv(
    "SERVERWARE_SETUP_HARDWARE_VERIFIER_KEY_ID", ""
).strip()
SETUP_HARDWARE_VERIFIER_PROVIDER = os.getenv(
    "SERVERWARE_SETUP_HARDWARE_VERIFIER_PROVIDER", ""
).strip()
_SETUP_FINAL_AUTHORITY_PUBLIC_KEY = os.getenv(
    "SERVERWARE_SETUP_FINAL_AUTHORITY_PUBLIC_KEY", ""
).strip()
SETUP_FINAL_AUTHORITY_PUBLIC_KEY_PATH = (
    Path(_SETUP_FINAL_AUTHORITY_PUBLIC_KEY)
    if _SETUP_FINAL_AUTHORITY_PUBLIC_KEY
    else None
)
SETUP_FINAL_AUTHORITY_KEY_ID = os.getenv(
    "SERVERWARE_SETUP_FINAL_AUTHORITY_KEY_ID", ""
).strip()
SETUP_FINAL_AUTHORITY_PROVIDER = os.getenv(
    "SERVERWARE_SETUP_FINAL_AUTHORITY_PROVIDER", ""
).strip()
SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS = int(
    os.getenv("SERVERWARE_SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS", "300")
)
if not 30 <= SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS <= 900:
    raise RuntimeError(
        "SERVERWARE_SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS must be between 30 and 900"
    )

CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES = int(
    os.getenv("SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES", "1000000")
)
if not 10_000 <= CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES <= 10_000_000:
    raise RuntimeError(
        "SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES must be between 10000 and 10000000"
    )

WEB_HOST = os.getenv("SERVERWARE_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("SERVERWARE_WEB_PORT", "3000"))
WEB_TLS_CERT_FILE = os.getenv("SERVERWARE_WEB_TLS_CERT_FILE", "").strip()
WEB_TLS_KEY_FILE = os.getenv("SERVERWARE_WEB_TLS_KEY_FILE", "").strip()
PROXY_HOST = os.getenv("SERVERWARE_PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.getenv("SERVERWARE_PROXY_PORT", "8080"))
PUBLIC_URL = os.getenv("SERVERWARE_PUBLIC_URL", f"http://localhost:{WEB_PORT}").strip()
GOOGLE_OAUTH_CLIENT_ID = os.getenv("SERVERWARE_GOOGLE_OAUTH_CLIENT_ID", "").strip()
GOOGLE_OAUTH_CLIENT_SECRET, GOOGLE_OAUTH_CLIENT_SECRET_FILE = _oauth_client_secret(
    value_name="SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET",
    file_name="SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
)
GOOGLE_OAUTH_REDIRECT_URI = os.getenv("SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI", f"{PUBLIC_URL}/api/oauth/callback/google").strip()
X_OAUTH_CLIENT_ID = os.getenv("SERVERWARE_X_OAUTH_CLIENT_ID", os.getenv("SERVERWARE_TWITTER_OAUTH_CLIENT_ID", "")).strip()
_X_OAUTH_LEGACY_CLIENT_SECRET = os.getenv("SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET", "").strip()
if _production_release() and _X_OAUTH_LEGACY_CLIENT_SECRET and os.getenv("SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE", "").strip():
    raise RuntimeError(
        "production must not set both SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET and "
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE"
    )
X_OAUTH_CLIENT_SECRET, X_OAUTH_CLIENT_SECRET_FILE = _oauth_client_secret(
    value_name="SERVERWARE_X_OAUTH_CLIENT_SECRET",
    file_name="SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE",
)
if not X_OAUTH_CLIENT_SECRET and not X_OAUTH_CLIENT_SECRET_FILE:
    X_OAUTH_CLIENT_SECRET = _X_OAUTH_LEGACY_CLIENT_SECRET
X_OAUTH_REDIRECT_URI = os.getenv("SERVERWARE_X_OAUTH_REDIRECT_URI", os.getenv("SERVERWARE_TWITTER_OAUTH_REDIRECT_URI", f"{PUBLIC_URL}/api/oauth/callback/x")).strip()
ADMIN_USER_ID = os.getenv("SERVERWARE_ADMIN_USER", "user:admin")
try:
    ADMIN_ROLES = tuple(
        normalize_rbac_roles(
            [
                role.strip()
                for role in os.getenv(
                    "SERVERWARE_ADMIN_ROLES",
                    "admin,approver,auditor,policy_author,policy_publisher,credential_owner,attestation_operator,attestation_reviewer",
                ).split(",")
                if role.strip()
            ]
        )
    )
except RBACRoleValidationError as exc:
    raise RuntimeError("SERVERWARE_ADMIN_ROLES is invalid") from exc
OIDC_ENABLED = os.getenv("SERVERWARE_OIDC_ENABLED", "0") == "1"
OIDC_ISSUER = os.getenv("SERVERWARE_OIDC_ISSUER", "").strip()
OIDC_AUDIENCE = os.getenv("SERVERWARE_OIDC_AUDIENCE", "").strip()
OIDC_JWKS_JSON = os.getenv("SERVERWARE_OIDC_JWKS_JSON", "").strip()
OIDC_JWKS_PATH = Path(os.getenv("SERVERWARE_OIDC_JWKS_PATH", str(DATA_DIR / "oidc-jwks.json")))
OIDC_ROLE_CLAIM = os.getenv("SERVERWARE_OIDC_ROLE_CLAIM", "serverware_roles").strip() or "serverware_roles"
OIDC_SUBJECT_CLAIM = os.getenv("SERVERWARE_OIDC_SUBJECT_CLAIM", "sub").strip() or "sub"
OIDC_ALLOWED_ALGORITHMS = tuple(
    item.strip()
    for item in os.getenv("SERVERWARE_OIDC_ALLOWED_ALGORITHMS", "RS256,ES256,EdDSA").split(",")
    if item.strip()
)
OIDC_LEEWAY_SECONDS = int(os.getenv("SERVERWARE_OIDC_LEEWAY_SECONDS", "60"))
OIDC_BROWSER_LOGIN_ENABLED = os.getenv("SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED", "0") == "1"
OIDC_AUTHORIZATION_ENDPOINT = os.getenv("SERVERWARE_OIDC_AUTHORIZATION_ENDPOINT", "").strip()
OIDC_TOKEN_ENDPOINT = os.getenv("SERVERWARE_OIDC_TOKEN_ENDPOINT", "").strip()
OIDC_CLIENT_ID = os.getenv("SERVERWARE_OIDC_CLIENT_ID", OIDC_AUDIENCE).strip()
OIDC_CLIENT_SECRET, OIDC_CLIENT_SECRET_FILE = _oauth_client_secret(
    value_name="SERVERWARE_OIDC_CLIENT_SECRET",
    file_name="SERVERWARE_OIDC_CLIENT_SECRET_FILE",
)
OIDC_REDIRECT_URI = os.getenv(
    "SERVERWARE_OIDC_REDIRECT_URI",
    f"{PUBLIC_URL}/api/auth/oidc/callback",
).strip()
OIDC_BROWSER_SCOPES = tuple(
    item.strip()
    for item in os.getenv("SERVERWARE_OIDC_BROWSER_SCOPES", "openid,profile,email").split(",")
    if item.strip()
)
OIDC_TOKEN_AUTH_METHOD = os.getenv("SERVERWARE_OIDC_TOKEN_AUTH_METHOD", "client_secret_basic").strip()
if OIDC_TOKEN_AUTH_METHOD not in {"client_secret_basic", "client_secret_post", "none"}:
    raise RuntimeError("SERVERWARE_OIDC_TOKEN_AUTH_METHOD is unsupported")
OIDC_LOGIN_STATE_TTL_SECONDS = int(os.getenv("SERVERWARE_OIDC_LOGIN_STATE_TTL_SECONDS", "300"))
if not 60 <= OIDC_LOGIN_STATE_TTL_SECONDS <= 900:
    raise RuntimeError("SERVERWARE_OIDC_LOGIN_STATE_TTL_SECONDS must be between 60 and 900 seconds")
OIDC_SESSION_TTL_SECONDS = int(os.getenv("SERVERWARE_OIDC_SESSION_TTL_SECONDS", "3600"))
if not 300 <= OIDC_SESSION_TTL_SECONDS <= 43_200:
    raise RuntimeError("SERVERWARE_OIDC_SESSION_TTL_SECONDS must be between 300 and 43200 seconds")
OIDC_SESSION_WEBAUTHN_REQUIRED = (
    os.getenv("SERVERWARE_OIDC_SESSION_WEBAUTHN_REQUIRED", "0") == "1"
)
OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS = int(
    os.getenv("SERVERWARE_OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS", "120")
)
if not 30 <= OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS <= 300:
    raise RuntimeError(
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_CHALLENGE_TTL_SECONDS must be between 30 and 300 seconds"
    )
OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS = int(
    os.getenv("SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS", "300")
)
if not 60 <= OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS <= 300:
    raise RuntimeError(
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS must be between 60 and 300 seconds"
    )
OIDC_SESSION_ACTIVATION_RETRY_TTL_SECONDS = int(
    os.getenv("SERVERWARE_OIDC_SESSION_ACTIVATION_RETRY_TTL_SECONDS", "20")
)
if not 5 <= OIDC_SESSION_ACTIVATION_RETRY_TTL_SECONDS <= 60:
    raise RuntimeError(
        "SERVERWARE_OIDC_SESSION_ACTIVATION_RETRY_TTL_SECONDS must be between 5 and 60 seconds"
    )
WEBAUTHN_RECOVERY_ENABLED = os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_ENABLED", "0") == "1"
_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY = os.getenv(
    "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY", ""
).strip()
WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY_PATH = (
    Path(_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY)
    if _WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY
    else None
)
WEBAUTHN_RECOVERY_ROOT_KEY_ID = os.getenv(
    "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_KEY_ID", ""
).strip()
WEBAUTHN_RECOVERY_ROOT_PROVIDER = os.getenv(
    "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PROVIDER", ""
).strip()
WEBAUTHN_RECOVERY_AUDIENCE = os.getenv(
    "SERVERWARE_WEBAUTHN_RECOVERY_AUDIENCE", ""
).strip()
WEBAUTHN_RECOVERY_TTL_SECONDS = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_TTL_SECONDS", "180")
)
if not 30 <= WEBAUTHN_RECOVERY_TTL_SECONDS <= 300:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_TTL_SECONDS must be between 30 and 300 seconds"
    )
if WEBAUTHN_RECOVERY_TTL_SECONDS > OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_TTL_SECONDS must not exceed "
        "SERVERWARE_OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS"
    )
WEBAUTHN_RECOVERY_MAX_LIVE = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_MAX_LIVE", "100")
)
if not 1 <= WEBAUTHN_RECOVERY_MAX_LIVE <= 10_000:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_MAX_LIVE must be between 1 and 10000"
    )
WEBAUTHN_RECOVERY_TERMINAL_RETENTION_SECONDS = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_TERMINAL_RETENTION_SECONDS", "7776000")
)
if not 86_400 <= WEBAUTHN_RECOVERY_TERMINAL_RETENTION_SECONDS <= 31_536_000:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_TERMINAL_RETENTION_SECONDS must be between 86400 and 31536000"
    )
WEBAUTHN_RECOVERY_MAX_RETAINED = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_MAX_RETAINED", "100000")
)
if not 100 <= WEBAUTHN_RECOVERY_MAX_RETAINED <= 1_000_000:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_MAX_RETAINED must be between 100 and 1000000"
    )
WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_COUNT = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_COUNT", "1000")
)
if not 1 <= WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_COUNT <= 10_000:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_COUNT must be between 1 and 10000"
    )
WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_BYTES = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_BYTES", "4194304")
)
if not 65_536 <= WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_BYTES <= 16_777_216:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_CREDENTIAL_HISTORY_MAX_BYTES must be between 65536 and 16777216"
    )
WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_COUNT = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_COUNT", "1000")
)
if not 1 <= WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_COUNT <= 10_000:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_COUNT must be between 1 and 10000"
    )
WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_BYTES = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_BYTES", "1048576")
)
if not 16_384 <= WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_BYTES <= 8_388_608:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_EXCLUDE_CREDENTIALS_MAX_BYTES must be between 16384 and 8388608"
    )
WEBAUTHN_RECOVERY_WITNESS_BACKEND = os.getenv(
    "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_BACKEND", "sqlite"
).strip().lower()
WEBAUTHN_RECOVERY_WITNESS_PATH = Path(
    os.getenv(
        "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_PATH",
        str(DATA_DIR / "webauthn-recovery-witness.sqlite3"),
    )
)
WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN = os.getenv(
    "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN", ""
).strip()
WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID = os.getenv(
    "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_FAULT_DOMAIN_ID", ""
).strip()
WEBAUTHN_RECOVERY_WITNESS_CONNECT_TIMEOUT_SECONDS = int(
    os.getenv("SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_CONNECT_TIMEOUT_SECONDS", "5")
)
if WEBAUTHN_RECOVERY_WITNESS_BACKEND not in {"sqlite", "local", "postgres", "postgresql"}:
    raise RuntimeError("SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_BACKEND is unsupported")
if not 1 <= WEBAUTHN_RECOVERY_WITNESS_CONNECT_TIMEOUT_SECONDS <= 30:
    raise RuntimeError(
        "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_CONNECT_TIMEOUT_SECONDS must be between 1 and 30"
    )
WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX = int(
    os.getenv("SERVERWARE_WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX", "50000")
)
WEBAUTHN_CHALLENGE_USER_LIVE_MAX = int(
    os.getenv("SERVERWARE_WEBAUTHN_CHALLENGE_USER_LIVE_MAX", "64")
)
WEBAUTHN_CHALLENGE_USER_RATE_MAX = int(
    os.getenv("SERVERWARE_WEBAUTHN_CHALLENGE_USER_RATE_MAX", "120")
)
WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX = int(
    os.getenv("SERVERWARE_WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX", "10000")
)
WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS = int(
    os.getenv("SERVERWARE_WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS", "60")
)
WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS = int(
    os.getenv("SERVERWARE_WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS", "900")
)
WEBAUTHN_CHALLENGE_MAX_RETAINED = int(
    os.getenv("SERVERWARE_WEBAUTHN_CHALLENGE_MAX_RETAINED", "100000")
)
if not 100 <= WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX <= 1_000_000:
    raise RuntimeError("SERVERWARE_WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX is invalid")
if not 4 <= WEBAUTHN_CHALLENGE_USER_LIVE_MAX <= 10_000:
    raise RuntimeError("SERVERWARE_WEBAUTHN_CHALLENGE_USER_LIVE_MAX is invalid")
if not 10 <= WEBAUTHN_CHALLENGE_USER_RATE_MAX <= 100_000:
    raise RuntimeError("SERVERWARE_WEBAUTHN_CHALLENGE_USER_RATE_MAX is invalid")
if not 100 <= WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX <= 1_000_000:
    raise RuntimeError("SERVERWARE_WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX is invalid")
if not 10 <= WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS <= 3600:
    raise RuntimeError("SERVERWARE_WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS is invalid")
if not 60 <= WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS <= 604_800:
    raise RuntimeError("SERVERWARE_WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS is invalid")
if not 100 <= WEBAUTHN_CHALLENGE_MAX_RETAINED <= 1_000_000:
    raise RuntimeError("SERVERWARE_WEBAUTHN_CHALLENGE_MAX_RETAINED is invalid")
WEBAUTHN_RP_ID = os.getenv("SERVERWARE_WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_ORIGIN = os.getenv("SERVERWARE_WEBAUTHN_ORIGIN", PUBLIC_URL)
WEBAUTHN_RP_NAME = os.getenv("SERVERWARE_WEBAUTHN_RP_NAME", "Serverware")
WEBAUTHN_BOOTSTRAP_TOKEN, _WEBAUTHN_BOOTSTRAP_TOKEN_FILE_PATH = (
    _service_credential(
        value_name="SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN",
        file_name="SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN_FILE",
    )
)
WEBAUTHN_TRUST_ROOTS_PATH = Path(os.getenv("SERVERWARE_WEBAUTHN_TRUST_ROOTS", str(DATA_DIR / "webauthn-trust-roots.pem")))
WEBAUTHN_TRUST_BUNDLE_PATH = Path(os.getenv("SERVERWARE_WEBAUTHN_TRUST_BUNDLE", str(DATA_DIR / "webauthn-trust-bundle.json")))
WEBAUTHN_TRUST_BUNDLE_STATE_PATH = Path(
    os.getenv("SERVERWARE_WEBAUTHN_TRUST_BUNDLE_STATE", str(DATA_DIR / "webauthn-trust-bundle-state.json"))
)
WEBAUTHN_TRUST_SIGNING_KEY_PATH = Path(
    os.getenv("SERVERWARE_WEBAUTHN_TRUST_SIGNING_KEY", str(DATA_DIR / "webauthn-trust-signing-ed25519.pem"))
)
WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH = Path(
    os.getenv("SERVERWARE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY", str(DATA_DIR / "webauthn-trust-signing-ed25519.pub.pem"))
)
DEV_AUTHENTICATOR_ENABLED = os.getenv("SERVERWARE_DEV_AUTHENTICATOR", "0") == "1"
CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED = os.getenv("SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED", "0") == "1"
CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION = (
    os.getenv("SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION", "0") == "1"
)
CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES = tuple(
    item.strip()
    for item in os.getenv("SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES", "").split(",")
    if item.strip()
)
CONTROL_PLANE_TWO_PERSON_REQUIRED = os.getenv("SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED", "0") == "1"
CONTROL_PLANE_TWO_PERSON_TTL_SECONDS = int(os.getenv("SERVERWARE_CONTROL_PLANE_TWO_PERSON_TTL_SECONDS", "300"))
CONTROL_PLANE_TWO_PERSON_ACTIONS = tuple(
    item.strip()
    for item in os.getenv(
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS",
        "credential.create,credential.oauth.activate,credential.oauth.uncertain.resolve,credential.update,credential.delete,route.create,route.update,route.delete,policy.publish,webauthn.credential.register,webauthn.credential.revoke,webauthn.oidc-session.activation.recover,webauthn.trust.publish,rbac.role.change,rbac.deprovision,control_plane.token.rotate,break_glass.grant,setup.attestation.finalize,workload.identity.issue",
    ).split(",")
    if item.strip()
)
DIRECT_CA_DOWNLOAD_ENABLED = os.getenv("SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED", "1") == "1"
CA_INSTALL_SESSION_TTL_SECONDS = int(os.getenv("SERVERWARE_CA_INSTALL_SESSION_TTL_SECONDS", "300"))
CA_INSTALL_SESSION_MAX_ENTRIES = int(os.getenv("SERVERWARE_CA_INSTALL_SESSION_MAX_ENTRIES", "10000"))
CA_INSTALL_SESSION_RETENTION_SECONDS = int(os.getenv("SERVERWARE_CA_INSTALL_SESSION_RETENTION_SECONDS", "86400"))
CA_INSTALL_SESSION_CLAIM_TTL_SECONDS = int(os.getenv("SERVERWARE_CA_INSTALL_SESSION_CLAIM_TTL_SECONDS", "30"))
POLICY_PUBLISH_DRY_RUN_REQUIRED = os.getenv("SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED", "0") == "1"
POLICY_CANARY_REQUIRED = os.getenv("SERVERWARE_POLICY_CANARY_REQUIRED", "0") == "1"
POLICY_CANARY_MIN_OBSERVATION_SECONDS = int(os.getenv("SERVERWARE_POLICY_CANARY_MIN_OBSERVATION_SECONDS", "0"))
POLICY_CANARY_MIN_AUDIT_EVENTS = int(os.getenv("SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS", "0"))
POLICY_CANARY_MAX_DENIALS = int(os.getenv("SERVERWARE_POLICY_CANARY_MAX_DENIALS", "0"))
POLICY_MIN_SEQUENCE = int(os.getenv("SERVERWARE_POLICY_MIN_SEQUENCE", "0"))
POLICY_MIN_ROLLBACK_EPOCH = int(os.getenv("SERVERWARE_POLICY_MIN_ROLLBACK_EPOCH", "0"))
SECRET_LEASE_TTL_SECONDS = float(os.getenv("SERVERWARE_SECRET_LEASE_TTL_SECONDS", "5"))
AUDIT_QUEUE_MAX = int(os.getenv("SERVERWARE_AUDIT_QUEUE_MAX", "10000"))
AUDIT_ANCHOR_URL = os.getenv("SERVERWARE_AUDIT_ANCHOR_URL", "").rstrip("/")
AUDIT_ANCHOR_TOKEN, _AUDIT_ANCHOR_TOKEN_FILE_PATH = _service_credential(
    value_name="SERVERWARE_AUDIT_ANCHOR_TOKEN",
    file_name="SERVERWARE_AUDIT_ANCHOR_TOKEN_FILE",
)
AUDIT_ANCHOR_TOKEN_FILE_PATH = _AUDIT_ANCHOR_TOKEN_FILE_PATH
AUDIT_ANCHOR_TOKEN_SOURCE = (
    "env"
    if "SERVERWARE_AUDIT_ANCHOR_TOKEN" in os.environ
    else "file"
    if AUDIT_ANCHOR_TOKEN_FILE_PATH is not None
    else "unconfigured"
)
AUDIT_ANCHOR_CA_BUNDLE = os.getenv("SERVERWARE_AUDIT_ANCHOR_CA_BUNDLE", "").strip()
AUDIT_ANCHOR_INTERVAL_SECONDS = float(os.getenv("SERVERWARE_AUDIT_ANCHOR_INTERVAL_SECONDS", "2"))
AUDIT_ANCHOR_TIMEOUT_SECONDS = float(os.getenv("SERVERWARE_AUDIT_ANCHOR_TIMEOUT_SECONDS", "10"))
GRANT_STORE_BACKEND = os.getenv("SERVERWARE_GRANT_STORE_BACKEND", "sqlite").strip().lower()
GRANT_STORE_POSTGRES_DSN = os.getenv("SERVERWARE_GRANT_STORE_POSTGRES_DSN", "")
GRANT_STORE_CONNECT_TIMEOUT_SECONDS = int(os.getenv("SERVERWARE_GRANT_STORE_CONNECT_TIMEOUT_SECONDS", "5"))
AUDIT_STORE_BACKEND = os.getenv("SERVERWARE_AUDIT_STORE_BACKEND", "sqlite").strip().lower()
AUDIT_STORE_POSTGRES_DSN = os.getenv("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", "")
AUDIT_STORE_CONNECT_TIMEOUT_SECONDS = int(os.getenv("SERVERWARE_AUDIT_STORE_CONNECT_TIMEOUT_SECONDS", "5"))
METADATA_STORE_BACKEND = os.getenv("SERVERWARE_METADATA_STORE_BACKEND", "sqlite").strip().lower()
METADATA_STORE_POSTGRES_DSN = os.getenv("SERVERWARE_METADATA_STORE_POSTGRES_DSN", "")
METADATA_STORE_FAULT_DOMAIN_ID = os.getenv(
    "SERVERWARE_METADATA_STORE_FAULT_DOMAIN_ID", ""
).strip()
METADATA_STORE_CONNECT_TIMEOUT_SECONDS = int(os.getenv("SERVERWARE_METADATA_STORE_CONNECT_TIMEOUT_SECONDS", "5"))
ATOMIC_RELEASE_AUTHORIZATION_ENABLED = (
    os.getenv("SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED", "0") == "1"
)
RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS = int(
    os.getenv("SERVERWARE_RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS", "15")
)
RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS = int(
    os.getenv("SERVERWARE_RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS", "30")
)
RELEASE_AUTHORIZATION_RECONCILE_LIMIT = int(
    os.getenv("SERVERWARE_RELEASE_AUTHORIZATION_RECONCILE_LIMIT", "100")
)
if not 1 <= RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS <= 300:
    raise RuntimeError(
        "SERVERWARE_RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS must be between 1 and 300"
    )
if not 1 <= RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS <= 300:
    raise RuntimeError(
        "SERVERWARE_RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS must be between 1 and 300"
    )
if not 1 <= RELEASE_AUTHORIZATION_RECONCILE_LIMIT <= 500:
    raise RuntimeError(
        "SERVERWARE_RELEASE_AUTHORIZATION_RECONCILE_LIMIT must be between 1 and 500"
    )
DECISION_GATE_BASE = os.getenv("SERVERWARE_DECISION_GATE_BASE", "").rstrip("/")
DECISION_GATE_TIMEOUT_SECONDS = float(os.getenv("SERVERWARE_DECISION_GATE_TIMEOUT_SECONDS", "2"))
DATA_PLANE_INSTANCE_ID = os.getenv("SERVERWARE_DATA_PLANE_INSTANCE_ID", "").strip()
DATA_PLANE_CREDENTIAL_LEASE_TOKEN, _DATA_PLANE_CREDENTIAL_LEASE_TOKEN_FILE_PATH = (
    _service_credential(
        value_name="SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN",
        file_name="SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN_FILE",
        strip_direct_value=True,
    )
)
DATA_PLANE_AUDIT_INGEST_TOKEN, _DATA_PLANE_AUDIT_INGEST_TOKEN_FILE_PATH = (
    _service_credential(
        value_name="SERVERWARE_DATA_PLANE_AUDIT_TOKEN",
        file_name="SERVERWARE_DATA_PLANE_AUDIT_TOKEN_FILE",
        strip_direct_value=True,
    )
)
DATA_PLANE_GRANT_CONSUME_TOKEN, _DATA_PLANE_GRANT_CONSUME_TOKEN_FILE_PATH = (
    _service_credential(
        value_name="SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN",
        file_name="SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN_FILE",
        strip_direct_value=True,
    )
)
DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN, _DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN_FILE_PATH = (
    _service_credential(
        value_name="SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
        file_name="SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN_FILE",
        strip_direct_value=True,
    )
)
(
    DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
    _DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN_FILE_PATH,
) = _service_credential(
    value_name="SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN",
    file_name="SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN_FILE",
    strip_direct_value=True,
)
DATA_PLANE_MANAGEMENT_TOKEN, _DATA_PLANE_MANAGEMENT_TOKEN_FILE_PATH = (
    _service_credential(
        value_name="SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN",
        file_name="SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN_FILE",
        strip_direct_value=True,
    )
)
# serverware.runtime still publishes development grants to the Rust management API
# through this internal symbol. It must never reuse an ingest or consume credential.
DATA_PLANE_AUDIT_TOKEN = DATA_PLANE_MANAGEMENT_TOKEN
DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED = (
    os.getenv("SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED", "0") == "1"
)
DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND = os.getenv(
    "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND",
    "",
).strip()
DATA_PLANE_UID = int(os.getenv("SERVERWARE_DATA_PLANE_UID", "10001"))
DATA_PLANE_GID = int(os.getenv("SERVERWARE_DATA_PLANE_GID", "10001"))
KEY_RELEASE_REQUIRED = os.getenv("SERVERWARE_KEY_RELEASE_REQUIRED", "1") == "1"
KEY_RELEASE_ALLOW_DEBUG = os.getenv("SERVERWARE_KEY_RELEASE_ALLOW_DEBUG", "1") == "1"
KEY_RELEASE_COMMAND = os.getenv("SERVERWARE_KEY_RELEASE_COMMAND", "").strip()
MASTER_KEY_UNSEAL_COMMAND = os.getenv("SERVERWARE_MASTER_KEY_UNSEAL_COMMAND", "").strip()
NITRO_NSM_UNSEAL_COMMAND_TEMPLATE = os.getenv("SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE", "").strip()
KEY_RELEASE_MIN_ROLLBACK_EPOCH = int(os.getenv("SERVERWARE_KEY_RELEASE_MIN_ROLLBACK_EPOCH", "1"))
KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST = os.getenv("SERVERWARE_KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST", "1") == "1"
EXPECTED_DATA_PLANE_BINARY_DIGEST = os.getenv("SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST") or None


_CONTROL_PLANE_SERVICE_TOKENS = {
    "SERVERWARE_ADMIN_TOKEN": ADMIN_TOKEN,
    "SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN": WEBAUTHN_BOOTSTRAP_TOKEN,
    "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": DATA_PLANE_CREDENTIAL_LEASE_TOKEN,
    "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": DATA_PLANE_AUDIT_INGEST_TOKEN,
    "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": DATA_PLANE_GRANT_CONSUME_TOKEN,
    "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN,
    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN": DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
    "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": DATA_PLANE_MANAGEMENT_TOKEN,
    "SERVERWARE_AUDIT_ANCHOR_TOKEN": AUDIT_ANCHOR_TOKEN,
}


def validate_internal_service_auth() -> None:
    if RELEASE_CHANNEL.strip().lower() in _DEVELOPMENT_RELEASE_CHANNELS:
        return
    if not ATOMIC_RELEASE_AUTHORIZATION_ENABLED:
        raise RuntimeError(
            "production requires SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED=1"
        )
    if not DATA_PLANE_INSTANCE_ID.startswith("spiffe://") or len(DATA_PLANE_INSTANCE_ID) <= len("spiffe://"):
        raise RuntimeError("production requires SERVERWARE_DATA_PLANE_INSTANCE_ID as a non-empty SPIFFE ID")
    for name, token in _CONTROL_PLANE_SERVICE_TOKENS.items():
        if len(token.encode("utf-8")) < 32 or len(set(token)) < 8:
            raise RuntimeError(f"production requires {name} with at least 32 high-entropy bytes")
    token_items = list(_CONTROL_PLANE_SERVICE_TOKENS.items())
    for index, (left_name, left_token) in enumerate(token_items):
        for right_name, right_token in token_items[index + 1 :]:
            if left_token == right_token:
                raise RuntimeError(f"production requires distinct internal service credentials: {left_name} and {right_name}")


def ensure_data_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MITMPROXY_CONF_DIR.mkdir(parents=True, exist_ok=True)
