"""Fixed inputs for a future, privately owned native-PG16 lifecycle.

No process, filesystem, environment, clock or database access occurs here.
The deadlines are a standalone profile, not an admitted controller deadline
override. Paths and observations do not attest a prepared image or authorize
cluster reuse, arbitrary SQL, storage allocation or release acceptance.
"""
from __future__ import annotations

from dataclasses import dataclass

from .native_postgres_batch import SOURCE_ROOT


PG_BINDIR = "/opt/catchplate/postgresql-16/bin"
PRIVATE_ROOT = "/var/lib/catchplate-runner"
NATIVE_ROOT = PRIVATE_ROOT + "/native-postgres"
PGDATA = NATIVE_ROOT + "/pgdata"
SOCKET_ROOT = "/run/catchplate-native-postgres"
OUTPUT_ROOT = "/opt/catchplate/output/native-postgres"
USER = "catchplate_fixture_admin"
UID = GID = 10001
# 5,100 suite seconds + 120/60/60 lifecycle seconds + the existing 360 slack.
# This source-only sub-job bound does not amend a signed controller deadline.
TOTAL_SECONDS = 5700
INIT_SECONDS = 120
STARTUP_SECONDS = 60
SHUTDOWN_SECONDS = 60

# name, explicit postmaster argument, PG16 pg_settings.setting representation.
# Memory GUCs use their implicit units, not current_setting's pretty units.
# shared_buffers is an 8-KiB block count; block_size is checked below.
_GUC_PROFILE = (
    ("listen_addresses", "", ""),
    ("unix_socket_directories", SOCKET_ROOT, SOCKET_ROOT),
    ("unix_socket_permissions", "0700", "0700"),
    ("port", "5432", "5432"),
    ("ssl", "off", "off"),
    ("fsync", "on", "on"),
    ("full_page_writes", "on", "on"),
    ("synchronous_commit", "on", "on"),
    ("log_destination", "stderr", "stderr"),
    ("logging_collector", "off", "off"),
    ("max_connections", "32", "32"),
    ("shared_buffers", "64MB", "8192"),
    ("work_mem", "4MB", "4096"),
    ("maintenance_work_mem", "32MB", "32768"),
    ("max_wal_size", "256MB", "256"),
    ("min_wal_size", "80MB", "80"),
    ("temp_file_limit", "128MB", "131072"),
    ("jit", "off", "off"),
    ("restart_after_crash", "off", "off"),
)
_PROBE_SETTINGS = tuple((name, expected) for name, _, expected in _GUC_PROFILE) + (
    ("data_directory", PGDATA),
    ("data_checksums", "on"),
    ("block_size", "8192"),
)


def initdb_argv() -> tuple[str, ...]:
    """Initialize only the caller-proven fresh owned PGDATA, never reuse it."""
    return (
        PG_BINDIR + "/initdb", "--pgdata=" + PGDATA, "--username=" + USER,
        "--encoding=UTF8", "--locale=C", "--locale-provider=libc",
        "--auth-local=trust", "--auth-host=reject", "--data-checksums",
        "--no-instructions", "--no-clean",
    )


def postgres_argv() -> tuple[str, ...]:
    """Foreground postmaster: no pg_ctl, shell, network listener or WAL path."""
    return (PG_BINDIR + "/postgres", "-D", PGDATA) + tuple(
        argument
        for name, value, _ in _GUC_PROFILE
        for argument in ("-c", name + "=" + value)
    )


def environment() -> dict[str, str]:
    """A new closed mapping; never merge ambient PG/LD/Python configuration."""
    return {
        "PATH": PG_BINDIR + ":/usr/local/bin:/usr/bin:/bin",
        "HOME": NATIVE_ROOT,
        "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        "PYTHONPATH": SOURCE_ROOT,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUNBUFFERED": "1",
    }


# Exact eleven-column tuple: version, server/client encodings, database,
# current/session roles, direct superuser flag, Unix peer address (NULL),
# recovery flag, observed cluster system identifier, and closed GUC values.
# The caller owns the connection, query timeout and single-row cardinality.
READINESS_SQL = (
    "SELECT pg_catalog.current_setting('server_version_num')::pg_catalog.int4, "
    "pg_catalog.getdatabaseencoding(), pg_catalog.current_setting('client_encoding'), "
    "pg_catalog.current_database(), current_user::pg_catalog.text, "
    "session_user::pg_catalog.text, role_record.rolsuper, "
    "pg_catalog.inet_server_addr(), pg_catalog.pg_is_in_recovery(), "
    "control.system_identifier::pg_catalog.text, "
    "(SELECT pg_catalog.jsonb_object_agg(setting.name, setting.setting) "
    "FROM pg_catalog.pg_settings AS setting WHERE setting.name = ANY (ARRAY["
    + ",".join("'" + name + "'" for name, _ in _PROBE_SETTINGS)
    + "]::pg_catalog.text[])) "
    "FROM pg_catalog.pg_roles AS role_record "
    "CROSS JOIN pg_catalog.pg_control_system() AS control "
    "WHERE role_record.rolname = current_user"
)


class NativePostgresProfileError(ValueError):
    pass


def _validate_identity(version: object, identifier: object) -> None:
    if type(version) is not int or not 160000 <= version < 170000:
        raise NativePostgresProfileError("native PostgreSQL readiness requires PG16")
    if (type(identifier) is not str or not 1 <= len(identifier) <= 20
            or identifier[0] == "0" or not identifier.isascii()
            or not identifier.isdecimal() or int(identifier) > (1 << 64) - 1):
        raise NativePostgresProfileError("native PostgreSQL system identifier is invalid")


@dataclass(frozen=True, slots=True)
class NativePostgresProbe:
    """Self-consistent observed data, not process identity or readiness authority."""

    server_version_num: int
    system_identifier: str

    def __post_init__(self) -> None:
        _validate_identity(self.server_version_num, self.system_identifier)


def validate_probe_row(row: object) -> NativePostgresProbe:
    """Reject missing, coerced or extra values; return only immutable scalars.

    No inference about a postmaster PID, image digest, socket ownership, HBA
    contents, physical durability or continued server health is made here.
    """
    if type(row) is not tuple or len(row) != 11:
        raise NativePostgresProfileError("native PostgreSQL readiness row is not exact")
    _validate_identity(row[0], row[9])
    expected = ("UTF8", "UTF8", "postgres", USER, USER, True, None, False)
    if any(type(actual) is not type(wanted) or actual != wanted
           for actual, wanted in zip(row[1:9], expected)):
        raise NativePostgresProfileError("native PostgreSQL readiness session differs")
    settings = row[10]
    required = dict(_PROBE_SETTINGS)
    if (type(settings) is not dict or len(settings) != len(required)
            or any(type(name) is not str or type(value) is not str
                   or len(name) > 64 or len(value) > 4096
                   or name not in required or value != required[name]
                   for name, value in settings.items())):
        raise NativePostgresProfileError("native PostgreSQL readiness settings differ")
    return NativePostgresProbe(row[0], row[9])
