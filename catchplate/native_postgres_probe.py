"""Deadline-bound, fixed local libpq readiness observation for the PG16 runner.

The caller owns the postmaster, socket directory and outer resource limits.
This is neither server authentication nor malicious-server memory isolation:
libpq allocates protocol input before the small returned-field checks below.
No synchronous connect/query, retry, worker thread or subprocess is used.

The nonblocking sequence follows the pinned psycopg 3.2.3 pq API and its
generators.py connect/send/fetch implementation. Only initial connection
failure is retryable by the owning runner; every later failure is terminal.
"""
from __future__ import annotations

import json
import math
import select
import time
from collections.abc import Callable

from .native_postgres_profile import (
    NativePostgresProbe, READINESS_SQL, SOCKET_ROOT, USER, validate_probe_row,
)


MAX_PROBE_SECONDS = 5.0
PUMP_SECONDS = 0.05
MAX_SCALAR_BYTES = 256
MAX_SETTINGS_BYTES = 16384
# Local trust is limited to this freshly initialized, caller-owned Unix socket.
# Explicit transport/credential values complement the runner's rejection of
# every ambient PG variable before creating the cluster.
CONNECTION_INFO = (
    f"host={SOCKET_ROOT} port=5432 dbname=postgres user={USER} "
    "password='' passfile=/dev/null sslmode=disable gssencmode=disable "
    "client_encoding=UTF8 application_name=catchplate-native-probe "
    "options='-c statement_timeout=3000 -c default_transaction_read_only=on'"
).encode("ascii")


class NativePostgresProbeError(RuntimeError):
    pass


class NativePostgresProbeUnavailable(NativePostgresProbeError):
    """Initial local connection failed, before any readiness query was sent."""


def _reject_json_number(value: str) -> object:
    raise NativePostgresProbeError("readiness settings contain a non-string value")


def _settings_object(pairs: list[tuple[str, object]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in pairs:
        if (type(name) is not str or type(value) is not str or name in result
                or "\x00" in name or "\x00" in value):
            raise NativePostgresProbeError("readiness settings are not a unique string mapping")
        result[name] = value
    return result


def _row(result: object, tuples_ok: object) -> tuple:
    if (result.status != tuples_ok or type(result.ntuples) is not int
            or result.ntuples != 1 or type(result.nfields) is not int
            or result.nfields != 11):
        raise NativePostgresProbeError("readiness result is not one exact eleven-column row")
    values: list[str | None] = []
    for index in range(11):
        field_format = result.fformat(index)
        if type(field_format) is not int or field_format != 0:
            raise NativePostgresProbeError("readiness result is not text format")
        raw = result.get_value(0, index)
        if index == 7:
            if raw is not None:
                raise NativePostgresProbeError("readiness did not use a Unix socket")
            values.append(None)
            continue
        cap = MAX_SETTINGS_BYTES if index == 10 else MAX_SCALAR_BYTES
        if type(raw) is not bytes or not 1 <= len(raw) <= cap or b"\x00" in raw:
            raise NativePostgresProbeError("readiness field is missing, malformed or oversized")
        try:
            values.append(raw.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise NativePostgresProbeError("readiness field is not ASCII") from exc
    version = values[0]
    if (not version.isdecimal() or version[0] == "0" or len(version) != 6
            or values[6] not in ("t", "f") or values[8] not in ("t", "f")):
        raise NativePostgresProbeError("readiness scalar spelling differs")
    try:
        settings = json.loads(
            values[10], object_pairs_hook=_settings_object,
            parse_int=_reject_json_number, parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise NativePostgresProbeError("readiness settings JSON is malformed") from exc
    return (int(version), *values[1:6], values[6] == "t", None,
            values[8] == "t", values[9], settings)


def probe(*, pump: Callable[[float], None], check_alive: Callable[[], None],
          deadline: float) -> NativePostgresProbe:
    """Observe the fixed local instance, within at most five monotonic seconds.

    Pump/check callbacks are the owning supervisor's actual log and liveness
    checks, not verification tokens. Their failures propagate, never becoming
    retryable connection errors. ``finish`` runs on every acquired connection.
    """
    now = time.monotonic()
    if (not callable(pump) or not callable(check_alive)
            or type(deadline) not in (int, float)
            or not now < deadline <= now + MAX_PROBE_SECONDS
            or not math.isfinite(deadline)):
        raise NativePostgresProbeError("readiness deadline or callbacks are invalid")

    def tick() -> None:
        pump(0.0)
        check_alive()
        if time.monotonic() >= deadline:
            raise NativePostgresProbeError("readiness deadline exceeded")

    def ready(socket: int, *, read: bool, write: bool) -> tuple[bool, bool]:
        if type(socket) is not int or socket < 0:
            raise NativePostgresProbeError("readiness socket is invalid")
        while True:
            tick()
            readable, writable, exceptional = select.select(
                [socket] if read else [], [socket] if write else [], [socket], 0.0,
            )
            if exceptional:
                raise NativePostgresProbeError("readiness socket has an exceptional condition")
            if readable or writable:
                tick()
                return bool(readable), bool(writable)
            pump(min(PUMP_SECONDS, max(0.0, deadline - time.monotonic())))

    tick()
    # Lazy loading leaves the component importable without a prepared libpq.
    from psycopg import OperationalError, pq

    def connecting(action: Callable[[], object]) -> object:
        try:
            return action()
        except OperationalError as exc:
            raise NativePostgresProbeUnavailable("local readiness connection unavailable") from exc

    connection = connecting(lambda: pq.PGconn.connect_start(CONNECTION_INFO))
    try:
        while True:
            tick()
            if connecting(lambda: connection.status) == pq.ConnStatus.BAD:
                raise NativePostgresProbeUnavailable("local readiness connection unavailable")
            status = connecting(connection.connect_poll)
            if status == pq.PollingStatus.OK:
                break
            if status == pq.PollingStatus.FAILED:
                raise NativePostgresProbeUnavailable("local readiness connection unavailable")
            if status not in (pq.PollingStatus.READING, pq.PollingStatus.WRITING):
                raise NativePostgresProbeError("readiness connection poll status is invalid")
            socket = connecting(lambda: connection.socket)
            ready(socket, read=status == pq.PollingStatus.READING,
                  write=status == pq.PollingStatus.WRITING)

        tick()
        connection.nonblocking = 1
        if connection.nonblocking != 1 or connection.status != pq.ConnStatus.OK:
            raise NativePostgresProbeError("readiness connection is not nonblocking and healthy")
        connection.send_query(READINESS_SQL.encode("ascii"))
        while True:
            tick()
            pending = connection.flush()
            if type(pending) is not int or pending not in (0, 1):
                raise NativePostgresProbeError("readiness flush status is invalid")
            if pending == 0:
                break
            readable, _ = ready(connection.socket, read=True, write=True)
            if readable:
                tick()
                connection.consume_input()

        observed: NativePostgresProbe | None = None
        while True:
            tick()
            busy = connection.is_busy()
            if type(busy) is not int or busy not in (0, 1):
                raise NativePostgresProbeError("readiness busy status is invalid")
            if busy:
                ready(connection.socket, read=True, write=False)
                tick()
                connection.consume_input()
                continue
            result = connection.get_result()
            if result is None:
                if observed is None:
                    raise NativePostgresProbeError("readiness result is missing")
                tick()
                if connection.status != pq.ConnStatus.OK:
                    raise NativePostgresProbeError("readiness connection was lost")
                return observed
            if observed is not None:
                raise NativePostgresProbeError("readiness returned extra results")
            observed = validate_probe_row(_row(result, pq.ExecStatus.TUPLES_OK))
    finally:
        connection.finish()
