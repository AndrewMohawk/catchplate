"""Closed PostgreSQL connection options without application or authority imports."""
from __future__ import annotations

import re


def bounded_connection_options(
    dsn: str, *, error_type: type[Exception]
) -> str:
    """Retain explicitly bounded connection timeouts, never its search path."""
    from psycopg.conninfo import conninfo_to_dict

    def refused() -> None:
        raise error_type("PostgreSQL bootstrap options are invalid") from None

    try:
        options = conninfo_to_dict(dsn).get("options", "")
    except Exception:
        refused()
    if type(options) is not str or len(options) > 4096 or not options.isascii():
        refused()
    # PostgreSQL pg_split_opts uses whitespace and backslash escapes, not
    # shell quote semantics. Decode before rebuilding a closed option roster.
    whitespace = " \t\r\n\f\v"
    tokens, token, index = [], [], 0
    while index < len(options):
        character = options[index]
        if character == "\\":
            index += 1
            if index == len(options):
                refused()
            token.append(options[index])
        elif character in whitespace:
            if token:
                tokens.append("".join(token))
                token = []
        else:
            token.append(character)
        index += 1
    if token:
        tokens.append("".join(token))
    names = (
        "statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout"
    )
    units = {None: 1, "ms": 1, "s": 1000, "min": 60_000,
             "h": 3_600_000, "d": 86_400_000}
    selected: dict[str, int] = {}
    index = 0
    while index < len(tokens):
        argument = tokens[index]
        index += 1
        if argument == "-c":
            if index == len(tokens):
                refused()
            assignment = tokens[index]
            index += 1
        elif argument.startswith("-c"):
            assignment = argument[2:]
        elif argument.startswith("--"):
            assignment = argument[2:]
        else:
            refused()
        name, separator, value = assignment.partition("=")
        if not separator or name not in (*names, "search_path"):
            refused()
        if name == "search_path":
            continue
        duration = re.fullmatch(r"([0-9]+)[ \t\r\n\f\v]*(ms|s|min|h|d)?", value)
        if duration is None:
            refused()
        milliseconds = int(duration[1]) * units[duration[2]]
        if not 1 <= milliseconds <= 2_147_483_647:
            refused()
        selected[name] = milliseconds
    return " ".join(
        [f"-c {name}={selected[name]}ms" for name in names if name in selected]
        + ["-c search_path=pg_catalog"]
    )
