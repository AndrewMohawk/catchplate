"""The original verifier's challenge projection, not the full custody row.

The selected challenge row and CAS retain every physical column. Only the
receipt's challenge commitment uses this fixed original ten-column projection;
later retention bookkeeping is not part of that producer's signed bytes.
"""
from __future__ import annotations

from catchplate.authority_webauthn_bindings import CHALLENGE_FIELDS


def challenge_original_sql(*, historical: bool = False) -> str:
    """Return one of two fixed executor expressions, never caller-supplied SQL.

    Fresh execution uses the exact selected before-image. Historical execution
    has separately required consumption, and reconstructs only its original
    unused value. Neither expression changes or substitutes the full-row CAS.
    """
    if type(historical) is not bool:
        raise ValueError("challenge SQL projection mode is invalid")
    row = "pg_catalog.to_jsonb(prior_challenge)" if historical else (
        "challenge_mutation.value->'expectedRow'"
    )
    fields = []
    for name in CHALLENGE_FIELDS:
        value = "'null'::pg_catalog.jsonb" if historical and name == "used_at" else (
            f"({row})->'{name}'"
        )
        fields.append(f"'{name}', {value}")
    return "pg_catalog.jsonb_build_object(" + ", ".join(fields) + ")"
