"""Closed ordinary X account operations; inputs confer no lifecycle authority."""
from __future__ import annotations

from pydantic import ConfigDict, Field, field_validator

from catchplate.operator_catalog_inputs import NamedInput, RevisionInput, _identifier


class StartInput(NamedInput):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    operation_id: str = Field(min_length=36, max_length=36)
    _canonical_id = field_validator("operation_id")(_identifier)


class DisconnectInput(RevisionInput):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    operation_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=36, max_length=36)
    expected_credential_generation: int = Field(ge=1, lt=9_007_199_254_740_991)
    review_digest: str = Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")
    _canonical_ids = field_validator("operation_id", "credential_id")(_identifier)
