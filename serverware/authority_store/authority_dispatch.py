from __future__ import annotations

import base64
import inspect
import os
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from serverware import authority_contract
from serverware import authority_release_private_input
from serverware import authority_transition_registry

_DB_GLOBALS: Mapping[str, Any] | None = None
_POLICY_AUTHORITY_CONTROLLED_WRITER_HANDLERS: dict[
    str, tuple[str, Any, inspect.Signature]
] = {}
_AUTHORITY_INTERNAL_ARGUMENTS = frozenset(
    {"authority_verifier_response"}
)


def bind_db_globals(namespace: Mapping[str, Any]) -> None:
    global _DB_GLOBALS
    _DB_GLOBALS = namespace
    for contract_id, producer in (
        authority_contract.OFFLINE_MIGRATION_RECEIPT_PRODUCERS.items()
    ):
        handler_name = str(producer["handler"])
        handler = namespace.get(handler_name)
        if (
            not callable(handler)
            or tuple(inspect.signature(handler).parameters)
                != tuple(producer["arguments"])
        ):
            raise RuntimeError(
                "offline migration receipt producer is not exact for "
                f"{contract_id}"
            )


def _db_value(name: str) -> Any:
    if _DB_GLOBALS is None:
        raise RuntimeError("database facade globals are not bound")
    return _DB_GLOBALS[name]


def _authority_marshal_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise _db_value("MetadataStoreError")(
                "authority writer arguments contain a non-finite number"
            )
        return value
    if isinstance(value, bytes):
        return {
            "$authorityType": "bytes",
            "base64Url": base64.urlsafe_b64encode(value).decode(
                "ascii"
            ).rstrip("="),
        }
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise _db_value("MetadataStoreError")(
                "authority writer datetime argument is not timezone aware"
            )
        return {
            "$authorityType": "datetime",
            "iso8601": value.astimezone(timezone.utc).isoformat(),
        }
    if isinstance(value, tuple):
        return {
            "$authorityType": "tuple",
            "items": [_authority_marshal_value(item) for item in value],
        }
    if isinstance(value, (set, frozenset)):
        items = [_authority_marshal_value(item) for item in value]
        items.sort(key=_db_value("dumps"))
        return {"$authorityType": "set", "items": items}
    if isinstance(value, list):
        return [_authority_marshal_value(item) for item in value]
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise _db_value("MetadataStoreError")(
                "authority writer argument object keys must be strings"
            )
        return {
            key: _authority_marshal_value(item)
            for key, item in sorted(value.items())
        }
    raise _db_value("MetadataStoreError")(
        "authority writer arguments contain an unsupported value"
    )


def _authority_unmarshal_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_authority_unmarshal_value(item) for item in value]
    if not isinstance(value, dict):
        return value
    value_type = value.get("$authorityType")
    if value_type is None:
        return {
            key: _authority_unmarshal_value(item)
            for key, item in value.items()
        }
    if value_type == "bytes" and set(value) == {
        "$authorityType",
        "base64Url",
    }:
        return _db_value("_candidate_authority_b64url_bounded")(
            "authority writer byte argument",
            value["base64Url"],
            maximum_bytes=4 * 1024 * 1024,
        )
    if value_type == "datetime" and set(value) == {
        "$authorityType",
        "iso8601",
    }:
        parsed = datetime.fromisoformat(str(value["iso8601"]))
        if parsed.tzinfo is None:
            raise _db_value("MetadataStoreError")(
                "authority writer datetime argument is not timezone aware"
            )
        return parsed
    if value_type in {"tuple", "set"} and set(value) == {
        "$authorityType",
        "items",
    } and isinstance(value["items"], list):
        items = [
            _authority_unmarshal_value(item)
            for item in value["items"]
        ]
        return tuple(items) if value_type == "tuple" else set(items)
    raise _db_value("MetadataStoreError")(
        "authority writer typed argument is invalid"
    )


def _authority_prepare_challenge_arguments(
    operation: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    if "businessIntent" in arguments:
        raise _db_value("MetadataStoreError")(
            "caller-supplied authority businessIntent is forbidden"
        )
    spec = authority_contract.operation_spec(operation)
    if str(spec["handler"]).startswith(
        "serverware_policy_authority_"
    ):
        prepared = _authority_marshal_value(dict(arguments))
        if not isinstance(prepared, dict):
            raise _db_value("MetadataStoreError")(
                "policy-authority challenge input is invalid"
            )
        try:
            authority_contract.synthesize_business_intent(
                operation,
                prepared,
            )
        except ValueError as exc:
            raise _db_value("MetadataStoreError")(
                "policy-authority challenge input is not canonical"
            ) from exc
        return prepared
    try:
        _handler_name, _handler, signature = (
            _POLICY_AUTHORITY_CONTROLLED_WRITER_HANDLERS[operation]
        )
        bound = signature.bind(**dict(arguments))
    except (KeyError, TypeError) as exc:
        raise _db_value("MetadataStoreError")(
            "authority challenge arguments do not match the operation"
        ) from exc
    if any(
        name.startswith("_") or name in _AUTHORITY_INTERNAL_ARGUMENTS
        for name in bound.arguments
    ):
        raise _db_value("MetadataStoreError")(
            "authority challenge contains an internal argument"
        )
    bound.apply_defaults()
    for name in tuple(bound.arguments):
        if name.startswith("_") or name in _AUTHORITY_INTERNAL_ARGUMENTS:
            bound.arguments.pop(name)
    prepared = _authority_marshal_value(dict(bound.arguments))
    if not isinstance(prepared, dict):
        raise _db_value("MetadataStoreError")(
            "authority challenge arguments are invalid"
        )
    try:
        authority_contract.synthesize_business_intent(
            operation,
            prepared,
        )
    except ValueError as exc:
        raise _db_value("MetadataStoreError")(
            "authority challenge arguments are not canonical"
        ) from exc
    return prepared


def execute_authority_controlled_writer(
    *,
    operation: str,
    arguments: Mapping[str, Any],
    capability_id: str,
    request_digest: str,
    deadline_monotonic_ns: int,
    fence: int,
    connection: Any,
) -> dict[str, Any]:
    if (
        os.environ.get("SERVERWARE_PROCESS_MODE", "").strip()
        != _db_value("_POLICY_AUTHORITY_EXECUTOR_PROCESS_MODE")
        or operation not in authority_contract.OPERATIONS
        or operation
            not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
        or not isinstance(arguments, Mapping)
        or not isinstance(deadline_monotonic_ns, int)
        or time.monotonic_ns() >= deadline_monotonic_ns
        or not isinstance(fence, int)
        or fence < 1
    ):
        raise _db_value("MetadataStoreError")(
            "controlled authority writer execution context is invalid"
        )
    if arguments.get("schema") == (
        "serverware.policyAuthorityControlledWriterV9Dispatch/v1"
    ):
        required = {
            "schema",
            "envelopeId",
            "plannerTransactionId",
            "exactRequestBase64url",
            "exactResultBase64url",
        }
        if set(arguments) != required:
            raise _db_value("MetadataStoreError")(
                "v9 controlled writer dispatch is not closed"
            )
        exact_request_bytes = _db_value(
            "_candidate_authority_b64url_bounded"
        )(
            "v9 authority exact request",
            arguments["exactRequestBase64url"],
            maximum_bytes=authority_contract.MAX_REQUEST_BYTES,
        )
        exact_result_bytes = _db_value(
            "_candidate_authority_b64url_bounded"
        )(
            "v9 authority exact result",
            arguments["exactResultBase64url"],
            maximum_bytes=authority_contract.MAX_RESULT_BYTES,
        )
        receipt_json = _db_value("execute_authority_v9")(
            capability_id=capability_id,
            envelope_id=str(arguments["envelopeId"]),
            planner_transaction_id=str(
                arguments["plannerTransactionId"]
            ),
            exact_request_bytes=exact_request_bytes,
            exact_result_bytes=exact_result_bytes,
            deadline_monotonic_ns=deadline_monotonic_ns,
            connection=connection,
        )
        receipt = _db_value("loads")(receipt_json, None)
        if (
            not isinstance(receipt, dict)
            or receipt.get("operation") != operation
            or receipt.get("requestDigest") != request_digest
            or int(receipt.get("fence", 0)) != fence
        ):
            raise _db_value("MetadataStoreError")(
                "v9 controlled writer receipt changed at dispatch"
            )
        return {
            "result": _authority_unmarshal_value(
                _db_value("loads")(
                    exact_result_bytes.decode("ascii"), None
                )
            ),
            "resultDigest": receipt.get("resultDigest"),
            "commitReceipt": receipt,
        }
    raise _db_value("MetadataStoreError")(
        "legacy controlled-writer dispatch is disabled"
    )


def _install_authority_controlled_writer_boundaries() -> None:
    if _DB_GLOBALS is None:
        raise RuntimeError("database facade globals are not bound")
    missing_handlers = tuple(
        sorted(
            handler_name
            for handler_name in authority_contract.HANDLER_TO_OPERATION
            if not callable(_DB_GLOBALS.get(handler_name))
        )
    )
    if missing_handlers:
        raise RuntimeError(
            "authority controlled-writer handlers are incomplete: "
            + ", ".join(missing_handlers)
        )
    for handler_name, operation in (
        authority_contract.HANDLER_TO_OPERATION.items()
    ):
        handler = _DB_GLOBALS.get(handler_name)
        if handler is None or not callable(handler):
            raise RuntimeError(
                "authority controlled-writer handler changed during install"
            )
        signature = inspect.signature(handler)
        _POLICY_AUTHORITY_CONTROLLED_WRITER_HANDLERS[operation] = (
            handler_name,
            handler,
            signature,
        )

        @wraps(handler)
        def controlled_writer(
            *args: Any,
            __operation: str = operation,
            __handler_name: str = handler_name,
            __handler: Any = handler,
            __signature: inspect.Signature = signature,
            **kwargs: Any,
        ) -> Any:
            if (__operation == "credential-nonce.reserve"
                    and __handler_name == "reserve_credential_lease_nonce"):
                from serverware.development_sandbox import active as sandbox_active
                if sandbox_active():
                    # The dedicated synthetic runner selects its separate
                    # nonce store; no other controlled writer is admitted.
                    return __handler(*args, **kwargs)
                from serverware.operator_demo import active as operator_demo_active
                if operator_demo_active():
                    # Only the explicit local demo nonce store, not native authorship.
                    return __handler(*args, **kwargs)
            if (
                __operation
                not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
            ):
                raise _db_value("MetadataStoreError")(
                    "authority writer operation has no exact typed "
                    "transition program"
                )
            if _db_value("_policy_authority_writer_context").get() is not None:
                return __handler(*args, **kwargs)
            if kwargs.get("_connection") is not None:
                raise _db_value("MetadataStoreError")(
                    "authority writer connection injection is forbidden"
                )
            try:
                bound = __signature.bind(*args, **kwargs)
            except TypeError as exc:
                raise _db_value("MetadataStoreError")(
                    f"{__handler_name} arguments are invalid"
                ) from exc
            if any(
                name.startswith("_")
                or name in _AUTHORITY_INTERNAL_ARGUMENTS
                for name in bound.arguments
            ):
                raise _db_value("MetadataStoreError")(
                    "authority writer internal argument injection is "
                    "forbidden"
                )
            bound.apply_defaults()
            for name in tuple(bound.arguments):
                if (
                    name.startswith("_")
                    or name in _AUTHORITY_INTERNAL_ARGUMENTS
                ):
                    bound.arguments.pop(name)
            if "businessIntent" in bound.arguments:
                raise _db_value("MetadataStoreError")(
                    "caller-supplied authority businessIntent is forbidden"
                )
            marshaled_arguments = _authority_marshal_value(
                dict(bound.arguments)
            )
            if (
                not isinstance(marshaled_arguments, dict)
                or "businessIntent" in marshaled_arguments
            ):
                raise _db_value("MetadataStoreError")(
                    "authority writer arguments are not closed"
                )
            try:
                authority_release_private_input.require_public_arguments(
                    __operation, marshaled_arguments
                )
            except authority_release_private_input.PrivateReleaseInputError:
                raise _db_value("MetadataStoreError")(
                    authority_release_private_input.ERROR
                ) from None
            if __operation == "jit.request":
                from serverware import authority_jit_private_request
                from serverware.authority_transition_core import (
                    TransitionKernelError,
                )

                try:
                    runtime_input = authority_jit_private_request.prepare(
                        marshaled_arguments
                    )
                except TransitionKernelError:
                    raise _db_value("MetadataStoreError")(
                        "authority writer arguments are not canonical"
                    ) from None
                return _db_value("dispatch_policy_authority_operation")(
                    __operation,
                    runtime_input,
                )
            try:
                authority_contract.synthesize_business_intent(
                    __operation,
                    marshaled_arguments,
                )
            except ValueError as exc:
                raise _db_value("MetadataStoreError")(
                    "authority writer arguments are not canonical"
                ) from exc
            return _db_value("dispatch_policy_authority_operation")(
                __operation,
                {
                    "schema":
                        "serverware.policyAuthorityControlledWriterInput/v1",
                    "handler": __handler_name,
                    "operationManifestDigest":
                        authority_contract.OPERATION_MANIFEST_DIGEST,
                    "arguments": marshaled_arguments,
                },
            )

        _DB_GLOBALS[handler_name] = controlled_writer


for _compatibility_export in (
    _authority_marshal_value,
    _authority_unmarshal_value,
    _authority_prepare_challenge_arguments,
    execute_authority_controlled_writer,
    _install_authority_controlled_writer_boundaries,
):
    _compatibility_export.__module__ = "serverware.db"
del _compatibility_export
