"""Fixed isolated pre-commissioning commands in the approved supervisor package.

Prepare one static closure set or cold binding, or issue one independently
approved assignment, cold parent, initial history or ordinary service original.
Cold key-delivery and verifier issuers use their own authenticated cold inputs;
keyless launch assembly emits a public bundle, never installs or launches it.
There is no child launch, publisher, provisioning, retry or default key. The
complete input and installed runtime have separate externally supplied pins.
Only these fixed commands exist; no caller-selected Python module is executed.
"""
from __future__ import annotations

import os
import re
import sys
import time

SCRIPT = "/supervisor/app/scripts/native_pilot_publication_runtime_entrypoint.py"
PYTHON = "/runtime/python/bin/python3"
IMPORT_ROOTS = ("/supervisor/app", "/authority/app", "/vendor", "/app")
INITIAL_MODES = {
    "--sign-genesis-ordinary-checkpoint": "checkpoint",
    "--sign-genesis-ordinary-root-anchor": "root-anchor",
    "--sign-genesis-ordinary-checkpoint-anchor": "checkpoint-anchor",
    "--sign-genesis-ordinary-service-anchor": "service-anchor",
    "--assemble-genesis-ordinary-history": "assemble",
}
ORDINARY_MODES = {"--sign-genesis-ordinary-delivery": "delivery", "--sign-genesis-ordinary-grant": "grant"}
NATIVE_MODES = {"--sign-genesis-native-" + label + "-" + operation: (role, operation)
    for label, role in (("retrieval", "publicationGenesisRetrieval"), ("publication", "publicationGenesis"),
        ("coordinator", "publicationGenesisCoordinator")) for operation in ("delivery", "role-keys", "admission", "closure")}
TRANSPORT_MODES = {"--sign-genesis-native-" + label + "-" + operation: (role, operation)
    for label, role in (("retrieval", "publicationGenesisRetrieval"), ("publication", "publicationGenesis"),
        ("coordinator", "publicationGenesisCoordinator")) for operation in ("encrypted-delivery", "verifier")}
LAUNCH_MODES = {"--assemble-genesis-native-" + label + "-launch": role
    for label, role in (("retrieval", "publicationGenesisRetrieval"), ("publication", "publicationGenesis"),
        ("coordinator", "publicationGenesisCoordinator"))}
SERVICE_MODES = {"--sign-genesis-native-publication-grant": "publication",
    "--sign-genesis-native-retrieval-grant": "retrieval"}
SIGNING_MODES = ("--sign-assignment", "--sign-genesis-precreation", "--sign-genesis-release", "--sign-genesis-endpoints-release") + tuple(ORDINARY_MODES) + tuple(
    mode for mode, operation in INITIAL_MODES.items() if operation != "assemble") + tuple(NATIVE_MODES) + tuple(SERVICE_MODES) + tuple(TRANSPORT_MODES)
MODES = ("--prepare-closure-set", "--prepare-genesis-binding", "--assemble-genesis-ordinary-history") + SIGNING_MODES + tuple(LAUNCH_MODES)


def valid_arguments(arguments):
    """Syntax only. All data, runtime and signing authority is admitted below."""
    if (type(arguments) is not list or not all(type(value) is str for value in arguments)
            or len(arguments) not in (9, 11) or arguments[0] not in MODES
            or len(arguments) != (11 if arguments[0] in SIGNING_MODES else 9)):
        return False
    descriptors = set()
    for offset, name in ((1, "supervisor-inventory"), (5, "input")):
        flag, number, pin_flag, pin = arguments[offset:offset + 4]
        if (flag != "--" + name + "-fd" or not _fd(number)
                or pin_flag != "--" + name + "-sha256"
                or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None
                or int(number) in descriptors):
            return False
        descriptors.add(int(number))
    return (len(arguments) == 9 or (arguments[9] == "--authority-key-fd"
        and _fd(arguments[10]) and int(arguments[10]) not in descriptors))


def _fd(value):
    return (re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None and 3 <= int(value) < (1 << 31))


def genesis_operation(mode):
    """Source-fixed signing purpose, never selected by the input payload."""
    return {"--sign-genesis-precreation": "precreation",
            "--sign-genesis-release": "release"}.get(mode)


def main():
    if not (
        sys.argv[0] == SCRIPT and __file__ == SCRIPT and os.path.realpath(__file__) == SCRIPT
        and sys.executable == PYTHON and os.path.realpath(sys.executable) == PYTHON
        and sys.prefix == sys.base_prefix == "/runtime/python" and sys.version_info[:2] == (3, 11)
        and sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
        and sys.flags.no_user_site == 1 and sys.flags.safe_path and sys.flags.dont_write_bytecode == 1
        and valid_arguments(sys.argv[1:])
    ):
        raise SystemExit("native publication commissioning invocation refused")
    sys.path[:0] = list(IMPORT_ROOTS)
    from scripts.run_native_pilot_supervisor import _SelfRuntime
    from scripts.authority import native_pilot_authority_io as io
    from scripts.authority import prepare_native_pilot_closure_set as preparation
    from serverware import native_pilot_assignment as assignment
    from serverware import native_pilot_genesis_parent_authority as genesis
    from serverware import native_pilot_genesis_ordinary_initial_authority as initial
    from serverware import native_pilot_genesis_ordinary_authority as ordinary
    from serverware import native_pilot_genesis_delivery_authority as delivery
    from serverware import native_pilot_genesis_key_authority as keys
    from serverware import native_pilot_genesis_closure_authority as closure
    from serverware import native_pilot_genesis_native_service_authority as service
    from serverware import native_pilot_genesis_endpoint_release_authority as endpoint_release
    from serverware import native_pilot_genesis_encrypted_authority as encrypted
    from serverware import native_pilot_genesis_verifier_authority as verifier
    from serverware import native_pilot_genesis_launch_profile as launch
    from serverware import native_pilot_publication_cold_binding as cold_binding
    from serverware import native_shadow_nitro_originals as originals

    runtime = None
    try:
        arguments = sys.argv[1:]
        p = assignment.p
        io._process()
        runtime = _SelfRuntime()
        runtime.admit(int(arguments[2]), arguments[4])
        mode = arguments[0]
        signing = mode in SIGNING_MODES
        purpose = genesis_operation(mode)
        initial_purpose = INITIAL_MODES.get(mode)
        ordinary_purpose = ORDINARY_MODES.get(mode)
        native_purpose, service_purpose = NATIVE_MODES.get(mode), SERVICE_MODES.get(mode)
        transport_purpose, launch_role = TRANSPORT_MODES.get(mode), LAUNCH_MODES.get(mode)
        transport = (encrypted if transport_purpose[1] == "encrypted-delivery" else verifier) if transport_purpose else None
        maximum = (transport.MAX_INPUT if transport is not None else launch.MAX_INPUT if launch_role is not None else
            endpoint_release.MAX_INPUT if mode == "--sign-genesis-endpoints-release" else
            delivery.MAX_INPUT if native_purpose is not None else
            service.MAX_INPUT if service_purpose is not None else ordinary.MAX_INPUT if ordinary_purpose is not None else
            initial.MAX_INPUT if initial_purpose is not None else
            genesis.MAX_INPUT if purpose is not None else cold_binding.MAX_INPUT
            if mode == "--prepare-genesis-binding" else assignment.MAX_INPUT
            if signing else preparation.closure_set.MAX_BYTES)
        input_fd = int(arguments[6])
        identity = io._input(input_fd, maximum)
        raw = io.read_public(input_fd, maximum)
        p.require(p.sha(raw) == arguments[8])
        owner = os.getpid(), originals._start(), originals._boot()
        before_boot, before_wall = originals._clock(), time.time_ns()
        key_fd = int(arguments[10]) if signing else None
        key_identity = None
        payload = deadline = epoch_limit = None
        previous_boot, previous_wall = before_boot, before_wall

        def check():
            nonlocal previous_boot, previous_wall
            runtime.check(installed=True)
            current_boot, current_wall = originals._clock(), time.time_ns()
            p.require(identity == io._input(input_fd, maximum)
                and io.read_public(input_fd, maximum) == raw
                and owner == (os.getpid(), originals._start(), originals._boot())
                and previous_boot <= current_boot and previous_wall <= current_wall)
            if key_identity is not None:
                p.require(io._input(key_fd, 32, private=True) == key_identity)
            # Reads and retained-package/input inspections consume the same
            # interval. Final success cannot use a clock sampled before them.
            after_boot, after_wall = originals._clock(), time.time_ns()
            p.require(current_boot <= after_boot and current_wall <= after_wall)
            previous_boot, previous_wall = after_boot, after_wall
            if deadline is not None:
                p.require(after_boot < deadline)
            if epoch_limit is not None:
                p.require(after_wall < epoch_limit)
            if payload is not None:
                p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], after_wall)

        if transport_purpose is not None:
            role, _ = transport_purpose
            approved = transport.prepare_input(role, raw, boot=originals._boot(),
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            deadline, epoch_limit = approved["deadline"], approved["epochLimit"]
            key_identity = io._input(key_fd, 32, private=True)
            check()  # Complete cold purpose/role admission precedes key bytes.
            result, result_deadline = transport.sign(role, input_original=raw, signing_key=io.signing_key(key_fd))
            p.require(result_deadline == deadline)
        elif launch_role is not None:
            approved = launch.prepare_input(launch_role, raw, boot=originals._boot(),
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            deadline, epoch_limit = approved["deadline"], approved["epochLimit"]
            check()
            result, result_deadline = launch.assemble(launch_role, input_original=raw)
            p.require(result_deadline == deadline and result == approved["bundleOriginal"])
        elif mode == "--sign-genesis-endpoints-release":
            approved = endpoint_release.prepare_input(raw, boot=originals._boot(),
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            deadline, epoch_limit = approved["deadline"], approved["epochLimit"]
            key_identity = io._input(key_fd, 32, private=True)
            check()
            result, result_deadline = endpoint_release.sign(input_original=raw, signing_key=io.signing_key(key_fd))
            p.require(result_deadline == deadline)
        elif native_purpose is not None:
            role, operation = native_purpose
            clocks = dict(boot=originals._boot(), now_boottime_ns=originals._clock())
            if operation == "delivery":
                approved = delivery.prepare_input(role, raw, **clocks)
            elif operation == "closure":
                approved = closure.prepare_input(role, raw, **clocks, now_unix_ns=time.time_ns())
            else:
                approved = keys.prepare_input(operation, role, raw, **clocks, now_unix_ns=time.time_ns())
            deadline, epoch_limit = approved["deadline"], approved.get("epochLimit")
            key_identity = io._input(key_fd, 32, private=True)
            check()  # Fixed role and purpose precede private-key access.
            selected_key = io.signing_key(key_fd)
            if operation == "delivery":
                result, result_deadline = delivery.sign(role, input_original=raw, signing_key=selected_key)
            elif operation == "closure":
                result, result_deadline = closure.sign(role, input_original=raw, signing_key=selected_key)
            else:
                result, result_deadline = keys.sign(operation, role, input_original=raw, signing_key=selected_key)
            p.require(result_deadline == deadline)
        elif service_purpose is not None:
            approved = service.prepare_input(service_purpose, raw, boot=originals._boot(),
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            deadline, epoch_limit = approved["deadline"], approved["epochLimit"]
            key_identity = io._input(key_fd, 32, private=True)
            check()
            result = service.sign(service_purpose, input_original=raw, signing_key=io.signing_key(key_fd))
        elif ordinary_purpose is not None:
            approved = ordinary.prepare_input(ordinary_purpose, raw, boot=originals._boot(),
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            deadline, epoch_limit = approved["deadline"], approved["epochLimit"]
            key_identity = io._input(key_fd, 32, private=True)
            check()
            result = ordinary.sign(ordinary_purpose, input_original=raw,
                signing_key=io.signing_key(key_fd))
        elif initial_purpose is not None:
            approved = initial.prepare_input(initial_purpose, raw,
                boot=originals._boot(), now_boottime_ns=originals._clock())
            deadline = approved["deadline"]
            if initial_purpose == "assemble":
                check()
                result, result_deadline = initial.assemble(input_original=raw)
            else:
                key_identity = io._input(key_fd, 32, private=True)
                check()  # Exact checkpoint/anchor purpose precedes key access.
                result, result_deadline = initial.sign(initial_purpose,
                    input_original=raw, signing_key=io.signing_key(key_fd))
            p.require(result_deadline == deadline)
        elif purpose is not None:
            value = genesis.input_document(raw)
            p.require(value["operation"] == purpose)
            approved = genesis.prepare_input(raw, boot=originals._boot(),
                now_boottime_ns=originals._clock())
            deadline = approved["deadline"]
            key_identity = io._input(key_fd, 32, private=True)
            check()  # Exact selected purpose is admitted before reading the key.
            result, result_deadline = genesis.sign(input_original=raw,
                signing_key=io.signing_key(key_fd))
            p.require(result_deadline == deadline)
        elif mode == "--sign-assignment":
            approved = assignment.prepare_input(raw, now_unix_ns=time.time_ns())
            epoch_limit = approved["epochLimit"]
            key_identity = io._input(key_fd, 32, private=True)
            check()  # Complete trust/closure/window admission precedes key bytes.
            result = assignment.sign(input_original=raw, signing_key=io.signing_key(key_fd))
            payload = p.document(result, assignment.MAX_BYTES)["payload"]
            # Sample boot first: a scheduling pause cannot extend the UNIX
            # expiry when it is converted to the monotonic output ceiling.
            now_boot, now_wall = originals._clock(), time.time_ns()
            p.require(previous_boot <= now_boot and previous_wall <= now_wall)
            previous_boot, previous_wall = now_boot, now_wall
            p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now_wall)
            deadline = now_boot + min(payload["expiresAtUnixNanos"], epoch_limit) - now_wall
            # Runtime reinspection consumes the original grant budget, not a
            # freshly opened signing window. write_public separately applies
            # its one-second pipe-write ceiling inside this original expiry.
        elif mode == "--prepare-genesis-binding":
            result = cold_binding.prepare(input_original=raw, expected_input_sha256=arguments[8],
                boot=originals._boot(), now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            payload = cold_binding.result_document(result)
            deadline = p.ns(payload["deadlineBoottimeNs"])
        else:
            p.require(mode == "--prepare-closure-set")
            result = preparation.prepare(raw, arguments[8])
        check()
        io.write_public(result, deadline_boottime_ns=deadline)
        check()
        runtime.close()
        final_boot, final_wall = originals._clock(), time.time_ns()
        p.require(previous_boot <= final_boot and previous_wall <= final_wall)
        if deadline is not None:
            p.require(final_boot < deadline)
        if epoch_limit is not None:
            p.require(final_wall < epoch_limit)
        if payload is not None:
            p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], final_wall)
        return 0
    except BaseException:
        if runtime is not None:
            try:
                runtime.close()
            except BaseException:
                pass
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
