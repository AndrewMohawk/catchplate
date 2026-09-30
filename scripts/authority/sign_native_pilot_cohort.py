#!/usr/bin/env python3
"""Sign one independently approved fixed-ten-endpoint cohort original.

Closed input grammar (canonical ASCII JSON, no LF, at most 2 MiB):
  Common exact fields: apiVersion="serverware.nativePilotCohortAuthorityInput/v1",
  operation (matching the CLI), configurationOriginal, configurationSha256,
  coldOriginals, payloadOriginal.
  Release adds exactly precreationOriginal and observationsOriginal.
Every *Original is a literal existing canonical original, not a parsed summary.
coldOriginals has exactly these ten keys: retrieval, persistence, trustedTime,
generationInstall, commitRequest, ingressAdmission, terminalAppend,
dispatchBarrier, activeEffectBarrier, activeEffectCommit. There is no bridge
child. configurationOriginal must select existing cohort configuration/v7.
payloadOriginal is the existing precreation window or release/v6 payload; the
existing producer validates every original and signs its unchanged domain.

An independent operator must approve the entire protected input before passing
its FD and provision the matching existing sealed authority seed. File custody
does not establish approval; no approval, observation, key, window or payload is
generated here. Release observations must be the real retained cohort original;
this data-signing CLI does not authenticate a process owner or act as a pilot
coordinator. Actual receiving owners revalidate processes and resources.

Run on the original admitted host and time namespace: boot identity and BOOTTIME
are read locally, never accepted from caller-selected clock fields. Stdout is
only the signed canonical original, without LF. Failure consumes this invocation;
partial pipe output is not retry authority. An external watchdog is required to
bound blocking filesystem/crypto work; no immediate cancellation is claimed.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

# Fixed locations also support python3 -I -B; no CWD/PYTHONPATH dependency.
_SCRIPT = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT))
sys.path.insert(0, str(_SCRIPT.parent.parent))

import native_pilot_authority_io as io
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as cohort

p = cohort.p
MAX_INPUT_BYTES = 2 * 1024 * 1024
ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall",
         "commitRequest", "ingressAdmission", "terminalAppend", "dispatchBarrier",
         "activeEffectBarrier", "activeEffectCommit")
FIELDS = ("apiVersion", "operation", "configurationOriginal", "configurationSha256",
          "coldOriginals", "payloadOriginal")
ARGUMENTS = ("retrieval_configuration_raw", "persistence_configuration_raw",
             "trusted_time_configuration_raw", "generation_install_configuration_raw",
             "commit_request_configuration_raw", "ingress_admission_configuration_raw",
             "terminal_append_configuration_raw", "dispatch_barrier_configuration_raw",
             "active_effect_barrier_configuration_raw", "active_effect_commit_configuration_raw")


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("native pilot cohort arguments refused")


def _original(value, maximum):
    p.require(type(value) is str and value.isascii())
    raw = value.encode("ascii")
    p.document(raw, maximum)
    return raw


def main():
    try:
        parser = _Parser(description=__doc__, allow_abbrev=False)
        parser.add_argument("--operation", choices=("precreation", "release"), required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        p.require(args.input_fd >= 3 and args.authority_key_fd >= 3
                  and args.input_fd != args.authority_key_fd)
        input_identity = originals._identity(os.fstat(args.input_fd))
        key_identity = originals._identity(os.fstat(args.authority_key_fd))
        raw = io.read_public(args.input_fd, MAX_INPUT_BYTES)
        extra = ("precreationOriginal", "observationsOriginal") if args.operation == "release" else ()
        value = p.fields(p.document(raw, MAX_INPUT_BYTES), FIELDS + extra)
        p.require(value["apiVersion"] == "serverware.nativePilotCohortAuthorityInput/v1"
                  and value["operation"] == args.operation)
        configuration_raw = _original(value["configurationOriginal"], cohort.MAX_BYTES)
        configuration_sha256 = p.digest(value["configurationSha256"])
        config = cohort.configuration(configuration_raw)
        p.require(config["apiVersion"] == "serverware.nativeShadowProofCohortConfiguration/v7"
                  and cohort.roles(config) == ROLES and p.sha(configuration_raw) == configuration_sha256)
        cold = p.fields(value["coldOriginals"], ROLES)
        kwargs = {name: _original(cold[role], cohort.delivery.MAX_DELIVERY)
                  for role, name in zip(ROLES, ARGUMENTS, strict=True)}
        payload_raw = _original(value["payloadOriginal"], cohort.MAX_BYTES)
        if args.operation == "release":
            kwargs["precreation_raw"] = _original(value["precreationOriginal"], cohort.MAX_BYTES)
            kwargs["observations_raw"] = _original(value["observationsOriginal"], cohort.MAX_BYTES)
            precreation = p.fields(p.document(kwargs["precreation_raw"], cohort.MAX_BYTES),
                                  ("apiVersion", "payload", "signatureBase64url"))
            window = precreation["payload"]
            producer = cohort.sign_release
        else:
            window = p.document(payload_raw, cohort.MAX_BYTES)
            producer = cohort.sign_precreation
        boot = originals._boot()
        key = io.signing_key(args.authority_key_fd)

        def check():
            p.require(originals._identity(os.fstat(args.input_fd)) == input_identity
                      and originals._identity(os.fstat(args.authority_key_fd)) == key_identity
                      and io.read_public(args.input_fd, MAX_INPUT_BYTES) == raw
                      and originals._boot() == boot)
            cohort._window(window, config, configuration_sha256, boot, originals._clock())

        check()
        signed = producer(configuration_raw=configuration_raw, configuration_sha256=configuration_sha256,
            bridge_configuration_raw=None, payload_raw=payload_raw, boot=boot,
            now=originals._clock(), signing_key=key, **kwargs)
        check()
        io.write_public(signed, deadline_boottime_ns=p.ns(window["startupDeadlineBoottimeNs"]))
        check()
        return 0
    except Exception:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
