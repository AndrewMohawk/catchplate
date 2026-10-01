"""Authenticate the exact predecessors of three fixed public installations.

Returns bytes and fixed destinations only. It opens nothing, owns no process,
and cannot turn a plan into an installation result. The real exclusive writer
retains partial creations and all original clock ceilings separately.
"""
from __future__ import annotations

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_jobs as jobs

p = g.p
PARENT_PATH = "/etc/serverware/native-publication-genesis-precreation.json"
SUFFIXES = ("runtime", "initial-history", "peer-inspection", "delivery", "guest")


def _prefix(prior, name):
    index = jobs.JOBS.index(jobs.job(name))
    return {selected.name: prior[selected.name] for selected in jobs.JOBS[:index]}


def _prepared(prior, name, observations, clocks):
    raw = jobs._record(prior, name, "input")
    prepared = jobs.prepare_input(name, raw, prior=_prefix(prior, name), observations=observations, **clocks)
    return raw, jobs._record(prior, name), prepared


def _result(raw):
    return {"original": raw.decode("ascii"), "sha256": p.sha(raw)}


def _file(path, raw, uid=0, gid=0):
    p.require(type(raw) is bytes and 0 < len(raw) <= g.MAX_BYTES)
    return dict(path=path, uid=uid, gid=gid, mode=0o400, raw=raw, sha256=p.sha(raw))


def publication_plan(name, *, prior, observations, boot, now_boottime_ns, now_unix_ns):
    selected = jobs.job(name)
    p.require(name == "install-precreation" or name in {"install-ordinary-" + role for role in jobs.ORDINARY})
    p.require(set(prior) == {item.name for item in jobs.JOBS[:jobs.JOBS.index(selected)]})
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    mono = dict(boot=boot, now_boottime_ns=now_boottime_ns)
    # These exact signed/current authorities remain the independent cold
    # commitment, not a hot configuration or an inferred installation grant.
    binding_input, binding_result, binding_context = _prepared(prior, "cold-binding", observations, clocks)
    p.require(binding_context["nativeContext"]["outputOriginal"] == binding_result)
    assignment_input = jobs._record(prior, "assignment", "input")
    assignment_context = jobs.assignment.prepare_input(assignment_input, now_unix_ns=now_unix_ns)
    deadlines = [binding_context["deadline"]]
    epochs = [binding_context["epochLimit"], assignment_context["epochLimit"]]
    if name == "install-precreation":
        input_raw, result, prepared = _prepared(prior, "parent-precreation", observations, clocks)
        jobs.parent.checked_result(input_raw, _result(result), **mono)
        deadlines.append(prepared["deadline"])
        files, pin = (_file(PARENT_PATH, result),), None
    else:
        role = selected.role
        p.require(role in jobs.ORDINARY)
        source_name = "ordinary-delivery-" + role
        input_raw, signed, prepared = _prepared(prior, source_name, observations, clocks)
        jobs.ordinary.checked_result("delivery", input_raw, _result(signed), **clocks)
        value = jobs.ordinary.input_document(input_raw)
        runtime_raw = jobs._record(prior, "ordinary-runtime-" + role)
        p.require(jobs._runtime(value, **mono) == runtime_raw)
        history_raw = jobs._record(prior, "initial-assemble-" + role)
        source = jobs.runtime.source_arguments(value["source"], role)
        held = jobs.ordinary.verify_delivery(signed_raw=signed, configuration_raw=source["configuration_raw"],
            runtime_raw=runtime_raw, history_raw=history_raw, activation=value["activation"], **mono)
        payload = held["guest"]
        envelope_payload = g.document(signed, jobs.ordinary.MAX_DELIVERY)["payload"]
        paths = {suffix: "/etc/serverware/custody-" + role + "-" + suffix + ".json" for suffix in SUFFIXES}
        p.require(envelope_payload["runtimeConfig"] == {"path": paths["runtime"], "sha256": p.sha(runtime_raw)})
        inspection = jobs.runtime.inspection_original(role, runtime_raw, held["cold"], payload)
        for suffix, credential, raw in (("initial-history", "authority-history", history_raw),
                ("peer-inspection", "peer-inspection-policy", inspection)):
            rows = [row for row in envelope_payload["credentials"] if row["name"] == credential]
            p.require(len(rows) == 1 and rows[0]["original"] == {"path": paths[suffix], "sha256": p.sha(raw)}
                and rows[0]["length"] == len(raw) and rows[0]["signing"] is None)
        # The actual grant is supplied later in the retained owner's sealed
        # memfd, not published as a private credential or inferred from a file.
        grant_input, grant_raw, grant_prepared = _prepared(prior, "ordinary-grant-" + role, observations, clocks)
        jobs.ordinary.checked_result("grant", grant_input, _result(grant_raw), **clocks)
        jobs.ordinary.verify_grant(grant_raw, item=held)
        deadlines.extend((prepared["deadline"], grant_prepared["deadline"]))
        epochs.append(grant_prepared["epochLimit"])
        launch_configuration = g.document(jobs._observed(observations, "ordinary.configuration"), 65536)
        configuration_pin = launch_configuration["services"][role]["deliveryConfiguration"]
        p.require(configuration_pin["sha256"] == p.sha(source["configuration_raw"]))
        launch_raw = g.canonical({"apiVersion": "serverware.custodyOrdinaryServiceGuestLaunch/v7",
            "deliveryConfiguration": configuration_pin, "delivery": {"path": paths["delivery"], "sha256": p.sha(signed)},
            "peerInspectionCredential": "peer-inspection-policy"})
        uid, gid = held["cold"]["uid"], held["cold"]["gid"]
        files = (_file(paths["runtime"], runtime_raw), _file(paths["initial-history"], history_raw, uid, gid),
            _file(paths["peer-inspection"], inspection, uid, gid), _file(paths["delivery"], signed),
            _file(paths["guest"], launch_raw))
        pin = {"path": paths["guest"], "sha256": p.sha(launch_raw)}
    deadline, epoch_limit = min(deadlines), min(epochs)
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    return {"files": files, "launchPin": pin, "deadline": deadline, "epochLimit": epoch_limit}
