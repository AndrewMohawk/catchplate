"""One initial-only request acquisition on the actual retained pilot owners.

No socket send, signer, currentness decision, consume head or readiness is
created. Real entropy and one fixed issuance time are sampled only after all
five admitted runtime/history/cursor associations pass. Failures retain the
same one-attempt owner until genuine pilot cleanup; no deadline is renewed.
"""
from __future__ import annotations

import os
import threading

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware import native_pilot_initial_requests_profile as profile

p = g.p
MAX_BYTES = profile.MAX_BYTES
MAX_RETAINED_BYTES = 32 * 1024 * 1024
_TOKEN = object()
_USED = False
_LIVE = None


class InitialRequests:
    def __init__(self, token, pilot):
        p.require(token is _TOKEN)
        self._pilot, self._generation, self._launcher = pilot, pilot._generation, pilot._five
        self._pid = os.getpid()
        self._closed = self._failed = self._consumed = False
        self._raw = self._source = self._selection = None
        self._previous = self._issued = None

    @classmethod
    def prepare(cls, pilot):
        global _USED, _LIVE
        from serverware.native_pilot_launch import NativePilotLaunch

        p.require(cls is InitialRequests and type(pilot) is NativePilotLaunch
            and not _USED and _LIVE is None and threading.current_thread() is threading.main_thread())
        pilot._origin()
        _USED = True
        owner = cls(_TOKEN, pilot)
        _LIVE = owner  # Retained before any partial validation or entropy read.
        try:
            owner._source = owner._snapshot()
            before = o.clock()
            owner._selection = owner._select(owner._source, before)
            # Coverage and authenticated sources are complete before either
            # fixed request issuance or entropy is sampled. A short read fails;
            # there is no resampling/retry and no caller-selected entropy.
            owner._issued = owner._previous = o.clock()
            p.require(before <= owner._issued)
            entropy = os.getrandom(32 * len(g.ROLES))
            p.require(len(entropy) == 32 * len(g.ROLES))
            rows = {}
            for index, role in enumerate(g.ROLES):
                selected = owner._selection[role]
                raw = profile.request_original(selected, entropy=entropy[index * 32:(index + 1) * 32],
                    issued_at_boottime_ns=owner._issued)
                rows[role] = {name: selected[name] for name in profile.ROW_FIELDS[:4]}
                rows[role].update(requestOriginal=raw.decode("ascii"), requestSha256=profile.head.request_sha256(raw))
            source = owner._source
            owner._raw = p.canonical({"apiVersion": profile.API,
                "launchSha256": p.sha(source["launch_original"]),
                "preparationSha256": p.sha(source["preparation_original"]),
                "resourcesSha256": p.sha(source["resources_original"]),
                "requestedAtBoottimeNanos": owner._issued,
                "startupDeadlineBoottimeNs": source["window"]["startupDeadlineBoottimeNs"],
                "lifetimeDeadlineBoottimeNs": source["window"]["lifetimeDeadlineBoottimeNs"], "requests": rows})
            profile.shape(owner._raw)
            owner.check()
            return owner
        except BaseException:
            owner._failed = True
            raise

    def _owner(self):
        from serverware.custody_generation_business import BusinessResources
        from serverware.custody_generation_inputs import GenerationInputs
        from serverware.custody_generation_launch import FiveServiceLaunch
        from serverware.native_pilot_launch import NativePilotLaunch

        p.require(_LIVE is self and not self._closed and not self._failed and not self._consumed
            and os.getpid() == self._pid and threading.current_thread() is threading.main_thread()
            and type(self._pilot) is NativePilotLaunch and type(self._generation) is GenerationInputs
            and type(self._launcher) is FiveServiceLaunch
            and self._pilot._generation is self._generation and self._pilot._five is self._launcher
            and self._generation._launcher is self._launcher and self._launcher._input_owner is self._generation
            and type(self._generation._business_owner) is BusinessResources
            and self._generation._business_owner is self._pilot._business
            and self._generation._business_owner._inputs is self._generation)
        self._pilot._preparing()
        p.require(self._pilot._service_inputs_attempted and self._generation._effects
            and self._generation._spool and self._generation._commitment and self._launcher._inspected
            and not self._generation._closed and not self._generation._taken and not self._generation._released
            and not self._launcher._attempted and not self._launcher._stop.is_set()
            and tuple(self._generation._roles) == tuple(self._launcher._children) == g.ROLES
            and all(child["phase"] == "parked" and not child["reaped"] for child in self._launcher._children.values())
            and self._pilot._driver._boot == self._launcher._boot)

    def _snapshot(self):
        from serverware import custody_generation_initial_state as state_owner
        from serverware.custody_generation_launch import EFFECTS_CONFIGURATION

        self._owner()
        inputs, launch = self._generation, self._launcher
        now = o.clock()
        p.require(now < launch._startup)
        preparation = launch.preparation_original()
        retained = inputs._initial_state
        p.require(inputs._initial_state_attempted and type(retained) is state_owner._InitialResources
            and retained.inputs is inputs and not retained.failed and type(retained.raw) is bytes
            and retained.preparation == preparation)
        resources = retained.raw
        observed = profile.initial.resources(resources)
        original = launch._originals[0]
        p.require(type(original) is o.Original and original.path == EFFECTS_CONFIGURATION)
        launch_raw = original.read()
        contexts, joins, total, identities = {}, {}, len(preparation) + len(resources) + len(launch_raw), set()
        for role in g.ROLES:
            item = inputs._roles[role]
            p.require(item["delivery_attempt"] and item["grant_attempt"] and item["launch"] is not None
                and type(item["delivery"]) is o.Original and type(item["runtime"]) is o.Original
                and type(item["grant_raw"]) is bytes and type(item["history_raw"]) is bytes)
            cold_raw, runtime_raw, delivery_raw = item["configuration"].read(), item["runtime"].read(), item["delivery"].read()
            p.require(runtime_raw == item["runtime_raw"] and delivery_raw == item["delivery_raw"])
            _, guest = g._admit_delivery(signed_raw=delivery_raw, cold_raw=cold_raw,
                cold_sha=item["configuration"].sha, role=role, activation=item["activation"], boot=launch._boot,
                startup=launch._startup, lifetime=launch._lifetime, now=now, **inputs._profile(role))
            p.require(g.canonical(guest) == g.canonical(item["guest"]))
            header = g.document(runtime_raw, g.MAX_BYTES)["runtime"]
            delivery = g.document(delivery_raw, 65536)["payload"]
            entries = [entry for entry in delivery["credentials"] if entry["name"] == header["authorityHistoryManifestCredential"]]
            p.require(len(entries) == 1 and entries[0]["signing"] is None)
            entry = entries[0]
            actual = [value for value in inputs._originals if type(value) is o.Original
                and value.path == entry["original"]["path"]]
            p.require(len(actual) == 1)
            history_raw = actual[0].read()  # Only selected public history, never a signing seed.
            p.require(history_raw == item["history_raw"] and len(history_raw) == entry["length"]
                and p.sha(history_raw) == entry["original"]["sha256"])
            g._admit_grant(signed_raw=item["grant_raw"], guest=guest, runtime_raw=runtime_raw,
                history_raw=history_raw, delivery_raw=delivery_raw, now=now, **inputs._profile(role))
            directories = dict(item["descriptors"])
            for name in state_owner.DIRECTORIES[role]:
                fd = directories[name]
                info = os.fstat(fd)
                identity = info.st_dev, info.st_ino
                p.require(identity not in identities and o.names(fd) == ()
                    and o.directory_identity(fd) == observed["services"][role]["directories"][name]["identity"])
                identities.add(identity)
            contexts[role] = dict(configurationOriginal=cold_raw, runtimeOriginal=runtime_raw,
                historyOriginal=history_raw, guest=guest)
            joins[role] = (delivery_raw, item["grant_raw"])
            total += sum(map(len, (cold_raw, runtime_raw, history_raw, delivery_raw, item["grant_raw"])))
            p.require(total <= MAX_RETAINED_BYTES)
        p.require(len(identities) == 15)
        scopes = [g.document(joins[role][1], 65536)["payload"]["scope"] for role in g.ROLES]
        p.require(all(value == scopes[0] for value in scopes))
        grant_deadline = min(g.document(joins[role][1], 65536)["payload"]["expiresAtBoottimeNanos"] for role in g.ROLES)
        window = p.document(p.canonical(self._pilot._driver._window), 32768)
        p.require((p.ns(window["startupDeadlineBoottimeNs"]), p.ns(window["lifetimeDeadlineBoottimeNs"]))
            == (launch._startup, launch._lifetime))
        self._owner()
        return dict(contexts=contexts, joins=joins, preparation_original=preparation,
            resources_original=resources, launch_original=launch_raw, window=window, boot=launch._boot,
            grant_deadline=grant_deadline)

    @staticmethod
    def _select(source, now):
        selected = profile.select(source["contexts"], **{name: source[name] for name in (
            "preparation_original", "resources_original", "launch_original", "window", "boot")}, now_boottime_ns=now)
        # _snapshot authenticates these exact grants before retaining their
        # earliest original expiry. Clip, never extend, each request deadline;
        # all terminal clock checks consequently retain this authority bound.
        grant_deadline = profile.key._uint(source["grant_deadline"])
        p.require(now < grant_deadline)
        for row in selected.values():
            row["deadline"] = min(row["deadline"], grant_deadline)
        return selected

    def check(self):
        try:
            self._owner()
            p.require(type(self._raw) is bytes and self._source is not None and self._selection is not None)
            now = o.clock()
            p.require(self._issued <= self._previous <= now < min(item["deadline"] for item in self._selection.values()))
            self._previous = now
            p.require(self._snapshot() == self._source and self._select(self._source, now) == self._selection)
            profile.shape(self._raw)
            after = o.clock()
            p.require(now <= after < min(item["deadline"] for item in self._selection.values()))
            self._previous = after
            self._owner()
            terminal = o.clock()
            p.require(after <= terminal < min(item["deadline"] for item in self._selection.values()))
            self._previous = terminal
        except BaseException:
            self._failed = True
            raise

    def original(self):
        self.check()
        return self._raw

    def consume(self):
        """One release fence; no socket send, approval or child release."""
        self.check()
        self._consumed = True


def close(pilot):
    """Retire public metadata only after the genuine cleanup graph is terminal."""
    global _LIVE
    from serverware.custody_generation_inputs import GenerationInputs
    from serverware.custody_generation_launch import FiveServiceLaunch
    from serverware.native_pilot_launch import NativePilotLaunch

    p.require(type(pilot) is NativePilotLaunch and pilot._closed
        and os.getpid() == pilot._pid and threading.current_thread() is threading.main_thread())
    if _LIVE is None:
        return
    owner = _LIVE
    p.require(type(owner) is InitialRequests and owner._pilot is pilot and os.getpid() == owner._pid
        and pilot._generation is owner._generation and pilot._five is owner._launcher)
    if owner._generation is not None:
        p.require(type(owner._generation) is GenerationInputs and owner._generation._closed)
    if owner._launcher is not None:
        p.require(type(owner._launcher) is FiveServiceLaunch and owner._launcher._closed
            and all(child["reaped"] for child in owner._launcher._children.values()))
    owner._closed = True
    owner._raw = owner._source = owner._selection = None
    _LIVE = None  # _USED deliberately remains true; terminal cleanup is not retry permission.
