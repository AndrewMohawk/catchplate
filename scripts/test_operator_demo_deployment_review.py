#!/usr/bin/env python3
"""Synthetic comparison controls only; no Docker, live state or secret reads."""
from contextlib import ExitStack
from copy import deepcopy
import unittest
from unittest.mock import patch

from scripts import operator_demo_deployment_review as review

NETWORKS = {"sandbox": {"name": "synthetic_sandbox"}}
SECRET = "synthetic-environment-canary-not-for-output"


def service(name):
    environment = {"SYNTHETIC_PRIVATE_VALUE": SECRET}
    if name == "catchplate":
        environment.update(review.NOTIFICATION_ENV)
        environment[review.EXPECTED_DIGEST] = "sha256:" + review.OLD_SHA
    if name == "edge":
        environment["NGINX_ENVSUBST_FILTER"] = "^TRAEFIK_IPV4$"
    expected = dict(environment)
    if name == "catchplate": expected[review.EXPECTED_DIGEST] = "sha256:" + review.NEW_SHA
    if name == "edge": expected["NGINX_ENVSUBST_FILTER"] = "^TRAEFIK_IPV4$$"
    image = {"Id": "sha256:" + "a" * 64, "Config": {"Env": [], "Labels": {}, "User": "10001:10001",
        "Cmd": ["fixed-process"], "Entrypoint": [], "WorkingDir": "/app"}}
    proposed = {"image": image["Id"], "environment": expected, "pull_policy": "never", "restart": "unless-stopped",
        "user": "10001:10001", "read_only": True, "init": True, "mem_limit": 1024, "cpus": 1,
        "pids_limit": 32, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "networks": {"sandbox": {"ipv4_address": "172.16.249.19"}}, "dns": [],
        "extra_hosts": {"decision-gate-rs": "172.16.249.20"}, "tmpfs": ["/tmp:rw,noexec,size=1m"],
        "logging": {"driver": "local", "options": {"max-size": "1m"}},
        "healthcheck": {"test": ["CMD", "fixed-health"], "interval": "10s", "timeout": "2s", "start_period": "5s", "retries": 3},
        "volumes": []}
    dependency = {"catchplate": "demo-upstream", "decision-gate-rs": "catchplate"}.get(name)
    if dependency: proposed["depends_on"] = {dependency: {"condition": "service_healthy", "required": True}}
    config = {"User": "10001:10001", "Env": [key + "=" + value for key, value in environment.items()],
        "Cmd": ["fixed-process"], "Entrypoint": [], "WorkingDir": "/app", "Labels": {},
        "Healthcheck": {"Test": ["CMD", "fixed-health"], "Interval": 10000000000, "Timeout": 2000000000,
            "StartPeriod": 5000000000, "Retries": 3}}
    host = {"ReadonlyRootfs": True, "Memory": 1024, "NanoCpus": 1000000000, "PidsLimit": 32,
        "MemorySwap": 2048, "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}, "Init": True,
        "CapDrop": ["ALL"], "CapAdd": [], "SecurityOpt": ["no-new-privileges"], "Dns": [],
        "ExtraHosts": ["decision-gate-rs:172.16.249.20"], "PortBindings": {},
        "Tmpfs": {"/tmp": "size=1m,noexec,rw"}, "LogConfig": {"Type": "local", "Config": {"max-size": "1m"}}}
    live = {"Image": image["Id"], "Config": config, "HostConfig": host, "Mounts": [],
        "NetworkSettings": {"Ports": {}, "Networks": {"synthetic_sandbox": {"IPAddress": "172.16.249.19",
            "IPAMConfig": {"IPv4Address": "172.16.249.19"}, "Aliases": [name]}}}}
    mounts = {
        "catchplate": [("/app", review.OLD_SOURCE, review.NEW_SOURCE, True),
            ("/notification-custody", review.CUSTODY, review.CUSTODY, False)],
        "decision-gate-rs": [(review.BINARY_TARGET, review.OLD_BINARY, review.NEW_BINARY, True)],
        "edge": [("/etc/nginx/templates/nginx.conf.template", "/retained/nginx.conf.template",
            str(review.STACK / "config/nginx.conf.template"), True)],
        "demo-upstream": [("/app", "/retained/fixture-source", "/retained/fixture-source", True)],
    }
    for target, old, new, readonly in mounts[name]:
        proposed["volumes"].append({"type": "bind", "source": new, "target": target,
            "read_only": readonly, "bind": {"create_host_path": False}})
        live["Mounts"].append({"Type": "bind", "Source": old, "Destination": target, "RW": not readonly,
            "Propagation": "rprivate"})
    return proposed, live, image


class DeploymentReviewTests(unittest.TestCase):
    def setUp(self):
        guard = ExitStack(); self.addCleanup(guard.close)
        for target in ("subprocess.run", "socket.socket", "socket.create_connection", "socket.getaddrinfo"):
            guard.enter_context(patch(target, side_effect=AssertionError("pure comparator test attempted external I/O")))

    def compare(self, name, inputs, digest=lambda _: "same-public-template-digest"):
        return review.compare_service(name, *inputs, NETWORKS, digest_file=digest)

    def test_only_the_three_approved_paired_differences(self):
        changes = set()
        for name in review.SERVICES:
            inputs = service(name); retained = deepcopy(inputs)
            changes.update(self.compare(name, inputs))
            self.assertEqual(inputs, retained, "comparison changed its inputs")
        self.assertEqual(changes, review.APPROVED_DELTAS)

    def test_exact_observed_compose_extension_and_empty_external_ipam(self):
        model = {"name": review.PROJECT, "services": {name: service(name)[0] for name in review.SERVICES},
            "networks": deepcopy(review.MODEL_NETWORKS), "x-isolated": deepcopy(review.BASE_EXTENSION)}
        review.validate_model(model)
        self.assertEqual(model["networks"]["traefik-v3-public"]["ipam"], {})
        for change in ("extra_extension", "changed_extension", "missing_extension", "external_ipam", "extra_service"):
            altered = deepcopy(model)
            if change == "extra_extension": altered["x-unreviewed"] = {}
            elif change == "changed_extension": altered["x-isolated"]["read_only"] = False
            elif change == "missing_extension": del altered["x-isolated"]
            elif change == "external_ipam": altered["networks"]["traefik-v3-public"]["ipam"] = {"driver": "default"}
            else: altered["services"]["unreviewed"] = {}
            with self.subTest(change=change), self.assertRaises(review.Refused): review.validate_model(altered)

    def test_environment_drift_fails_without_exposing_values(self):
        for name in review.SERVICES:
            proposed, live, image = service(name)
            proposed["environment"]["SYNTHETIC_PRIVATE_VALUE"] = "changed-secret-value"
            with self.subTest(name=name), self.assertRaises(review.Refused) as caught:
                self.compare(name, (proposed, live, image))
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertNotIn("changed-secret-value", str(caught.exception))
        proposed, live, image = service("catchplate")
        proposed["environment"]["CATCHPLATE_OPERATOR_NOTIFICATIONS_ENABLED"] = "0"
        with self.assertRaises(review.Refused): self.compare("catchplate", (proposed, live, image))

    def test_wrong_source_binary_or_partial_pair_is_refused(self):
        for name, change in (("catchplate", "source"), ("catchplate", "digest"), ("decision-gate-rs", "source")):
            inputs = service(name)
            if change == "source": inputs[0]["volumes"][0]["source"] = "/unreviewed/artifact"
            else: inputs[0]["environment"][review.EXPECTED_DIGEST] = "sha256:" + review.OLD_SHA
            with self.subTest(name=name, change=change), self.assertRaises(review.Refused): self.compare(name, inputs)

    def test_bounds_dns_hosts_auth_and_mount_drift_refused(self):
        for field in ("cpus", "dns", "extra_hosts", "labels", "network_address", "dependency", "mount", "sysctls", "healthcheck"):
            proposed, live, image = service("catchplate")
            if field == "cpus": proposed["cpus"] = 2
            elif field == "dns": proposed["dns"] = ["8.8.8.8"]
            elif field == "extra_hosts": proposed["extra_hosts"] = {"decision-gate-rs": "172.16.249.34"}
            elif field == "labels": proposed["labels"] = {"traefik.http.routers.test.middlewares": "unreviewed"}
            elif field == "network_address": proposed["networks"]["sandbox"] = {}
            elif field == "dependency": proposed["depends_on"]["demo-upstream"]["condition"] = "service_started"
            elif field == "mount": proposed["volumes"][1]["read_only"] = True
            elif field == "sysctls": proposed["sysctls"] = {"net.ipv4.ip_forward": "1"}
            else: proposed["healthcheck"]["retries"] = 4
            with self.subTest(field=field), self.assertRaises(review.Refused): self.compare("catchplate", (proposed, live, image))

    def test_only_empty_fixed_external_overlay_attachment_allows_allocated_ipam(self):
        proposed, live, image = service("decision-gate-rs")
        networks = {**NETWORKS, "traefik-v3-public": deepcopy(review.MODEL_NETWORKS["traefik-v3-public"]),
            "outbound": {"name": "synthetic_outbound"}}
        proposed["networks"].update({"traefik-v3-public": {}, "outbound": {"ipv4_address": "172.16.249.34"}})
        live["NetworkSettings"]["Networks"].update({
            "traefik-v3-public": {"IPAddress": "10.77.0.160", "IPAMConfig": {"IPv4Address": "10.77.0.160"}},
            "synthetic_outbound": {"IPAddress": "172.16.249.34", "IPAMConfig": {"IPv4Address": "172.16.249.34"}},
        })
        self.assertEqual(review.compare_service("decision-gate-rs", proposed, live, image, networks), {review.BINARY_DELTA})
        for change in ("selected_external_mismatch", "outbound_mismatch", "sandbox_omitted", "different_network", "external_definition"):
            candidate, actual, selected_networks = deepcopy(proposed), deepcopy(live), deepcopy(networks)
            if change == "selected_external_mismatch": candidate["networks"]["traefik-v3-public"] = {"ipv4_address": "10.77.0.161"}
            elif change == "outbound_mismatch": actual["NetworkSettings"]["Networks"]["synthetic_outbound"]["IPAMConfig"]["IPv4Address"] = "172.16.249.35"
            elif change == "sandbox_omitted": candidate["networks"]["sandbox"] = {}
            elif change == "external_definition": selected_networks["traefik-v3-public"]["external"] = False
            else:
                selected_networks["traefik-v3-public"]["name"] = "different-overlay"
                actual["NetworkSettings"]["Networks"]["different-overlay"] = actual["NetworkSettings"]["Networks"].pop("traefik-v3-public")
            with self.subTest(change=change), self.assertRaises(review.Refused):
                review.compare_service("decision-gate-rs", candidate, actual, image, selected_networks)

    def test_edge_path_exception_requires_equal_bytes_and_fixture_no_exception(self):
        self.assertEqual(self.compare("edge", service("edge")), set())
        with self.assertRaises(review.Refused):
            self.compare("edge", service("edge"), digest=lambda path: path)
        inputs = service("demo-upstream"); inputs[0]["volumes"][0]["source"] = review.NEW_SOURCE
        with self.assertRaises(review.Refused): self.compare("demo-upstream", inputs)

    def test_duration_host_and_environment_normalization_is_strict(self):
        self.assertEqual(review.duration("1m2.5s"), 62500000000)
        self.assertEqual(review.hosts({"gate": ["172.16.249.20"]}), review.hosts(["gate:172.16.249.20"]))
        self.assertEqual(review.hosts(["gate=172.16.249.20"]), [("gate", "172.16.249.20")])
        for raw in (True, "", "1s trailing", "0.1ns"):
            with self.subTest(raw=raw), self.assertRaises(review.Refused): review.duration(raw)
        for raw in (["TOKEN=" + SECRET, "TOKEN=other"], ["missing-equals"]):
            with self.assertRaises(review.Refused): review.envmap(raw)
        with self.assertRaises(review.Refused): review.hosts(["gate:1", "gate:1"])

    def test_discovery_requires_one_healthy_service_per_project(self):
        observed = []
        for index, name in enumerate(sorted(review.SERVICES), 1):
            _, live, _ = service(name)
            live.update(Id=str(index) * 64, RestartCount=0, State={"Running": True, "Health": {"Status": "healthy"}})
            live["Config"]["Labels"].update({"com.docker.compose.project": review.PROJECT,
                "com.docker.compose.service": name, "com.docker.compose.oneoff": "False"})
            observed.append(live)
        ids = ("\n".join(item["Id"] for item in observed) + "\n").encode()
        with patch.object(review, "command", return_value=ids) as command, patch.object(review, "command_json", return_value=observed):
            self.assertEqual(set(review.discover()), review.SERVICES)
            self.assertEqual(command.call_args.args[0][:2], ["docker", "ps"])
            for field, value in (("RestartCount", 1), ("State", {"Running": True, "Health": {"Status": "starting"}})):
                changed = deepcopy(observed); changed[0][field] = value
                with patch.object(review, "command_json", return_value=changed), self.assertRaises(review.Refused): review.discover()
            duplicate = deepcopy(observed); duplicate[0]["Config"]["Labels"]["com.docker.compose.service"] = duplicate[1]["Config"]["Labels"]["com.docker.compose.service"]
            with patch.object(review, "command_json", return_value=duplicate), self.assertRaises(review.Refused): review.discover()


if __name__ == "__main__":
    unittest.main()
