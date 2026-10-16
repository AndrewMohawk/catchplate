#!/usr/bin/env python3
"""One existing-harness stock Boto3 -> Rust -> CP -> synthetic ECR publication.

No build, download, AWS request, seeded authority, SDK transport patch or retry.
All services share one network-none namespace; one public-looking address lives
only on its loopback. Actual public proxy routes perform staging and dispatch.
Fixture AWS keys are synthetic, and only hashes/metadata leave the checker.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import hmac
from http.server import HTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import ssl
import sys
import time
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import operator_common_apps_fixture as network
from scripts import prepare_operator_guided_fixture as recipe
from scripts.check_operator_catalog import COLLECTIONS, PREFIX, OperatorCatalogCheck, claim_fixture
from scripts.check_operator_demo import Endpoint, SHA256, require, token_file
from scripts.check_operator_ordinary_client import OrdinaryClientCheck, START, RELEASE
from scripts.run_operator_guided_fixture import GuidedRun, admitted_image_entrypoint
from scripts.run_operator_npm_example_fixture import environment
from scripts.run_operator_x_examples_fixture import failure_site

SCRIPT = "scripts/test_operator_ecr_gate_connected.py"
HOST = "api.ecr.us-east-1.amazonaws.com"
ORIGINS = ["https://" + HOST]
SCOPE = {"registry_id": "123456789012", "region": "us-east-1",
    "repository_name": "serverware-fixture/image", "image_tag": "reviewed-1"}
ACCESS, SECRET = "AKIA" + "F" * 16, "G" * 40
CONFIG = b'{"architecture":"amd64","os":"linux"}'
LAYER = b"ecr-gate-connected-exact-image-canary"
SDK_RECEIPT_SCHEMA = "serverware.ecrSdkPackages/v1"
SDK_REQUIREMENTS = "examples/ecr-publish-python/requirements.txt"


def sdk_receipt(packages, receipt_path, expected_sha256, source):
    """Reuse the existing bounded archive inventory and externally pinned JSON."""
    receipt = recipe.basic.pinned_json(receipt_path, expected_sha256)
    require(type(receipt) is dict and set(receipt) == {"schema", "packages", "requirementsSha256", "files"}
        and receipt["schema"] == SDK_RECEIPT_SCHEMA, "SDK receipt shape differs")
    requirements = source / SDK_REQUIREMENTS
    require(recipe.base.digest(requirements) == receipt["requirementsSha256"], "SDK requirements pin differs")
    pins = {}
    for line in requirements.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+-]*)", line)
        require(match is not None and match[1] not in pins, "exact SDK requirement pins required")
        pins[match[1]] = match[2]
    require(bool(pins) and receipt["packages"] == pins, "SDK dependency versions differ")
    inventory = recipe.basic.inventory(packages, limit=16384, byte_limit=512 * 1024**2)
    require({name: item["sha256"] for name, item in inventory.items()} == receipt["files"],
        "SDK installed file inventory differs")
    return receipt


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def image_bytes():
    from serverware import ecr_image_artifact as artifact
    def descriptor(media, raw):
        return {"mediaType": media, "digest": digest(raw), "size": len(raw)}
    manifest = encoded({"schemaVersion": 2, "mediaType": artifact.OCI_MANIFEST,
        "config": descriptor(artifact.OCI_CONFIG, CONFIG),
        "layers": [descriptor("application/vnd.oci.image.layer.v1.tar", LAYER)]})
    return manifest, {digest(CONFIG): CONFIG, digest(LAYER): LAYER}


def configure_network():
    # Reuse the exact existing namespace, PKI and relay implementation, changing
    # only the finite fixture hostname set within this dedicated process.
    network.PROVIDERS = (HOST,)
    network.HOSTS = ("127.0.0.1 localhost serverware decision-gate-rs "
        + network.guided.CONTROL_HOST + " " + network.guided.PROXY_HOST + "\n127.0.0.2 demo-upstream\n"
        + network.isolated.FIXTURE_IP + " api.github.com " + HOST + "\n").encode("ascii")
    network.configure_network()


def signature_valid(headers, body):
    names = ("accept", "content-type", "host", "x-amz-date", "x-amz-target")
    require(headers["accept"] == "*/*" and headers["host"] == HOST
        and headers["content-type"] == "application/x-amz-json-1.1", "signed header profile differs")
    timestamp = headers["x-amz-date"]
    require(re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", timestamp), "signing clock differs")
    scope = timestamp[:8] + "/us-east-1/ecr/aws4_request"
    canonical = ("POST\n/\n\n" + "".join(name + ":" + headers[name] + "\n" for name in names)
        + "\n" + ";".join(names) + "\n" + hashlib.sha256(body).hexdigest()).encode("ascii")
    signing_string = ("AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n"
        + hashlib.sha256(canonical).hexdigest()).encode("ascii")
    key = ("AWS4" + SECRET).encode("ascii")
    for part in (timestamp[:8], "us-east-1", "ecr", "aws4_request"):
        key = hmac.new(key, part.encode("ascii"), hashlib.sha256).digest()
    expected = ("AWS4-HMAC-SHA256 Credential=" + ACCESS + "/" + scope + ", SignedHeaders="
        + ";".join(names) + ", Signature=" + hmac.new(key, signing_string, hashlib.sha256).hexdigest())
    require(hmac.compare_digest(headers["authorization"], expected), "exact request HMAC differs")


class Provider(network.Handler):
    def send(self, status, value):
        raw = encoded(value)
        self.send_response_only(status)
        for key, value in (("Content-Type", "application/x-amz-json-1.1"),
                ("Content-Length", str(len(raw))), ("Connection", "close")):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_GET(self):
        if self.path == "/_fixture/observations":
            return self.send(200, {"total": self.server.total, "attempts": self.server.attempts})
        self.send(404, {"error": "fixture_path_refused"})

    def do_POST(self):
        self.server.total += 1
        row = {"accepted": False}
        if self.server.total <= 8:
            self.server.attempts.append(row)
        try:
            require(self.path == "/" and self.server.total <= 8, "fixed request roster exceeded")
            fields = [(key.lower(), value) for key, value in self.headers.raw_items()]
            require(len(fields) == len(dict(fields)) and len(fields) <= 12, "header shape differs")
            headers = dict(fields)
            require(set(headers) <= {"accept", "authorization", "content-type", "content-length", "host",
                "x-amz-date", "x-amz-target", "connection"}, "unselected header forwarded")
            length = int(headers["content-length"])
            require(0 < length < 8192, "tiny fixture request size differs")
            raw = self.rfile.read(length)
            require(len(raw) == length and SECRET.encode() not in raw, "request bytes differ")
            signature_valid(headers, raw)
            action = headers["x-amz-target"].removeprefix("AmazonEC2ContainerRegistry_V20150921.")
            body = json.loads(raw)
            require(body["registryId"] == SCOPE["registry_id"]
                and body["repositoryName"] == SCOPE["repository_name"], "provider destination scope differs")
            manifest, blobs = image_bytes()
            common = {"registryId": SCOPE["registry_id"], "repositoryName": SCOPE["repository_name"]}
            index = self.server.total
            if index == 1:
                require(action == "BatchCheckLayerAvailability", "first action differs")
                expected = {**common, "layerDigests": list(blobs)}
                ack = {"layers": [{"layerDigest": key, "layerAvailability": "UNAVAILABLE"} for key in blobs]}
            elif index == 8:
                require(action == "PutImage", "final action differs")
                expected = {**common, "imageManifest": manifest.decode(),
                    "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json",
                    "imageTag": SCOPE["image_tag"], "imageDigest": digest(manifest)}
                ack = {"image": {"imageId": {"imageDigest": digest(manifest), "imageTag": SCOPE["image_tag"]}}}
            else:
                blob_index, phase = divmod(index - 2, 3)
                key, blob = list(blobs.items())[blob_index]
                upload = str(uuid.UUID(int=blob_index + 1, version=4))
                expected_action = ("InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload")[phase]
                require(action == expected_action, "ordered upload action differs")
                if phase == 0:
                    expected = common
                    ack = {"uploadId": upload, "partSize": 10 * 1024 * 1024}
                elif phase == 1:
                    expected = {**common, "uploadId": upload, "partFirstByte": 0,
                        "partLastByte": len(blob) - 1, "layerPartBlob": base64.b64encode(blob).decode()}
                    ack = {"uploadId": upload, "lastByteReceived": len(blob) - 1}
                else:
                    expected = {**common, "uploadId": upload, "layerDigests": [key]}
                    ack = {"uploadId": upload, "layerDigest": key}
            require(body == expected, "exact reviewed image input differs")
            # Stock botocore's JSON serializer retains these ordinary separators.
            require(raw == json.dumps(expected).encode("utf-8"), "stock SDK bytes changed before upstream")
            row.update(accepted=True, action=action, bodySha256=digest(raw), bodyBytes=len(raw),
                responseSha256=digest(encoded(ack)), exactSignatureVerified=True)
            self.send(200, ack)
        except Exception:
            self.send(400, {"error": "synthetic_ecr_request_refused"})


def serve():
    configure_network()
    network.assert_isolated()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/data/demo-upstream/cert.pem", "/data/demo-upstream/key.pem")
    signal.alarm(300)
    with HTTPServer((network.isolated.FIXTURE_IP, 443), Provider) as server:
        server.total, server.attempts, server.timeout = 0, [], 0.5
        server.socket = context.wrap_socket(server.socket, server_side=True)
        until = time.monotonic() + 290
        while time.monotonic() < until:
            server.handle_request()


class EcrCheck(OperatorCatalogCheck):
    audit_drained = OrdinaryClientCheck.audit_drained

    def __init__(self, args):
        configure_network()
        network.assert_isolated()
        super().__init__(argparse.Namespace(**{**vars(args), "upstream_address": "127.0.0.1"}))
        self.phase, self.last, self.credential = "preflight", None, SECRET
        require(args.control_base == "http://127.0.0.1:3000" and args.management_base == "http://127.0.0.1:9091"
            and args.proxy_url == recipe.PROXY_URL and args.operator_origin == recipe.CONTROL_ORIGIN,
            "exact isolated endpoints required")
        self.provider = Endpoint(ORIGINS[0], address="127.0.0.1")
        self.provider.address = network.isolated.FIXTURE_IP

    def clean(self, raw, *, allow_client_token=False):
        super().clean(raw, allow_client_token=allow_client_token)
        require(ACCESS.encode() not in raw and b"AWS4-HMAC-SHA256 Credential=" not in raw,
            "private signing material escaped into public output")

    def catalog(self):
        value = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(value.get("schema") == "serverware.operatorCatalog/v1" and value.get("mode") == "operator-development"
            and value.get("allowed_upstreams") == ORIGINS and all(isinstance(value.get(key), list) for key in COLLECTIONS)
            and SHA256.fullmatch(value.get("policy", {}).get("policy_hash", "")), "fixture catalog differs")
        self.snapshot = value
        return value

    def provider_observations(self):
        status, value = self.json_request(self.provider, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200 and set(value) == {"total", "attempts"}, "provider observations unavailable")
        return value

    def run(self):
        from serverware import ecr_image_custody as custody
        sdk_receipt(Path("/sdk-packages"), Path("/sdk-receipt.json"),
            self.args.expected_sdk_receipt_sha256, Path("/app"))
        spec = importlib.util.spec_from_file_location("ecr_client_example",
            Path("/app/examples/ecr-publish-python/publish.py"))
        example = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(example)
        example.isolate_environment()
        example.check_versions()
        self.admin_token = token_file(self.args.admin_token_file)
        self.health()
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] for key in COLLECTIONS)
            and self.provider_observations() == {"total": 0, "attempts": []}, "fresh fixture required")
        self.phase = "catalog"
        application, self.client_token, _ = self.mutate("/applications", {"name": self.run_id,
            "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        credential, _, _ = self.mutate("/credentials/aws-sigv4", {"name": self.run_id + "-aws", "credential_kind": "long_term",
            "access_key_id": ACCESS, "secret_access_key": SECRET, "session_token": None, "expires_at": None},
            collection="credentials", result_key="credential", event="operator_catalog.credential.aws_sigv4_created", creates=True)
        rule, _, _ = self.mutate("/access-rules/aws-ecr-publication", {"name": self.run_id + "-image",
            "application_id": application["id"], "credential_id": credential["id"], "operation_bundle": "aws_ecr_publish_v1",
            "approval_mode": "host_review_v1", **SCOPE}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.ecr_publication_created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("ecr_permission_loaded")
        config = {"schema": example.SCHEMA, "operation_bundle": "aws_ecr_publish_v1", **SCOPE,
            "application_id": application["id"], "access_rule_id": rule["id"], "expected_policy_hash": self.policy_hash,
            "proxy_url": self.args.proxy_url, "control_api_url": self.args.proxy_url + example.CONTROL_PATH,
            "proxy_authentication": "basic_and_bearer_v1", "proxy_username": application["id"],
            "proxy_password": self.client_token, "token_expires_at_epoch_ms": application["token_expires_at_epoch_ms"],
            "ca_file": str(self.args.ca_file), "proxy_ca_file": str(self.args.proxy_ca_file)}
        path = self.args.run_claim_file.parent / "ecr-client.json"
        network.guided.write_once(path, encoded(config))
        config = example.load_configuration(path)
        control = example.Control(config)
        manifest, blobs = image_bytes()
        with custody.capture(manifest, {key: io.BytesIO(raw) for key, raw in blobs.items()}) as sealed:
            self.phase = "public_proxy_staging"
            staged = example.stage(config, sealed, control)
            identifier = staged["id"]
            self.last = {"publicationId": identifier, "status": staged["status"]}
            require(staged["status"] == "awaiting_review" and self.provider_observations()["total"] == 0,
                "staging sent upstream or skipped review")
            admin_path = PREFIX + "/ecr-publications/" + identifier
            self.phase = "operator_review"
            review = self.control_json(admin_path + "/review", method="POST", payload={}, authenticated=True)
            require(review["publication"]["artifact"] == sealed.image.commitment(), "review artifact differs")
            approved = self.control_json(admin_path + "/decision", method="POST", payload={"decision": "approve", "note": None,
                "review_receipt_id": review["review_receipt_id"], "review_digest": review["review_digest"]}, authenticated=True)
            require(approved["status"] == "approved", "publication not approved")
            self.phase = "stock_boto3_publication"
            published = example.publish(config, identifier, sealed, control, execute_write=True)
            require(published["status"] == "published" and published["sdk_calls"] == 8
                and published["automatic_retries"] == 0, "stock SDK publication differs")
        final = example.publication(control.call("GET", "/" + identifier), config, identifier)
        require(final["status"] == "published" and final["progress"]["calls"] == 8, "owner did not commit published")
        self.phase = "audit"
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        rows = self.audit()
        owner = [row for row in rows if row["event_type"].startswith("operator.ecr_publication.")]
        require(all(row["event"].get("publication_id") == identifier and row["event"].get("policy_hash") == self.policy_hash
            and row["event"].get("credential_generation") == 1 for row in owner), "owner audit binding differs")
        acks = [row for row in owner if row["event_type"] == "operator.ecr_publication.acknowledged"]
        sends = [row for row in owner if row["event_type"] == "operator.ecr_publication.possible_send"]
        observed = self.provider_observations()
        require(observed["total"] == len(acks) == len(sends) == 8
            and all(row["accepted"] and row["exactSignatureVerified"] for row in observed["attempts"]), "exact signing/ACK count differs")
        require(Counter(row["bodySha256"] for row in observed["attempts"])
            == Counter(row["event"]["request_sha256"] for row in acks), "provider bytes and owner ACK bindings differ")
        actions = Counter(row["action"] for row in observed["attempts"])
        require(actions == Counter({"BatchCheckLayerAvailability": 1, "InitiateLayerUpload": 2,
            "UploadLayerPart": 2, "CompleteLayerUpload": 2, "PutImage": 1}), "five-action roster differs")
        ecr_ack = "data_plane.ecr_publication.acknowledged"
        proxy = [row for row in rows if row["event_type"] in {START, RELEASE, ecr_ack}]
        require(Counter(row["event_type"] for row in proxy) == Counter({ecr_ack: 8, RELEASE: 8}),
            "dedicated signing and response release audit count differs")
        return {"schema": "serverware.ecrGateConnectedCheck/v1", "ok": True, "syntheticOnly": True,
            "realAwsVerified": False, "stockBoto3Verified": True, "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            "policyHash": self.policy_hash, "publicationId": identifier, "status": final["status"],
            "actions": dict(actions), "provider": observed, "ownerAcknowledgments": len(acks),
            "proxyAuditCounts": dict(Counter(row["event_type"] for row in proxy)), "automaticRetries": 0}


def check(args):
    signal.alarm(180)
    instance = None
    try:
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        instance = EcrCheck(args)
        result = instance.run()
    except Exception as error:
        result = {"ok": False, "phase": instance.phase if instance else "preflight", "exceptionType": type(error).__name__,
            "failureSite": failure_site(error, Path(__file__).resolve().parents[1]), "observation": instance.last if instance else None}
        if instance is not None:
            try:
                result["provider"] = instance.provider_observations()
            except Exception:
                pass
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["ok"] else 1


def build(args):
    config = recipe.build(args.source, args.binary, args.initializer, args.job_root,
        expected_binary_sha256=args.expected_binary_sha256)
    services = config["services"]
    helper = ["python", "-B", "-m", "scripts.test_operator_ecr_gate_connected"]
    services["network-files"]["command"] = helper + ["setup"]
    services["network"].update(user="0:0", init=False, cap_add=["NET_ADMIN", "SETUID", "SETGID"], command=helper + ["network"])
    services["network"]["healthcheck"]["test"][3] = "import os; os.setgroups([]); os.setgid(10001); os.setuid(10001); " + services["network"]["healthcheck"]["test"][3]
    services["provider"].update(image=recipe.base.APP_IMAGE, command=helper + ["provider"])
    services["provider"]["healthcheck"]["test"][3] = ("import ssl,urllib.request; c=ssl.create_default_context(cafile='/data/demo-upstream/ca.pem'); "
        "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
        "r=o.open('https://" + HOST + "/_fixture/observations',timeout=2); raise SystemExit(0 if r.status==200 else 1)")
    services["edge"]["command"] = ["-m", "scripts.test_operator_ecr_gate_connected", "edge"]
    for name in ("serverware", "decision-gate-rs"):
        services[name]["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(ORIGINS)
        # Match docker-compose.host-approvals.yml; ECR requires this explicit
        # ordinary host-trusted profile, never native/TEE approval authority.
        services[name]["environment"]["SERVERWARE_HOST_TRUSTED_APPROVALS_ENABLED"] = "1"
        services[name]["environment"].pop("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS", None)
    # Ordinary activation requires /data to start empty and writes its own
    # identity marker. Provision artifact custody in a separate private mount.
    services["serverware"]["environment"]["SERVERWARE_ECR_ARTIFACT_ROOT"] = "/ecr-artifacts"
    services["serverware"]["volumes"].append(recipe.base.bind(
        args.job_root / "runtime/upstream-data/ecr-artifacts", "/ecr-artifacts", False))
    check = services["check"]
    check.update(image=recipe.base.APP_IMAGE, entrypoint=["python", "-B"])
    check["environment"]["PYTHONPATH"] = "/app:/sdk-packages"
    check["command"][0:1] = ["/app/" + SCRIPT, "check"]
    check["command"] += ["--expected-sdk-receipt-sha256", args.expected_sdk_receipt_sha256]
    check["volumes"] += [recipe.base.bind(args.sdk_packages, "/sdk-packages"),
        recipe.base.bind(args.sdk_receipt, "/sdk-receipt.json")]
    return config


def run(args):
    source, root = args.source, args.job_root
    require(Path(__file__).resolve() == source / SCRIPT and re.fullmatch(r"[0-9a-f]{40}", args.commit), "frozen source required")
    require(source.is_dir() and not source.stat().st_mode & 0o222, "source export must be nonwritable")
    require(root.is_dir() and not list(root.iterdir()) and root.stat().st_mode & 0o777 == 0o700
        and args.evidence.is_dir() and not list(args.evidence.iterdir()), "fresh private roots required")
    require(recipe.base.digest(args.binary) == args.expected_binary_sha256, "normal binary pin differs")
    dependencies = sdk_receipt(args.sdk_packages, args.sdk_receipt, args.expected_sdk_receipt_sha256, source)
    args.initializer = source / "scripts/private_operator_audit/initialize.py"
    require(recipe.base.digest(args.initializer) == recipe.base.INITIALIZER_SHA256, "initializer pin differs")
    runner = GuidedRun(args)
    begun = time.monotonic()
    runner.deadline = begun + 300
    success, clean, armed, phase, failure = False, False, False, "prepare", None
    try:
        config = build(args)
        services = config["services"]
        runner.project, runner.services = config["name"], services
        require(not runner.container_rows("preexisting") and runner.no_project_networks("preexisting-networks"), "project already exists")
        images, runner.image_environments = {}, {}
        for index, image in enumerate(sorted({service["image"] for service in services.values()})):
            value = json.loads(runner.command("image-" + str(index), ["docker", "image", "inspect", "--format",
                '{"id":{{json .Id}},"environment":{{json .Config.Env}},"entrypoint":{{json (index .Config "Entrypoint")}}}', image], 10))
            require(admitted_image_entrypoint(image, value["entrypoint"]), "image entrypoint differs")
            images[image], runner.image_environments[image] = value["id"], environment(value["environment"])
        runner.save("run.claim.json", {"sourceCommit": args.commit, "source": str(source), "binarySha256": args.expected_binary_sha256,
            "checkerSha256": recipe.base.digest(source / SCRIPT), "images": images, "jobRoot": str(root), "syntheticOnly": True,
            "sdkPackages": dependencies["packages"], "sdkPackagesRoot": str(args.sdk_packages),
            "sdkReceiptSha256": args.expected_sdk_receipt_sha256,
            "sdkRequirementsSha256": dependencies["requirementsSha256"]})
        (root / "runtime").mkdir(mode=0o700)
        compose_file = root / "compose.json"
        with compose_file.open("x") as stream:
            json.dump(config, stream, sort_keys=True, indent=2)
        compose = ["docker", "compose", "-f", str(compose_file), "-p", runner.project]
        armed = True
        for phase, profile in (("initialize", "prepare"), ("network-files", "network-files")):
            runner.command(phase, compose + ["--profile", profile, "run", "--rm", "--no-deps", "--pull", "never", phase], 30)
        phase, keeper = "network", time.monotonic()
        runner.command("network", compose + ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "15", "network"], 20)
        phase = "app-and-gate"
        runner.start_app_then_gate(compose)
        phase = "pki-edge"
        runner.command("basic-pki", compose + ["--profile", "basic-pki", "run", "--rm", "--no-deps", "--pull", "never", "basic-pki"], 25)
        runner.command("edge", compose + ["--profile", "edge", "up", "-d", "--no-build", "--pull", "never", "--no-deps", "edge"], 10)
        runner.command("create-check", compose + ["--profile", "check", "up", "--no-start", "--no-recreate", "--no-build", "--pull", "never", "--no-deps", "check"], 10)
        phase = "inspect"
        identities = runner.inspect_runtime(config, images, keeper_anchor=keeper)
        runner.deadline = runner.admit_checker_window(identities["edge"], keeper_anchor=keeper, work_anchor=begun)
        phase = "check"
        result = json.loads(runner.command("connected-check", ["docker", "start", "--attach", identities["check"]], 190))
        runner.save("result.json", result)
        require(result.get("ok") is True, "connected check failed")
        phase, success = "complete", True
    except BaseException as error:
        failure = {"exceptionType": type(error).__name__, "sourceSite": failure_site(error, source)}
    finally:
        runner.deadline = time.monotonic() + 60
        if armed:
            try:
                rows = runner.container_rows("cleanup-before")
                for row in rows:
                    name = row["Config"]["Labels"]["com.docker.compose.service"]
                    if name in {"provider", "serverware", "decision-gate-rs"}:
                        runner.command("retained-" + name + "-logs", ["docker", "logs", "--tail", "60", row["Id"]], 3)
                ids = [row["Id"] for row in rows]
                if ids:
                    runner.command("cleanup-stop", ["docker", "stop", "--time", "5", *ids], 20)
                    runner.command("cleanup-remove", ["docker", "rm", *ids], 10)
                clean = not runner.container_rows("cleanup-after") and runner.no_project_networks("cleanup-networks")
            except Exception:
                clean = False
        terminal = {"success": success, "cleanup": clean, "phase": phase, "failure": failure,
            "sourceCommit": args.commit, "binarySha256": args.expected_binary_sha256,
            "elapsedSeconds": round(time.monotonic() - begun, 3), "syntheticOnly": True, "realAwsVerified": False}
        runner.save("terminal.json", terminal)
        print(json.dumps(terminal, sort_keys=True), flush=True)
    return 0 if success and clean else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    host = modes.add_parser("run")
    for name in ("source", "binary", "job-root", "evidence", "sdk-packages", "sdk-receipt"):
        host.add_argument("--" + name, type=Path, required=True)
    for name in ("commit", "expected-binary-sha256", "expected-sdk-receipt-sha256"):
        host.add_argument("--" + name, required=True)
    client = modes.add_parser("check")
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-curl-sha256", "expected-sdk-receipt-sha256"):
        client.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file", "curl-binary"):
        client.add_argument("--" + name, type=Path, required=True)
    for name in ("proxy-ca-file", "control-ca-file", "management-ca-file"):
        client.add_argument("--" + name, type=Path)
    client.add_argument("--timeout-seconds", type=int, default=180)
    for name in ("setup", "network", "provider", "edge"):
        modes.add_parser(name)
    args = parser.parse_args()
    os.umask(0o077)
    if args.mode == "run":
        for name in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"):
            os.environ.pop(name, None)
        os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
        return run(args)
    if args.mode == "check":
        return check(args)
    configure_network()
    if args.mode == "setup":
        signal.alarm(20)
        network.setup()
        Path("/upstream-data/ecr-artifacts").mkdir(mode=0o700)
    elif args.mode == "network":
        network.isolated.keep_namespace()
    elif args.mode == "edge":
        network.guided.edge()
    else:
        serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
