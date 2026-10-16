"""Portable ordinary-host Compose model; never builds, pulls, or creates state."""
from pathlib import Path

EDGE_IMAGE = "nginx@sha256:1ed1b0e1d7652937d6cbdaf4018c7b6fc009a7dd6c3047351e2eddda745de43f"
TOKENS = {
    "ADMIN": "admin.token",
    "DATA_PLANE_CREDENTIAL_LEASE": "credential-lease.token",
    "DATA_PLANE_AUDIT": "audit.token",
    "DATA_PLANE_GRANT_CONSUME": "grant-consume.token",
    "DATA_PLANE_RATE_LIMIT_CONSUME": "rate-limit-consume.token",
    "DATA_PLANE_RELEASE_AUTHORIZATION": "release-authorization.token",
    "DATA_PLANE_MANAGEMENT": "management.token",
}
PUBLICATION_FILES = (
    "gate-runtime/policy-bundle.json", "gate-runtime/operator-google-configuration.json",
    "gate-runtime/operator-x-configuration.json", ".operator-publication.lock",
    ".serverware-operator-demo.json", "mitmproxy/mitmproxy-ca-cert.pem",
    "mitmproxy/mitmproxy-ca.pem",
)


def _bind(source, target, readonly=False):
    return {"type": "bind", "source": str(source), "target": target,
        "read_only": readonly, "bind": {"create_host_path": False}}


def _health(port):
    code = ("import json,urllib.request; "
        "o=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
        f"r=o.open('http://127.0.0.1:{port}/healthz',timeout=2); "
        "b=r.read(65537); raise SystemExit(0 if r.status==200 and len(b)<=65536 "
        "and json.loads(b).get('ok') is True else 1)")
    return {"test": ["CMD", "python", "-I", "-B", "-c", code],
        "interval": "5s", "timeout": "3s", "retries": 6, "start_period": "30s"}


def render(config, artifact, instance_id):
    """Inputs are validated/pinned by init; generated model contains no secrets."""
    import json
    state = Path(config["state_dir"])
    shared = {
        "SERVERWARE_OPERATOR_DEMO": "1", "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": json.dumps(config["allowed_upstreams"], separators=(",", ":")),
        "SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS": "[]",
        "SERVERWARE_OPERATOR_DEMO_PROXY_URL": config["proxy_origin"],
        "SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1",
        "SERVERWARE_OPERATOR_MANAGED_X_ENABLED": "1",
        "SERVERWARE_HOST_TRUSTED_APPROVALS_ENABLED": "1",
        "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
        "SERVERWARE_DATA_PLANE_INSTANCE_ID": instance_id,
    }
    isolated = {
        "image": config["paired_image"], "pull_policy": "never", "restart": "unless-stopped",
        "user": "10001:10001", "init": True, "read_only": True, "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"], "pids_limit": 128,
        "labels": {"io.serverware.installation": instance_id},
        "networks": ["control", "outbound"],
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700"],
        "logging": {"driver": "local", "options": {"max-size": "2m", "max-file": "2"}},
    }
    app_environment = {**shared,
        "SERVERWARE_PROCESS_MODE": "serverware-control-plane", "SERVERWARE_DATA_DIR": "/data",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite", "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite", "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_DEV_AUTHENTICATOR": "0", "SERVERWARE_DEV_DEMO_SEED": "0",
        "SERVERWARE_PUBLIC_URL": config["console_origin"], "SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED": "1",
        "SERVERWARE_ADMIN_USER": "user:" + config["admin_username"],
        "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
        "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": artifact["dataPlaneBinaryDigest"],
        "SERVERWARE_DECISION_GATE_BASE": "http://decision-gate-rs:9091",
        "SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED": "1",
        "SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR": "/provider-custody",
        "SERVERWARE_OPERATOR_X_CUSTODY_DIR": "/x-custody",
        "SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED": "1",
        "SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR": "/notification-custody",
        "SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON": '{"bindings":[]}',
        "SERVERWARE_ECR_ARTIFACT_ROOT": "/ecr-artifacts",
        **{"SERVERWARE_" + key + "_TOKEN_FILE": "/run/secrets/serverware/" + filename
            for key, filename in TOKENS.items()},
    }
    app = {**isolated, "command": ["app"], "working_dir": "/app", "cpus": 2,
        "mem_limit": "8g", "environment": app_environment, "healthcheck": _health(3000),
        "volumes": [_bind(state / "app-data", "/data"),
            _bind(state / "service-secrets", "/run/secrets/serverware", True),
            *[_bind(state / name, "/" + name) for name in
                ("provider-custody", "x-custody", "notification-custody", "ecr-artifacts")]]}
    gate_tokens = ("credential-lease.token", "audit.token", "management.token")
    gate_environment = {**shared,
        "SERVERWARE_ALLOW_INSECURE_DEV_CREDENTIAL_LEASES": "1",
        "SERVERWARE_POLICY_BUNDLE": "/data/policy-bundle.json",
        "SERVERWARE_POLICY_HIGH_WATER_FILE": "/gate-data/policy-high-water.json",
        "SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL": "http://serverware:3000/attestation",
        "SERVERWARE_CONTROL_PLANE_CREDENTIAL_LEASE_URL": "http://serverware:3000/api/data-plane/credential-leases",
        "SERVERWARE_CONTROL_PLANE_AUDIT_URL": "http://serverware:3000/api/data-plane/audit",
        "SERVERWARE_DATA_PLANE_AUDIT_BATCH_MAX": "1",
        "SERVERWARE_MITM_CA_CERT": "/data/mitmproxy/mitmproxy-ca-cert.pem",
        "SERVERWARE_MITM_CA_KEY": "/data/mitmproxy/mitmproxy-ca.pem",
        "SERVERWARE_PROXY_INGRESS_MODE": "operator-demo-tls-edge",
        "SERVERWARE_DECISION_GATE_HOST": "0.0.0.0", "SERVERWARE_DECISION_GATE_PORT": "9090",
        "SERVERWARE_DECISION_GATE_MANAGEMENT_HOST": "0.0.0.0", "SERVERWARE_DECISION_GATE_MANAGEMENT_PORT": "9091",
        **{"SERVERWARE_" + key + "_TOKEN_FILE": "/run/secrets/serverware/" + filename
            for key, filename in TOKENS.items() if filename in gate_tokens},
    }
    gate = {**isolated, "command": ["gate"], "cpus": 1, "mem_limit": "512m",
        "environment": gate_environment, "healthcheck": _health(9091),
        "volumes": [_bind(state / "app-data/gate-runtime", "/data", True),
            _bind(state / "gate-data", "/gate-data"),
            *[_bind(state / "app-data" / name, "/data/" + name, True) for name in
                (".operator-publication.lock", ".serverware-operator-demo.json",
                 "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")],
            *[_bind(state / "service-secrets" / name, "/run/secrets/serverware/" + name, True)
                for name in gate_tokens]]}
    edge = {**isolated, "image": config["edge_image"], "networks": ["control", "outbound"],
        "entrypoint": ["nginx"], "command": ["-g", "daemon off;"], "cpus": 0.25,
        "mem_limit": "64m", "pids_limit": 32,
        "volumes": [_bind(state / "edge/nginx.conf", "/etc/nginx/nginx.conf", True),
            _bind(state / "edge-secrets", "/run/serverware", True)],
        "healthcheck": {"test": ["CMD", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8081/edge-healthz"],
            "interval": "5s", "timeout": "3s", "retries": 6, "start_period": "5s"}}
    if config.get("publish_address") is not None:
        edge["ports"] = [config["publish_address"] + ":8443"]
    networks = {"control": {"internal": True, "labels": {"io.serverware.installation": instance_id}},
        "outbound": {"labels": {"io.serverware.installation": instance_id}}}
    if config.get("network_subnets") is not None:
        for name in networks:
            networks[name]["ipam"] = {"config": [{"subnet": config["network_subnets"][name]}]}
    return {"name": config["project_name"], "services": {
        "serverware": app, "decision-gate-rs": gate, "edge": edge},
        "networks": networks}
