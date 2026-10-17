"""Closed public-file installation approval, not native admission or readiness.

Only receiver cold/v2 explicitly delegates this purpose to its existing C9
authority. Every file byte is signed; no credential, journal or executable can
enter the fixed roster. The enclave verifies this before exclusive writes.
"""
from catchplate import native_activation_receiver_profile as profile

p = profile.p
INPUT_API = "catchplate.nativeActivationReceiverInstallationAuthorityInput/v1"
API = "catchplate.nativeShadowActivationReceiverInstallation/v1"
COMPLETION_API = "catchplate.nativeShadowActivationReceiverCompletion/v2"
DOMAIN = "catchplate.nativeShadowActivationReceiverInstallation.signature/v1"
NAMESPACE = "/etc/catchplate/native-activation-inputs"
LAUNCH = "/etc/catchplate/native-shadow-guest-launch.json"
VERIFIER = "/etc/catchplate/native-shadow-public-exchange.json"
MAX_COMPLETION = 1024 * 1024
MAX_TOTAL = 720 * 1024
ROSTER = {
    **{NAMESPACE + "/" + name + ".json": maximum for name, maximum in (
        ("activation-authority", 512 * 1024), ("activation", 65536), ("admission", 65536),
        ("assignment", 512 * 1024), ("closure", 512 * 1024), ("delivery", 65536),
        ("encrypted-keys", 65536), ("keys", 65536), ("runtime", 512 * 1024),
        ("time-bootstrap", 65536), ("trust", 512 * 1024))},
    LAUNCH: 32768, VERIFIER: 32768,
}
PAYLOAD_FIELDS = ("apiVersion", "purpose", "observationSha256", "configurationSha256",
    "deliveryConfigurationSha256", "launchSha256", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "files")
LAUNCH_FIELDS = ("apiVersion", "deliveryConfiguration", "delivery", "trust", "timeBootstrap", "assignment",
    "closure", "keys", "encryptedKeys", "admission", "verifierTransport")


def completion(payload, signature):
    p.decoded(signature, size=64)
    raw = p.canonical({"apiVersion": COMPLETION_API, "installation": {"payload": payload, "signature": signature}})
    p.require(len(raw) <= MAX_COMPLETION)
    return raw


def prepare(raw, *, now_unix_ns):
    value = p.fields(p.document(raw, profile.MAX_INPUT),
        ("apiVersion", "serviceInputOriginal", "signedServiceOriginal", "payloadOriginal"))
    p.require(value["apiVersion"] == INPUT_API)
    service_input, _ = profile.original(value["serviceInputOriginal"], 4 * 1024 * 1024)
    service = profile.prepare_service(service_input, now_unix_ns=now_unix_ns)
    service_raw, _ = profile.original(value["signedServiceOriginal"], 65536)
    profile.verify_service(service, service_raw)
    delivery = service["delivery"]
    receiver = delivery["receiver"]
    p.require(receiver["apiVersion"] == "catchplate.nativeShadowActivationReceiverConfiguration/v2"
        and receiver["installationAuthority"] == delivery["cold"]["authority"])
    payload_raw, payload = profile.original(value["payloadOriginal"], MAX_COMPLETION)
    p.fields(payload, PAYLOAD_FIELDS)
    p.require(payload["apiVersion"] == API and payload["purpose"] == "install-activation-public-originals"
        and payload["observationSha256"] == p.sha(delivery["observation_raw"])
        and payload["configurationSha256"] == p.sha(delivery["receiver_raw"])
        and payload["deliveryConfigurationSha256"] == receiver["deliveryConfiguration"]["sha256"]
        and payload["issuedAtBoottimeNs"] == delivery["payload"]["issuedAtBoottimeNs"]
        and payload["startupDeadlineBoottimeNs"] == delivery["payload"]["startupDeadlineBoottimeNs"])
    entries = payload["files"]
    p.require(type(entries) is list and len(entries) == len(ROSTER))
    files, total = {}, 0
    for entry, path in zip(entries, sorted(ROSTER)):
        p.fields(entry, ("path", "sha256", "originalBase64url"))
        p.require(entry["path"] == path)
        original = p.decoded(entry["originalBase64url"], maximum=ROSTER[path])
        p.require(p.sha(original) == p.digest(entry["sha256"]))
        p.document(original, ROSTER[path])
        total += len(original); p.require(total <= MAX_TOTAL)
        files[path] = original

    def pin(selected, path):
        profile.delivery._pin(selected)
        p.require(selected == {"path": path, "sha256": p.sha(files[path])})

    launch = p.fields(p.document(files[LAUNCH], ROSTER[LAUNCH]), ("apiVersion", "keyAdmission", "activation"))
    p.require(launch["apiVersion"] == "catchplate.nativeShadowActivationGuestLaunch/v1"
        and payload["launchSha256"] == p.sha(files[LAUNCH]))
    inner = p.fields(launch["keyAdmission"], LAUNCH_FIELDS)
    p.require(inner["apiVersion"] == "catchplate.nativeShadowGuestLaunch/v1"
        and inner["deliveryConfiguration"] == receiver["deliveryConfiguration"])
    for field, leaf in (("delivery", "delivery"), ("trust", "trust"), ("timeBootstrap", "time-bootstrap"),
            ("assignment", "assignment"), ("closure", "closure"), ("keys", "keys"),
            ("encryptedKeys", "encrypted-keys"), ("admission", "admission")):
        pin(inner[field], NAMESPACE + "/" + leaf + ".json")
    pin(inner["verifierTransport"], VERIFIER)
    pin(launch["activation"], NAMESPACE + "/activation.json")
    pin(delivery["payload"]["runtimeConfig"], NAMESPACE + "/runtime.json")
    pin(service["payload"]["authority"], NAMESPACE + "/activation-authority.json")
    p.require(files[NAMESPACE + "/delivery.json"] == service["delivery_original"]
        and files[NAMESPACE + "/activation.json"] == service_raw
        and files[NAMESPACE + "/admission.json"] == p.canonical(service["configuration"]["admissionAuthorization"]))
    keys = p.fields(p.document(files[NAMESPACE + "/keys.json"], 65536), ("apiVersion", "authorization"))
    p.require(keys["apiVersion"] == "catchplate.nativeShadowRoleKeys/v2"
        and keys["authorization"] == service["configuration"]["authorization"])
    encrypted = p.fields(p.document(files[NAMESPACE + "/encrypted-keys.json"], 65536), ("apiVersion", "authorization"))
    p.require(encrypted["apiVersion"] == "catchplate.nativeShadowEncryptedKeyDelivery/v1")
    inventory_sha = p.digest(encrypted["authorization"]["payload"]["transport"]["encryptedInventorySha256"])
    inventories = 0
    for credential in delivery["payload"]["credentials"]:
        path = credential["original"]["path"]
        p.require(path not in files and path != NAMESPACE and not path.startswith(NAMESPACE + "/")
            and not credential["name"].startswith("shadow-key-custody-"))
        if credential["name"] == "shadow-encrypted-role-inventory":
            p.require(credential["signing"] is None and 1 <= credential["length"] <= 32768
                and credential["original"]["sha256"] == inventory_sha)
            inventories += 1
    p.require(inventories == 1)
    # A fixed-width placeholder bounds the final wrapper; it never leaves this
    # public size check or confers a signature-verification result.
    completion(payload, p.encoded(bytes(64)))
    return {"service": service, "payload": payload, "payload_raw": payload_raw, "signer": delivery["signer"]}
