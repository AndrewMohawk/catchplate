"""Closed lease representations; profile selection grants no release authority."""

from __future__ import annotations

import hmac

from serverware import release_authorization_profiles as release_profiles


NATIVE_REQUEST_V1 = "serverware.nativeCredentialLeaseRequest/v1"
NATIVE_REQUEST_V2 = "serverware.nativeCredentialLeaseRequest/v2"
NATIVE_AUTHORITY_V1 = "serverware.nativeCredentialLeaseRequestAuthority/v1"
BROKER_REQUEST_V1 = "serverware.nativeBrokerCredentialLeaseRequest/v1"
BROKER_REQUEST_V2 = "serverware.nativeBrokerCredentialLeaseRequest/v2"
POLICY_AWARE_REQUEST_V1 = "serverware.policyAwareCredentialLeaseRequest/v1"
POLICY_AWARE_REQUEST_V2 = "serverware.policyAwareCredentialLeaseRequest/v2"
POLICY_AWARE_AUTHORITY_V1 = "serverware.policyAwareCredentialLeaseRequestAuthority/v1"
OPERATOR_X_QUOTA_REQUEST_V1 = "serverware.operatorXQuotaCredentialLeaseRequest/v1"


def request_representation(api_version: str) -> tuple[str, bool]:
    if api_version == OPERATOR_X_QUOTA_REQUEST_V1:
        # Distinct ordinary signed wrapper; no native/requestAuthority fields.
        # The existing unbound recipient encryption is retained inside it.
        return "operator-x-quota", False
    if api_version == BROKER_REQUEST_V1:
        return "native-broker", False
    if api_version == BROKER_REQUEST_V2:
        return "native-broker", True
    if api_version == POLICY_AWARE_REQUEST_V1:
        return "policy-aware", False
    if api_version == POLICY_AWARE_REQUEST_V2:
        return "policy-aware", True
    native, bound = request_profile(api_version)
    return ("native" if native else "legacy"), bound


def request_profile(api_version: str) -> tuple[bool, bool]:
    profiles = {
        "serverware.credentialLeaseRequest/v3": (False, False),
        "serverware.credentialLeaseRequest/v4": (False, True),
        NATIVE_REQUEST_V1: (True, False),
        NATIVE_REQUEST_V2: (True, True),
    }
    try:
        return profiles[api_version]
    except (KeyError, TypeError) as exc:
        raise ValueError("unsupported credential lease request profile") from exc


def _version(family: str, *, native: bool, version: int,
             policy_aware: bool = False) -> str:
    if type(native) is not bool or type(policy_aware) is not bool or (native and policy_aware):
        raise ValueError("credential lease profile must be explicit")
    prefix = ("nativeCredentialLease" if native else
              "policyAwareCredentialLease" if policy_aware else "credentialLease")
    return f"serverware.{prefix}{family}/v{version}"


def authority_version(*, native: bool, policy_aware: bool = False) -> str:
    return _version("RequestAuthority", native=native, policy_aware=policy_aware, version=1)


def release_version(*, native: bool, durable: bool, policy_aware: bool = False) -> str:
    if type(durable) is not bool:
        raise ValueError("credential release durability must be explicit")
    return _version("ReleaseAuthorization", native=native, policy_aware=policy_aware,
                    version=2 if durable else 1)


def envelope_version(*, native: bool, bound: bool, policy_aware: bool = False,
                     broker: bool = False) -> str:
    if type(bound) is not bool:
        raise ValueError("credential request binding must be explicit")
    if type(broker) is not bool or (broker and (native is not True or policy_aware is not False)):
        raise ValueError("ciphertext delivery requires the explicit native broker profile")
    if broker:
        return "serverware.nativeBrokerCredentialLeaseEnvelope/v" + str(1 + int(bound))
    return _version("Envelope", native=native, policy_aware=policy_aware,
                    version=(1 if native or policy_aware else 2) + int(bound))


def set_version(*, native: bool, bound: bool, policy_aware: bool = False,
                broker: bool = False) -> str:
    if type(bound) is not bool:
        raise ValueError("credential request binding must be explicit")
    if type(broker) is not bool or (broker and (native is not True or policy_aware is not False)):
        raise ValueError("ciphertext delivery requires the explicit native broker profile")
    if broker:
        return "serverware.nativeBrokerCredentialLeaseSet/v" + str(1 + int(bound))
    return _version("Set", native=native, policy_aware=policy_aware,
                    version=(1 if native or policy_aware else 3) + int(bound))


def native_identity(value: str, *, principal: bool = False) -> str:
    # Rust's retained nonprincipal predicate uses the same Unicode Cc rule,
    # but only the separately versioned principal may exceed 256 UTF-8 bytes.
    release_profiles.native_principal(value)
    if not principal and len(value.encode("utf-8")) > 256:
        raise ValueError("native credential lease identity exceeds 256 UTF-8 bytes")
    return value


def policy_aware_identity(value: str) -> str:
    return native_identity(value)


def text_matches(actual: str, expected: str, *, native: bool,
                 policy_aware: bool = False) -> bool:
    if type(native) is not bool or type(policy_aware) is not bool or (native and policy_aware):
        raise ValueError("credential lease comparison profile must be explicit")
    if not isinstance(actual, str) or not isinstance(expected, str):
        return False
    if native or policy_aware:
        try:
            return hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8"))
        except UnicodeError:
            return False
    return hmac.compare_digest(actual, expected)
