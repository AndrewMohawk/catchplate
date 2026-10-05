"""Distinct fixed maintenance custody principals, never runtime provisioning.

Separate principals preserve the existing aggregate successor roles' exact
single-function grants. A cold source installation must bind their actual TLS
and measured identities; constants and supplied configuration are not evidence
that that installation or measured launch happened.
"""
from types import MappingProxyType


OPERATION = "webauthn.challenge.maintain"
ISSUER_ROLE = "serverware_policy_authority_challenge_issuer"
EXECUTOR_ROLE = "serverware_policy_authority_challenge_executor"
STEP_FUNCTION = "serverware_policy_authority_retain_challenge_step"
SEAL_FUNCTION = "serverware_policy_authority_seal_challenge_execution"
EXECUTE_FUNCTION = "serverware_policy_authority_execute_challenge"
ISSUER_IDENTITY_DOMAIN = "serverware.policyAuthorityChallengeMaintenanceIssuerSession/v1"
EXECUTOR_IDENTITY_DOMAIN = "serverware.policyAuthorityChallengeMaintenanceExecutorSession/v1"
FUNCTION_SIGNATURES = MappingProxyType({
    STEP_FUNCTION: ("text", "integer", "text", "text", "bigint"),
    SEAL_FUNCTION: ("text", "text", "text"),
    EXECUTE_FUNCTION: ("text", "text"),
})
ROLE_FUNCTIONS = MappingProxyType({ISSUER_ROLE: (STEP_FUNCTION, SEAL_FUNCTION),
    EXECUTOR_ROLE: (EXECUTE_FUNCTION,)})
