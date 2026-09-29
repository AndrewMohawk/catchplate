# Native encrypted service-token startup

`serverware.nativeStartupConfiguration/v6` connects the full native proxy's service credentials to the actual enclave broker. This is source integration only: no build, enclave execution, provider contact or deployment acceptance is claimed. It does not establish a secretless EIF, complete configuration delivery, measured OAuth effects or N06 closure.

## Explicit cold selection

The fixed native enclave image entrypoint now executes `--native-encrypted-startup`, which requires exact v6. Its existing configuration/launch path-and-hash flags and optional public-identity output remain unchanged. Direct `--native-enclave-startup` still selects exact v5; `--native-startup` preserves v1-v5 and refuses v6. Unknown versions and failed encrypted startup never select an older mode or an environment token.

The [closed v6 schema](../schemas/native-startup-configuration.v6.schema.json) preserves v5's twelve top-level fields and adds required `encryptedServiceTokens`. All six bearer slots in `gate` must be explicitly null: `credentialLeaseToken`, `grantConsumeToken`, `rateLimitConsumeToken`, `releaseAuthorizationToken`, `managementToken` and `auditToken`. No placeholder bearer value is generated. Measured audit still requires its URL and independently generated mTLS owner, not a bundle token.

Non-atomic service authorization requires both grant and rate-limit URLs. Atomic authorization requires its release base URL. For every configured service URL, the eventual corresponding bundle token is required; an absent optional URL requires a null token. Lease and management tokens are always required. Existing token length, whitespace/control, strength and pairwise-distinctness checks remain, with bounded HTTP header syntax checked before installation. The older wire versions retain their plaintext requirements.

## Actual binding and installation

The bundle is the separately defined [purpose-fixed envelope](../schemas/native-service-tokens.v1.schema.json#/$defs/envelope). Its binding commits the instance, actual gate binary digest, admitted policy hash, atomic-mode selection and exact lease/grant/rate/release endpoints. Cold parsing compares it to the retained startup inputs; bootstrap compares it again after measuring the running executable and admitting the exact policy snapshot. The instance is the same retained value used for the actual ingress identity. An envelope-supplied binding is not substituted for any of those inputs.

The existing [permanent serving privilege transition](native-serving-privilege-separation.md) runs first: privileged NSM/helper preparation, irreversible gate drop, then real native identity/proof construction. Bootstrap joins the identity and broker on the original deadline, and only then calls `Owner::open_service_tokens` with the expected binding. The broker owns KMS/KEK provenance, the private helper, its one-shot service phase and the fresh gate recipient; there is no general decrypt call or plaintext parent response.

The helper opens only the bounded fixed-purpose AES-GCM envelope, whose padded plaintext is 32 KiB. Gate-recipient ciphertext is a separate output family from credential delivery. The gate validates the returned five nullable token fields before taking them from the zeroizing token owner into its ordinary in-memory service fields. Unused values remain under that owner's drop handling. No token or decrypted bundle is printed, written into a cold configuration or added to audit output by this integration.

The binary's pending state is consumed before opening. Failed or still-pending state cannot enter `GateState`; both actual state constructors propagate that refusal. Installation and full validation happen before audit initialization, state sharing, credential workers and serving. No contact/start deadline is renewed, and opening uncertainty aborts this startup rather than retrying.

## Provisioning and verification still required

The encrypted bundle requires an independently assigned genuine broker KEK and exact binding; ciphertext alone is not authorization. The original protected configuration, launch references/nonces, release admission, policy, ledger permissions, response-custody assignment, immutable helper closure and measured audit admission remain mandatory. Configuration files still use the existing owner-only custody rules even when these bearer slots contain no plaintext.

Tokens intentionally exist inside the gate after installation and are sent only by their actual service clients. This change does not claim memory never contains secrets, that every startup artifact is public, that a self-contained EIF can already be produced, or that old provisioning material can be silently migrated. Real AWS/KMS, negative-path, failure-cleanup and full proxy validation remain unperformed.
