# Native Setup runtime-evidence portal

Source-only UI consumer of the [protected runtime-evidence backend](setup-native-runtime-evidence.md).
No browser, parser, test, build, proxy request or signing operation was executed
for this batch. It does not complete native host, final Setup or pilot acceptance.

The native Setup page adds one explicit workflow after native-canary association:

1. The current OIDC-session requester with both `credential_owner` and
   `policy_author` selects the exact Setup session and confirms preparation.
   The fixed `options` route returns the actual purpose-specific hardware
   challenge and source-selected arguments digest. The browser validates that
   fixed purpose; it does not reconstruct the server's protected arguments.
2. A fresh passkey precedes the one `prepare` call. A nonsecret marker is retained
   in sessionStorage before its dispatch. The exact returned attempt/scope/native
   expectations strings are byte-preserved and available as separate downloads.
   Review the target before any independently authorized operator proxy action.
3. The operator imports the actual buffered `nativeResponseCapture/v2` file,
   at most 512 KiB. The browser rejects duplicate keys and unsupported outer
   profiles, structurally rejoins the nonce/request/policy and retains the exact
   original UTF-8 bytes, including whitespace and LF. It neither trusts a capture
   verdict nor performs cryptographic verification on the server's behalf.
4. Explicit confirmation precedes one `complete` upload, with its own
   sessionStorage marker before dispatch. The protected backend independently verifies
   original collector/native signatures, quote, dispatch receipt and current
   source state before its CAS. Only the returned fixed result is displayed.

Lost responses permit `lookup`, not automatic retry. Lookup recovers the exact
old bundle and definite recorded result where present, without clearing either
marker or renewing the original deadline. The browser holds originals only in
memory and clears them on Setup/auth changes or page exit. No private key,
capture bytes, assertion or full original is placed in browser storage.
SessionStorage is a same-tab warning fence, not the durable authority: the
protected server-side attempt is the one-use CAS and survives browser loss.

The page never contacts the proxy, creates a collector key, signs a receipt,
executes an installer or treats downloaded expectations as new trust authority.
One-use evidence consumption is not enforced single upstream contact. The
existing proof client can be rerun, so a separately pinned local contact owner
remains required before claiming a no-repeat network guarantee. Historical
downloads are not permission to repeat an uncertain request.

Every accepted response preserves `okForAction`, `automaticRetryAllowed`,
`nativeHostVerified`, `enrollmentComplete` and `proxyReady` as false. The exact
HTTP fields and original byte limits are in the [schema](../schemas/setup-native-runtime.v1.schema.json).
