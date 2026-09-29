# Native principal preflight

This source-only opt-in adds `serverware.nativeProxyIngress/v3` to the
[native proof client](native-proof-client.md). It verifies the expected
principal and complete identity-policy commitment on the actual outer mTLS
connection before CONNECT, then retains a private typed proof through that
transport's reads, writes and flushes. It is not a JSON-verdict gate, provider
request authorization, successful canary, installation permission or production
readiness claim. No build or runtime validation is claimed for this slice.

## Independent configuration

The [v3 schema](../schemas/native-proxy-ingress.v3.schema.json) has exactly eight
fields: `apiVersion`, `startupEvidence`, `startupExpectations`, `sessionScope`,
`trustRoots`, `workloadIssuer`, `expectedPrincipal` and
`expectedIdentityPolicySha256`. The same existing configuration path and exact
SHA-256 pin arguments select it; neither a server response nor an installation
receipt may replace those originals. Configuration is capped at 16 KiB.

Startup evidence (64 KiB), startup expectations and session scope (16 KiB each),
Nitro roots (1 MiB), and the independently pinned canonical single-certificate
workload issuer PEM (64 KiB; DER 16 KiB) retain their existing held-file and
currentness checks. The initial startup quote must still be fresh before client
private-key loading. Current independent release, policy, runtime configuration,
server identity and trust pins remain required; installing a CA does not supply
their provenance.

`expectedPrincipal` must exactly equal the independent
`--expected-principal-id`. V3 preflight accepts 1..1024 UTF-8 bytes with no
leading/trailing Unicode whitespace or control characters. The identity-policy
pin is a nonzero lowercase `sha256:` digest of the complete policy, not a digest
invented from a certificate-selector subset. V1 and v2 remain strict and reject
both new fields, including null. Their principal limit remains 256 bytes.

## Same-connection continuation

The client sends the exact configured proxy authentication headers in the
principal-preflight exchange and later in CONNECT from the same immutable
argument vector. The bounded exchange helper derives its canonical sent-request
original from the same header map it writes to TLS; protocol-header overrides,
case-normalized duplicates and malformed values are refused. Header values may
be secrets. That original is temporary zeroizing storage for verification and
is never included in public capture output or error text.

Fresh original evidence is verified with the retained client challenge, the
actual `ClientConnection` and its TLS exporter, independently pinned scope and
Nitro roots, the selected workload issuer, and the public certificate chain
actually chosen by the original client certificate resolver. The issuer must
belong to the authenticated native framed-DER trust inventory; the selected
chain is genuinely verified under only that issuer. A standard PEM-bundle hash
or installation-result field is not equivalent to this proof.

The verifier returns only a private, non-serializable `PrincipalSession` owner
to the transport. It binds the expected principal, identity policy and actual
sent request to that connection. The transport checks this owner against its
same connection and selected chain before and after CONNECT and every later
read, write and flush, including buffered TLS plaintext. A failed v3 guard is
sticky. No copied success summary can construct or renew it, and failure does
not fall back to v1/v2. The existing empty-buffer continuation checks remain.

The original caller deadline is inherited, not restarted after preflight.
Quote, certificate and process/time validity can only narrow it. These checks
do not make blocked kernel operations a hard real-time watchdog, revoke bytes
already sent, establish an off-host latest-state witness, or provide continuous
policy refresh or long-running rotation/revocation handling.

## Deliberate remaining boundaries

The preflight authenticates a principal under the current full identity policy;
it does not authorize any particular provider route, credential, request body,
response handling or JIT grant. Those existing gates still run separately.
Legacy provider-response proof schemas and validators keep their own identity
limits. Under legacy response expectations the capture client checks compatibility
after genuinely opening its pinned ingress profile and before loading private
capture inputs or connecting.
The server checks the actual selected principal before response-proof setup or
provider effects, including the selected mode on each inner request. Buffered
proofs require a trim-stable, control-free identity of at most 256 UTF-8 bytes.
Streaming and observation additionally require an ASCII alphanumeric first
character and only ASCII alphanumerics or `._:/@-` afterward. These are early
refusals, not a change to the signed legacy contracts; the full existing response
validators still run. Errors do not echo the principal or authentication headers.

Standalone preflight still supports its own 1024-byte contract. A successful
preflight must not be presented as provider-proof compatibility. Separately
pinned [response expectations v2](native-response-principal-profiles.md) select
new native statement, receipt and binding profiles, with genuine control-plane
preparation/reservation and native custody signing. They do not reinterpret
legacy signed bytes or truncate, rename or remap identities. The separate
[native credential-lease profiles](native-credential-leases.md) connect the actual
recipient owner, broker and exact encrypted request scope without widening old
contracts or treating preflight as credential-release authority. Their independent
recipient expectations and real issuance checks remain mandatory. Egress and
canaries are still separate open work. Public captures remain
supporting local evidence with no new action authority.

The separate [native egress installation design](native-egress-installation-design.md)
records the next ownership and authorization boundary. It is a design, not an
implemented firewall or a successful onboarding canary.
