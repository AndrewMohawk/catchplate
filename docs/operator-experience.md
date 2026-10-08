# Operator experience

## Product mental model

**Let applications use APIs without giving them the provider's keys.**

An application authenticates to Serverware with its own scoped identity.
Serverware checks what that application may do, attaches the authorized provider
credential, and returns only a response allowed by the configured policy. The
provider credential stays out of the calling application's configuration.
The application still needs its Serverware identity; this is not a claim that
every client is secretless.

The interface should follow the operator's task, not the internal arrangement
of brokers, compilers, authorities, leases, and receipts.

## Target workflow

1. **Connect account.** Connect a provider account or store a supported API
   credential. Show which account is connected and its granted permissions,
   without displaying the secret. Operator sign-in and connecting a provider
   account are different actions.
2. **Set allowed actions.** Choose the application, API operations, constraints,
   and any required approval. Explain the proposed access in plain language;
   keep exact policy details available for review. Deny everything not allowed.
3. **Give app access.** Provision the application's scoped Serverware identity
   and provide verified connection instructions. Test an allowed request and a
   denied request before enabling real credentials. Never hand the provider's
   key to the application.
4. **Review activity.** Explain what was requested, what was allowed or blocked,
   and why. Make approvals, investigation, and export available where supported.

These are the broader product's target tasks, not a statement that the fixed
sandbox can perform account connection, policy publication, workload enrollment,
or production setup. Do not offer inactive versions of these controls as if
they were usable.

## First-class workspaces

The sandbox demonstrates the core request flow using a real proxy and an
isolated synthetic upstream. It is already configured, retains its test data
across reloads and restarts, and does not connect real provider accounts.

- **Overview** explains the product in one sentence, shows the application to
  Serverware to API flow, and offers one primary **Run demo** action. Results
  explain the observed behavior rather than only reporting a test count.
- **Proxy setup** makes the actual proxy connection settings, listener scope,
  client configuration, and downloadable public CA certificate easy to find.
  Distinguish the operator portal URL from the HTTP CONNECT proxy endpoint and
  the private management endpoint. Clearly state which settings are deployment
  managed and which client settings can be adjusted. Do not imply that changing
  a client example changes the server listener or access policy.
- **Credentials** shows the stored synthetic credential's name, kind, version,
  and non-secret metadata. Credential management is a first-class product task,
  not an incidental detail hidden under policy. Explain that adding or rotating
  real provider credentials is unavailable in this fixed sandbox.
- **Access rules** shows readable selections from the actual signed policy.
  Identify the application, destination, allowed methods and paths, and
  configured response restrictions.
  Local prototype route rows are not the effective policy; their enabled flags
  must not be presented as proof of allowed or implemented behavior.
- **Audit log** presents persisted events in understandable language, with
  search, local audit verification, and raw evidence secondary. It must be
  clear when no events have been loaded or a query returns no matches.

Configuration must remain easy to find: simplifying the interface is not a
reason to remove usable proxy settings, the CA download, or product workspaces.
Keep raw JSON and internal IDs secondary. Show security-relevant fingerprints
and actionable connection settings where they help the user perform the task.
Keep a concise, persistent demo-only notice; place the full limitations nearby
without repeating them in every panel. No dead controls, hidden prerequisites,
or unrelated initialization steps belong in this flow.

## Proxy configuration and CA trust

The current sandbox proxy is `http://decision-gate-rs:9090` on its private Docker
network. Its public HTTPS address serves the operator portal, not a public
forward proxy. A downloaded CA does not make that private listener reachable
from a laptop or another network. Instructions must state the client location
they support and must not substitute an unreachable endpoint or expose a new
listener silently.

The authenticated development download at `/ca.pem` supplies the public
interception CA certificate, never its private key. It is an audited debug
download, not verifier-mediated production trust. Client examples should scope
trust to the chosen client or isolated test environment; never recommend
disabling certificate validation or globally trusting a demo CA by default.
Production retains its separate verifier-mediated installation requirement.

The private management listener is `http://decision-gate-rs:9091`. It is neither
a client proxy URL nor an interface to expose through the browser portal.
Listener and destination changes remain deployment-managed in this sandbox;
client configuration must preserve its synthetic-only destination restrictions.

## What the demo outcomes mean

| Outcome | Meaning |
| --- | --- |
| Allowed request | The actual TLS proxy forwarded an allowed request with the synthetic credential, removed tested caller-sensitive headers, and returned the permitted response fields. |
| Unauthorized requests blocked | The tested identity, destination, credential-header collision, path, and method denials behaved as expected. Relevant upstream counters confirm tested requests did not reach their destinations. |
| Unsafe response blocked | The synthetic upstream reflected its credential, and Serverware refused to release that response. This happens after upstream dispatch; it does not undo an upstream action. |
| Activity recorded | Persisted audit events correlate with the demo request and blocked response, without the tested credential material appearing in those events. |

An outcome is successful only when the corresponding real checks have
completed. Before a run, show an untested state. While running, show progress
without invented intermediate success. On failure, preserve completed results
and describe the failed check; do not paint all outcomes green or automatically
retry an uncertain request.

Transforming request streams, including nested JSON, is unsupported in this
sandbox. The demo checks that such a request is refused before dispatch. That
negative control is not proof of a working transformation feature.

## Evidence and safety language

- **Local audit verified** means the stored audit chain passed the local
  verification check. It is not hardware verification, an independent witness,
  or proof of enclave execution. Show incomplete and failed verification
  distinctly from success.
- **Demo passed** means the fixed synthetic checks passed for that run. It does
  not mean production acceptance, real-provider integration, or full policy
  feature coverage. A configured policy entry alone is not a capability test.
- A healthy service or ready certificate authority is a component observation,
  not an overall readiness result. Technical status must not replace the
  user's task or imply that untested workflows work.
- Never reveal credentials in results, activity, error messages, or copied
  technical details. Keep existing authentication, authorization, and
  sandbox-only mutation restrictions intact.

The simplified experience changes presentation and navigation, not the
credential boundary or the full production acceptance requirements.
