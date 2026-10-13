> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Connected X accounts

This implementation belongs to the ordinary, persistent Serverware workspace;
it is not a second demo or an alternative approval authority. It is feature
gated and **not deployed or accepted against real X**. The running deployment
remains the pair recorded in [project completion](project-completion.md).
The connected Node/Python/Go posting flow has passed isolated synthetic-provider
acceptance through the normal Rust proxy; see the checkpoint below.

## User workflow

1. The operator configures the X OAuth application and explicitly allows the
   provider destination. Configuration alone does not grant posting access.
2. When the app and proxy report the same configuration and policy, an
   administrator starts consent and connects an X account. The callback uses
   PKCE, one-use state and a browser-bound cookie; identity is verified with X.
3. Assign an application the fixed text-post permission. It admits only the
   typed `x.post.v1` operation on `POST https://api.x.com/2/tweets`.
4. Near-expiry tokens refresh automatically through the retained X account
   owner, with the same numeric subject, client, application and rule bindings.
5. Review and disconnect the account. Local access is fenced before provider
   cleanup. This protective action remains available when proxy readiness is
   unavailable; an uncertain cleanup result never means remote revocation was
   confirmed.

This slice does **not** provide a shared daily quota, approval actions, a
host-trusted substitute for measured authority, native enrollment, or general
X API permissions. It does not adopt legacy X credentials or use Google OAuth
configuration. Public proxy DNS and real-provider consent remain separate.

## Recovery and credential boundaries

The browser retains only operation UUIDs, never authorization URLs, state,
codes or tokens. Recovery GETs inspect durable state without resubmission,
provider calls or publication repair. Uncertain work is held for inspection.
Explicit acknowledgement clears only a validated terminal operation.

Provider requests are bounded, one-shot, fixed-origin HTTPS exchanges. Claims
are persisted before contact and private response material is captured before
classification. Original deadlines are not renewed. Token expiry is anchored
conservatively before dispatch, not after delayed persistence. Cleanup material
and journal capacity are reserved before issuing further tokens, so normal
capacity exhaustion cannot disable protective local disconnect.

Generic credential, refresh, cache and injection paths refuse managed-X
markers. The dedicated lease path checks the actual application/rule/policy
before refresh, before subsequent contacts, at adoption, and in the final
credential snapshot. An expired original deadline after audit also prevents
envelope output. Google and X generation-reconciliation capabilities remain
distinct; native/currentness restrictions are unchanged.

## Verification checkpoint

The October 12 source checkpoint has 20 passing isolated SQLite/configuration/
manifest/store tests, 18 refresh/reconciliation component checks, seven lease
boundary checks using real envelope encryption, and four generic-secret
boundary checks. The UI's 15 inert-controller and 14 asset checks also passed.
These are bounded component results, not a complete posting demonstration.

The first mixed test invocation failed during environment setup (missing
scratch directory and process mode). Corrected isolated execution produced the
results above. Catalog timing passed 21 tests with exit zero. Catalog observation
completed all ten assertions, but its outer command timed out with exit 124;
that is not a clean command receipt.

Six rendered desktop/mobile browser groups passed against real assets with
intercepted synthetic APIs, including UUID-only recovery and protective
disconnect with an unavailable gate. The first browser attempt exposed an
incorrect test expectation for an intentionally disabled selector option;
the corrected check passed without a production UI change.

At source checkpoint `c207ac75`, the feature-gated connected account, callback,
quota-free typed grant, refresh, protective disconnect and console controls are
implemented. Joined attempt `joined-05` subsequently passed all four groups
across five actual ASGI workers in 83.961 seconds (87.673 seconds outer), exit
zero. It uses real SQLite, encrypted custody and lifecycle owners with synthetic
provider HTTP wire and gate health, not actual TLS, Rust or SDK-through-proxy
traffic. Controls include one-use callback binding, lost acknowledgements,
uncertain outcomes without replay, refresh single-flight and a disconnect fence
against a late refresh response.

The fresh-process reopen preserves the key, signed policy, schema and all other
retained cells. Its sole allowed database change is the `applied_at` startup
stamp on the `policy_candidate_authority` row of `serverware_store_migrations`,
proven within the actual startup interval. Earlier namespace and overly strict
reopen-oracle failures remain retained; `interpretation-correction.md` explains
why the first failure was a reopen, not a failure before consent. The namespace
repair avoids creating an empty temp schema; it does not relax shadow detection
or Google's main-only startup guard.

The separate frozen `c207ac75` ordinary regression run finished **27/29 suites
passing**, not a clean full-roster pass. Its two stale expectations were fixed:
the focused body-routing suite passed 5/5 in 44.63 seconds outer, and the
runtime-browser asset/checker suite passed 27 groups in 0.994 seconds. Those
later source/results do not rewrite the original failed receipt.
After pushing `1ee2f04d`, hosted [CI run 38326557489](https://github.com/example/private-deployment)
passed all 29 suites in 396.277 seconds; every suite exited successfully, with
no skips. Its
downloaded structural result is retained in `x-ordinary-ci.3pUvRs5z`; this is a
new full-roster pass, separate from the earlier local failure.

Corrected Rust source `6d67ab37` passed 112 tests across 15 nonoverlapping
filters. The initial run's two X failures came from a synthetic lease fixture
using the wrong expiry metadata field; the closed production validator was not
relaxed. The corrected test compilation took 328.625 seconds and the normal
executable build took 363.707 seconds, with 224 cached dependency/library
artifacts fresh. Normal executable SHA-256 is
`811082ac5e87f9ec05b9252cc53c180e965e563799b07235976c1654e6672d6e`;
its actual compiler receipt contains 515 inputs. All 18 owned containers were
removed and the failed attempt remains retained. The independent join in
`x-normal-source-join.514GRT8L/join.json` verified all 515 compiler inputs and
1,173 pinned files against build `6d67ab37` and committed candidate `1ee2f04d`.
Its SHA-256 is `e6cdc8b79b90fea710ea8cf8bb8cdedabf44c370a4e68182a260fa908dae1c9f`.
It also verified the separate test executable and terminal cleanup receipts.
Preserved cache metadata does not authenticate cached compiler outputs or
establish independent release provenance. The normal binary was subsequently
executed in the connected checkpoint below. Deployment, shared daily quota and
real-X acceptance remain open.

Evidence is retained under
`serverware-operator-workspace-evidence/x-accounts-connected.hWXZjH`
(`joined-05-result.json`, joined logs, and `ordinary-regression/`), alongside
`x-ordinary-rust-r2.evutcaLq/attempt-result.json`, the independent source join,
the earlier failed
`x-ordinary-rust.epw6xQIQ` build, and `catalog-test-environment.8kKB0J` receipts.

## Connected SDK acceptance

Source `1e891965cdd8bb48cf8971cbd8d9a8fb7e1c3bd2` passed all 19 SDK phases
through normal Rust `811082ac…`, with real configuration, synthetic-provider
consent, identity, account adoption and grant APIs. Node/Python/Go each completed
one post before the initial token's genuine 120-second expiry and one after
exactly one automatic refresh. Both TLS legs were verified. A seventh, Node
reflection response was withheld without replay; all 12 wrong-app, outer-CA,
inner-CA and disconnected controls added zero provider posts. Four synthetic
revocations, seven paired audit attempts and final audit-chain verification
passed. Cleanup completed; total runtime was 202.355 seconds.

Receipts are `x-post-sdk-acceptance.rdUYbhx5/checker-result.stdout.log` and
`terminal.json` under the retained evidence root. See
[project completion](project-completion.md) for the full checkpoint and preserved
earlier failures. This is isolated synthetic-provider acceptance, not deployment,
real-X access or revocation propagation, quota or native-authority acceptance.

The posting-specific Go executable was built once offline in 41.584 seconds:
`x-post-go-build.IYll2SyG/x-post`, SHA-256
`e4f25370c9fa4e078a958adcbbe70e1fcd464abb283b060e6aceff4b49fb0129`.
Go 1.23.12, go-twitter 2.1.5 and the complete toolchain/module input inventories
were retained and unchanged; module verification passed. The build container
was removed. This executable was used in the connected pass above. The complete
Node/Python runtime inventory was pinned as
`2326e887f6e424632077a4ea90f81a083ed5eba584110ae54fe40cd7a671c463`.
