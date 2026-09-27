# Dedicated finalization caller and ordered planning

This is source-only implementation, unbuilt, unexecuted and unprovisioned, not
a deployed or verified registration flow. Existing plan-only preparation routes
and portal buttons retain their behavior. The separate
[public grant-preparation routes](public-registration-finalization-grant.md)
now invoke the authorization-before-new-plan continuation and retain its grant;
they do not reserve roots or execute credential finalization.

## Why a separate path

Finalization has its own root-enrolled caller identity and signature domains.
Evidence-admission permission and permission to inspect or prepare a transition
are not permission to execute finalization. The existing grant contract also
requires authorization to be issued before the signed plan. Asking for fresh
authorization after retaining an old raw7 cannot satisfy that contract.

The new private continuation implements the correct order:

```mermaid
flowchart TD
    A["Live subject inspection, then public purpose/current-caller admission"] --> B["Repeat retained ownership and stored acknowledged completion replay"]
    B --> C["Derive exact finalization request and observe bounded sibling hints"]
    C --> D["Dedicated cold caller signs authorization at current time"]
    D --> E["Request one NEW finalization plan within authorization expiry"]
    E --> F["Verify original authorization, raw7 and same-read complete vector"]
    F --> G["Dedicated authorizer signs genuine replayed grant; caller verifies"]
    G --> H["Durably retain raw10, then publish finalization association"]
    H -. "Remaining integration" .-> I["Independent reserve, protected execution and completion"]
    I -.-> J["Separately authenticated OIDC session activation"]
```

The first box is enforced by the separate public handlers, not inferred by this
private helper. Their purpose is `prepare-registration-finalization-grant` and
action is `webauthn.registration.finalization.authorize`; older preparation or
evidence-execution permission cannot substitute.

## Actual source path

[`prepare_and_retain_registration_finalization_grant`](../serverware/control_plane_registration_finalization.py)
accepts only the existing evidence-admission local locator and independently
authenticated user/session scalars. A local locator is not ownership. Under
the actual cold owner's lock and one work/window, the shared retained-original
path loads the exact associated signer/grant pair, reservation, irreversible
SQL claim and acknowledged completion originals. It genuinely replays live
ownership and completion against independently admitted pending-state pins.
An uncertain result is not a substitute, and this path never calls recovery
or retries SQL to manufacture a completed prerequisite.

The [dedicated cold profile](control-plane-registration-finalization-custody.md)
must be enabled before this continuation starts. Its separately held key and
root-signed purpose enrollment do not replace application-level permission.
Old enrollment profiles do not silently gain this purpose.

[`control_plane_registration_finalization_execution`](../serverware/control_plane_registration_finalization_execution.py)
then replays the actual signer originals to derive lookup selectors. It obtains
bounded sibling IDs from the existing database observer, and the dedicated
[authorization issuer](registration-finalization-authorization.md) reconstructs
the exact request with that same hint set before signing. Hints are not proof
of the complete population: the genuine measured transition planner still
proves all required history, sibling and committed evidence-row preconditions.

Authorization issuance completes before the existing custody client makes
one new finalization-planning request. The old prepared raw7 is not an input.
The request deadline is capped at the authentic authorization expiry. Genuine
local [plan admission](registration-finalization-plan-admission.md) then checks
the returned original custody controls, independently configured history and
actual transition replay, joining the exact request/operation and interval to
the original authorization. A changed request or plan issued too early fails;
there is no automatic reauthorization, replanning or timestamp adjustment.

The separate private `prepare_authorized_retained_registration_finalization`
still returns `(existing_evidence_locator, original_raw8)` without dispatch or
retention. Raw8 is:

1. Original dedicated finalization authorization.
2. Original verifier custody intent.
3. Original planner custody relay.
4. Signed transition envelope.
5. Transition proof.
6. Original inputs.
7. Original evaluation context.
8. Separate signed-custody-committed historical expectations.

It is not a new local journal locator or a successful-verification token. The
public grant facade explicitly selects the new-plan/vector variant, whose
complete before-vector comes from the same actual verifier-side read transaction.
The cold-owner grant-request method authenticates the original permission and
plan, performs one bounded [original-byte exchange](registration-finalization-authorization.md#bounded-finalization-grant-transport)
with the [dedicated cold authorizer](registration-finalization-authorizer.md),
then genuinely verifies the returned grant and full before/after vector. The
facade durably appends authorization + raw7 + before-vector + grant as raw10 and
publishes the new finalization association last, referencing the existing
evidence/signer association. It returns only
`(existing_evidence_locator, finalization_grant_local_locator)`. This is an
explicit action, not automatic dispatch after old plan-only preparation.

## Limits and remaining work

All work uses the existing cumulative allowance. The supplied current clock
bracket remains unchanged; attestation, signer, authorization, custody and
transport limits only reduce remaining time. Epoch/monotonic checks reject
observed reversals. Cooperative checks cannot interrupt blocked native work.
The complete retained input inventory plus new enrollments, authorization and
returned plan/vector/grant is capped at 64 MiB. Existing per-original bounds
also apply.

Public present-purpose admission, same-read full-vector acquisition, the cold
authorizer source and durable grant association are now connected in source.
Independently current reservation, protected one-use execution and completion
remain to be connected. The existing credential-finalization kernel does not
activate an OIDC browser session; that is a separate authenticated transition.

No keys, services or socket permissions were provisioned. No build, import,
parser, tests or runtime verification ran. Frozen verification must cover old
profile compatibility, purpose/key separation, authorization-before-plan
ordering, changed authentic requests/siblings, expiry during callbacks,
aggregate/work limits and failures between signing and the new plan response.
This source checkpoint closes no production acceptance gate.
