# Authority row-mutation SQL boundary

Status: source-reviewed correction and component fixture; unbuilt and
unexecuted. This does not repair the missing WebAuthn
kernels, establish independent database authority, or make startup healthy.

## Source defects

Review of `052c490` found related defects in the v9 executor's actual SQL path:

- The UPDATE predicate reads the full mutation's `key`, but its bound parameter
  was only the replacement `row`. Normal updates therefore do not select the
  intended primary key. Payload fields must never redefine the selector.
- A missing SELECT result is SQL NULL, whereas the serialized absent prestate
  is JSON null. Comparing them directly with `IS DISTINCT FROM` rejects valid
  absence. The same mismatch appears in the selected-business-row and
  authorization-source checks before mutation execution.
- The installer receives an already quoted schema identifier. Reusing that
  quoted spelling as a catalog `nspname` or an argument to SQL `format('%I', ...)`
  looks up or quotes a different name. Static qualification and identifier
  values require separate, validated representations.
- Two object-shape guards call `pg_catalog.jsonb_object_length`; this is not a
  PostgreSQL 17 built-in. Closed object-key checks must use supported operations
  and deny missing, additional and differently typed fields.

PostgreSQL documents JSON extraction, `jsonb_object_keys`,
`jsonb_populate_record` and JSON-null conversion in its
[JSON function reference](https://www.postgresql.org/docs/17/functions-json.html).
These source findings are not a report of a successful full-executor replay.

## Required correction boundary

Use shared rendered SQL in both the production installer and the component
fixture. The narrow execution block follows manifest/template/write-set and
selected-row admission; it is not a standalone authority endpoint.

Keep the exact admitted key columns, locked full-row compare-and-swap,
operation-specific preconditions, one-row affected cardinality and exact
postcondition. INSERT requires an explicit JSON-null prestate and an absent
SQL row. UPDATE and DELETE require an object prestate equal to the current
row. Missing fields, JSON-string booleans and malformed envelopes must never
fall through SQL three-valued logic as success. For selected rows, `present`
must be an actual JSON boolean and the row must have its matching exact shape.

Retain authorization row-digest recomputation, exact selector-key checks and
all earlier capability, deadline, source, proof and manifest checks. Bind the
full mutation envelope and read replacement columns from its `row` member;
never replace the selector's parameter with that row alone. Keep
primary-key moves unsupported: reread at the original admitted key and reject
a different poststate. Do not silently turn this repair into a key-move API.

## Installation and verification

The installed executor's normalized `pg_get_functiondef` is part of the
expected PostgreSQL structural manifest. Fresh initialization can install a
corrected function, but an existing v9 installation with the old definition
must continue to fail admission before replacement. The existing
`repair_policy_candidate_authority_completed_v9_receipt` contract addresses
only its exact historical receipt-table shape, not executor-function repair.
Neither retaining nor changing the source-revision string authorizes repair.
An existing-installation repair requires a separately reviewed contract binding
exact old/new definitions, structural and owner commitments, and unchanged data
invariants.

`scripts/test_authority_mutation_postgres.py` contains 14 authored component
and source-wiring methods. Its PostgreSQL cases call those same shared SQL
blocks in one random schema, using only an externally prepared disposable
Unix-socket cluster. It must retain the local DSN restrictions and fixed
timeouts, reject ambient PostgreSQL configuration, and clean only its own
schema. Positive INSERT/UPDATE/DELETE and negative stale, missing, malformed,
collision, cardinality and postcondition cases, plus rollback and bounded
cross-connection locking controls, are included but have not run. A fixture with
synthetic admitted inputs does not execute the full authenticated planner,
capability admission, witness, root transition or migration.

Staging a script in the Makefile inventory or exposing a component target does
not prepare controller coverage. The existing PostgreSQL component scripts
are excluded, and changed/added excluded scripts deliberately stop preparation.
Keep that refusal until the authorized native controller plan binds the frozen
script/interpreter/arguments, PostgreSQL-capable image, private cluster
lifecycle, resources, deadlines, terminal evidence and cleanup. A Dockerfile
target or a manually supplied DSN is not this authorization. No manual runner
or registry stub may replace the prescribed preparation and no-build lane.
