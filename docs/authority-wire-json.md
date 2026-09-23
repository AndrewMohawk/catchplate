# Authority SQL wire JSON repair

Status: source implementation and review only. No interpreter, SQL engine,
build or test has executed this revision. This does not unblock startup,
authorize an installed-function replacement, or establish production readiness.

## Two deliberately different representations

Python authority messages use sorted, compact JSON with ASCII escapes. The
persisted primary radix tree uses literal UTF-8 JSON and its separate digest
framing. Reusing the tree serializer for messages makes non-ASCII keys, rows,
authorization projections and results disagree with their Python commitments.
Changing the tree serializer would instead change existing tree addresses and
roots. Neither representation nor its digest framing is interchangeable.

`authority_store/wire_json_sql.py` installs a separate
`serverware_policy_authority_wire_json(jsonb)` function. The existing
`serverware_policy_authority_canonical_json` definition, recursion and all 11
primary-tree call sites remain unchanged. The 71 message call sites in `db.py`
now use the wire function; v9 executor and root-transition message consumers
also use it. Export-chain message commitments are wire consumers, not persisted
primary-tree hashes, even when their field names contain `root`.

## Accepted values and fixed bounds

The wire function emits compact ASCII JSON for null, booleans, lossless integer
numbers, strings, arrays and string-keyed objects. It sorts original object keys
using PostgreSQL `C` collation in a UTF-8 database. It preserves array order and
does not normalize Unicode. Escaping includes lowercase hexadecimal escapes,
DEL, short control escapes and paired surrogate escapes for astral characters;
slash remains literal. This targets the existing Python `ensure_ascii=True`,
`sort_keys=True`, compact-separator convention, not a new wire version. Reference
semantics are the [Python JSON documentation](https://docs.python.org/3/library/json.html)
and [CPython encoder](https://raw.githubusercontent.com/python/cpython/3.12/Modules/_json.c).

Every helper enforces its applicable fixed ceiling:

- Maximum depth: 128, with the input value at depth zero.
- Maximum visited nodes: 1,000,000, counting each value and object key.
- Maximum emitted bytes: 72 MiB, including quotes, escapes and separators.

The entry point first measures and validates, then renders under the measured
budgets. Child calls receive the remaining budget, not a reset allowance. String
rendering accumulates bounded chunks. Direct helper calls cannot increase the
fixed ceilings. The 72 MiB ceiling must equal the existing SQL digest-frame
ceiling at installation; it does not raise the separate 64 MiB plan/transport or
primary-root evaluator limits. These bounds do not establish a total-memory or
runtime bound: PostgreSQL parsing, detoasting, set-returning functions and sort
allocations occur outside the measured output budget. Depth acceptance and
stack/resource behavior still require the controlled real-engine run.

Fractional and scale-bearing numeric values such as `1.0` are rejected, not
rounded. This is not universal Python float/Decimal parity. The reviewed typed
paths use integer counters/times and lossless rows; generic Python marshal
helpers can still encode finite floats, which this SQL boundary will refuse.
Any future operation needing fractional values requires a reviewed cross-runtime
numeric protocol. Existing legacy ASCII-only admission is not relaxed here.

## Rendering does not authenticate original bytes

JSONB discards duplicate members and original whitespace, and normalizes numeric
exponents while retaining fractional scale. Thus the renderer cannot determine
whether integer `100` originally arrived as `1e2`, or whether an object had a
duplicate member. NUL and unpaired surrogates also remain outside PostgreSQL's
JSONB/text domain. See [PostgreSQL 16 JSON types](https://www.postgresql.org/docs/16/datatype-json.html).

The shared `assert_root_transition_payload_sql` fragment compares the original
request/result bytes to their canonical wire rendering. It also preserves
decoded-value joins to the exact stored plan and authorization projection, and
the independently stored request base64, byte count and SHA-256 anchors. It does
not replace received bytes with a normalized serialization. Noncanonical UTF-8,
spacing, duplicate members and alternate escape spellings cannot pass that
byte-equality check merely because their decoded values agree.

The complete stored plan remains bound by its original ASCII bytes, strict
base64, byte count and SHA-256, plus the existing closed-record checks. This
repair does not replace those checks with whole-plan JSONB equality or claim
that rendering proves all nested original token types. Source parsing and
operation-specific strict admission remain required.

## Installation and authored acceptance coverage

The string, walk and entry functions have fixed signatures and are immutable,
strict, security-invoker functions with `pg_catalog` search paths and qualified
helper calls. All three enter the required structural and owner implementation
inventories. Existing schema sealing revokes public/runtime access; no new
direct helper grant is added. Existing exact-definition pinning still rejects
old installations without a separately authorized transition. The narrow
receipt-table repair exception is not permission to replace these functions.

Authored coverage, all unexecuted:

- `test_authority_wire_json_source.py`: seven source-partition controls, including
  byte fingerprints of the unchanged tree functions at `984ca5c`, all 11 tree
  arguments/domains, and missing/extra/count-preserving migration controls.
- `test_authority_wire_json_postgres.py`: 14 real-engine component methods for
  the actual shared renderer against an independent Python oracle, Unicode and
  numeric boundaries, resource counters, depth and installed function modes.
- `test_authority_root_transition_postgres.py`: five additional methods (21
  total) covering original-byte rejection, payload joins, independent request
  anchors, Unicode wire-domain commitments and unchanged tree serialization.

Source inspection is not SQL parsing. The PostgreSQL fixtures use an externally
prepared private Unix-socket database and random disposable schemas; they do not
prove the full signed planner/executor/witness flow or production ACL behavior.
The root-transition fixture still uses explicit synthetic post-admission roots
and an opaque proof, not a complete real operation.
The [shared primary-tree SQL](authority-primary-tree-sql.md) now has a separate
native fixture for actual row triggers and independently rebuilt roots. Its
source extraction preserves tree/hash templates with an explicitly reviewed
epoch-call grammar correction; the original source fingerprints are not
silently replaced. These new tests also remain unexecuted.

The source-partition script enters the isolated inventory. The new PostgreSQL
script joins the excluded real-engine inventory until the trusted controller
binds its exact command, engine, dependencies, coverage and cleanup. A
changed-excluded-test refusal must not be bypassed. Full controlled verification,
independent root/time authority, complete queries and missing WebAuthn operations
remain requirements in [the startup blocker](authority-transition-startup-blocker.md).
