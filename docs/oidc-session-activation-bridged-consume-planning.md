# Bridged consume protected planning

This source slice connects the previously signed consume-input bridge to the
actual private planner constructor, current-state reads, protected prepare and
export. It does not enable historical public consume execution. The source is
unbuilt and unexecuted; no runtime or production acceptance is claimed.

## Original-only custody join

`OidcSessionActivationHistoryCustody._consume_context_on_work` accepts the
current root, exact current state-enrollment original and current configuration,
plus the caller's existing work/window/deadline. It re-admits its own immutable
history original. No caller-selected old root, policy object or successful
result carrier is accepted.

For fixed history v7, genuine policy admission independently authenticates the
old activation context and current planner context. The method joins the
current root/configuration/state original and verifies the current enrollment
under that root. Its private same-call result supplies old root, state original,
configuration, planner and operation keys only for original activation replay.
The original issuer-policy and custody bytes remain available for exact input
binding. Ordinary live consume purposes retain their same-root semantics.

The result's guard checks the actual owner, immutable configuration, original
fresh outer interval and monotonic clock floors. It is a base guard, not a
recursive re-admission or lock-taking child, so genuine custody replay can
sample it while holding the original owner lock. The old `bind_context_on_work`
remains strict and does not acquire an implicit bridge profile.

## Actual worker and protected planner

The protected owner constructor joins old activation expectations and keys to
that genuine context, while current enrollment, state root, configuration,
journal and new planner key remain separately checked. Cold construction and
subsequent owner checks use the actual admitted historical operation key;
they do not substitute the current root for old evidence.

The lower planner keeps old authority solely on provenance replay and current
authority on current state/read/write evidence. Its bridge-specific private
input commitment binds the exact policy and old state original; purpose-specific
custody envelopes are not interchangeable execution authority. Legacy plan
envelopes and legacy private-input commitments remain unchanged.

Before worker cold bodies are read, actual sealed lengths reserve sixteen
original footprints plus 128 KiB inside the existing 64 MiB ceiling. Root file
delivery applies the same remaining-capture limit before each body read. The
reservation covers simultaneous cold and nested history admissions; measured
decoded old/current policy inventories must fit it before private recovery.
Static and dynamic request/export paths retain that cold allowance and pass
tighter response limits to actual export allocation. The private context also
preflights its supplied held-byte count plus nested original captures before
re-admission. No work ledger, processing window or original expiry is renewed.

## Explicit unfinished boundary

Public historical consume execution remains closed. Current fixed history v3
grant, v4 reservation, v5 SQL issuer and v6 completion purposes do not contain
the independent bridge policy. They need separate versioned original producers
and genuine receiving paths; planning v7 cannot stand in for any of them.
Historical admission of newly created planner v3 also needs an explicit
completion profile. Legacy historical planner v2 and completion history v6
remain strict. These are real downstream implementation boundaries, not
permission inferred from a prepared plan, missing record or successful export.
