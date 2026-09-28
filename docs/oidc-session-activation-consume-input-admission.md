# Receiving consume inputs

The private original-only receiver re-derives a request's expected history and
consume-planner payloads before accepting the issuer's raw2 response. A response
cannot supply its own expected target, predecessor, resource policy or signer.
This is source-only receiving code, not a deployed acquisition service.

`_verify_on_work` accepts the original raw16 request suffix, returned raw2,
independent issuer-policy and activation-planner originals, the root public key,
and the existing work/window/deadline. The optional private continuity hook
exchanges restrictive clock floors only. No private signing or AES key enters.

The shared read-only derivation genuinely authenticates the independently pinned
policy, historical activation planner, caller/grant and reservation/completion
controls, plus actual old-token possession. It derives the typed consume request,
activation scope and completed root vector. Historical evidence never becomes
renewed activation execution authority.

The receiving path then calls the actual live-purpose consume-planner verifier,
which verifies the returned planner, exact history original and embedded
activation bootstrap. Both complete signed payloads must match the independently
derived expectations. Signed output timestamps derive from signed policy and
source/activation age limits, not a newly sampled issuance time or a receiver's
different processing opening. Processing still remains within the receiver's
original, possibly shorter allowance.

Encoded originals and retained decoded/comparison graphs are bounded by the
64 MiB inventory, alongside the unchanged cumulative work budget. Final live
checks preserve both fresh returned intervals, the policy and original clock
floors. The immutable seven-field result contains the two originals, genuine
planner/policy data, narrowed window/deadline and a same-call guard. It is output
data: no public admission API accepts it in place of originals.

This path supplies no private replay, fresh database observation, durable
retention, one-use journal claim, key/resource delivery, worker readiness or
token release. The eventual acquisition caller must claim before issuer I/O,
retain opaque response originals before semantic admission, and keep this within
the actual live permission. Those service/client connections remain open; the
existing direct `prepare_consume` path is not silently changed into a network
acquisition path. No build or execution has been performed.
