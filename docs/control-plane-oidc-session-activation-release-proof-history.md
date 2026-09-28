# Archived intent/proof cold authority

Activation history v3 adds independently archived proof enrollment to the
existing root-authenticated history archive. This is cold authority for later
original verification, not permission to sign, contact a proof service, choose a
release checkpoint or disclose a token.

## Closed versions

`serverware.controlPlaneOidcSessionActivationHistory/v3` retains the exact
`schema`/`activations` object. Each entry retains every v2 field and adds the
required nullable `releaseProof` field. A non-null value has the existing closed
`serverware.controlPlaneOidcSessionActivationReleaseProof/v1` shape: original
`proofEnrollment`, independent `expectedScope` and the fixed proof endpoint.
Null explicitly disables archived proof authority for that entry.

History v1/v2 retain their exact shapes and always produce `release_proof=None`.
No enrollment found inside retained proof raw4 can fill that missing cold pin.
The parent envelope/payload pair is version 22, with the same closed fields as
v21. Parent v19 remains history-v1-only; v20/v21 remain history-v1/v2-only.
Parent v22 admits history v1/v2/v3 without changing older versions' meaning.

## Genuine same-RI admission

`control_plane_oidc_session_activation_history_bootstrap` first admits the
existing archive-selected registration, finalization, activation, planning,
consume and release-intent originals. The actual configuration snapshot and
root RI come from the shared archive, not from a candidate proof.

For non-null `releaseProof`, the existing proof configuration verifier genuinely
re-admits the original intent enrollment and proof enrollment under that same
RI. It checks their shared configuration, database, generation, runtime closure
and receiver identity, plus exact configured keys and purpose separation. The
proof producer identity remains independently signed; it is not relabeled as
the intent caller.

The private `_ActivationHistoryScope` appends
`release_proof: _ReleaseProofMaterial | None`. The proof material keeps its six
existing fields: proof public key, enrollment bytes/digest, expected-scope
bytes, endpoint and forbidden public keys. The outer history material and
lookup APIs are unchanged. Later consumers must select an exact genuine scope,
retain its original interval/processing guard, and reverify their actual signed
intent/proof originals. A successful cold material is not external authority.

## Parent and startup boundary

`control_plane_enrollment_bootstrap._produce_v22_on_work` accepts the same
original payload/history/root/work keywords as v21. It measures the unchanged
bounded payload and output, admits all nested originals, and uses the distinct
v22 signature domain. Admission checks the matching envelope/payload version
before genuine nested processing. It does not rewrite signed historical source
labels or renew historical intervals.

The actual `authority_fd_entrypoint` projects v22 through the existing ten
purpose slots. History fields remain data-only: archived key-slot numbers and
proof endpoints never add a descriptor, open a retired private key or authorize
a current socket. The startup owner continues to enforce the shared archive's
current authorization interval before using live private keys.

The 4 MiB archive/parent limits and shared sixteen historical entries plus the
current entry are unchanged. New enrollment originals and their canonical
wrappers fit inside those same inventories and original work limits; there is
no new allowance or persistence slot. Larger valid inventories may be refused.

The [actual retained-intent integration](control-plane-retained-intent-history.md)
now selects these public originals before a fresh proof-preparation actor and
joins the same RI to genuine retained intent/proof receiving. The cold material
alone still authorizes no effect. Retired-RI token delivery, retries and RECOVERY
fallback are not enabled. Source-only; no runtime or provisioning evidence is
claimed.
