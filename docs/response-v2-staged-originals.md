# Sequence fences and authenticated staged originals

This source slice connects the state mutation owner to a fresh-database sequence profile and a signed current-state original query. It does **not** yet connect the public Reserve/Authority/Stage orchestration to that owner. It is source-only; no database, signed generation, guest, migration or runtime acceptance has been provisioned or exercised.

## Explicit fresh profile

`state_authority/postgres/sequence_originals.rs` defines `sequence-request-originals/v2`. Its migration commitment is SHA-256 of the byte-identical legacy `schema::BOOTSTRAP_SQL` followed by the fixed `EXTENSION_SQL`; `bootstrap_sql()` returns those exact bytes. Provisioning must apply that closed fresh-only DDL and insert the singleton metadata row using existing `INSERT_SCHEMA_METADATA_SQL` and `schema_metadata_parameters()` (version 2 and that digest). The extension refuses existing generations, attempts, operations, metadata or a previously used allocation sequence. Runtime code neither runs DDL nor inserts/repairs this metadata.

The independently admitted `ProviderGeneration.migrationSha256` selects the closed profile. The actual state owner verifies the full retained generation against its separately pinned `pinnedGenerationSha256`, then checks the database metadata on its held transaction. The same admission runs for generation installation and subsequent writer/query transactions. The RPC `schemaVersion` stays `1`; it is not the PostgreSQL profile version. Unknown profile digests fail closed.

Legacy bootstrap bytes, hash-fence construction and low-level legacy contracts remain distinct. There is no row rewrite, backfill, hash truncation, hexadecimal-to-integer conversion or guessed sequence. Historical migration is required follow-on implementation, not completed by refusing old rows.

## Producer and original custody

Fresh Reserve allocates the actual PostgreSQL sequence, stores its exact positive decimal spelling in both attempt and fence, and returns that allocation. Values must fit the existing JCS safe-integer bound, 1 through 9007199254740991; there is no wrap or reset. Failed transactions may leave sequence gaps. The canonical reader joins the real allocation row and rejects alternate spellings.

The additive custody execution label is `catchplate.responseObservationV2SequenceStateAuthority/v1`, using the existing closed nine-field `StateMutationExecutionRequestV1`. Only its Reserve request may use wrapper revision/fence zero with a signed `ALLOCATE`/null request. This is pre-allocation intent, never a resulting fence. The actual owner requires the independently selected fresh profile before effects, and the receipt uses the positive allocated result. Existing execution labels remain strict; positive exact-fence DispatchBegin/ObjectCommitRaw/RecordOutcome calls continue unchanged against the selected database.

Successful Reserve, Stage and DispatchBegin transactions append one immutable original slot each. `attempt_request_originals` retains the canonical **whole signed `RpcRequestFrame`**, not just its unsigned request or authentication payload. It shares the real mutation transaction, operation ID and existing committed result/replay ledger. Rejected/rolled-back mutations do not create successful original slots. A commit-unknown result is not proof of success and is never reconstructed from missing rows.

Each retained frame and result is capped at 24 KiB, with at most three pairs per attempt. New sequence execution and original queries require the signed service configuration's existing 256 KiB frame bound. No transport bound is silently widened. The SQL original row is append-only; update/delete are rejected. Results remain in the existing operation/replay store, with exact bytes and hashes required to agree.

For this new profile, Reserve `requestSha256` means the original client request commitment, `routeSha256` the transaction route-semantics commitment, and `credentialScopeSha256` the transaction credential-binding commitment. Stage must retain exactly that binding and select an immutable `objectKind: "staged-request"` reference. Its original deadline cannot exceed Reserve's original same-boot deadline. This object is the **credential-free HTTP template**, not final injected HTTP bytes. The final request hash remains separately gate-owned; neither the original journal nor router/state/ledger receives injected credential plaintext through this contract.

DispatchBegin must consume the exact current Stage revision, fence, object and credential-binding commitment and cannot extend its deadline. The existing actual signed transport authorization remains required; an original query is not a new dispatch grant.

## Actual query and receiver

`services::query_staged_original` invokes StateAuthority `STATE_CAS` over the existing authenticated role channel. The closed query has 12 fields; `expectedDispatchRequestSha256` is required null for `STAGED`, and required SHA-256 of the full signed DispatchBegin frame for `DISPATCHING`. These are separate purposes, not interchangeable states or interpretations of the fence's `ACTIVE` label.

On one owned serializable transaction the state owner admits its pinned generation/profile, locks the current attempt and actual fence, requires the exact head/resume/owner and original live boot deadline, and reads only positive committed originals joined to their operation and replay rows. It independently verifies the original caller signatures and state-result signatures under that generation. Missing, ambiguous, changed or noncanonical originals refuse; no inventory inference or repair is attempted.

The signed response has 10 fields. Its body has nine: attempt, resume ID, revision, allocated fence, state, original deadline, Reserve original, Stage original, and required nullable DispatchBegin original. Each original has exactly `frame`, `exactRequestSha256`, `result`, `exactResultSha256`. The actual retained linearizable-store key signs the dedicated `catchplate.response-v2/staged-request-original/v1\0` domain using the existing role-signature canonicalization and standard padded Base64 signature encoding (no added prefix). The independent receiver verifies the state role/scope, exact full-frame/result hashes, chain and query equality, including its unchanged deadline. This is an authenticated snapshot, not a promise that a later CAS will succeed or that a target received anything.

The paired [schema](../schemas/response-v2-staged-original.v1.schema.json) records the closed wire profiles; cryptographic, canonical-byte, SQL transaction and cross-field checks remain executable source obligations.

## Required next public orchestration

`response_v2/transaction.rs` already builds public `V2OperationRequest::Reserve` from route/policy/runtime exact objects and `Stage` from the source-built credential template, credential-free HTTP request and optional credential reference. The supervisor admits those public operation variants. However, the baseline lifecycle provider's actual Reserve/Authority/Stage implementations are the refusing `FailClosedProviderSet`; no service engine constructs their signed Reserve/Stage mutation frames or persists the selected template on that path.

The fixed state-authority service operation matrix assigns AttemptReserve and AttemptStage to StateAuthority, with its actual generation-bound linearizable-store signer; the router has no such signing authority. Authorize additionally involves the actual PolicyProofVerifier. The next source task must connect genuine public session/evidence verification, Reserve allocation, authority transition, immutable credential-free template persistence and Stage signing to these owners, preserving exact original deadlines and returning real committed state/evidence. Configuring a table or supplying a caller DTO cannot replace that implementation. The new dispatch consumer must refuse until those originals genuinely exist. Broader lifecycle, historical migration and runtime acceptance are not claimed complete here.
