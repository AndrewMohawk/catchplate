"""Pure assignment wire-field inventories; no database or authority admission."""

LEGACY_FIELDS = (
    "assignmentId",
    "canaryId",
    "assignmentRevision",
    "generationEpoch",
    "minimumGenerationTombstoneEpoch",
    "policyIdentity",
    "expectedLoadedSnapshots",
    "responseValidationObligations",
    "responseValidationObligationsRootSha256",
    "fleet",
    "observationWindow",
    "readinessThresholds",
    "issuedAtUnixNanos",
    "expiresAtUnixNanos",
)

# Preserve the existing native tuple order as well as its exact field set.
NATIVE_FIELDS = LEGACY_FIELDS[:10] + (
    "custodyAuthority", "authorityKeyIndependence",
) + LEGACY_FIELDS[10:]
