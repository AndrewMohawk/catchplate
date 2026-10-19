> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Existing private client configurations

The project is now **Catchplate**. Current examples use `CATCHPLATE_*` environment
variables, Catchplate public authentication placeholders, and the
`mcpServers.catchplate` launch entry. Renaming the project does not renew a client
token or grant a new permission.

**Using `catchplate.example.com`?** Its cutover issued a new CA. Obtain a
fresh private configuration, verified Catchplate CA and the
[matching client release](../docs/developer-quickstart.md#before-you-start).
The converter below deliberately retains original CA paths; it is not the
handoff procedure for this instance and does not make its old CA or hostname
usable again. Never keep an old CA as a fallback or disable TLS verification.

For a new client, use the current console's private configuration download and
public CA. For another deployment whose operator confirms unchanged CA trust,
the local converter below retains
the client token, IDs, expiry, scopes, query and request body. It changes only the
known public markers and supported recipe identifiers. It never contacts the
proxy/provider, reads a provider credential, executes the recipe or rotates a
token. An expired token stays expired.

## Convert an existing ordinary download

First ask the operator to confirm that the server and saved permission have
completed the Catchplate cutover. Conversion alone does not migrate server state
or prove that a request will work. Use Python 3.11 or newer on Linux/macOS; no
dependency installation is needed. From the repository root:

```sh
chmod 600 /private/old-client.json
python3 -I -B examples/migrate_client_config.py \
  --input /private/old-client.json \
  --output /private/catchplate-client.private.json
```

The input is preserved. Output must not already exist and is created with mode
`0600`. The converter refuses symlink inputs/outputs, duplicate JSON keys,
non-finite numbers and files larger than 64 KiB. It prints only fixed status
messages, never config contents or token values.

The proxy URL stays unchanged by default. If the operator provides a **new proxy
origin**, add `--proxy-url https://the-confirmed-proxy.example`. Do not substitute
the web console URL. CA filenames are not renamed: their paths become absolute
references to the same original files, including an optional separate proxy CA.
Confirm that those public certificates remain correct after cutover; this tool
does not fetch, replace or weaken CA trust.

Supported downloads use standard `basic_and_bearer_v1` proxy login and an exact
named permission: the common-app presets, GitHub, Gmail, Alchemy, X, and npm
metadata/install/publish. Converting a write-capable config does **not** select or
authorize a write; the existing explicit command/confirmation remains required.
User text containing the former project name is preserved, not globally replaced.

For a common-app download, the existing local check can validate the converted
file and prepared dependencies without making a request:

```sh
examples/common-apps/.venv/bin/python -I -B examples/common-apps/request.py \
  --config /private/catchplate-client.private.json --check-config
```

## MCP, environment settings and CI

Point the current MCP server's `--config alias=...` argument at the converted
file, then run `--print-client-config` again as shown in the
[MCP instructions](mcp/README.md). Replace the old launch entry with the generated
`mcpServers.catchplate` entry; do not leave two independently callable servers
pointed at the same write permission. Actions remain disabled unless explicitly
enabled. The converter does not edit an MCP client's settings.

For environment-based clients, use the current example's `.env.example` or
console recipe: variable names now start with `CATCHPLATE_`. Keep token values
unchanged and private. The converter does not read or modify your shell
environment. CI secret **names** also changed in the current sample workflows;
update those names and the private config secret deliberately. Never paste a
private download into workflow source, a prompt or an issue.

## Configurations that need a new handoff

Do not apply text replacement to ECR publication configs, managed-client
setup/state, signed enrollment packets, policy bundles, certificates, approval
receipts, or custom/generic permissions. The converter refuses these formats and
any top-level policy hash. Their signatures, identities and/or policy hashes have
independent validation rules. Ask the operator for the current corresponding
handoff; do not reuse an old expected policy hash or replay a pending write.

Legacy Bearer-only downloads also require a current supported handoff; conversion
does not silently upgrade their authentication mode. If you no longer have a
valid client token, use the normal deliberate renewal/replacement workflow.
Catchplate cannot reconstruct a previously displayed one-time token.
