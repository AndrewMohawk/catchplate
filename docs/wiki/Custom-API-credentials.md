# Custom API credentials

[Home](Home.md) · [Credentials and providers](Credentials-and-providers.md) · [Proxy and CA](Proxy-and-CA.md)

Use a manual credential when your API accepts a Bearer token or a key in one HTTP header and its requests fit Catchplate's supported JSON profile. This example gives a status-checking script access to **one GET endpoint**, without giving the script the provider secret.

`https://api.example.test/v1/status` is an illustrative address, not a running service. Substitute an API you control or are authorized to use, its actual status path, and its documented authentication. Do not add the example hostname to your running instance. Saving the configuration below is not evidence that a provider request succeeded.

## Three values with different jobs

| Value | Where it belongs | What it does |
| --- | --- | --- |
| Provider token or API key | The write-only credential form in Catchplate | Authenticates the permitted request to the upstream API. |
| Catchplate client proxy token | Your script's protected runtime configuration | Authenticates that client to the proxy; grants only its active permissions. |
| Optional public dummy value | The permission and the client's provider-auth header | Gives an existing library something nonsecret to send; Catchplate replaces it after authorization. |

Never put the provider secret into the client, a URL, the dummy-value field, source control or chat. A dummy is not authentication to Catchplate.

## 1. Check the destination and save the credential

The operator must already have approved your API's HTTPS origin, for example `https://api.example.test`. Check **Proxy setup → Proxy destinations**. If the actual origin is absent, use the [destination configuration procedure](Proxy-and-CA.md#let-the-proxy-reach-a-new-provider) with the deployment owner. Preparing a destination change is not live activation; a permission cannot add a host or wildcard.

Open **Credentials → Manual API key**:

Bearer authentication is the default. For a custom-header API, expand
**Authentication settings** and select **API key in a custom header**.

| Field | Bearer-token API | Custom-header API |
| --- | --- | --- |
| Give this credential a name | `Status API — read only` | `Status API — read only` |
| How the provider expects it | **Bearer token** | **API key in a custom header** |
| Provider header name | Automatically `Authorization` | The documented name, for example `X-API-Key` |
| Provider key or token | The token itself, without `Bearer ` | The header's secret value, without `X-API-Key:` |

Choose **Save credential**. Catchplate stores the secret encrypted; the ordinary instance uses local key custody, not hardware-verified custody. This save does not contact the API, verify the key, create a client or grant permission. Manual credentials are not automatically refreshed OAuth connections.

Choose **Back to Credentials** if you only wanted to store it. To continue, use **Set up access for a client**, or the saved card's **Use with a client**. Both reuse that exact saved credential without revealing its secret.

## 2. Create a client and one narrow permission

In the guided setup, select an existing client or create `Status checker`. Choose a suitable **Client token lifetime** and save the displayed one-time proxy token privately. It is displayed once, but can authenticate multiple permitted requests until expiry or revocation. A new client alone has no access.

At **What may this client do?**, create a new permission with these settings, substituting your real approved origin and exact path:

| Setting | Example |
| --- | --- |
| Approved destination | `https://api.example.test` |
| Exact URL path | `/v1/status` |
| Allowed methods | **GET** only |
| How your existing client sends provider authentication | **Add credential automatically** |
| Add restrictions → Permission name | `Read API status` |
| Add restrictions → Request content | **Restrict JSON fields (empty blocks bodies)**; leave request fields empty |
| Add restrictions → Response content | **Do not filter response content**, when offered |
| Query parameters and client headers → Allowed query parameter names | Empty |
| Query parameters and client headers → Allowed client headers | `accept` and `user-agent`, one per line |

This authorizes that exact host/path and GET method—not `/v1/users`, all subpaths, other hosts, POST, or arbitrary query parameters. Provider authentication is controlled separately; do not add the credential header or `Proxy-Authorization` to the ordinary client-header list.

Choose **Review access**, inspect the credential, client and effective scope, then **Grant access**. Wait for the matching policy to become active before testing. If the result is uncertain, use the offered refresh/recovery controls; do not repeatedly create the same permission.

### Optional response filtering

If the API returns an object such as `{"status":"ok","version":"1","internal_note":"private"}`, you can instead choose **Only return selected JSON fields** and enter `status` and `version`, one per line. Those are allowed successful-response fields, not invented required values; this is not a check that `status` equals `ok`. Error responses use the fixed `error`, `code` and `message` projection.

**Do not filter response content** needs no response-field list. It still enforces the advertised JSON/empty-response contract, size/status limits and credential-reflection protections. It does not permit arbitrary HTML, files or streaming. Check the displayed compatibility limits, especially if the API returns empty HTTP 204. Closing **Add restrictions** does not remove selected restrictions.

## 3. Configure curl without the provider secret

Open **Proxy setup**, select `Status checker` and `Read API status`, choose GET, download the public CA certificate, and set **Downloaded CA file** to its local path. Prefer **Copy connection template**: it uses the saved permission and that client's actual proxy-login mode.

The following Bash example assumes **standard client login**: the client UUID is the username, and its Catchplate proxy token is the password. New guided clients use this mode when supported. For an older Bearer-only client, either use its generated Bearer template or explicitly choose **Clients → Enable standard client login**; do not silently assume it supports Basic.

Replace all public placeholders before running this on a trusted workstation:

```bash
set +x
export CATCHPLATE_PROXY_URL='https://your-approved-proxy.example.test'
export CATCHPLATE_APP_ID='replace-with-the-saved-client-uuid'
export CATCHPLATE_CA_FILE='/absolute/path/catchplate-ca.pem'
read -r -s -p 'Catchplate client proxy token: ' CATCHPLATE_PROXY_TOKEN
printf '\n'
export CATCHPLATE_PROXY_TOKEN

curl --fail-with-body --show-error --http1.1 \
  --connect-timeout 10 --max-time 30 \
  --noproxy '' \
  --proxy "$CATCHPLATE_PROXY_URL" \
  --proxy-basic \
  --proxy-user "${CATCHPLATE_APP_ID}:${CATCHPLATE_PROXY_TOKEN}" \
  --cacert "$CATCHPLATE_CA_FILE" \
  --request GET \
  --header 'Accept: application/json' \
  --header 'User-Agent:' \
  'https://api.example.test/v1/status'

unset CATCHPLATE_PROXY_TOKEN
```

There is deliberately **no `Authorization` or `X-API-Key` header** here. With automatic insertion, the target credential header must be absent; an existing one is refused rather than overwritten. Catchplate adds the saved credential only after authorizing the request.

`--noproxy ''` keeps environment bypass settings from sending the request directly. `--cacert` trusts the intercepted API connection; the outer HTTPS proxy still needs its normal trusted certificate. Use the actual proxy endpoint, not the console URL. Do not disable either TLS check, add redirect following, or use automatic retries to work around a denial.

The shell expands the token into curl's arguments. Use a trusted host, keep tracing/debug logs off, and protect output if the API returns private data. Reading it interactively avoids a literal token in shell history; it does not hide process arguments from sufficiently privileged local observers.

## 4. If your existing library insists on a provider header

Use **Replace a dummy header value** instead of automatic insertion when creating its permission. The header name still comes from the saved credential. Enter the **full value**, not the header name:

| Saved credential | Exact dummy header value in permission | Client header |
| --- | --- | --- |
| Bearer token | `Bearer CATCHPLATE_STATUS_DUMMY` | `Authorization: Bearer CATCHPLATE_STATUS_DUMMY` |
| Custom header `X-API-Key` | `CATCHPLATE_STATUS_DUMMY` | `X-API-Key: CATCHPLATE_STATUS_DUMMY` |

For the Bearer variant, the curl request above would add `--header 'Authorization: Bearer CATCHPLATE_STATUS_DUMMY'`; for the custom-header variant it would add `--header 'X-API-Key: CATCHPLATE_STATUS_DUMMY'`. Use only the variant matching the saved credential and permission. Keep the separate proxy login unchanged.

Send exactly one matching header. A missing, different or duplicate value is refused. The dummy is case-sensitive, printable text with no leading/trailing spaces; it is never the provider secret or the client proxy token. This is exact replacement of one credential header, not general text replacement across URLs, bodies or responses. Use a distinct client if another workload needs a different permission; do not create conflicting rules for the same client/path/method.

## 5. Verify the result and audit trail

Check the actual API response, then open **Audit log → Refresh log**. Search by the saved client or permission reference and compare the recorded identity and timing with your request. Use **Allowed responses** or **Blocked / withheld responses** to narrow the results; use **All events** when investigating failures that did not release a response.

An active permission proves policy activation, not provider-key validity. A denied request may indicate the wrong proxy token, expiry, host/path/method, header/dummy value or unsupported response. Do not fix it by broadening every permission. Follow [Troubleshooting](Troubleshooting.md).

**Verify audit log** checks the local stored chain, not an independent witness or hardware attestation. A withheld response can follow an attempted upstream request. If you later adapt this recipe to writes, an error or timeout is not proof that nothing happened; never automatically replay an uncertain write.

Source contracts: [manual setup UI](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/workspace_connect.js), [curl template](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/app.js), [ordinary JSON compatibility](https://github.com/AndrewMohawk/catchplate/blob/main/docs/ordinary-client-compatibility.md). This guide does not establish compatibility with every SDK, request-signing scheme or API.
