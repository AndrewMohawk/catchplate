# One ordinary native GET: operator collection and Setup handoff

Source-only connection. No build, proxy request, signing, provisioning, parser,
browser or test was run. The commands below are operator instructions, not an
assertion that deployment inputs exist or that the pilot has passed.

## Which evidence goes where

The actual `serverware-proof-client` makes the authenticated buffered request
and verifies its response, same-connection TLS bindings and original native
quote before its independently held collector key signs
`serverware.nativeResponseCapture/v2`. That exact file is the existing protected
Setup native-runtime consumer's input. The Python command below is just its
fixed caller: it has no signing implementation and never reads private keys.

The same ordinary GET also reaches the installed gate's `native_canary_runtime`
owner. With the actual selected runtime9/finalization configuration it captures
the genuine protected request facts and retained native `CommitRequest`
computation in `nativeRequestObservationOriginal/v3`, then signs/delivers the
accounting original through the existing one-shot durable canary protocol.
That is server-side evidence, not the client capture and not a CLI input. Do not
copy a client nonce, captured response, counter or collector verdict into a
request-original/v3 or a readiness record. The installed native generation,
independent purposes, genuine effects and full finalization conditions must all
exist. There is no `native_canary_runtime` shell command or caller success flag.

## Prerequisites and fixed configuration

An authorized operator must first provision the independently approved binaries,
native verifier/trust/ingress originals, outer mTLS identity, exact inner CA,
control-plane response public key and separately assigned collector private key.
Keep their real ownership/modes and original lifetimes. The proof client still
checks these actual inputs; a config path is not authority. This lane does not
build binaries, create keys, install trust or authorize an upstream action.

Use the closed [local routing schema](../schemas/setup-native-runtime-collector.v1.schema.json).
`proofClient`, `nativeVerifier`, `nativeTrustRoots` and `nativeIngress` are exact
`{path,sha256}` public input pins. `proxy` is one canonical unicast IP and port;
`proxyServerName` is the independently expected TLS name. The remaining path
fields are `proxyCa`, `proxyClientCertificate`, `proxyClientKey`, `innerCa`,
`collectorKey`, `controlPlaneResponseKey`. No key bytes or bearer credentials go
in JSON, CLI flags, stdout, logs or shell substitutions. `maximumContactSeconds`
is 1–120 and can only shorten the original attempt. Native ingress is mandatory
for this caller; the existing pinned ingress profile must actually admit the
principal and workload identity. Old collector invocations are unchanged.

The configuration's `apiVersion` is `serverware.setupNativeRuntimeCollector/v1`.
Its exact original digest and proof-client executable digest are independently
supplied operator pins, not learned from a proxy reply. The caller seals a copy
of those exact ELF executable bytes and invokes it directly, with no shell,
arbitrary trailing arguments or inherited loader environment. This is not a
new binary-closure attestation or a substitute for artifact admission.

Provision one persistent owner-only mode-0700 state directory for this operator
and deployment (for example `/var/lib/serverware-pilot/collector`). Do not use a
temporary directory, per-invocation empty directory, writable shared ancestry,
symlinks or network storage with unestablished durability. The operator owns
directory creation and durable backup. The command never clears old slots.

## Prepare, collect once, import

1. In the authenticated Setup portal, complete the genuine existing issuance,
   CA readback and native-canary association. Select **Fresh requester passkey +
   prepare once** under native runtime evidence. Review the actual empty-body
   HTTPS GET, principal, route and original expiry. This reserves evidence; it
   does not grant the underlying request.
2. Select **Collector bundle + exact digest**. Keep its exact bytes and the
   displayed SHA-256. The bundle contains the already-existing exact attempt,
   scope and native expectations strings. Move the download into a protected
   operator input directory without editing or reserializing it.
3. From the admitted Serverware source/package environment, use the actual
   module entrypoint (replace the illustrative pins/paths with admitted values):

   ```text
   python3 -B -m serverware.native_setup_runtime_collector collect --help
   python3 -B -m serverware.native_setup_runtime_collector collect \
     --bundle /approved/setup-native-runtime-collector-bundle.json \
     --bundle-sha256 sha256:<exact-portal-download-digest> \
     --configuration /approved/setup-runtime-collector.json \
     --configuration-sha256 sha256:<independently-pinned-config-digest> \
     --state-directory /var/lib/serverware-pilot/collector
   ```

   The request URL, GET method, no body/custom request headers, principal,
   server identity, nonce and expectations are fixed from the actual prepared
   scope. The actual collector signer must match that scope before contact.
   Native output is capped at the existing Setup limit of 512 KiB **before
   publication**, including original formatting and LF. Overflow is not retry
   permission. Stdout/stderr from the child are discarded, not echoed as proof.
4. A successful caller prints only the retained capture path/digest and false
   action/retry flags. Import that exact `capture.json` through the portal,
   choose **Review original capture binding**, then submit once. The protected
   backend independently verifies collector/native signatures, quote, CP receipt
   and current scope before its CAS. A command's exit status is not that CAS.

The original Setup/attempt expiry is never changed. The caller additionally
retains a `CLOCK_BOOTTIME` deadline, clips the native client's timeout and owns
the one spawned process/session through completion or kill/reap. System calls
may return late; this is not a hard real-time or hostile-host watchdog. Abrupt
caller/host loss can leave the child executing until its existing limits apply.
No result from a late contact renews the original deadline.

## Loss, export and truthful limits

Before any child spawn, an exclusive per-Setup directory and contact-unknown
marker are fsynced. An existing directory refuses even if preparation failed
before spawn, the response was lost or no capture exists. After an attempt,
never delete/reset the slot or choose a fresh directory to try again. The fence
trusts this host, same-UID operator and durable filesystem: it cannot stop that
operator bypassing the command, invoking the old proof client directly, rolling
back storage or using another host. It is not global exactly-once enforcement.

If a genuine capture was published before caller loss, recover only its data:

```text
python3 -B -m serverware.native_setup_runtime_collector export \
  --bundle /approved/setup-native-runtime-collector-bundle.json \
  --bundle-sha256 sha256:<same-exact-portal-download-digest> \
  --state-directory /var/lib/serverware-pilot/collector \
  --out /private-export/setup-native-runtime-capture.json
```

The export parent must already be owner-only mode0700 and the target must not
exist. Export verifies the retained original joins and collector signature, then
copies the exact bytes without replacement. It never contacts the proxy, signs,
relaunches the collector or extends expiry. Historical export may work after
expiry; that does not make an expired capture admissible to Setup. If no capture
is retained, no success is inferred and there is no retry command. Lost Setup
prepare/complete responses use the portal's read-only retained-state lookup.

The existing Setup receiver accepts only a buffered successful ordinary non-JIT
GET without quota/streaming/durable variants. A denied request is not converted
into a successful capture. Allowed/denied behavior, uncertainty, native effects,
request-original/v3, final cumulative readiness, hardware/proxy evidence and
independent final Setup must all pass the eventual connected acceptance gate;
this command alone claims none of those outcomes.
