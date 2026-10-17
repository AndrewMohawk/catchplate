"""Distinct native rotation purpose on the actual retained broker channel.

The shared custody lifecycle retains the same provisioned KEK, exact browser
nonce, immutable candidate, original clocks, and one-use preparation fence.
Its trusted selectors below cannot be changed by channel/browser input. No
create policy admits this purpose. Neither this owner nor its public bindings
prove the predecessor is current: the independent rotation kernel must join
the authenticated committed history and consume the actual drain barrier.
"""
from catchplate import authority_static_credential_rotate as profile
from catchplate import native_static_credential_rotation as material
from catchplate.native_static_credential_owner import Owner as _CreationOwner

CHANNEL = "catchplate.nativeStaticCredentialRotationChannel/v1"
CONFIG = "catchplate.nativeStaticCredentialRotationConfiguration/v1"


class Owner(_CreationOwner):
    _profile = profile
    _material = material
    _channel_api = CHANNEL
    _config_api = CONFIG

    def _predecessor_bindings(self, request):
        return {"previousCredentialVersion": request["previousCredentialVersion"],
            "previousCredentialSha256": request["previousCredentialSha256"],
            "previousCurrentnessOriginRequestDigest": request["previousCurrentnessOriginRequestDigest"],
            "previousProvenanceSha256": profile.sha256(request["previousProvenanceOriginal"].encode("ascii")),
            "predecessorBarrierSha256": request["predecessorBarrierSha256"],
            "predecessorCurrentnessRootSha256": request["predecessorCurrentnessRootSha256"]}
