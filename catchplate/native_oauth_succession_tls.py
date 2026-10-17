"""Single fixed succession TLS contact; only encrypted records cross parent."""
import ssl
from catchplate import native_oauth_refresh as m
from catchplate import native_oauth_exchange as provider_codec
from catchplate import native_oauth_succession as material
from catchplate.native_oauth_cleanup import ENDPOINTS as RETIREMENT_ENDPOINTS
from catchplate.native_oauth_refresh_tls import Contact as _Framing


class Contact:
    call = _Framing.call

    def __init__(self, *, channel, provider, purpose, roots, request, check, deadline):
        m.require(provider in provider_codec.AUTHORIZATION and purpose in {"retirement", "token", "identity"})
        self.channel, self.provider, self.purpose = channel, provider, purpose
        self.check, self.deadline = check, deadline
        if purpose in {"retirement", "token"}:
            host, path, headers, body, _commitment = request
            m.require((host, path) == (RETIREMENT_ENDPOINTS if purpose == "retirement" else m.ENDPOINTS)[provider] and len(body) <= 32768)
            method = "POST"
        else:
            host, path, headers = request
            m.require((host, path) == provider_codec.IDENTITY[provider])
            method, body = "GET", b""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname, context.verify_mode = True, ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=roots); context.set_alpn_protocols(["http/1.1"])
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname=host)
        self.sequence, self.wire_bytes, self.eof = 0, 0, False
        pairs = [("Host", host), ("Connection", "close"), ("Content-Length", str(len(body))), *headers.items()]
        m.require(all(type(key) is str and type(value) is str and key and not any(char in key + value for char in "\r\n\0") for key, value in pairs))
        self.request = (method + " " + path + " HTTP/1.1\r\n" + "".join(key + ": " + value + "\r\n" for key, value in pairs) + "\r\n").encode("ascii") + body

    def transfer(self, *, read):
        self.check()
        output = self.outgoing.read()
        m.require(len(output) <= 65536 and self.sequence < 512 and not (read and self.eof))
        self.sequence += 1
        self.channel.send({"apiVersion": material.TLS, "providerId": self.provider, "purpose": self.purpose,
            "sequence": self.sequence, "ciphertext": m.encoded(output) if output else None, "read": read}, self.deadline)
        value = self.channel.receive(self.deadline)
        m.require(set(value) == {"apiVersion", "sequence", "ciphertext", "eof"} and value["apiVersion"] == material.TLS
            and value["sequence"] == self.sequence and type(value["eof"]) is bool)
        incoming = b"" if value["ciphertext"] is None else m.decoded(value["ciphertext"], 65536)
        m.require(read or not incoming and not value["eof"])
        self.wire_bytes += len(output) + len(incoming)
        m.require(self.wire_bytes <= 512 * 1024 and not (incoming and value["eof"]))
        if incoming:
            self.incoming.write(incoming)
        if value["eof"]:
            self.eof = True; self.incoming.write_eof()
        self.check()

    def run(self):
        raw, received, status, body = _Framing.run(self)
        m.require(self.purpose != "identity" or len(body) <= provider_codec.MAX_IDENTITY_REPLY)
        return raw, received, status, body
