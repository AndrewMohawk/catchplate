"""Single fixed-provider TLS contact inside the measured helper.

Only encrypted TLS records cross the private channel. The untrusted parent
relay sees neither the authorization header nor the token reply. No redirect,
reconnect, HTTP retry, proxy configuration, DNS, cookie, or ambient CA source.
"""
from __future__ import annotations

import ssl
import time
from catchplate import native_oauth_refresh as m

EVENT = "catchplate.nativeOAuthRefreshTls/v1"


class Contact:
    _endpoints = m.ENDPOINTS
    _event = EVENT

    def __init__(self, *, channel, provider, roots, request, check, deadline):
        self.channel, self.provider, self.check = channel, provider, check
        self.deadline = deadline
        host, path, headers, body, _commitment = request
        m.require((host, path) == self._endpoints[provider])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname, context.verify_mode = True, ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=roots)
        context.set_alpn_protocols(["http/1.1"])
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname=host)
        self.sequence, self.wire_bytes, self.eof = 0, 0, False
        pairs = [("Host", host), ("Connection", "close"),
            ("Content-Length", str(len(body))), *headers.items()]
        m.require(len(body) <= 32768 and all(type(key) is str and type(value) is str
            and key and not any(c in key + value for c in "\r\n\0") for key, value in pairs))
        self.request = ("POST " + path + " HTTP/1.1\r\n" + "".join(key + ": " + value + "\r\n" for key, value in pairs)
            + "\r\n").encode("ascii") + body

    def transfer(self, *, read):
        self.check()
        output = self.outgoing.read()
        m.require(len(output) <= 64 * 1024 and self.sequence < 512 and not (read and self.eof))
        self.sequence += 1
        self.channel.send({"apiVersion": self._event, "providerId": self.provider, "sequence": self.sequence,
            "ciphertext": m.encoded(output) if output else None, "read": read}, self.deadline)
        value = self.channel.receive(self.deadline)
        m.require(set(value) == {"apiVersion", "sequence", "ciphertext", "eof"} and value["apiVersion"] == self._event
            and value["sequence"] == self.sequence and type(value["eof"]) is bool)
        incoming = b"" if value["ciphertext"] is None else m.decoded(value["ciphertext"], 64 * 1024)
        m.require(read or not incoming and not value["eof"])
        self.wire_bytes += len(output) + len(incoming)
        m.require(self.wire_bytes <= 512 * 1024 and not (incoming and value["eof"]))
        if incoming:
            self.incoming.write(incoming)
        if value["eof"]:
            self.eof = True; self.incoming.write_eof()
        self.check()

    def call(self, operation):
        while True:
            self.check()
            try:
                value = operation()
                if self.outgoing.pending:
                    self.transfer(read=False)
                return value
            except ssl.SSLWantWriteError:
                self.transfer(read=False)
            except ssl.SSLWantReadError:
                self.transfer(read=True)

    def run(self):
        self.call(self.tls.do_handshake)
        m.require(self.tls.selected_alpn_protocol() in {None, "http/1.1"})
        offset = 0
        while offset < len(self.request):
            count = self.call(lambda: self.tls.write(self.request[offset:]))
            m.require(count > 0); offset += count
        response = bytearray()
        while True:
            # EOF is a transport observation, never evidence that an attempted
            # POST did not run. An absent/truncated response stays uncertain.
            chunk = self.call(lambda: self.tls.read(16384))
            if not chunk:
                break
            response.extend(chunk)
            m.require(len(response) <= m.MAX_REPLY + 8192)
        self.check()
        received = time.time_ns()
        status, headers, body = parse_http(bytes(response))
        original = m.canonical({"status": status, "rawHeaders": headers, "bodyBase64url": m.encoded(body) if body else ""})
        m.require(len(original) <= m.MAX_ORIGINAL)
        return original, received, status, body


def parse_http(raw):
    # Preserve every original header and the decoded complete body. The fixed
    # request asks for Connection:close; neither keep-alive nor partial framing
    # can silently manufacture a complete issued-material capture.
    first, separator, body = raw.partition(b"\r\n\r\n")
    m.require(separator and len(first) <= 8192)
    lines = first.split(b"\r\n")
    statusline = lines.pop(0).decode("ascii").split(" ", 2)
    m.require(len(statusline) >= 2 and statusline[0] == "HTTP/1.1" and len(statusline[1]) == 3 and statusline[1].isdigit())
    status = int(statusline[1]); m.require(200 <= status <= 599)
    headers, framing = [], {}
    for line in lines:
        name, separator, value = line.partition(b":")
        m.require(separator and name and len(headers) < 64 and all(33 <= c <= 126 and c != 58 for c in name)
            and all(c == 9 or 32 <= c <= 126 for c in value))
        name, value = name.decode("ascii"), value.decode("ascii")
        headers.append([name, value])
        if name.lower() in {"content-length", "transfer-encoding", "content-encoding"}:
            m.require(name.lower() not in framing); framing[name.lower()] = value.strip().lower()
    m.require(len(m.canonical(headers)) <= 8192 and framing.get("content-encoding", "identity") == "identity")
    if "transfer-encoding" in framing:
        m.require(framing["transfer-encoding"] == "chunked" and "content-length" not in framing)
        decoded, offset = bytearray(), 0
        while True:
            end = body.find(b"\r\n", offset)
            m.require(end >= offset and end - offset <= 8)
            size_text = body[offset:end]
            m.require(size_text and all(c in b"0123456789abcdefABCDEF" for c in size_text))
            size = int(size_text, 16); offset = end + 2
            if size == 0:
                m.require(body[offset:] == b"\r\n"); break
            m.require(size <= m.MAX_REPLY and offset + size + 2 <= len(body) and body[offset + size:offset + size + 2] == b"\r\n")
            decoded.extend(body[offset:offset + size]); offset += size + 2
            m.require(len(decoded) <= m.MAX_REPLY)
        body = bytes(decoded)
    elif "content-length" in framing:
        size_text = framing["content-length"]
        m.require(size_text.isascii() and size_text.isdigit() and len(size_text) <= 7 and int(size_text) == len(body))
    m.require(len(body) <= m.MAX_REPLY)
    return status, headers, body
