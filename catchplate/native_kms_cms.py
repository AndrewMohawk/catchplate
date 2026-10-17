"""Closed AWS KMS Recipient CMS decoding; no key export or general CMS API.

Only structure is decoded here. RSA/OAEP, AES-CBC and padding are supplied by
the pinned cryptography implementation. This module is private to the measured
broker helper, not a request handler. All errors terminate that one owner.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_DATA = bytes.fromhex("2a864886f70d010701")
_ENVELOPED = bytes.fromhex("2a864886f70d010703")
_OAEP = bytes.fromhex("2a864886f70d010107")
_MGF1 = bytes.fromhex("2a864886f70d010108")
_PSPECIFIED = bytes.fromhex("2a864886f70d010109")
_SHA256 = bytes.fromhex("608648016503040201")
_AES256CBC = bytes.fromhex("60864801650304012a")


def _require(condition):
    if not condition:
        raise ValueError("invalid closed KMS recipient original")


class _Ber:
    def __init__(self, original):
        _require(type(original) is bytes and 1 <= len(original) <= 65536)
        self.original, self.nodes = original, 0

    def node(self, position, end, depth=0):
        self.nodes += 1
        _require(self.nodes <= 96 and depth <= 12 and position + 2 <= end)
        tag, length = self.original[position:position + 2]
        position += 2
        _require(tag != 0 and tag & 31 != 31)
        indefinite = length == 128
        if length > 128:
            count = length & 127
            _require(1 <= count <= 3 and position + count <= end
                and self.original[position] != 0)
            length = int.from_bytes(self.original[position:position + count], "big")
            position += count
            _require(length >= 128 and length.bit_length() > (count - 1) * 8)
        if indefinite:
            _require(tag & 32 != 0)
            limit = end
        else:
            limit = position + length
            _require(limit <= end)
        if tag & 32:
            _require(tag in {0x30, 0x31, 0x24, 0xA0, 0xA1, 0xA2})
            values = []
            while position < limit:
                if indefinite and self.original[position:position + 2] == b"\0\0":
                    return (tag, values), position + 2
                item, position = self.node(position, limit, depth + 1)
                values.append(item)
            _require(not indefinite and position == limit)
            return (tag, values), position
        _require(not indefinite and tag in {2, 4, 5, 6, 0x80})
        return (tag, self.original[position:limit]), limit

    def complete(self):
        value, end = self.node(0, len(self.original))
        _require(end == len(self.original))
        return value


def _children(value, tag, count):
    _require(value[0] == tag and type(value[1]) is list and len(value[1]) == count)
    return value[1]


def _primitive(value, tag):
    _require(value[0] == tag and type(value[1]) is bytes)
    return value[1]


def _oid(value, expected):
    _require(_primitive(value, 6) == expected)


def _sha256_algorithm(value):
    _require(value[0] == 0x30 and len(value[1]) in {1, 2})
    _oid(value[1][0], _SHA256)
    if len(value[1]) == 2:
        _require(_primitive(value[1][1], 5) == b"")


def _oaep_algorithm(value):
    algorithm, parameters = _children(value, 0x30, 2)
    _oid(algorithm, _OAEP)
    _require(parameters[0] == 0x30 and len(parameters[1]) in {2, 3})
    values = parameters[1]
    # Absence of these fields would select SHA-1 defaults, never this profile.
    _sha256_algorithm(_children(values[0], 0xA0, 1)[0])
    mgf = _children(_children(values[1], 0xA1, 1)[0], 0x30, 2)
    _oid(mgf[0], _MGF1)
    _sha256_algorithm(mgf[1])
    if len(values) == 3:
        label = _children(_children(values[2], 0xA2, 1)[0], 0x30, 2)
        _oid(label[0], _PSPECIFIED)
        _require(_primitive(label[1], 4) == b"")


def _content(value):
    if value[0] == 0x80:
        result = _primitive(value, 0x80)
    else:
        _require(value[0] == 0xA0 and 1 <= len(value[1]) <= 16)
        # BER may scatter the IMPLICIT encrypted OCTET STRING. Permit only
        # bounded primitive chunks, never arbitrary recursive normalization.
        chunks = [_primitive(item, 4) for item in value[1]]
        _require(all(chunks))
        result = b"".join(chunks)
    _require(len(result) == 48)  # exactly one padded 32-byte broker KEK
    return result


def unwrap_broker_kek(original, private_key):
    """Internal one-shot operation; the caller never serializes this result."""
    content_type, wrapper = _children(_Ber(original).complete(), 0x30, 2)
    _oid(content_type, _ENVELOPED)
    version, recipients, encrypted = _children(_children(wrapper, 0xA0, 1)[0], 0x30, 3)
    _require(_primitive(version, 2) == b"\x02")
    recipient = _children(_children(recipients, 0x31, 1)[0], 0x30, 4)
    _require(_primitive(recipient[0], 2) == b"\x02")
    # The sole CMS subject identifier is syntax, not key-admission authority.
    # Actual private-key possession and the independently assigned full KEK
    # commitment close that join; no parent-provided recipient label does.
    _require(1 <= len(_primitive(recipient[1], 0x80)) <= 64)
    _oaep_algorithm(recipient[2])
    encrypted_key = _primitive(recipient[3], 4)
    _require(private_key.key_size == 2048 and len(encrypted_key) == 256)
    kind, algorithm, encrypted_content = _children(encrypted, 0x30, 3)
    _oid(kind, _DATA)
    cipher_oid, iv = _children(algorithm, 0x30, 2)
    _oid(cipher_oid, _AES256CBC)
    iv = _primitive(iv, 4)
    _require(len(iv) == 16)
    ciphertext = _content(encrypted_content)
    key = private_key.decrypt(encrypted_key, rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    _require(len(key) == 32)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    result = unpadder.update(padded) + unpadder.finalize()
    _require(len(result) == 32)
    return result
