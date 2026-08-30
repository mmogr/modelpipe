#!/usr/bin/env python3
"""Reference implementation of the modelpipe ticket format (v0) — the
executable companion to docs/ticket-format-v0.md.

Deliberately dependency-free (pure stdlib + a hand-rolled CRC-32C) so it
runs anywhere and doubles as pseudocode for a non-Rust implementer. Run it
to (re)generate the spec's test vectors; the spec's vectors MUST equal this
script's output byte for byte, and this decoder follows the spec's decoding
order exactly.
"""

import base64
import ipaddress

KIND = "pipe"
VERSION = 0x00
BACKEND_OPENAI_COMPATIBLE = 0x00
TAG_RELAY = 0x00
TAG_IP4 = 0x01
TAG_IP6 = 0x02
MAX_TICKET_BYTES = 1024
MIN_V0_TICKET_BYTES = 39  # version + id + addr_count + backend + crc


def crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), reflected, poly 0x1EDC6F41 (table 0x82F63B78),
    init and xorout 0xFFFFFFFF. Check value: crc32c(b"123456789") ==
    0xE3069283."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


assert crc32c(b"123456789") == 0xE3069283, "CRC-32C self-test failed"


def encode_addr(addr) -> bytes:
    kind, value = addr
    if kind == "relay":
        url = value.encode("utf-8")
        assert len(url) <= 0xFFFF
        return bytes([TAG_RELAY]) + len(url).to_bytes(2, "big") + url
    if kind == "ip":
        ip, port = value
        ip = ipaddress.ip_address(ip)
        tag = TAG_IP4 if ip.version == 4 else TAG_IP6
        return bytes([tag]) + ip.packed + port.to_bytes(2, "big")
    raise ValueError(kind)


def encode_ticket(endpoint_id: bytes, addrs, backend: int = BACKEND_OPENAI_COMPATIBLE) -> bytes:
    assert len(endpoint_id) == 32
    # Canonical form: sorted by encoded byte string, duplicates never emitted.
    encoded_addrs = sorted({encode_addr(a) for a in addrs})
    assert len(encoded_addrs) <= 0xFF
    body = (
        bytes([VERSION])
        + endpoint_id
        + bytes([len(encoded_addrs)])
        + b"".join(encoded_addrs)
        + bytes([backend])
    )
    ticket = body + crc32c(body).to_bytes(4, "big")
    assert len(ticket) <= MAX_TICKET_BYTES
    return ticket


def encode_string(ticket: bytes) -> str:
    b32 = base64.b32encode(ticket).decode("ascii").rstrip("=")
    return (KIND + b32).lower()


def decode_string(s: str) -> bytes:
    """The spec's decoding order: prefix, strict base32, the 1024 cap (all
    malformed on failure), then version dispatch; the v0 minimum and the
    CRC are owned by version 0x00. Returns the verified ticket bytes;
    decode_ticket() parses the structure."""
    s = s.lower()  # parse is case-insensitive over the whole string
    if not s.startswith(KIND):
        raise ValueError("malformed: wrong kind prefix")
    b32 = s[len(KIND):].upper()
    try:
        ticket = base64.b32decode(b32 + "=" * (-len(b32) % 8))
    except Exception as e:
        raise ValueError(f"malformed: {e}") from None
    # Strict canonicality: python's b32decode tolerates non-zero bits in a
    # final partial group; re-encoding catches that and every impossible
    # length class, so two different strings never decode to one ticket.
    if base64.b32encode(ticket).decode("ascii").rstrip("=") != b32:
        raise ValueError("malformed: non-canonical base32")
    if len(ticket) > MAX_TICKET_BYTES:
        raise ValueError("malformed: over the 1024-byte cap")
    if not ticket or ticket[0] != VERSION:
        version = ticket[0] if ticket else None
        raise ValueError(f"unsupported version: {version}")
    if len(ticket) < MIN_V0_TICKET_BYTES:
        raise ValueError("malformed: below the v0 minimum length")
    body, crc = ticket[:-4], int.from_bytes(ticket[-4:], "big")
    if crc32c(body) != crc:
        raise ValueError("malformed: checksum failure")
    return ticket


def _take(buf: bytes, pos: int, n: int):
    if pos + n > len(buf):
        raise ValueError("malformed: truncated structure")
    return buf[pos : pos + n], pos + n


def decode_ticket(ticket: bytes):
    """Parse verified v0 ticket bytes into (endpoint_id, addrs, backend),
    enforcing exact consumption: a v0 ticket has zero bytes between the
    structure's end and the CRC."""
    body = ticket[:-4]
    endpoint_id, pos = _take(body, 1, 32)
    (count,), pos = _take(body, pos, 1)
    addrs = []
    for _ in range(count):
        (tag,), pos = _take(body, pos, 1)
        if tag == TAG_RELAY:
            n_bytes, pos = _take(body, pos, 2)
            raw, pos = _take(body, pos, int.from_bytes(n_bytes, "big"))
            try:
                addr = ("relay", raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise ValueError("malformed: relay URL is not UTF-8") from None
        elif tag in (TAG_IP4, TAG_IP6):
            size = 4 if tag == TAG_IP4 else 16
            ip, pos = _take(body, pos, size)
            port, pos = _take(body, pos, 2)
            addr = ("ip", (str(ipaddress.ip_address(ip)), int.from_bytes(port, "big")))
        else:
            raise ValueError(f"malformed: unknown address tag {tag:#04x}")
        if addr not in addrs:  # duplicates collapse: the result is a set
            addrs.append(addr)
    (backend,), pos = _take(body, pos, 1)
    if pos != len(body):
        raise ValueError("malformed: trailing bytes after the structure")
    return bytes(endpoint_id), addrs, backend


# RFC 8032 section 7.1, TEST 1 public key — a real, citable ed25519 key.
RFC8032_TEST1_PK = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

VECTORS = [
    ("minimal: no transport addrs", RFC8032_TEST1_PK, []),
    (
        "one relay + one IPv4",
        RFC8032_TEST1_PK,
        [("relay", "https://relay.example.com/"), ("ip", ("192.168.1.7", 4433))],
    ),
    ("one IPv6", RFC8032_TEST1_PK, [("ip", ("2001:db8::1", 8080))]),
]

if __name__ == "__main__":
    for name, endpoint_id, addrs in VECTORS:
        ticket = encode_ticket(endpoint_id, addrs)
        s = encode_string(ticket)
        assert decode_string(s) == ticket
        assert decode_string(s.upper()) == ticket, "QR upcase must round-trip"
        got_id, got_addrs, got_backend = decode_ticket(ticket)
        assert got_id == endpoint_id and got_backend == BACKEND_OPENAI_COMPATIBLE
        assert sorted(map(str, got_addrs)) == sorted(map(str, addrs))
        print(f"### {name}")
        print(f"payload+crc ({len(ticket)} bytes): {ticket.hex()}")
        print(f"ticket: {s}")
        print()
