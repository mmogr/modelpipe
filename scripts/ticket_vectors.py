#!/usr/bin/env python3
"""Reference implementation of the modelpipe ticket format (v0) — the
executable companion to docs/ticket-format-v0.md.

Deliberately dependency-free (pure stdlib + a hand-rolled CRC-32C) so it
runs anywhere and doubles as pseudocode for a non-Rust implementer. This
decoder follows the spec's decoding order exactly.

Usage:
    scripts/ticket_vectors.py            print the vectors, spec-formatted
    scripts/ticket_vectors.py --check    assert the spec's vectors match

There is deliberately no --update. A v0 vector that changes is not a stale
fixture, it is a broken client in some other language: the vectors are the
contract a Swift or Kotlin implementer builds against, and rewriting them
in place would turn an incompatibility into a green build. When the format
has to change, it gets a new version byte and a new vector section beneath
this one. A missing flag reads as an oversight; a refused one reads as a
decision, which is why --check says so out loud when asked to rewrite.
"""

import re
import sys
from pathlib import Path

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

# The string form's own bound, checked BEFORE base32 decoding. The cap the
# spec states is on decoded bytes, but enforcing it only after decoding means
# a hostile megabyte-long string is fully allocated — and, by the canonicality
# re-encode below, allocated twice — before the guard it exists for ever
# fires. ceil(1024 * 8 / 5) = 1639 base32 characters, plus the prefix.
MAX_TICKET_CHARS = len(KIND) + (MAX_TICKET_BYTES * 8 + 4) // 5

SPEC = Path(__file__).resolve().parent.parent / "docs" / "ticket-format-v0.md"


class TicketError(ValueError):
    """Base for every refusal, so a caller can tell a ticket problem from a
    bug in its own code."""


class Malformed(TicketError):
    """Re-copy it. Everything the checksum and the framing rules catch."""


class UnsupportedVersion(TicketError):
    """Upgrade. The payload parsed far enough to read a version this build
    does not speak."""


class TooLarge(TicketError):
    """An encoder was asked to mint a ticket no conforming parser would
    accept. Distinct from Malformed because it is raised on the way out,
    not on the way in."""


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
    """tag || u16 body length || body.

    Every body is length-prefixed, including the fixed-width IP ones where
    the length is redundant. Two bytes per address buys the property the
    redundancy pays for: a parser that meets a tag it does not know can skip
    exactly that many bytes and carry on, so adding a transport later is a
    graceful degrade rather than a flag day for every paired device.
    """
    kind, value = addr
    if kind == "relay":
        body = value.encode("utf-8")
        tag = TAG_RELAY
    elif kind == "ip":
        ip, port = value
        ip = ipaddress.ip_address(ip)
        tag = TAG_IP4 if ip.version == 4 else TAG_IP6
        body = ip.packed + port.to_bytes(2, "big")
    elif kind == "raw":
        # For building the unknown-tag vector: an address this version has
        # no meaning for, which a v0 parser must skip rather than reject.
        tag, body = value
    else:
        raise ValueError(kind)
    if len(body) > 0xFFFF:
        raise TooLarge(f"address body is {len(body)} bytes, over the u16 length")
    return bytes([tag]) + len(body).to_bytes(2, "big") + body


def encode_ticket(endpoint_id: bytes, addrs, backend: int = BACKEND_OPENAI_COMPATIBLE) -> bytes:
    if len(endpoint_id) != 32:
        raise ValueError("endpoint id must be 32 bytes")
    # Canonical form: sorted by encoded byte string, duplicates never emitted.
    encoded_addrs = sorted({encode_addr(a) for a in addrs})
    if len(encoded_addrs) > 0xFF:
        raise TooLarge(f"{len(encoded_addrs)} addresses, over the u8 count")
    body = (
        bytes([VERSION])
        + endpoint_id
        + bytes([len(encoded_addrs)])
        + b"".join(encoded_addrs)
        + bytes([backend])
    )
    ticket = body + crc32c(body).to_bytes(4, "big")
    # An encoder obligation, not merely a parser one. The field widths admit
    # 255 addresses and a 65535-byte relay body, so the layout alone permits
    # tickets far past the cap every parser enforces; without this an encoder
    # could mint one no decoder on earth accepts and only find out in the
    # field. The real ceiling is well under 255 — about 109 IPv4 addresses,
    # 46 IPv6 — and depends on what is in the ticket, which is exactly why it
    # is checked here rather than written down as a number.
    if len(ticket) > MAX_TICKET_BYTES:
        raise TooLarge(
            f"ticket is {len(ticket)} bytes, over the {MAX_TICKET_BYTES}-byte cap; "
            "drop lowest-priority addresses rather than emitting it"
        )
    return ticket


def encode_string(ticket: bytes) -> str:
    b32 = base64.b32encode(ticket).decode("ascii").rstrip("=")
    return (KIND + b32).lower()


def decode_string(s: str) -> bytes:
    """The spec's decoding order: ASCII, the character bound, prefix, strict
    base32, the byte cap (all malformed on failure), then version dispatch;
    the v0 minimum and the CRC are owned by version 0x00. Returns verified
    ticket bytes; decode_ticket() parses the structure."""
    # ASCII first, and as a refusal rather than a coercion. Python's str.lower
    # is full Unicode case folding, under which U+212A KELVIN SIGN lowercases
    # to "k" — so without this a ticket containing one would decode here and
    # be rejected by any implementation doing ASCII-only casing, which is what
    # the spec requires and what Rust's eq_ignore_ascii_case does.
    if not s.isascii():
        raise Malformed("malformed: a ticket is ASCII")
    if len(s) > MAX_TICKET_CHARS:
        raise Malformed("malformed: longer than any ticket can be")
    s = s.lower()  # parse is case-insensitive over the whole string
    if not s.startswith(KIND):
        raise Malformed("malformed: wrong kind prefix")
    b32 = s[len(KIND):].upper()
    try:
        ticket = base64.b32decode(b32 + "=" * (-len(b32) % 8))
    except Exception as e:
        raise Malformed(f"malformed: {e}") from None
    # Strict canonicality: python's b32decode tolerates non-zero bits in a
    # final partial group; re-encoding catches that and every impossible
    # length class, so no two strings of one case decode to one ticket.
    if base64.b32encode(ticket).decode("ascii").rstrip("=") != b32:
        raise Malformed("malformed: non-canonical base32")
    if len(ticket) > MAX_TICKET_BYTES:
        raise Malformed("malformed: over the 1024-byte cap")
    # Before the version dispatch, because there is no version to dispatch on.
    # UnsupportedVersion carries a u8 and has nothing to hold for an empty
    # payload; "cannot read the version byte" is a framing failure, not a
    # newer format.
    if not ticket:
        raise Malformed("malformed: no version byte")
    if ticket[0] != VERSION:
        raise UnsupportedVersion(f"unsupported version: {ticket[0]}")
    if len(ticket) < MIN_V0_TICKET_BYTES:
        raise Malformed("malformed: below the v0 minimum length")
    body, crc = ticket[:-4], int.from_bytes(ticket[-4:], "big")
    if crc32c(body) != crc:
        raise Malformed("malformed: checksum failure")
    return ticket


def _take(buf: bytes, pos: int, n: int):
    if pos + n > len(buf):
        raise Malformed("malformed: truncated structure")
    return buf[pos : pos + n], pos + n


def decode_ticket(ticket: bytes):
    """Parse verified v0 ticket bytes into (endpoint_id, addrs, backend),
    enforcing exact consumption: a v0 ticket has zero bytes between the
    structure's end and the CRC.

    Addresses whose tag this version does not know are skipped, so the
    returned list may be shorter than the ticket's address count."""
    body = ticket[:-4]
    endpoint_id, pos = _take(body, 1, 32)
    (count,), pos = _take(body, pos, 1)
    addrs = []
    for _ in range(count):
        (tag,), pos = _take(body, pos, 1)
        n_bytes, pos = _take(body, pos, 2)
        raw, pos = _take(body, pos, int.from_bytes(n_bytes, "big"))
        if tag == TAG_RELAY:
            try:
                addr = ("relay", raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise Malformed("malformed: relay URL is not UTF-8") from None
        elif tag in (TAG_IP4, TAG_IP6):
            size = 4 if tag == TAG_IP4 else 16
            if len(raw) != size + 2:
                raise Malformed(f"malformed: tag {tag:#04x} body is {len(raw)} bytes")
            addr = (
                "ip",
                (str(ipaddress.ip_address(raw[:size])), int.from_bytes(raw[size:], "big")),
            )
        else:
            # The whole point of length-prefixing every body: an address this
            # version cannot read costs the parse nothing.
            continue
        if addr not in addrs:  # duplicates collapse: the result is a set
            addrs.append(addr)
    (backend,), pos = _take(body, pos, 1)
    if pos != len(body):
        raise Malformed("malformed: trailing bytes after the structure")
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
    (
        # Proves the graceful degrade: tag 0x7f is meaningless in v0, and a
        # conforming v0 parser skips its four bytes and still finds the IPv4.
        "an unknown address tag, skipped",
        RFC8032_TEST1_PK,
        [("ip", ("192.168.1.7", 4433)), ("raw", (0x7F, bytes.fromhex("deadbeef")))],
    ),
    (
        # "Carried verbatim" made checkable: every part of this URL is
        # something a URL library normalizes away — uppercase host, trailing
        # dot, explicit default port, unreserved percent-escape.
        "a relay URL no parser may normalize",
        RFC8032_TEST1_PK,
        [("relay", "https://Relay.Example.COM.:443/%7Efoo")],
    ),
]

# Inputs that must be refused, and the verdict each must produce. The three
# happy-path vectors say nothing about the error taxonomy, which is half the
# contract a non-Rust implementer has to get right.
def _negative_cases():
    good = encode_string(encode_ticket(RFC8032_TEST1_PK, []))
    body = encode_ticket(RFC8032_TEST1_PK, [])[:-4]
    bad_crc = encode_string(body + b"\x00\x00\x00\x00")
    v1 = bytes([0x01]) + encode_ticket(RFC8032_TEST1_PK, [])[1:]
    return [
        ("the wrong kind prefix", "note" + good[4:], "malformed"),
        ("an empty payload", KIND, "malformed"),
        ("a character outside the alphabet", good[:-1] + "1", "malformed"),
        ("an impossible length class", good + "a", "malformed"),
        ("non-zero bits in the final group", "pipeab", "malformed"),
        ("a corrupted checksum", bad_crc, "malformed"),
        ("truncation", good[: len(good) // 2], "malformed"),
        ("a non-ASCII lookalike", good.replace("k", "K", 1), "malformed"),
        ("a string longer than any ticket", KIND + "a" * MAX_TICKET_CHARS, "malformed"),
        ("a format version this build does not speak", encode_string(v1), "unsupported-version"),
    ]


def _verdict(s: str) -> str:
    try:
        decode_string(s)
    except UnsupportedVersion:
        return "unsupported-version"
    except Malformed:
        return "malformed"
    return "accepted"


def _render():
    """The vectors, formatted exactly as the spec renders them, so --check is
    a comparison and regenerating is a copy."""
    out = []
    for name, endpoint_id, addrs in VECTORS:
        ticket = encode_ticket(endpoint_id, addrs)
        s = encode_string(ticket)
        assert decode_string(s) == ticket
        assert decode_string(s.upper()) == ticket, "QR upcase must round-trip"
        got_id, got_addrs, got_backend = decode_ticket(ticket)
        assert got_id == endpoint_id and got_backend == BACKEND_OPENAI_COMPATIBLE
        known = [a for a in addrs if a[0] != "raw"]
        assert sorted(map(str, got_addrs)) == sorted(map(str, known))
        out.append((name, f"bytes ({len(ticket)}): {ticket.hex()}", f"ticket: {s}"))
    return out


def _check() -> int:
    if not SPEC.exists():
        print(f"✗ spec not found: {SPEC}", file=sys.stderr)
        return 1
    text = SPEC.read_text()
    # Line-anchored rather than fence-scraping: the document has other fenced
    # blocks, and these two prefixes are unambiguous document-wide.
    spec_bytes = re.findall(r"^bytes \((\d+)\): ([0-9a-f]+)$", text, re.M)
    spec_tickets = re.findall(r"^ticket: (pipe[a-z2-7]+)$", text, re.M)
    rendered = _render()

    failed = False
    if len(spec_bytes) != len(rendered) or len(spec_tickets) != len(rendered):
        print(
            f"✗ spec has {len(spec_bytes)} byte lines and {len(spec_tickets)} ticket "
            f"lines; this script produces {len(rendered)} vectors",
            file=sys.stderr,
        )
        failed = True
    else:
        for i, (name, want_bytes, want_ticket) in enumerate(rendered):
            got_bytes = f"bytes ({spec_bytes[i][0]}): {spec_bytes[i][1]}"
            got_ticket = f"ticket: {spec_tickets[i]}"
            if got_bytes != want_bytes:
                print(f"✗ vector {i + 1} ({name}) bytes disagree", file=sys.stderr)
                print(f"    spec: {got_bytes}", file=sys.stderr)
                print(f"    here: {want_bytes}", file=sys.stderr)
                failed = True
            if got_ticket != want_ticket:
                print(f"✗ vector {i + 1} ({name}) ticket disagrees", file=sys.stderr)
                print(f"    spec: {got_ticket}", file=sys.stderr)
                print(f"    here: {want_ticket}", file=sys.stderr)
                failed = True

    negatives = _negative_cases()
    for label, value, want in negatives:
        got = _verdict(value)
        if got != want:
            print(f"✗ negative case '{label}': expected {want}, got {got}", file=sys.stderr)
            failed = True

    # The refusal table is the spec's half of the same contract, so it is
    # checked against this list rather than trusted. Without this the table
    # could name a case the script never runs, or miss one it does, and the
    # document would read as normative while asserting nothing.
    spec_name = {"malformed": "Malformed", "unsupported-version": "UnsupportedVersion"}
    want_rows = {(label, spec_name[verdict]) for label, _, verdict in negatives}
    got_rows = set(
        re.findall(r"^\| (.+?) \| `(Malformed|UnsupportedVersion)` \|$", text, re.M)
    )
    for row in sorted(want_rows - got_rows):
        print(f"✗ refusal table is missing: | {row[0]} | `{row[1]}` |", file=sys.stderr)
        failed = True
    for row in sorted(got_rows - want_rows):
        print(f"✗ refusal table names a case this script does not run: {row[0]}", file=sys.stderr)
        failed = True

    if failed:
        print(
            "\nThe spec and this script disagree. Fix whichever is wrong — there is\n"
            "deliberately no --update, because a v0 vector that changes is a broken\n"
            "client somewhere, not a stale fixture. A format that must change gets a\n"
            "new version byte and a new section.",
            file=sys.stderr,
        )
        return 1

    print(
        f"✓ {len(rendered)} vectors and {len(_negative_cases())} negative cases "
        "agree with the spec"
    )
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["--check"]:
        raise SystemExit(_check())
    if args == ["--update"]:
        # Answered explicitly rather than by "unknown flag", because someone
        # reaching for it has a failing --check in front of them and needs
        # the reason, not a usage line.
        print(
            "There is no --update, deliberately.\n\n"
            "A v0 vector that changes is not a stale fixture — it is a broken\n"
            "client in another language. These bytes are the contract a Swift or\n"
            "Kotlin implementation was built against, and rewriting them in place\n"
            "would turn an incompatibility into a green build.\n\n"
            "If --check is failing, exactly one of these is true:\n"
            "  * the script changed and the change is wrong — revert it;\n"
            "  * the script changed and the change is right — then the format\n"
            "    changed, which means a new version byte and a new vector\n"
            "    section beneath the v0 one, not an edit to it;\n"
            "  * the spec was hand-edited — restore it from this script's output.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if args:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    for name, byte_line, ticket_line in _render():
        print(f"### {name}")
        print(byte_line)
        print(ticket_line)
        print()
