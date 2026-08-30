# modelpipe ticket format, version 0

Status: **draft for review** — this is the byte-level spec the README's
ticket-format section promises. Once merged it is the contract a non-Rust
client implements against; the test vectors at the bottom are normative,
and `scripts/ticket_vectors.py` is the executable reference that
regenerates them (the two must never disagree).

## String form

A ticket is the ASCII string:

```
"pipe" + base32-nopad(ticket-bytes)
```

- The base32 alphabet is RFC 4648 (`A–Z`, `2–7`), **without padding**.
- Producers emit the entire string **lowercase** — the same convention as
  [iroh-tickets](https://crates.io/crates/iroh-tickets) (lowercase kind
  prefix followed by base32-nopad of the bytes).
- Parsers accept the entire string **case-insensitively**, prefix
  included. This is deliberately *looser* than iroh-tickets' default
  (which matches the prefix case-sensitively): QR alphanumeric mode only
  encodes uppercase, so a display layer may upcase the whole ticket for a
  smaller QR code, and a scan of that code must round-trip through a
  parser unchanged.
- Base32 decoding is **strict**: a character outside the alphabet, a
  character count that encodes no whole-byte string (length mod 8 of 1,
  3 or 6), or non-zero bits in the final partial group are all malformed.
  Two different strings never decode to the same ticket.
- Parsers reject a decode above **1024 bytes** — a denial-of-service
  guard, independent of format version; no legitimate ticket approaches
  it.

## Byte layout

All multi-byte integers are **big-endian**. There is no framing beyond
what is listed; fields are contiguous.

| offset | size | field |
|---|---|---|
| 0 | 1 | `version` — `0x00` for this format |
| 1 | 32 | `endpoint_id` — the serve side's ed25519 public key, raw bytes |
| 33 | 1 | `addr_count` — number of transport addresses (0–255) |
| 34 | … | `addr_count` transport addresses, each as below |
| … | 1 | `backend` — `0x00` = `openai-compatible` (only value assigned in v0) |
| … | 4 | `crc` — CRC-32C of every preceding byte, big-endian |

Each transport address is a 1-byte tag followed by a tag-specific body:

| tag | body |
|---|---|
| `0x00` relay | `u16` byte length, then that many bytes of UTF-8 relay URL, carried verbatim |
| `0x01` IPv4 | 4 address bytes, then `u16` port |
| `0x02` IPv6 | 16 address bytes, then `u16` port |

## Rules

**Decoding order and error taxonomy.** A parser checks, in order: the
kind prefix, strict base32, the 1024-byte cap — every failure among
these is `Malformed` — then reads `version` and dispatches. A version it
does not speak is `UnsupportedVersion(v)`, distinct from `Malformed`
because the advice differs ("upgrade" vs "re-copy"). Everything after
the version byte is owned by that version, and v1+ may change any of
it; for `0x00` that means: a decoded length below **39 bytes** (the
minimal v0 ticket) is `Malformed`, then the checksum is verified, then
the structure is parsed under the rules below — every failure in the
version-owned stage is likewise `Malformed`. One consequence, accepted:
the checksum is itself version-owned, so a parser cannot verify it for
a version it does not speak — a transcription error that strikes the
version byte therefore surfaces as "upgrade" rather than "re-copy",
the one corruption class the checksum cannot catch.

**Checksum.** CRC-32C (Castagnoli; reflected, polynomial `0x1EDC6F41`,
init and xor-out `0xFFFFFFFF`; check value: `crc32c("123456789") =
0xE3069283`). It guards against transcription and scan corruption — a
mistyped character, a misread QR — **not** against tampering: anyone who
can modify your ticket in transit can replace it wholesale, and the
transport's real authentication is the endpoint key itself plus the
bearer token that never rides in the ticket. A checksum mismatch is
`Malformed`.

**Address order.** Encoders emit addresses sorted by their encoded byte
string (which groups relays before IPv4 before IPv6) and never emit
duplicates, so equal tickets compare equal as strings. Decoders accept
any order and any mix, including zero addresses (an id-only ticket
remains resolvable through address lookup); a duplicated address
collapses — the parsed result is a set.

**Exact consumption.** The layout is self-delimiting: `addr_count` fixes
where `backend` and `crc` sit. A v0 ticket has exactly zero bytes
between the end of the structure and the checksum; a structure that runs
past the available bytes, or leaves bytes over, is `Malformed`.

**Relay URLs.** The body must be valid UTF-8; bytes that are not are
`Malformed`. "Carried verbatim" means no normalization: a parser must
not rewrite case, percent-encoding, or trailing dots — the string that
went in is the string that comes out.

**Unknown values.** An unknown address tag is `Malformed`, and adding a
tag is a version bump — a deliberate v0 trade-off: only the relay body
is length-prefixed, so unknown tags are not skippable. (The
alternative — length-prefixing every body so an older client could
degrade gracefully around transports it doesn't speak — is a live
option for v1.) An unknown `backend` value parses successfully and is
surfaced as unknown: the field is a hint, and a newer serve side must
remain pairable from an older client.

**Endpoint id.** Parsers treat it as 32 opaque bytes; curve validity is
the transport's business at connect time, not the parser's.

**What is deliberately absent.** The bearer token (it travels separately
— that is the two-locks design), expiry (v0 tickets live until the serve
process restarts), and any signature (see *Checksum* above).

## Why an explicit layout instead of postcard

The README long leaned toward "iroh-tickets conventions: base32-nopad
over postcard." The string half of that survives verbatim. The byte half
does not, deliberately: postcard-serializing iroh's own types would make
the wire format an echo of `iroh-base`'s serde internals — a
`#[non_exhaustive]` enum with a `Custom` variant, a hand-written
`PublicKey` impl, `BTreeSet` ordering — documented nowhere but in Rust
source, and quietly changeable by any iroh release. A mobile client in
Swift or Kotlin implements the table above from this page alone, which
is the entire point of writing it down.

## Test vectors (normative)

All three use the ed25519 public key from RFC 8032 §7.1 TEST 1:
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`.

**1. Minimal — no transport addresses**

```
bytes (39): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0000a1d6fd34
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na
```

**2. One relay (`https://relay.example.com/`) + one IPv4 (`192.168.1.7:4433`)**

```
bytes (75): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0200001a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f01c0a80107115100f02ef9a1
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqaaangq5duobztulzpojswyylzfzsxqylnobwgkltdn5ws6aoavaaqoekradyc56nb
```

**3. One IPv6 (`[2001:db8::1]:8080`)**

```
bytes (58): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a010220010db80000000000000000000000011f9000dd373c48
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaiceaaq3oaaaaaaaaaaaaaaaaaaaepzaag5g46eq
```

A conforming parser additionally accepts each `ticket` string fully
uppercased and yields identical bytes.
