# modelpipe ticket format, version 0

Status: **shipped in 0.1.0**. This is the contract a non-Rust client
implements against. The test vectors at the bottom are normative,
`scripts/ticket_vectors.py` is the executable reference that regenerates
them, and `scripts/ticket_vectors.py --check` asserts the two agree on every
CI run — as does the Rust codec, which hard-codes the same vectors rather
than generating them, so three independent implementations have to agree
before anything is released.

A v0 ticket will always parse as a v0 ticket. Changing any of what follows
means a new version byte and a new section beneath this one, never an edit
to this one — which is why the reference implementation refuses to have an
`--update` flag.

Why the bytes are laid out explicitly rather than serialized from the
transport's own types is recorded in
[ADR 0001](https://github.com/mmogr/modelpipe/blob/main/docs/adr/0001-an-explicit-ticket-byte-layout.md).

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
- **A ticket is ASCII, and case-insensitivity is ASCII case-insensitivity.**
  A parser must reject any non-ASCII input rather than case-folding it.
  This is not pedantry: under full Unicode folding U+212A KELVIN SIGN
  lowercases to `k`, so a ticket carrying one would be accepted by an
  implementation that folds and rejected by one that does not — an
  interoperability split with no upside. Rust's `eq_ignore_ascii_case` is
  the correct behaviour; Python's `str.lower` is not, and the reference
  implementation guards against its own language here.
- Base32 decoding is **strict**: a character outside the alphabet, a
  character count that encodes no whole-byte string (length mod 8 of 1,
  3 or 6), or non-zero bits in the final partial group are all malformed.
  The encoding is canonical, so no two strings **of the same case** decode
  to the same ticket. (Across cases they deliberately do — that is what
  the QR rule above requires — and at the semantic level several distinct
  byte strings can describe one pairing, since decoders accept addresses
  in any order. Only encoder output is canonical.)
- Parsers reject a decode above **1024 bytes**. A parser may — and should
  — reject an over-long *input string* before decoding it: the cap is
  stated on the decoded bytes, but enforcing it only afterwards means a
  hostile megabyte-long string is fully allocated, and re-allocated by the
  canonicality check, before the guard it exists for ever fires. The
  equivalent bound is `4 + ceil(1024 * 8 / 5)` = **1643 characters**.

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

Each transport address is:

| size | field |
|---|---|
| 1 | `tag` |
| 2 | `len` — byte length of `body` |
| `len` | `body` — tag-specific, below |

| tag | body |
|---|---|
| `0x00` relay | UTF-8 relay URL, carried verbatim |
| `0x01` IPv4 | 4 address bytes, then `u16` port (`len` is always 6) |
| `0x02` IPv6 | 16 address bytes, then `u16` port (`len` is always 18) |

**Every body is length-prefixed, including the fixed-width ones.** The two
bytes are redundant for `0x01` and `0x02` and are spent deliberately: they
are what lets a parser skip a tag it does not recognise. Without them,
adding a transport in a later version would be a flag day — every paired
device re-scanning a new ticket — because an old parser could not find
where the unknown address ended. With them it is a graceful degrade. This
is the one framing decision a version byte cannot rescue later, since the
rescue is precisely the thing that would have been deferred.

## Rules

**Decoding order and error taxonomy.** A parser checks, in order: that
the input is ASCII, that it is within the character bound, the kind
prefix, strict base32, the 1024-byte cap, and that at least one byte
remains — every failure among these is `Malformed`. It then reads
`version` and dispatches. A version it does not speak is
`UnsupportedVersion(v)`, distinct from `Malformed` because the advice
differs ("upgrade" vs "re-copy"). Everything after the version byte is
owned by that version, and v1+ may change any of it; for `0x00` that
means: a decoded length below **39 bytes** (the minimal v0 ticket) is
`Malformed`, then the checksum is verified, then the structure is parsed
under the rules below — every failure in the version-owned stage is
likewise `Malformed`.

The empty-payload case is called out because it is the one place the
order matters and the obvious implementation gets it wrong: `"pipe"`
alone passes the prefix, base32 and cap checks and then has no version
byte to dispatch on. `UnsupportedVersion` carries a `u8` and has nothing
to put in it, so **an empty or sub-one-byte payload is `Malformed`** —
"cannot read the version byte" is a framing failure, not a newer format.

One consequence, accepted: the checksum is itself version-owned, so a
parser cannot verify it for a version it does not speak — a transcription
error that strikes the version byte therefore surfaces as "upgrade"
rather than "re-copy", the one corruption class the checksum cannot catch.

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

**Encoder size obligation.** The field widths admit 255 addresses and a
65535-byte relay body, so the layout alone permits tickets far past the
cap every parser enforces. An encoder **must not** emit a ticket over
1024 bytes: it drops lowest-priority addresses until the ticket fits
rather than minting one no conforming parser will accept. The practical
ceiling depends on what is in the ticket — roughly 109 IPv4 addresses or
46 IPv6 — which is why this is an obligation to check rather than a
number to write down.

**Exact consumption.** The layout is self-delimiting: `addr_count` fixes
where `backend` and `crc` sit. A v0 ticket has exactly zero bytes
between the end of the structure and the checksum; a structure that runs
past the available bytes, or leaves bytes over, is `Malformed`.

**Relay URLs.** The body must be valid UTF-8; bytes that are not are
`Malformed`. "Carried verbatim" means no normalization: a parser must
not rewrite case, percent-encoding, trailing dots, or an explicitly
written default port — the string that went in is the string that comes
out. Implementations should note that passing the body through a URL
library on the way in or out will silently break this; vector 5 exists to
catch exactly that.

**Unknown values.** An unknown address tag is **skipped**: a parser reads
its `len`, advances by that many bytes, and continues. The address is
absent from the parsed result, so the returned address list may be
shorter than `addr_count` — including empty, which is a valid ticket. An
unknown `backend` value likewise does not fail the parse; v0 defines no
accessor for it, so there is nothing for a v0 consumer to observe, and
`backend` remains a hint whose only purpose is that a newer serve side
stays pairable from an older client.

**Endpoint id.** Parsers treat it as 32 opaque bytes; curve validity is
the transport's business at connect time, not the parser's.

**What is deliberately absent.** The bearer token (it travels separately
— that is the two-locks design), expiry, and any signature (see *Checksum*
above).

A v0 ticket carries no lifetime of its own: it is valid for exactly as long
as the endpoint it names is reachable. By default a serving process mints a
fresh endpoint key on every run, so restarting invalidates every ticket it
ever printed; a process that stores its key keeps them working. Both are
properties of the *serving side*, not of the ticket, and a parser cannot
tell the two apart — which is why there is nothing here to encode.

## Test vectors (normative)

All five use the ed25519 public key from RFC 8032 §7.1 TEST 1:
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`.

**1. Minimal — no transport addresses**

```
bytes (39): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0000a1d6fd34
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na
```

**2. One relay (`https://relay.example.com/`) + one IPv4 (`192.168.1.7:4433`)**

```
bytes (77): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0200001a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f010006c0a80107115100c5fdbc79
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqaaangq5duobztulzpojswyylzfzsxqylnobwgkltdn5ws6aiaa3akqaihcfiqbrp5xr4q
```

**3. One IPv6 (`[2001:db8::1]:8080`)**

```
bytes (60): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0102001220010db80000000000000000000000011f9000032990f6
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaicaajcaainxaaaaaaaaaaaaaaaaaaach4qaabstehw
```

**4. An unknown address tag, skipped** — one IPv4 (`192.168.1.7:4433`)
plus tag `0x7f` carrying four bytes. A conforming v0 parser yields
exactly one address.

```
bytes (55): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a02010006c0a8010711517f0004deadbeef00046ac5b0
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqbaadmbkaba4ivc7yaatpk3pxpaacgvrnq
```

**5. A relay URL no parser may normalize** —
`https://Relay.Example.COM.:443/%7Efoo`. Every part of it is something a
URL library rewrites: uppercase host, trailing dot, explicitly written
default port, unreserved percent-escape. The bytes below carry it
unchanged, and a round-trip that alters any of them is a bug.

```
bytes (79): 00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0100002568747470733a2f2f52656c61792e4578616d706c652e434f4d2e3a3434332f253745666f6f00d76d87c7
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaiaaaswq5duobztulzpkjswyylzfzcxqylnobwgklsdj5gs4orugqzs6jjxivtg63ya25wypry
```

A conforming parser additionally accepts each `ticket` string fully
uppercased and yields identical bytes.

## The protocol a ticket leads to (normative)

A ticket says *where* a peer is. What to say once you get there is the other
half, and a client cannot guess it.

The QUIC ALPN is the ASCII string **`modelpipe/0`**. A dialer offers exactly
this; a listener may offer several, which is what makes introducing
`modelpipe/1` a rollout rather than a flag day.

The version here is **independent of the ticket's version byte**. They are
separate compatibility spaces, and the ticket's version cannot cover for
this one: a ticket that parses perfectly still reaches a peer you cannot
speak to if the ALPNs do not overlap. A refusal to negotiate is what a
client sees when the two sides speak different protocol versions, and it is
distinct from being unable to reach the peer at all.

What travels *over* an accepted connection is not specified in this
document. It will be, before anything claims to be stable — until then, a
non-Rust client can pair and negotiate, and the exchange format is the Rust
implementation's.

## Refusals (normative)

The vectors above are all happy paths, and the error taxonomy is half of
what an implementer has to get right. Each input below must be refused,
with the verdict given. `scripts/ticket_vectors.py --check` constructs
each case and asserts the verdict, and asserts that this table lists the
same set.

| input | verdict |
|---|---|
| the wrong kind prefix | `Malformed` |
| an empty payload | `Malformed` |
| a character outside the alphabet | `Malformed` |
| an impossible length class | `Malformed` |
| non-zero bits in the final group | `Malformed` |
| a corrupted checksum | `Malformed` |
| truncation | `Malformed` |
| a non-ASCII lookalike | `Malformed` |
| a string longer than any ticket | `Malformed` |
| a format version this build does not speak | `UnsupportedVersion` |

The verdicts are deliberately coarse. A ticket is pasted or scanned, so
the advice a user can act on is one line — re-copy it, or upgrade — and
the two rows above are exactly those two lines. This table pins the
*classification*, not any message text.
