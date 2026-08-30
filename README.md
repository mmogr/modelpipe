# modelpipe

**Your model server, from anywhere. No VPN, no account, no cloud in the path.**

modelpipe makes local AI inference reachable from your other devices over an
end-to-end encrypted peer-to-peer connection, paired by a ticket. Neither
machine needs a public IP, an open port, a VPN profile, or an account with
anyone. It works with any OpenAI-compatible server.

```bash
# On the machine with the models
modelpipe serve http://127.0.0.1:11434
# → prints a pairing ticket (and a QR code), plus a bearer token

# On any other machine
modelpipe connect <ticket> --bind 127.0.0.1:8080
# → http://127.0.0.1:8080/v1 on this machine now *is* your model server
#   (omit --bind and it picks a free loopback port, printing the URL)
```

Point any OpenAI-compatible client at the printed URL, with the token from
the serve side as the API key. That's the whole product.

## Install

```bash
cargo install modelpipe-cli   # installs a binary named `modelpipe`
```

Embedding it instead? The library is `cargo add modelpipe`.

## How it works

modelpipe embeds [iroh](https://github.com/n0-computer/iroh), the Rust p2p
library ([1.0](https://www.iroh.computer/blog/the-road-to-iroh-1-0), and
production-proven well before that). Both machines dial *outward* to a
public relay, which introduces them; they then hole-punch a direct
encrypted QUIC connection — roughly 90% of connections go direct in
[iroh's published numbers](https://www.iroh.computer/docs/protocols/net/holepunching),
carrying ~95% of data volume. When hole-punching fails — strict corporate
or carrier-grade NAT — traffic falls back to the relay, which only ever
carries ciphertext. The encryption keys are the machines' identities; no
TLS certificates, no certificate authorities, no third party that can read
a byte.

## Auth is not optional

`modelpipe serve` generates a bearer token and validates
`Authorization: Bearer …` on every request **before** a byte reaches your
backend. Ollama has no built-in auth;
[researchers found ~175,000 Ollama hosts exposed raw to the internet](https://thehackernews.com/2026/01/researchers-find-175000-publicly.html).
modelpipe in front of a naked backend gives it the API key it never
shipped. Running open requires an explicit flag whose name
(`--insecure-no-auth`) makes you feel bad typing it.

Two independent locks, and they travel separately: the **ticket** gates
who can connect at all, the **token** gates who can make requests. The
token is deliberately *not* inside the ticket — a leaked ticket alone
cannot make a request, and a leaked token alone cannot reach the listener.
Rotation is asymmetric on purpose: restarting the listener rotates the
ticket (and re-pairs everyone), while the token rotates in place with no
re-pairing (`ServeHandle::rotate_token`). One honest caveat for v0: a
ticket has no expiry and no revocation list, so a leaked ticket can reach
the listener until the serve process restarts. Treat tickets like keys,
not like invitations.

The backend itself must be local: loopback always, private (RFC 1918 /
ULA) ranges only behind an explicit `--allow-private-backend`, link-local
ranges — where cloud instance metadata lives — never. The check runs
against resolved addresses, not URL text, so a DNS name can't smuggle an
address past it. modelpipe extends trust outward from your machine; it
does not re-export someone else's server.

## Ticket format (v0 — draft)

A ticket is a base32 string encoding a versioned payload:

| field | contents |
|---|---|
| `version` | ticket format version (u8) |
| `endpoint` | iroh endpoint id + a set of transport addresses (relay URLs and/or direct socket addresses) |
| `backend` | hint: `openai-compatible` (only value in v0) |

The bearer token is **not** in the ticket — it travels separately, which
is what makes it a second lock.

This table is the shape of the payload, not yet a wire spec: the base32
alphabet, payload codec, field framing and integrity check get pinned down
by the implementation (most likely following
[iroh-tickets](https://crates.io/crates/iroh-tickets)' conventions —
base32-nopad over postcard). Until a byte-level spec with test vectors
lands here, a non-Rust client cannot interoperate from this document
alone. If you want to build one — mobile apps via iroh's official
Swift/Kotlin bindings are the obvious case — open an issue and the spec
gets written with you.

## Non-goals (v0)

- Multiple backends per ticket, named endpoints, routing — one pipe, one
  backend.
- A daemon, config files, a UI, accounts, hosted relays (iroh's public
  relays are the default; `--relay` if you run your own).
- Browser support (browsers can't hole-punch; a relay-only WASM client is
  possible but out of scope here).
- Model management of any kind. modelpipe moves requests; it has no opinion
  about what serves them.

## Relationship to gglib

modelpipe was extracted from (and is consumed by)
[gglib](https://github.com/mmogr/gglib)'s `gglib remote` feature. gglib is
the reliability layer for llama.cpp — tool-call repair, loop defense,
sampling authority; modelpipe is the transport that makes any such endpoint
reachable. gglib is AGPL-3.0; both projects have the same author and
copyright holder, and this extraction is relicensed MIT by that copyright
holder specifically so clients and other servers can embed it. gglib's
licensing does not apply here.

## Status

Pre-implementation. The API sketch in `modelpipe/src/lib.rs` and this README
are the contract under review; implementation follows a two-week dogfooding
gate of the manual dumbpipe equivalent. Issues and opinions welcome.
