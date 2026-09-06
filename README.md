# modelpipe

[![modelpipe-cli on crates.io](https://img.shields.io/crates/v/modelpipe-cli?style=flat-square&label=modelpipe-cli)](https://crates.io/crates/modelpipe-cli)
[![modelpipe on crates.io](https://img.shields.io/crates/v/modelpipe?style=flat-square&label=modelpipe)](https://crates.io/crates/modelpipe)
[![docs.rs](https://img.shields.io/docsrs/modelpipe?style=flat-square&label=docs.rs)](https://docs.rs/modelpipe)
[![CI](https://img.shields.io/github/actions/workflow/status/mmogr/modelpipe/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/mmogr/modelpipe/actions/workflows/ci.yml)

**Your model server, from anywhere. No VPN, no account, no cloud in the path.**

modelpipe puts your local model server on your other devices. Ollama,
llama.cpp, vLLM, anything that speaks the OpenAI API — including
[gglib](https://github.com/mmogr/gglib), which is what I actually built it
for. The other machine gets a `http://127.0.0.1:<port>/v1` that *is* that
server, over an end-to-end encrypted peer-to-peer connection. No port
forwarding, no public IP, no VPN, no account with anyone.

```bash
# On the machine with the models
modelpipe serve http://127.0.0.1:11434
# → prints a pairing ticket (and a QR code), plus a bearer token

# On any other machine
modelpipe connect <ticket> --bind 127.0.0.1:8080
# → http://127.0.0.1:8080/v1 on this machine now *is* your model server
#   (omit --bind and it picks a free loopback port, printing the URL)
```

Point any OpenAI-compatible client at that URL, with the token as the API
key. That's the whole product.

## Install

```bash
cargo install modelpipe-cli   # the binary is called `modelpipe`
```

Embedding it in something else? `cargo add modelpipe`.

## Using it

`serve` prints two things, and they go to two different places:

- the **ticket** goes to `modelpipe connect` on the other machine
- the **token** goes into your client, as the API key

The base URL is exactly what `connect` printed; it already ends in `/v1`.
So for a client that asks for a base URL and a key, it's
`http://127.0.0.1:8080/v1` and the token. The same for curl:

```bash
curl http://127.0.0.1:8080/v1/models -H "Authorization: Bearer <token>"
```

Neither string ever needs to go anywhere but those two places. A ticket
alone can't make a request, and a token alone can't find the listener,
which is the point of there being two.

### When it says no

modelpipe answers with a JSON error that names which machine to look at.
Three of them cover nearly everything:

| `code` | Who said it | What it means |
|---|---|---|
| `invalid_api_key` | the serving side | Your client sent the wrong token, or none. Check what the client is putting in the `Authorization` header. |
| `backend_unreachable` | the serving side | The token was fine. The model server behind it isn't answering on the port you gave `serve`. |
| `tunnel_unavailable` | the connecting side | The other machine is gone. It'll reconnect when it's back. |

## How it works

It's [iroh](https://github.com/n0-computer/iroh). Both machines dial *out*
to a public relay, which introduces them; then they hole-punch a direct,
encrypted QUIC connection to each other. When the punch fails — some
corporate and carrier-grade NATs — traffic goes through the relay instead,
and the relay only ever sees ciphertext. The machines' keys are their
identities. No certificates, no certificate authorities, nobody in the
middle who can read a byte.

## Auth is not optional

`serve` checks `Authorization: Bearer …` in constant time before a byte
reaches your backend. Ollama has no auth of its own
([and it shows](https://thehackernews.com/2026/01/researchers-find-175000-publicly.html));
modelpipe in front of it is the API key it never had. Running open takes a
flag called `--insecure-no-auth`, and the name is the warning.

Restarting `serve` mints a new ticket and everyone has to re-pair. That's
revocation, and it's free. If you'd rather pair once, `--identity <file>`
keeps the endpoint key, so the ticket survives restarts, and revoking it
becomes `rm`. One catch: the stored key keeps the *name* in the ticket, but
the addresses beside it still go stale, and finding the new ones is n0's
discovery service's job — the same service the section on what modelpipe
contacts is about. Measured with n0's DNS blocked: a restarted listener
minted the identical ticket, a fresh ticket from it worked, and the old one
could not reach it at all. The full trade is
[ADR 0002](docs/adr/0002-a-stored-endpoint-key-opt-in.md).

Already have a key you want enforced? `--token-file` and friends are in the
table below. Tickets have no expiry and no revocation list yet, so treat
them like keys, not invitations.

Embedding the library and want a new device to *fetch* the key over the
encrypted hop instead of a person carrying it? `ServeHandle::grant_once`
admits exactly one request bearing a short-lived code you mint, so your
backend can serve a pairing route that answers with the real key. The code
is spent when presented and dead at its deadline either way. While it is
live it is worth as much as the token, so keep the window short and count
attempts on your side.

The backend has to be local: loopback always, private ranges only behind
`--allow-private-backend`, link-local — where cloud instance metadata
lives — never. The check runs on resolved addresses, not URL text.
modelpipe extends trust outward from your machine; it doesn't re-export
someone else's server.

## Every flag

`modelpipe serve <BACKEND_URL>` — host and port only; the path comes from
the client.

| Flag | What it does |
|---|---|
| `--token <T>` | Enforce this token instead of generating one. Also read from `MODELPIPE_TOKEN` (exported but empty is refused, not enforced); `--help` never prints the value. Visible in `ps` and shell history, so prefer the next one. |
| `--token-file <PATH>` | Read the token from a file, trimming the trailing newline every editor adds. |
| `--insecure-no-auth` | Serve with no token at all. The name is the warning. |
| `--identity <FILE>` | Keep the endpoint key here so the ticket survives a restart. Created `0600`; refuses to start if others can read it. |
| `--allow-private-backend` | Accept a backend on a private (RFC 1918 / ULA) address, not only loopback. Link-local is never accepted. |
| `--relay <URL>` | Use your own relay instead of the public ones. Does **not** disable discovery — see below. |
| `--no-qr` | Don't print the QR code beside the ticket. |

`modelpipe connect <TICKET>`

| Flag | What it does |
|---|---|
| `--bind <ADDR>` | Local address to listen on. Defaults to a free loopback port. Binding off loopback exposes the one hop with no encryption in front of it, and warns you. |

Both commands

| Flag | What it does |
|---|---|
| `-v`, `-vv`, `-vvv` | Say more about what the pipe is doing. Works before or after the subcommand. |
| `--version` | Print the version. |
| `--help` | Print help. |

## Seeing what it is doing

`-v` prints a line per request on the serve side: method, path, the status
your backend gave, and how long it took. `-vv` adds the transport, which is
where the answer usually is when two machines won't pair.

```
$ modelpipe serve http://127.0.0.1:11434 -v
ticket: pipeaabjlod6a2h5g6lxw53tnnw7727qadq7iultzkz2xgd76bffp7r7uaibaadmaaacalemwagwxdija
token:  L3TY477IP3LQNAJDNJDC2KHVQTWIE66ZNT3WJFL3ONUEBQUMIRFA
status: direct
2026-09-03T05:32:54.574788Z  INFO peer{peer=3ca82708b995 path="direct"}: peer connected
2026-09-03T05:32:59.580759Z  INFO peer{peer=3ca82708b995 path="direct"}:exchange{method="GET" path="/v1/models" status=200}: exchange outcome="forwarded" elapsed_ms=1
2026-09-03T05:32:59.588755Z  INFO peer{peer=3ca82708b995 path="direct"}:exchange{method="POST" path="/v1/chat/completions" status=200}: exchange outcome="forwarded" elapsed_ms=0
```

The first two lines are stdout, the rest is stderr, so
`modelpipe serve … | head -1` still gives you just the ticket. No line ever
carries your token, your ticket, a header, or a query string. `RUST_LOG`
takes over entirely if you want to pick targets and levels yourself.

Embedding the library? It emits [`tracing`](https://docs.rs/tracing) events
and installs no subscriber, so they go wherever your binary already sends
them, and nowhere if it sends them nowhere.

## What it contacts, and what it doesn't

"No cloud in the path" is a claim about your **data**, and it holds: the
relay carries ciphertext it can't read, and most connections don't touch a
relay at all. It is not a claim that nothing is contacted. By default iroh
publishes address records to n0's discovery service and may ask your router
for a UPnP/NAT-PMP mapping, both before any client connects.

`--relay` turns off neither. It swaps the relay and nothing else: discovery
still goes through n0's DNS, the port-mapping attempt still happens, and
the connect side always uses the public relays and discovery regardless. If
contacting n0 at all is what you need to avoid, v0 isn't the tool yet.
That's a gap, not a setting you missed.

A relay, when one is used, sees endpoint identities, both IP addresses,
timing and volume. Observability isn't readability, and it isn't nothing.
[`SECURITY.md`](SECURITY.md) has the rest, including the one most people
miss: the token is full access to your backend, `/api/pull` included.

## Ticket format (v0)

A ticket is `pipe` followed by base32: a version, the serve side's endpoint
id, its addresses, and a backend hint. The token is not in it. Parsers take
the whole string case-insensitively, so a QR code can upcase it and it
still round-trips. The byte layout lives in one place,
[docs/ticket-format-v0.md](docs/ticket-format-v0.md), with test vectors and
a reference implementation that CI checks the page against, so a client in
another language can be written from that page alone. If the page leaves
you a question, that's a spec bug: open an issue. Why the bytes are spelled
out by hand is [ADR 0001](docs/adr/0001-an-explicit-ticket-byte-layout.md).

## Non-goals (v0)

- Multiple backends per ticket, named endpoints, routing. One pipe, one
  backend.
- A daemon, config files, a UI, accounts, hosted relays.
- Browser support. Browsers can't hole-punch.
- Model management of any kind. modelpipe moves requests; it has no opinion
  about what serves them.
