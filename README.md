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

Embedding it in something else? `cargo add modelpipe`. Add
`--features serde` if your status DTOs hold a `Ticket` or a `PipeStatus`:
the ticket serializes as its canonical string, the status as the
identifier `as_str` already freezes.

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

Two headers reach your backend on every tunnelled request, set by the
serve side and never inherited from the client: `Via: 1.1 modelpipe`, and
`X-Modelpipe-Peer` carrying the same twelve-character fingerprint the log
uses for that device. A third, `X-Modelpipe-Device`, arrives only on a
request admitted by a token that was added by name, and carries the name.
They let a backend *restrict* — refuse a route to remote requests, count
them, name the device — and are not for trusting beyond that: a local
client can forge them, and gains nothing by it but a refusal.

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
live it is worth as much as the token, so keep the window short. If the
listener's ticket outlives a restart (`--identity`), use
`grant_once_bounded` instead: it also burns the code after a number of
wrong bearers at the edge — three, say — because a ticket that lasts gives
a guesser every pairing window you ever open, and the edge is the only
place that sees every guess.

More than one paired device, and the wish to drop one without touching
the rest? `TokenPolicy::Named` starts a listener with no token of its own,
and `ServeHandle::add_token(name, token)` holds one per device; every
request such a token admits reaches your backend with
`X-Modelpipe-Device: <name>`, and `remove_token(name)` refuses exactly that
device from then on. The name is an identifier — letters, digits, `.`, `_`,
`-` — because it is a header value and a log field; keep "Matt's iPhone" on
your side, keyed by it.

Rotating a key that several paired machines are already holding?
`ServeHandle::set_token_with_grace` keeps the key it replaces admitting for
a window you name, so the rollout is not a race between reconfiguring those
machines and locking them out. Two caveats worth reading the doc for: the
window widens the tunnel edge only — a backend that also rotated will refuse
the old key a layer later — and it is the wrong tool for a *leaked* key,
where `rotate_token` and no window at all is the point.

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
| `--no-portmap` | Don't ask the router for a UPnP/NAT-PMP mapping. Free: pairing is unaffected, a few NATs fall back to the relay more often. |
| `--no-discovery` | Don't publish to, or resolve through, n0's discovery service. The ticket then carries every path it will ever have — see below before using it. |
| `--relay-only` | Serve through the relay and never directly — a measuring switch, not a production one. See below. |

`modelpipe connect <TICKET>`

| Flag | What it does |
|---|---|
| `--bind <ADDR>` | Local address to listen on. Defaults to a free loopback port. Binding off loopback exposes the one hop with no encryption in front of it, and warns you. |
| `--relay <URL>` | The relay *this* side registers with and falls back to. The serve side's relay is in the ticket and is dialled regardless. |
| `--no-portmap` | As for `serve`. |
| `--no-discovery` | Don't resolve the peer through n0; dial only the paths the ticket carries. |
| `--relay-only` | As for `serve`, and it takes only one side. Needs no re-pairing: the ticket is untouched. |

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

The `path=` field on the span above is how that peer *arrived*. A
connection commonly establishes through the relay and hole-punches to a
direct path a moment later, and both sides follow that while the connection
lives — so a migration in either direction gets its own line, with what the
new path costs:

```
2026-09-03T05:33:04.011927Z  INFO peer{peer=3ca82708b995 path="relayed"}: the path to the peer changed path="direct" rtt_ms=7
```

There is one more line, and it appears only when it has to. A relay that
is **rate limiting** this endpoint is the one problem nothing else shows:
the status still reads `relayed`, the peer is still there, nothing fails,
and requests just crawl. When it happens, both commands say so — under the
status line it contradicts:

```
status: relayed
relay:  rate limiting this endpoint — 1 of 3 relay connections throttled
```

The count is a running total for this endpoint and only ever climbs. The line
is printed when the pipe is first parked and then at each status change, so a
throttle that begins while the status holds steady is reported at the next
transition rather than the moment it happens — the metric is read alongside the
status, not on a clock of its own. A pipe no relay has throttled prints nothing
extra, which is nearly every pipe. If you keep seeing it, `--relay <URL>` is the
answer — it is then your own relay's capacity in question rather than a public
one's.

Embedding the library? It emits [`tracing`](https://docs.rs/tracing) events
and installs no subscriber, so they go wherever your binary already sends
them, and nowhere if it sends them nowhere. For a status page rather than
a log, `ServeHandle::status` is the aggregate (the worst path across every
connected peer) and `ServeHandle::peers` is the list behind it — each peer
by the same fingerprint the log shows, with its own direct-or-relayed path,
re-read while it is connected, and the round-trip time over it.

Four more accessors, on both handles, for the things a status line and a
mobile client need and could not previously ask for:

| Call | What it answers |
|---|---|
| `status_changed_since(held)` | Everything after the value you last rendered — no transition coalesced away, and the sequence **ends** (`None`) once the pipe is closed, rather than repeating `Closed` for ever. `status_changed()` is unchanged and still snapshots at the call. |
| `notify_network_change()` | Nothing — it *tells* the pipe the network moved and forces a rebind. Call it from an app's resume handler: on iOS and Android nothing else will, and a pipe bound to an interface that no longer exists cannot repair itself. |
| `network_metrics()` | Relay connections made, failed, and **rate limited**. A throttled pipe is not a broken one — every other signal says it is fine — so this is where an embedder reads that distinction; the CLI reads it for you. |
| `Ticket::relay_urls()` / `direct_addrs()` | What the ticket you are about to print actually carries. The relay is the half that arrives last, so a ticket read the instant `serve` returns can name direct addresses and nothing else; an empty `relay_urls()` is how you find out before somebody copies it. |

## What it contacts, and what it doesn't

"No cloud in the path" is a claim about your **data**, and it holds: the
relay carries ciphertext it can't read, and most connections don't touch a
relay at all. It is not a claim that nothing is contacted. Three things
are, by default, on both sides, and each has its own switch:

| Contact | What it is for | Who sees what | Switch |
|---|---|---|---|
| **n0's relays** (`*.relay.n0.iroh.link`) | The introduction, and the fallback path when hole-punching fails. | Both endpoint ids, both IPs, timing and volume. Never content. | `--relay <URL>` on either side, to run your own. There is no "no relay" — without one, two machines behind NATs cannot find each other. |
| **n0's discovery service** (`dns.iroh.link`) | A signed record saying which relay this endpoint is at, republished every few minutes while it runs; the connect side resolves the peer's id through it. | Your endpoint id and the IP the record was published from, refreshed while the process lives. | `--no-discovery`, on either side. |
| **Your router** | One UPnP/NAT-PMP/PCP mapping request, to be reachable directly more often. | Your own LAN. | `--no-portmap`. Free. |

`--relay` swaps the relay and **nothing else**: it does not turn discovery
off, and it does not turn the port-mapping probe off. Those are the other
two flags, and they are separate because they cost different things.

`--relay-only` is the opposite kind of switch — it is an instrument. Whether
hole punching works is the far NAT's decision, so "it went direct" is easy
to observe and "it fell back, and the fallback is fast enough to live with"
is not: you would have to find a hostile enough network to sit behind. This
removes every IP transport from one endpoint, which makes the relay the only
path left, so the same pipe can be measured with and without it on any
network at all. On `serve` the ticket it mints then carries the relay and no
direct addresses — which is the switch working, not a limitation of it,
because a holder on the same LAN would otherwise go direct and quietly
measure the case being excluded. Where this machine reaches no relay, that
leaves the ticket with no address in it at all, and `serve` refuses rather
than printing a ticket nobody could dial; the refusal names which half went
missing. On `connect` nothing needs re-pairing. Do not leave it on: a direct
path is faster and costs nobody's relay anything.

`--no-portmap` costs nothing that matters. Pairing works the same; behind a
few NATs a connection falls back to the relay a little more often.

`--no-discovery` costs a real property. With discovery on, a ticket names
the endpoint and n0 says where it is now, so the same ticket keeps working
after the serve side changes network — which is the whole of what
`--identity` buys. With it off, the ticket carries every path its holder
will ever have: the LAN addresses it was minted with and the relay it
names. That is enough on one network and through the relay, and it stops
working the moment the serve side's addresses change. If you mint a fresh
ticket per session anyway, you lose little. If you rely on `--identity`,
you lose the thing it was for.

A relay, when one is used, sees endpoint identities, both IP addresses,
timing and volume. Observability isn't readability, and it isn't nothing.

The ticket discloses two addresses of its own to whoever holds it — this
machine's LAN address, and the public IP a relay saw it from — and that's a
disclosure to weigh rather than a filter to add, because those addresses
*are* the direct path that keeps most traffic off a relay to begin with.

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
