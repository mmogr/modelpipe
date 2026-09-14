# Security

## Reporting

Report a vulnerability privately through GitHub's [security advisory
form](https://github.com/mmogr/modelpipe/security/advisories/new). Please do
not open a public issue for anything exploitable.

This is a one-person project. You will get an acknowledgement within a few
days; a fix depends on what it is.

## What modelpipe defends

**The backend gets an API key it never shipped.** Every request is checked
against a bearer token, in constant time, before a byte reaches your server.
Ollama and llama-server have no built-in authentication; modelpipe in front
of one is the credential it was missing.

**Two independent locks, travelling separately.** The ticket gates who can
connect at all; the token gates who can make requests. The token is
deliberately not inside the ticket, so a leaked ticket alone cannot make a
request and a leaked token alone cannot reach the listener.

**A superseded token is another credential, and it is the loosest one.**
`ServeHandle::set_token_with_grace` keeps the replaced token admitting requests
for a window the operator chooses, so a rollout to several clients does not have
to race their reconfiguration. It is not scoped: for the length of that window two full credentials open the door, and a
window measured in hours is a second standing key with a comment attached. It
expires on its own and a plain `set_token` closes it immediately — a rotation
that says nothing about grace is a rotation that wants none. Choose the shortest
window the rollout can survive.

**The backend must be local.** Loopback always, private ranges only behind
an explicit flag, link-local — where cloud instance metadata lives — never,
whatever that flag says. The check runs against the *resolved* address of
every outbound connection, and resolution and connection are one operation,
so a DNS name cannot smuggle an address past it.

**The transport is end-to-end encrypted** and authenticated by the machines'
own keys. A relay carries ciphertext it cannot read.

**Requests that are ambiguous are refused, not resolved.** A message
carrying both `Content-Length` and `Transfer-Encoding` is rejected rather
than interpreted, because interpreting it correctly is what makes a proxy
exploitable — the next hop resolves the same ambiguity the other way. So is
a request carrying two `Authorization` headers: the edge would check one,
and a backend handed the client's bearer could read the other.

## What modelpipe does not defend against

Stated plainly, because each of these surprises somebody.

**The token is equivalent to full access to your backend.** modelpipe is a
tunnel, not a policy layer: it forwards every path. On Ollama that includes
`/api/pull` and `/api/delete`. Anyone holding the token can do anything your
backend allows, not merely run inference. This inverts the usual framing of
"put a key in front of it" — the key is total.

**A leaked ticket has no expiry and no revocation list.** By default it
works until the serve process restarts, and restarting is the only
revocation. Treat tickets like keys, not like invitations. (The token,
separately, rotates in place without re-pairing.)

**`--identity` trades that away deliberately, and you should know which
half.** With a stored endpoint key the ticket survives a restart — which is
the point, and is also true of a *leaked* ticket. Revocation becomes
deleting the identity file and restarting, which costs exactly what
restarting cost before: a re-pairing of every device. What it removes is
revocation happening by *accident*, which is what a reboot used to be.

What it adds is a secret on disk, where there was none. modelpipe creates
the file readable only by its owner and refuses to start on one others can
read — the check `ssh` makes on a private key — but that is a floor, not a
guarantee: backups, sync clients, shared home directories and container
images all copy files that mode bits do not stop. **On Windows there is no
mode to set or inspect**, so the file lands with whatever the directory
grants and this crate cannot narrow it; put it somewhere only you can read.
Why the flag exists and why it is off by default is
[ADR 0002](docs/adr/0002-a-stored-endpoint-key-opt-in.md).

One thing `--identity` does *not* buy on its own: reachability. The stored
key fixes the name in the ticket, while the addresses beside it are a
snapshot of the ports the old process held, so finding the restarted
listener is discovery's job. Where discovery is unreachable, an old ticket
resolves to nobody even though the key is intact — so this flag and the
disclosure about what iroh contacts are the same subject, and turning the
second off takes the first with it. `README.md` records the measurement.

**A ticket also says where that machine is.** The addresses beside the key
are this machine's **private LAN address** and — once the endpoint has
reached a relay — the **public address that relay saw the connection come
from**, which is the larger disclosure of the two, and anyone holding the
ticket reads both. That is a disclosure to weigh rather than a filter to
add: those addresses *are* the direct path, so removing them would put every
holder on a relay, and the "relay metadata" entry below is what that costs.

**A malicious connect side.** Anyone you give a ticket and token to has the
access above. There is no per-client scoping, quota or audit.

**The tunnel markers are for restricting, not trusting.** The edge sets
`Via: 1.1 modelpipe` and `X-Modelpipe-Peer: <fingerprint>` on every request
it forwards, after removing any copy the client sent. A backend may refuse
or count on them; it must not grant on them, because anything that reaches
the backend without passing through modelpipe can write them too. The one
direction that matters holds: a tunnelled peer cannot make its request look
local, because the edge always overwrites.

**A compromised backend.** modelpipe forwards what your server says. If it
is compromised, modelpipe faithfully delivers whatever it returns.

**Relay metadata.** Hole-punching fails under some NATs and traffic then
falls back to a relay. The relay cannot read your data, but a relay operator
sees endpoint identities, both IP addresses, timing and volume.
*Observability is not readability, and it is not nothing.*

**What the default configuration contacts before any client connects.** With
default settings, on both sides, iroh registers with n0's public relays,
publishes a signed address record to n0's discovery service and republishes
it while the process runs, and may solicit a UPnP/NAT-PMP port mapping on
your LAN. "No cloud in the path" is a claim about your data — which is true
— not a claim that nothing is contacted. The README's "What it contacts"
table names each contact, what it reveals, and the flag that removes it.

**`--relay` changes one of the three.** It swaps the relay and nothing
else; discovery and port-mapping are `--no-discovery` and `--no-portmap`,
on either side, and they are separate flags because they cost different
things. Turning discovery off removes the presence record n0 holds for
you, and with it the property that a ticket keeps working after the serve
side changes network — which is what `--identity` depends on. Turning
port-mapping off costs nothing that matters. There is no switch for the
relay itself: two machines behind NATs need an introduction from
somewhere, and running your own is the option.

**Anything reachable from the local port on the connect side.** That port is
the one hop with no encryption in front of it. It binds to loopback by
default; binding it elsewhere exposes the pipe to anyone who can reach it,
and the CLI warns when you do.

**Denial of service.** Four bounds hold on what an unauthenticated
ticket-holder can cost. A request head may be at most 64 KiB, and it must
arrive within thirty seconds. One peer may have 64 exchanges in flight
across every connection it holds, and further streams wait. The listener
carries at most 32 distinct peers and 256 connections at once by default,
which `ServeOptions::max_peers` and `max_connections` change, and refuses
the next of either rather than queueing it. Three things are not bounded:
request bodies, deliberately, because a legitimate vision payload is
megabytes; the request rate, since there is no rate limiting and no
per-client quota; and endpoint identities, which cost nothing to mint, so a
peer can leave and come back as another as often as it likes. The caps
bound what the listener spends, not who gets in: a ticket-holder that holds
thirty-two identities open fills the peer set, and a device not already
connected is refused until it lets go.

## Cryptography

None of it is ours. The transport is iroh's QUIC with TLS 1.3; the bearer
comparison is `subtle`; tokens are 256 bits from the operating system's
CSPRNG. The ticket carries a CRC-32C, which guards transcription and QR
scans and is **not** a signature — anyone who can modify a ticket in transit
can replace it wholesale. The security is the endpoint key and the
out-of-band token.

## Status

modelpipe has not been audited. It is early software whose security claims
are tested but not externally reviewed, and the honest summary is that it
raises the floor for a backend that had no authentication at all rather than
being a hardened perimeter.
