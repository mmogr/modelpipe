# 0003 — The backend carries its own permission, and a bind address derives it

## Context

`serve` takes a backend and refuses to dial one that is not local. Loopback
always passes; RFC 1918 and `fc00::/7` pass only with the operator's say-so;
link-local and public never pass. `locality.rs` is the mechanism and
`ServeError::BackendNotLocal` is where an operator reads the rule.

Until now the say-so was `ServeOptions::allow_private_backend`, a `bool`
beside the auth policy and the relay URL — a field about the *backend*
sitting in a struct about the *listener*. Two things follow from that
placement, and both showed up in use.

The flag outlives the thing it is about. Options are built once and reused;
a caller that sets it for one backend has set it for whatever the next one
is. Nothing in the type system says the permission and the address belong
together, so nothing stops them drifting apart.

And a caller holding a **bind address** could not express what it knew. gglib
starts its own proxy, reads back the address it bound, and points a tunnel at
it. It knows the address is its own — it chose the interface — but `serve`
could not be told that, so gglib wrote the derivation itself: a wildcard
rewritten to loopback, and a hand-written `is_private` its own comment
described as "a mirror of `locality::classify`". A mirror of a private
function is a copy that cannot be kept honest, and this one predicted the
verdict of a rule it could not see.

## Decision

The backend is a value, [`BackendUrl`], and the permission travels inside it.
`serve` takes `impl Into<BackendUrl>`, so `serve("http://127.0.0.1:11434",
opts)` is unchanged, and `ServeOptions::allow_private_backend` is removed.

Two constructors, and the difference between them is the decision:

- **`BackendUrl::dial(url)`** takes a URL as written and never permits a
  private address. Saying yes is a separate, visible
  `.allow_private()`. This is the existing rule, unchanged, for the caller
  the existing rule was written for.
- **`BackendUrl::at(bind)`** takes a bind address, rewrites a wildcard to the
  loopback literal of its own family, and **derives** the permission from the
  address it ends up with.

The wildcard rewrite also gets one home, `dialable_ip`, which `at` is now
the third in-crate caller of. It existed separately in the pairing
exchange, in the connect side's base URL and in gglib, and "a bind address
is not a dial address" is the kind of rule that gets re-derived slightly
differently each time.

## Why a derived permission is not the thing the rule forbids

`locality.rs` says a private address is "the operator's explicit decision, and
only theirs", and `at` does not ask. That reads like the rule being quietly
weakened, so the argument has to be made rather than assumed.

The rule exists to stop modelpipe re-exporting a server this machine does not
own. That is what a routable backend would be, and it is what a *private*
backend might be: some other host on the operator's LAN, reachable but not
theirs to publish.

A bind address is not that. A caller passing one is passing the address of a
socket on this machine that it already owns — it chose the interface, or read
it back from a listener it started. There is no third party whose server could
be re-exported by accident, because there is no third party. The URL is built
from that same address, so the permission cannot travel to another host even
by mistake; it is not a mode that stays switched on.

A caller that merely *has* a private URL — from a config file, an argument, an
environment variable — is in the position the rule was written for, and for it
nothing changes. That is why `dial` never derives and why `From<&str>` is
`dial`: the ergonomic path is the conservative one.

**What does not move.** `at` grants nothing to link-local or public addresses,
and neither does `allow_private`. `169.254.169.254` is cloud instance metadata
and stays refused however it is asked for. The permission moves exactly one
class, which is what it always did.

## What this costs an operator

Nothing at the CLI: `--allow-private-backend` is unchanged and now maps to
`BackendUrl::dial(url).allow_private()`.

Embedders pay a one-line edit. `opts.allow_private_backend = true` becomes
`BackendUrl::dial(url).allow_private()`, and an embedder that had been
deriving the flag from a bind address — gglib — deletes that code for
`BackendUrl::at`. The break is a compile error in every case, which is the
point of doing it as one.

The subtler cost is that `at` is now a place where a permission is granted
without the word appearing at the call site. A reader of
`serve(BackendUrl::at(addr), opts)` cannot see that a private bind is
admitted; they have to know what `at` means. That is a real loss of local
legibility, accepted because the alternative was every embedder
re-implementing `classify` against a function it cannot read — which is worse
in the same way, and silent.

## Change criteria

Revisit if a caller appears that holds a bind address it does *not* own — a
socket handed to it by a supervisor, a systemd-activated descriptor, a port
read from another process's config. `at`'s argument is that the caller chose
the interface, and such a caller did not. The answer would be to name the
constructor for what it assumes rather than to widen it.
