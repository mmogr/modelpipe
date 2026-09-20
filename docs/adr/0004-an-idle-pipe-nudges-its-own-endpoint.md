# 0004 — An idle pipe tells its own endpoint the network may have changed

## Context

The connect side gives up on nothing. A peer it cannot reach is `Idle` and
is dialled again, with a backoff, for as long as the pipe is held. That is
the right behaviour and it is not what this is about.

What the re-dial loop cannot fix is the socket underneath it. A laptop that
changed network while suspended, or a phone that came back on cellular, has
an endpoint bound to an interface that no longer exists. Every dial from it
fails, for ever, and from the outside that is indistinguishable from a serve
side that is switched off. iroh rebinds when it is told the network moved —
`Endpoint::network_change` — and until now **nothing in this crate ever told
it**. `notify_network_change` existed on both handles and was the embedder's
to call.

Two embedders found this independently. gglib's tunnel watcher nudges every
sixty seconds while the far machine is away; ggchat wired an `NWPathMonitor`
to the same call. The second is the better answer and the first is the one
every embedder without a platform path monitor has to write.

There is also a measurement gap beside it. `Idle` says the peer is not
reachable; it does not say for how long, and both embedders wrote a timer to
find out. That half is [`ConnectHandle::idle_for`], and it carries no policy:
how long is too long is a product decision, and a desktop tunnel and a phone
app reasonably answer it differently.

## Decision

`ConnectOptions::idle_network_nudge: Option<Duration>`, defaulting to
`Some(60s)`. While the pipe has no connection, the re-dial loop calls the
endpoint's network-change hook on that cadence. `None` switches it off.

It fires **only while there is no connection**, so the cost is bounded by
how long there is nobody to talk to, and it is paced on its own clock rather
than on the backoff — which starts at half a second and is reset by every
death, and would otherwise fire the nudge in a burst after each one and then
hardly at all. It is also reached after the backoff sleep rather than before
the first dial, so a freshly bound handle's first attempt is never delayed.

**The interval is a floor, not a period.** The check is polled once per
re-dial round, and a round against a peer that is simply gone is as long as
iroh takes to give up — tens of seconds — plus the backoff. So a minute's
interval means a nudge every minute *or more*, in practice one or two, and
never more often than once a round. It is also re-anchored on the moment it
fires rather than on the deadline it passed, so a long round does not leave
a backlog to work through; and a successful re-dial skips the check
entirely, so a connection that outlasts the interval is followed by a nudge
on its first failed dial. A connection shorter than the interval changes
nothing, because the deadline it was re-armed to has not passed.

`ConnectHandle::idle_for` reports how long the pipe has been `Idle`, or
`None` when it is not — which covers both a reached peer and a closed
pipe, told apart by the status rather than by this. The clock starts at the *transition*
into `Idle`, so a re-dial that finds nobody does not restart it — a peer that
is simply gone would otherwise never look away — and it starts at birth,
because a handle is `Idle` from the moment it is returned and a pipe that has
never reached its peer is the case the feature exists for.

`Duration`, not an `Instant`. The accuracy argument favours an anchor a
caller can pass to `sleep_until`, but this crate keeps foreign types out of
its public surface so that an upgrade underneath is its own problem rather
than its dependents', and `tokio::time::Instant` is exactly such a type. The
cost is one clock read at the caller, on a threshold measured in tens of
seconds.

## Why on by default

A default of `None` would be the conservative choice on the usual grounds:
the crate does something on a timer that it did not do before.

It is the wrong choice here because of who is harmed by each mistake. With
it off, a caller that watches nothing gets a pipe that is permanently dead
after a suspend, silently, and has to discover a hook it has no reason to
know exists — which is what happened twice already. With it on, a caller
that watches the real thing sets it to `None` and loses nothing, because
they already know the hook exists: they are calling it.

## What this costs an operator

At most one local call per re-dial round while a pipe has no peer, and by
default no more often than once a minute. It is not a network request — it asks the endpoint to re-examine its own interfaces — but iroh
may then rebind a socket and re-register with a relay, which is traffic.

Unmeasured: whether that is detectable on a phone's battery. ggchat is the
place that would show it, and it sets `None` anyway because it has
`NWPathMonitor`. Worth measuring before defending the default on a mobile
client that does not.

## Change criteria

Revisit if a nudge is ever observed to *cause* a rebind that breaks a
working path — the call is documented as harmless when nothing has changed,
and this decision rests on that. Revisit the cadence if sixty seconds proves
either too slow to feel responsive or frequent enough to matter to a battery.
