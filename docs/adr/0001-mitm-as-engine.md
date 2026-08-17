# Intercept via Engine, not a new Inbound

TUN/mixed already own the sockets. Adding a `mitm` inbound or config reload to toggle Capture would fork the connection pipeline and make process-scoped hot register impossible.

We decided the Engine is a singleton in context. Router asks it after sniff and ConnectionOwner lookup. Clash API and the Go interface mutate the same Engine. Dynamic `inbound.Create` is out.

Status: accepted
