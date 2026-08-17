# CaptureState is memory-only

Scopes, Filters, and the Capture switch are debug controls, not part of the proxy profile. Persisting them would need a path besides `/usr/local/etc/sing-box` and would surprise a restart into a still-terminating TLS path.

v1 keeps CaptureState in Engine memory. Restart is off. Re-register via API.

Status: accepted
