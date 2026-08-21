# sing-box MITM

This context names the plaintext interception model for local debugging. It is not a description of sing-box routing or proxy protocols.

## Language

**Capture**:
The user-facing switch that terminates matching Client Legs and exposes decrypted HTTP. Off means new matching connections are forwarded as ciphertext.
_Avoid_: sniff, dump, record-only, 抓包开关拆成 enabled+capture

**Engine**:
The singleton that owns CA issuance, Scopes, Filters, and the Capture switch. Traffic already inside tun/mixed asks the Engine; the Engine is not an Inbound.
_Avoid_: MITM inbound, hijack inbound, detour inbound

**Scope**:
A runtime-registered matcher that decides which connections the Engine may terminate. Keys off domain (SNI or CONNECT Fqdn) and/or ConnectionOwner (`process_name` is a regex on the basename, `process_id` is exact). Empty matcher is forbidden. Domain-only still captures every process on that host. Process-only captures matching processes on any host that still has SNI/Fqdn.
_Avoid_: host rule, hostname list, MITM inbound tag, process-first matcher, `*.*` global intercept, exact-only process_name

**Client Leg**:
The TLS session between a local process and the Engine. The process is the TLS client. The Engine presents a leaf signed by the Capture CA.
_Avoid_: inbound TLS, 入站 TLS, sing-box inbound handshake

**Origin Leg**:
The TLS session the Engine opens to the real server after decrypting the Client Leg. This ride uses the already selected Outbound as a dialer.
_Avoid_: outbound TLS, 出站 TLS, second MITM

**Filter**:
A declarative interceptor that sees decrypted HTTP messages on an intercepted Session. v1 is `header` and `block` with an optional `when`.
_Avoid_: script, addon, byte-stream rewriter, sniff action

**Session**:
One intercepted TCP connection plus the HTTP exchanges on it after both legs are up.
_Avoid_: connection (clash tracker), conn, flow

**Bypass**:
Forward ciphertext unchanged and emit a warning. Used when Capture cannot terminate (QUIC / HTTP3, no SNI), and after a Client Leg handshake failure for the same ConnectionOwner+host so later requests still succeed. The failed first connection cannot Bypass because ServerHello was already sent.
_Avoid_: reject, hijack-dns style drop, 旁路监听当 TCP TLS 明文方案, 失败后继续拆同一 process+host

**CaptureState**:
Enabled flag, Scopes, and Filters owned by the Engine and persisted in a sidecar beside the Capture CA. Restart and subscription rebuild reload that sidecar. Not part of the subscription profile or cache.db.
_Avoid_: memory-only MITM table, writing CaptureState into subscription JSON, cache_file

**ConnectionOwner**:
The local process bound to a TUN 5-tuple. Exists in the router today. Optional extra Scope predicate: missing owner never matches a process-keyed Scope.
_Avoid_: user, app, inbound tag, process as the only product identity
