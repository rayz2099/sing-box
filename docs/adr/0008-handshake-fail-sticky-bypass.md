# Client Leg handshake failure Bypass later (owner, host)

The failed connection already sent ServerHello, so it cannot become Bypass. Closing every later curl to the same host makes Capture look like "the proxy is broken" (error 60). v1 marks `(ConnectionOwner basename, host)` and Match returns false until Capture is toggled. No owner means no mark, because a host-only mark would 连坐 every process. The skip table is memory-only and is not written to the CaptureState sidecar.

Status: accepted
