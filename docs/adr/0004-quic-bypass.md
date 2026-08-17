# QUIC is Bypass, not reject

Seeing plaintext requires terminating the Client Leg. QUIC carries TLS 1.3 on UDP; v1 has no QUIC terminator. Rejecting QUIC would make Capture look like "the proxy is broken".

v1 Bypass: sniff QUIC SNI if possible, if it matches a Scope log a warning and forward ciphertext. Never fail the proxy to force HTTP/2-over-TCP. TCP Client Leg still terminates; that is not passive tapping.

Status: accepted
