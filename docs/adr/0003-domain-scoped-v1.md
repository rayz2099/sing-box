# v1 Scope is domain-only

Process-first Capture is the longer-term product (ADR-0002) but not the first ship. v1 Scope matches SNI / CONNECT Fqdn only. Domain is required. No owner lookup, no process field, no fallback to intercept everything.

Client Leg vs Origin Leg is unchanged. Engine vs Inbound is unchanged. Process can come back later as an extra predicate on the same Engine without a new inbound type.

Status: accepted
