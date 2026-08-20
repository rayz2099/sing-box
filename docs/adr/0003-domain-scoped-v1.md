# v1 Scope is domain-only

Process-first Capture is the longer-term product (ADR-0002) but not the first ship. v1 Scope matches SNI / CONNECT Fqdn only. Domain is required. No owner lookup, no process field, no fallback to intercept everything.

Client Leg vs Origin Leg is unchanged. Engine vs Inbound is unchanged. Process later returned as an extra predicate (ADR-0006), not as the primary key (ADR-0002).

Status: superseded in part by ADR-0006
