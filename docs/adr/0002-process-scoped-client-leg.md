# Process-scoped Client Leg is the product

The hard problem is TUN ciphertext: a local process speaks TLS to an IP, sing-box only forwards bytes, Origin Leg never sees plaintext either.

Originally Scope keyed off ConnectionOwner first. That is deferred: process attribution is accurate enough for routing rules, but using it as a Capture primary key makes pinning failures look like "the whole app is broken", and early TUN packets can miss the owner.

Status: superseded by ADR-0003
