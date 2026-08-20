# Process is an extra Scope predicate, not a new primary key

ADR-0003 shipped domain-only Capture. Process-first (ADR-0002) stays rejected: pinning failures must not look like "the whole app is broken", and early TUN packets can miss the owner.

We add `process_name` (RE2 regex on basename, compiled at register) and `process_id` as optional AND predicates on the same Engine Scope. Domain-only behavior is unchanged. Process-only is allowed because it is bounded by owner, not `*.*`. Lookup miss or pid=0 never matches a process-keyed Scope. TCP still requires SNI/Fqdn to sign a leaf. Exact full-name match is not a separate field: write `^Google Chrome$` if you need anchors.

Status: accepted
