# Persist CaptureState in a sidecar

Subscription rebuild replaces the whole profile and therefore a new Engine. Putting CaptureState in the subscription JSON would be overwritten on every Update. cache.db is the wrong store. The Engine writes enabled/scopes/filters next to the Capture CA (`capture-state.json`, or `state_path`). Sidecar wins over template seed. Subscription merge is left untouched.

Status: accepted
Supersedes: 0005
