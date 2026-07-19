---
icon: material/cloud-sync
---

!!! question "Added in radiance fork"

# Subscription

Built-in subscription runtime for mutually exclusive full sing-box profiles
(same semantics as `config.json`). No rule merging across subscriptions.

### Structure

```json
{
  "listen": "unix:///var/run/sing-box/subscription.sock",
  "active": "default",
  "update_interval": "24h",
  "cache_dir": "/var/lib/sing-box/subscriptions",
  "download_detour": "",
  "subscriptions": [
    {
      "tag": "default",
      "builtin": "default"
    },
    {
      "tag": "tun",
      "url": "https://example.com/sb-tun.json",
      "path": "/usr/local/etc/sing-box/sb-tun.json"
    }
  ]
}
```

### Fields

| Key | Format | Description |
|-----|--------|-------------|
| `listen` | string | Unix socket path for the control plane. Default: `<meta_dir>/subscription.sock` |
| `active` | string | Active subscription tag |
| `update_interval` | duration | Refresh interval for remote profiles. Default: `24h` |
| `cache_dir` | string | Cache directory. Default: `<meta_dir>/subscription-cache` |
| `download_detour` | string | Outbound tag in the **current** profile used to fetch updates. Empty means direct. Missing tag fails the fetch (no silent fallback) |
| `subscriptions` | array of [Subscription Entry](#subscription-entry) | Profile sources |

#### Subscription Entry

| Key | Format | Description |
|-----|--------|-------------|
| `tag` | string | Unique tag |
| `builtin` | string | Embedded profile name. Currently only `default` |
| `url` | string | Remote full sing-box config URL |
| `path` | string | Local seed/full config path (optional; missing file falls through to `url`) |
| `hash` | string | Optional SHA-256 pin (`hex` or `sha256:` / `sha256-` prefix). When set, content must not drift |

At least one of `builtin` / `url` / `path` is required.

### Resolve order

`builtin` → `cache` → `path` (skip if missing) → `url` (cold start uses direct)

### Run

```bash
sing-box run --subscription /usr/local/etc/sing-box/subscriptions.json
```

`-c` is unchanged and still runs a normal full config.

### Control

```bash
sing-box subscription -s /usr/local/etc/sing-box/subscriptions.json status
sing-box subscription -s /usr/local/etc/sing-box/subscriptions.json switch tun
sing-box subscription -s /usr/local/etc/sing-box/subscriptions.json switch default
sing-box subscription -s /usr/local/etc/sing-box/subscriptions.json update
```

Switch/update talk to the unix socket from `listen`. Do **not** append `status` to `run`.

### Behavior notes

* Profiles are full sing-box configs; switching rebuilds the Box in-process.
* Auto-update refreshes all remote caches; only an active content change triggers rebuild.
* Built-in `default` is a minimal direct profile so the daemon can start without a seed file or network.
* Remote rule-set init may log `initialize rule-set take too much time to finish!` when downloads exceed `StartTimeout` (10s). It is a progress warning; startup continues if fetches succeed.
