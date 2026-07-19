---
icon: material/cloud-sync
---

!!! question "radiance fork 新增"

# 订阅

内置订阅运行时: 多份完整 sing-box 配置 (与 `config.json` 同语义) **互斥切换**, 不做跨订阅规则合并.

### 结构

默认配置 home: `/usr/local/etc/sing-box/`.  
`listen` / `cache_dir` / `update_interval` / `active` 均可省略 (相对 meta 目录补齐; `active` 默认 `default`).

```json
{
  "subscriptions": [
    {
      "tag": "default",
      "builtin": "default"
    },
    {
      "tag": "tun",
      "url": "https://file.linran.top/singbox/sb-tun.json",
      "path": "sb-tun.json"
    }
  ]
}
```

### 字段

| 键 | 格式 | 说明 |
|----|------|------|
| `listen` | string | 控制面 unix socket. 默认 `<meta_dir>/subscription.sock` |
| `active` | string | 当前激活的订阅 tag |
| `update_interval` | duration | 远端刷新间隔. 默认 `24h` |
| `cache_dir` | string | 缓存目录. 默认 `<meta_dir>/subscription-cache` |
| `download_detour` | string | 用**当前** profile 里的 outbound tag 拉更新; 空为 direct; tag 不存在则 fetch 失败 (不静默降级) |
| `subscriptions` | [订阅条目](#订阅条目) 数组 | profile 源 |

#### 订阅条目

| 键 | 格式 | 说明 |
|----|------|------|
| `tag` | string | 唯一标签 |
| `builtin` | string | 内置 profile 名, 目前仅 `default` |
| `url` | string | 远端完整 sing-box 配置 URL |
| `path` | string | 本地种子/完整配置路径 (可选; 文件不存在则继续尝试 `url`) |
| `hash` | string | 可选 SHA-256 pin (`hex` 或 `sha256:` / `sha256-` 前缀). 设置后内容不可漂 |

`builtin` / `url` / `path` 至少一个.

### 取数顺序

`builtin` → `cache` → `path` (缺失跳过) → `url` (冷启动 direct)

### 启动

```bash
# 无参即默认 home: /usr/local/etc/sing-box/subscriptions.json
sing-box run --subscription
```

`-c` 语义不变, 仍直接跑完整配置.

### 控制

```bash
sing-box subscription status
sing-box subscription switch tun
sing-box subscription switch default
sing-box subscription update
```

switch/update 打到 `listen` 对应的 unix socket. **不要**写成 `run --subscription ... status`.

### 推荐流程

1. `active` 先用 `default` (内置, 无种子也能起)
2. 进程起来后 `switch tun` 拉远端完整 TUN 配置
3. 之后靠定时 `update` / 手动 `update` 刷新

### 行为说明

* 切换 = 同进程 teardown + rebuild 完整 Box
* 定时刷新全部远端 cache; 仅 active 内容变化才 rebuild
* 内置 `default` 是最小 direct profile, 保证无种子/无网时也能起控制器
* 远端 rule-set 初始化超过 `StartTimeout` (10s) 可能打出 `initialize rule-set take too much time to finish!`. 这是耗时告警, 拉取成功则启动继续, 不代表订阅控制器失败
