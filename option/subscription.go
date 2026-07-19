package option

import "github.com/sagernet/sing/common/json/badoption"

// SubscriptionMetaOptions 是订阅运行时的薄控制器配置.
// 与完整 config.json 分离, 避免 profile 更新冲掉控制面字段.
type SubscriptionMetaOptions struct {
	Listen         string                     `json:"listen,omitempty"`
	Active         string                     `json:"active"`
	UpdateInterval badoption.Duration         `json:"update_interval,omitempty"`
	CacheDir       string                     `json:"cache_dir,omitempty"`
	DownloadDetour string                     `json:"download_detour,omitempty"`
	Subscriptions  []SubscriptionEntryOptions `json:"subscriptions"`
}

// SubscriptionEntryOptions 描述一份互斥的完整 profile 源.
// builtin / url / path 至少一个: 内置 default、纯本地与远端刷新共用同一模型.
type SubscriptionEntryOptions struct {
	Tag     string `json:"tag"`
	Builtin string `json:"builtin,omitempty"`
	URL     string `json:"url,omitempty"`
	Path    string `json:"path,omitempty"`
	Hash    string `json:"hash,omitempty"`
}
