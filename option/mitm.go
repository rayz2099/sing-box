package option

// MITMOptions 描述 Capture CA, 以及启动时的 Scope/开关种子.
// 运行时 API 改动仍只活在内存, 不会回写这份 JSON.
type MITMOptions struct {
	Certificate     string      `json:"certificate,omitempty"`
	CertificatePath string      `json:"certificate_path,omitempty"`
	Key             string      `json:"key,omitempty"`
	KeyPath         string      `json:"key_path,omitempty"`
	AutoGenerate    bool        `json:"auto_generate,omitempty"`
	Insecure        bool        `json:"insecure,omitempty"`
	Enabled         bool        `json:"enabled,omitempty"`
	Scopes          []MITMScope `json:"scopes,omitempty"`
}

// MITMScope 是启动白名单种子. 域名和进程都空则非法.
type MITMScope struct {
	ID           string   `json:"id,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	ProcessName  []string `json:"process_name,omitempty"` // basename 正则, 未锚定
	ProcessID    []uint32 `json:"process_id,omitempty"`
}
