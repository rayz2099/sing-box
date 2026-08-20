package adapter

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
)

// MITMEngine 是拆 Client Leg 的单例. 不是 Inbound, 也不改路由表.
type MITMEngine interface {
	LifecycleService
	Enabled() bool
	SetEnabled(enabled bool) error
	CACertificatePEM() ([]byte, error)

	AddScope(scope MITMScope) error
	RemoveScope(id string) error
	Scopes() []MITMScope

	AddFilter(filter MITMFilter) error
	RemoveFilter(id string) error
	Filters() []MITMFilter

	// Match 只看能不能拆 Client Leg: Capture 开, 有 SNI/Fqdn, 命中 Scope (域名 ∩ 进程).
	// 协议门槛在 Router: 已知非 TLS 不进; 无 sniff 时 peek SNI 再 Match. QUIC 只 Bypass.
	Match(metadata *InboundContext) bool
	// NeedFindProcess 告诉 Router 进程谓词是否存在, 配置种子在 Engine.Start 前就能看见.
	NeedFindProcess() bool
	// PublishBypass 让 Capture WS 能看见 QUIC / 非 HTTP ALPN 这类 Bypass, 不只打 log.
	PublishBypass(ctx context.Context, metadata InboundContext, reason string)

	Intercept(
		ctx context.Context,
		conn net.Conn,
		metadata InboundContext,
		dialer N.Dialer,
		onClose N.CloseHandlerFunc,
	)

	SubscribeCapture() (<-chan MITMCaptureEvent, func())
}

// MITMScope 是运行时白名单. 域名和进程都空则非法 (会变成拦一切).
type MITMScope struct {
	ID           string   `json:"id"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	ProcessName  []string `json:"process_name,omitempty"` // 对 basename 的正则, 未锚定
	ProcessID    []uint32 `json:"process_id,omitempty"`
}

// MITMFilter 是解密后 HTTP 上的声明式拦截器.
type MITMFilter struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Priority int              `json:"priority,omitempty"`
	When     MITMFilterWhen   `json:"when,omitempty"`
	Request  *MITMHeaderPatch `json:"request,omitempty"`
	Response *MITMHeaderPatch `json:"response,omitempty"`
	Status   int              `json:"status,omitempty"`
}

// MITMFilterWhen 收窄 Filter. 全空表示命中所有已拦截 Session.
type MITMFilterWhen struct {
	Host       []string `json:"host,omitempty"`
	PathPrefix []string `json:"path_prefix,omitempty"`
	Method     []string `json:"method,omitempty"`
}

// MITMHeaderPatch 描述 header 增删改. Type=header 时使用.
type MITMHeaderPatch struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

// MITMCaptureEvent 是一条明文 HTTP 交换的可见切片. 不落盘.
type MITMCaptureEvent struct {
	SessionID       string              `json:"session_id"`
	Host            string              `json:"host"`
	ProcessName     string              `json:"process_name,omitempty"`
	ProcessID       uint32              `json:"process_id,omitempty"`
	ALPN            string              `json:"alpn,omitempty"`
	Method          string              `json:"method,omitempty"`
	Path            string              `json:"path,omitempty"`
	Status          int                 `json:"status,omitempty"`
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	Warning         string              `json:"warning,omitempty"`
}
