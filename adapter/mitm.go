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

	// Match 只看 TCP 明文拦截条件: Capture 开, 有 SNI/Fqdn, 命中 Scope.
	Match(metadata *InboundContext) bool
	// MatchHost 给 QUIC Bypass 用: 只判断域名表, 不管协议.
	MatchHost(host string) bool

	Intercept(
		ctx context.Context,
		conn net.Conn,
		metadata InboundContext,
		dialer N.Dialer,
		onClose N.CloseHandlerFunc,
	)

	SubscribeCapture() (<-chan MITMCaptureEvent, func())
}

// MITMScope 是运行时域名白名单. 禁止空域名.
type MITMScope struct {
	ID           string   `json:"id"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
}

// MITMFilter 是解密后 HTTP 上的声明式拦截器.
type MITMFilter struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Priority int               `json:"priority,omitempty"`
	When     MITMFilterWhen    `json:"when,omitempty"`
	Request  *MITMHeaderPatch  `json:"request,omitempty"`
	Response *MITMHeaderPatch  `json:"response,omitempty"`
	Status   int               `json:"status,omitempty"`
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
	ALPN            string              `json:"alpn,omitempty"`
	Method          string              `json:"method,omitempty"`
	Path            string              `json:"path,omitempty"`
	Status          int                 `json:"status,omitempty"`
	RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	Warning         string              `json:"warning,omitempty"`
}
