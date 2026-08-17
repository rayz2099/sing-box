package route

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// mitmInterceptTCP 在选完 outbound 之后决定要不要拆 Client Leg.
// 为什么: Router 只负责 sniff 和选路, 拆 TLS / 签 leaf 必须留给 Engine, 无 SNI 也交给 Match=false, 避免按 IP 乱签.
func (r *Router) mitmInterceptTCP(
	ctx context.Context,
	conn net.Conn,
	metadata adapter.InboundContext,
	dialer N.Dialer,
	onClose N.CloseHandlerFunc,
) bool {
	engine := service.FromContext[adapter.MITMEngine](ctx)
	if engine != nil && engine.Match(&metadata) {
		engine.Intercept(ctx, conn, metadata, dialer, onClose)
		return true
	}
	return false
}

// mitmBypassQUIC 在 sniff 出 QUIC 且域名命中 Scope 时只告警.
// 为什么: v1 不做 h3, 命中 Scope 的 QUIC 必须照常转发, 这里 reject 会把本机调试流量打挂.
func (r *Router) mitmBypassQUIC(ctx context.Context, metadata adapter.InboundContext) {
	if metadata.Protocol != C.ProtocolQUIC {
		return
	}
	engine := service.FromContext[adapter.MITMEngine](ctx)
	if engine == nil {
		return
	}
	host := metadata.Domain
	if host == "" {
		host = metadata.Destination.Fqdn
	}
	if engine.MatchHost(host) {
		r.logger.WarnContext(ctx, "mitm bypass quic")
	}
}
