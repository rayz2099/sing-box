package route

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mitm"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// mitmInterceptTCP 在选完 outbound 之后决定要不要拆 Client Leg.
// 为什么: 已知明文协议不能进 Intercept; 关 sniff 时必须自己 peek SNI, 否则 Scope 整表失效.
func (r *Router) mitmInterceptTCP(
	ctx context.Context,
	conn net.Conn,
	metadata adapter.InboundContext,
	dialer N.Dialer,
	onClose N.CloseHandlerFunc,
) (net.Conn, bool) {
	if !mitmTCPCandidate(metadata.Protocol) {
		return conn, false
	}
	engine := service.FromContext[adapter.MITMEngine](ctx)
	if engine == nil || !engine.Enabled() {
		return conn, false
	}
	if engine.Match(&metadata) {
		engine.Intercept(ctx, conn, metadata, dialer, onClose)
		return conn, true
	}
	if len(engine.Scopes()) == 0 {
		return conn, false
	}
	if metadata.Domain != "" || metadata.Destination.Fqdn != "" {
		return conn, false
	}
	hello, replay, err := mitm.PeekClientHello(ctx, conn)
	conn = replay
	if err != nil && hello == nil {
		return conn, false
	}
	if hello == nil || hello.ServerName == "" {
		return conn, false
	}
	metadata.Domain = hello.ServerName
	if !engine.Match(&metadata) {
		return conn, false
	}
	engine.Intercept(ctx, conn, metadata, dialer, onClose)
	return conn, true
}

func mitmTCPCandidate(protocol string) bool {
	return protocol == "" || protocol == C.ProtocolTLS
}

// mitmBypassQUIC 在 sniff 出 QUIC 且 Match 命中时只告警并推 Capture.
// 为什么: v1 不做 h3, 命中 Scope 的 QUIC 必须照常转发, 这里 reject 会把本机调试流量打挂.
func (r *Router) mitmBypassQUIC(ctx context.Context, metadata adapter.InboundContext) {
	if metadata.Protocol != C.ProtocolQUIC {
		return
	}
	engine := service.FromContext[adapter.MITMEngine](ctx)
	if engine == nil {
		return
	}
	if engine.Match(&metadata) {
		engine.PublishBypass(ctx, metadata, "quic")
	}
}
