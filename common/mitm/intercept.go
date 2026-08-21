package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	sbufio "github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

const (
	nextH2 = "h2"
	nextH1 = "http/1.1"
)

var sessSeq atomic.Uint64

// bufConn 把 Peek 过的字节还回后续解码器.
// 为什么: 无 ALPN 时要先看 h2 preface, 丢掉已读字节会把整条流打坏.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// sess 绑住一次拦截的两段 TLS.
// 为什么: Filter/Capture 只活在两段之间, Origin 必须按需建, 否则 block 也会打真站.
type sess struct {
	ctx     context.Context
	engine  *Engine
	meta    adapter.InboundContext
	dialer  N.Dialer
	filters []adapter.MITMFilter
	sid     string
	host    string
	alpns   []string
	neg     string
	cli     net.Conn
	cliR    *bufio.Reader
	orig    net.Conn
	origR   *bufio.Reader
	h2cc    *http2.ClientConn
	origMu  sync.Mutex
}

func (e *Engine) Intercept(
	ctx context.Context,
	conn net.Conn,
	metadata adapter.InboundContext,
	dialer N.Dialer,
	onClose N.CloseHandlerFunc,
) {
	hello, conn, err := PeekClientHello(ctx, conn)
	if hello != nil && !allowInterceptALPN(hello.SupportedProtos) {
		e.bypass(ctx, conn, metadata, dialer, onClose, "non-http alpn")
		return
	}
	if err != nil && hello == nil {
		e.bypass(ctx, conn, metadata, dialer, onClose, "client hello")
		return
	}
	cli, hello, host, err := e.hsClient(ctx, conn, metadata)
	if err != nil {
		// Client Leg 验签失败必须进 ERROR: tun 的 err.log 只收 warn/error, 只推 WS 会让本机看起来像「没 MITM」.
		e.logHsFail(ctx, metadata, err)
		e.markSkip(metadata)
		e.logger.WarnContext(ctx, "mitm client handshake failed, later Bypass host=", leafHint(metadata), " process=", skipOwner(metadata.ProcessInfo))
		e.publish(captureEvent(metadata, adapter.MITMCaptureEvent{
			Host:    leafHint(metadata),
			Warning: err.Error(),
		}))
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}

	s := &sess{
		ctx:     ctx,
		engine:  e,
		meta:    metadata,
		dialer:  dialer,
		filters: sortedFilters(e.snapshotFilters()),
		sid:     newSessID(host),
		host:    host,
		alpns:   httpALPNs(hello.SupportedProtos),
		neg:     cli.ConnectionState().NegotiatedProtocol,
		cli:     cli,
	}
	e.logSess(ctx, metadata, host, s.neg)

	err = s.serve()
	s.closeOrig()
	_ = cli.Close()
	if err != nil && !isNormalClose(err) {
		e.logger.ErrorContext(ctx, "mitm intercept: ", err)
		e.publish(s.event(adapter.MITMCaptureEvent{
			Warning: err.Error(),
		}))
	} else {
		err = nil
	}
	if onClose != nil {
		onClose(err)
	}
}

// hsClient 用 Capture CA 终态 Client Leg.
// 为什么: 无 SNI/Fqdn 时按 IP 乱签会让证书和目标对不上.
func (e *Engine) hsClient(
	ctx context.Context,
	conn net.Conn,
	metadata adapter.InboundContext,
) (*tls.Conn, *tls.ClientHelloInfo, string, error) {
	var (
		hello *tls.ClientHelloInfo
		host  string
	)
	cli := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			name, err := leafName(chi.ServerName, metadata.Destination.Fqdn)
			if err != nil {
				return nil, err
			}
			leaf, err := e.ca.leafFor(name)
			if err != nil {
				return nil, err
			}
			next, err := selectALPNs(chi.SupportedProtos)
			if err != nil {
				return nil, err
			}
			copied := *chi
			copied.SupportedProtos = append([]string{}, chi.SupportedProtos...)
			hello = &copied
			host = name
			return &tls.Config{
				Certificates: []tls.Certificate{*leaf},
				NextProtos:   next,
				MinVersion:   tls.VersionTLS12,
			}, nil
		},
	})
	err := cli.HandshakeContext(ctx)
	if err != nil {
		return nil, nil, "", E.Cause(err, "mitm client handshake")
	}
	if hello == nil || host == "" {
		_ = cli.Close()
		return nil, nil, "", E.New("mitm leaf requires server name")
	}
	return cli, hello, host, nil
}

// hsOrigin 用已选 dialer 建 Origin TLS.
// 为什么: SNI/ALPN 必须复用 ClientHello, 禁止再 Match 以免二次 MITM.
func (e *Engine) hsOrigin(
	ctx context.Context,
	dialer N.Dialer,
	metadata adapter.InboundContext,
	sni string,
	alpns []string,
) (*tls.Conn, error) {
	raw, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		return nil, E.Cause(err, "mitm origin dial")
	}
	cfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpns,
		InsecureSkipVerify: e.options.Insecure,
		RootCAs:            adapter.RootPoolFromContext(e.ctx),
		MinVersion:         tls.VersionTLS12,
	}
	orig := tls.Client(raw, cfg)
	err = orig.HandshakeContext(ctx)
	if err != nil {
		_ = raw.Close()
		return nil, E.Cause(err, "mitm origin handshake")
	}
	return orig, nil
}

func (s *sess) serve() error {
	switch s.neg {
	case nextH2:
		return s.serveH2()
	case nextH1, "http/1.0":
		return s.serveH1(bufio.NewReader(s.cli))
	case "":
		br := bufio.NewReader(s.cli)
		pre, err := br.Peek(len(http2.ClientPreface))
		if err == nil && string(pre) == http2.ClientPreface {
			s.cli = &bufConn{Conn: s.cli, r: br}
			return s.serveH2()
		}
		if err != nil && !isNormalClose(err) && err != bufio.ErrBufferFull {
			return E.Cause(err, "mitm peek http preface")
		}
		return s.serveH1(br)
	default:
		return E.New("mitm unsupported alpn: ", s.neg)
	}
}

func (s *sess) ensureOrig(want string) (net.Conn, error) {
	s.origMu.Lock()
	defer s.origMu.Unlock()
	if s.orig != nil {
		return s.orig, nil
	}
	next := s.alpns
	if want != "" {
		next = []string{want}
	} else if s.neg != "" {
		next = []string{s.neg}
	}
	orig, err := s.engine.hsOrigin(
		s.ctx,
		s.dialer,
		s.meta,
		s.host,
		next,
	)
	if err != nil {
		return nil, err
	}
	neg := orig.ConnectionState().NegotiatedProtocol
	if want != "" && neg != "" && neg != want {
		_ = orig.Close()
		return nil, E.New("mitm origin alpn mismatch: ", neg)
	}
	if want == nextH2 && neg != "" && neg != nextH2 {
		_ = orig.Close()
		return nil, E.New("mitm origin alpn is not h2")
	}
	s.orig = orig
	s.origR = bufio.NewReader(orig)
	return orig, nil
}

func (s *sess) closeOrig() {
	s.origMu.Lock()
	defer s.origMu.Unlock()
	if s.h2cc != nil {
		_ = s.h2cc.Close()
		s.h2cc = nil
	}
	if s.orig != nil {
		_ = s.orig.Close()
		s.orig = nil
	}
	s.origR = nil
}

func (e *Engine) logHsFail(
	ctx context.Context,
	metadata adapter.InboundContext,
	err error,
) {
	host := leafHint(metadata)
	if metadata.ProcessInfo != nil && metadata.ProcessInfo.ProcessPath != "" {
		e.logger.ErrorContext(ctx, "mitm client handshake: ", err, " host=", host, " process=", metadata.ProcessInfo.ProcessPath, " pid=", metadata.ProcessInfo.ProcessID)
		return
	}
	e.logger.ErrorContext(ctx, "mitm client handshake: ", err, " host=", host)
}

func (e *Engine) logSess(
	ctx context.Context,
	metadata adapter.InboundContext,
	sni string,
	neg string,
) {
	if metadata.ProcessInfo != nil && metadata.ProcessInfo.ProcessPath != "" {
		if metadata.ProcessInfo.ProcessID != 0 {
			e.logger.InfoContext(ctx, "mitm intercept sni=", sni, " alpn=", neg, " process=", metadata.ProcessInfo.ProcessPath, " pid=", metadata.ProcessInfo.ProcessID)
			return
		}
		e.logger.InfoContext(ctx, "mitm intercept sni=", sni, " alpn=", neg, " process=", metadata.ProcessInfo.ProcessPath)
		return
	}
	e.logger.InfoContext(ctx, "mitm intercept sni=", sni, " alpn=", neg)
}

func leafName(sni string, fqdn string) (string, error) {
	name := sni
	if name == "" {
		name = fqdn
	}
	if name == "" || net.ParseIP(name) != nil {
		return "", E.New("mitm leaf requires server name")
	}
	return name, nil
}

func leafHint(metadata adapter.InboundContext) string {
	if metadata.Domain != "" {
		return metadata.Domain
	}
	return metadata.Destination.Fqdn
}

func selectALPNs(protos []string) ([]string, error) {
	if len(protos) == 0 {
		return nil, nil
	}
	next := httpALPNs(protos)
	if len(next) == 0 {
		return nil, E.New("mitm unsupported alpn")
	}
	return next, nil
}

func allowInterceptALPN(protos []string) bool {
	if len(protos) == 0 {
		return true
	}
	return len(httpALPNs(protos)) > 0
}

var errPeekHello = E.New("mitm peek client hello")

// PeekClientHello 读 ClientHello 并把字节塞回 CachedConn.
// 为什么: 关 sniff 时 Router 要自己拿 SNI 再 Match, 丢掉前缀会把后续转发打坏.
func PeekClientHello(ctx context.Context, conn net.Conn) (*tls.ClientHelloInfo, net.Conn, error) {
	var cache bytes.Buffer
	reader := io.TeeReader(conn, &cache)
	var hello *tls.ClientHelloInfo
	err := tls.Server(sbufio.NewReadOnlyConn(reader), &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			copied := *chi
			copied.SupportedProtos = append([]string{}, chi.SupportedProtos...)
			hello = &copied
			return nil, errPeekHello
		},
	}).HandshakeContext(ctx)
	replay := conn
	if cache.Len() > 0 {
		replay = sbufio.NewCachedConn(conn, buf.As(cache.Bytes()).ToOwned())
	}
	if hello == nil {
		return nil, replay, err
	}
	return hello, replay, nil
}

func (e *Engine) bypass(
	ctx context.Context,
	conn net.Conn,
	metadata adapter.InboundContext,
	dialer N.Dialer,
	onClose N.CloseHandlerFunc,
	reason string,
) {
	e.PublishBypass(ctx, metadata, reason)
	dest, err := dialer.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	err = sbufio.CopyConn(ctx, conn, dest)
	if onClose != nil {
		onClose(err)
	}
}

func httpALPNs(protos []string) []string {
	var next []string
	for _, proto := range protos {
		if proto == nextH2 || proto == nextH1 || proto == "http/1.0" {
			next = append(next, proto)
		}
	}
	return next
}

func newSessID(host string) string {
	return host + "-" + itoa(sessSeq.Add(1))
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func isNormalClose(err error) bool {
	return err == nil || E.IsClosedOrCanceled(err) || E.IsClosed(err) || err == io.EOF
}

func (s *sess) event(event adapter.MITMCaptureEvent) adapter.MITMCaptureEvent {
	if event.SessionID == "" {
		event.SessionID = s.sid
	}
	if event.Host == "" {
		event.Host = s.host
	}
	if event.ALPN == "" {
		event.ALPN = s.neg
	}
	fillOwner(&event, s.meta.ProcessInfo)
	return event
}
