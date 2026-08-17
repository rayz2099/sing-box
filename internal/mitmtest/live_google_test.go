package mitmtest

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// TestMITMLiveGoogleViaTunOutbounds 用 macos-tun.json 里的出站访问 www.google.com 并按名抓包.
// 为什么: 密钥只运行时读 gitignore 的 json, 不进仓; 去掉 TUN/clash, 避免抢本机网卡.
func TestMITMLiveGoogleViaTunOutbounds(t *testing.T) {
	if testing.Short() {
		t.Skip("live google skipped in short mode")
	}
	opts := loadMacosTunOptions(t)
	stripHostConflicts(&opts)
	injectLewisHTTP(&opts)
	opts.MITM = &option.MITMOptions{AutoGenerate: true}
	opts.Log = &option.LogOptions{Level: "warn"}

	ctx := include.Context(context.Background())
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { _ = instance.Close() })

	engine := service.FromContext[adapter.MITMEngine](ctx)
	require.NotNil(t, engine)
	require.NoError(t, engine.SetEnabled(true))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:     "google",
		Domain: []string{"www.google.com", "google.com"},
	}))

	dialer := pickTunDialer(t, instance, probeTags(instance))
	err = captureGoogle(t, engine, dialer, "www.google.com")
	require.NoError(t, err)
}

func loadMacosTunOptions(t *testing.T) option.Options {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "macos-tun.json"),
		"macos-tun.json",
		"/usr/local/etc/sing-box/macos-tun.json",
	}
	var raw []byte
	var err error
	for _, path := range candidates {
		raw, err = os.ReadFile(path)
		if err == nil {
			t.Logf("loaded tun outbounds from %s", path)
			break
		}
	}
	require.NoError(t, err, "macos-tun.json not found")
	ctx := include.Context(context.Background())
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, raw)
	require.NoError(t, err)
	return opts
}

func stripHostConflicts(opts *option.Options) {
	var inbounds []option.Inbound
	for _, inbound := range opts.Inbounds {
		if inbound.Type == C.TypeTun {
			continue
		}
		inbounds = append(inbounds, inbound)
	}
	opts.Inbounds = inbounds
	if opts.Experimental != nil {
		opts.Experimental.ClashAPI = nil
		opts.Experimental.CacheFile = nil
	}
}

func injectLewisHTTP(opts *option.Options) {
	opts.Outbounds = append(opts.Outbounds, option.Outbound{
		Type: C.TypeHTTP,
		Tag:  "lewis-http",
		Options: &option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "lewis.home.linran.top",
				ServerPort: 1088,
			},
		},
	})
}

func probeTags(instance *box.Box) []string {
	skip := map[string]struct{}{
		"url-test-out":       {},
		"proxy-out":          {},
		"direct-out":         {},
		"vpn-direct-out":     {},
		"ssh-bastion":        {},
		"m-local-socks-1089": {},
	}
	tags := []string{"lewis-http"}
	for _, outbound := range instance.Outbound().Outbounds() {
		tag := outbound.Tag()
		if _, found := skip[tag]; found {
			continue
		}
		if tag == "lewis-http" {
			continue
		}
		tags = append(tags, tag)
		if len(tags) >= 9 {
			break
		}
	}
	return tags
}

func pickTunDialer(t *testing.T, instance *box.Box, tags []string) adapter.Outbound {
	t.Helper()
	for _, tag := range tags {
		outbound, loaded := instance.Outbound().Outbound(tag)
		if !loaded {
			t.Logf("outbound %s not found", tag)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		conn, err := outbound.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("www.google.com", 443))
		cancel()
		if err != nil {
			t.Logf("outbound %s probe failed: %v", tag, err)
			continue
		}
		_ = conn.Close()
		t.Logf("using outbound %s", tag)
		return outbound
	}
	t.Fatal("no tun outbound can reach www.google.com:443")
	return nil
}

func captureGoogle(
	t *testing.T,
	engine adapter.MITMEngine,
	dialer adapter.Outbound,
	site string,
) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	events, unsub := engine.SubscribeCapture()
	defer unsub()

	client, server := net.Pipe()
	defer client.Close()
	go engine.Intercept(
		ctx,
		server,
		adapter.InboundContext{
			Domain:      site,
			Destination: M.ParseSocksaddrHostPort(site, 443),
		},
		dialer,
		nil,
	)

	pem, err := engine.CACertificatePEM()
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem))
	tlsClient := tls.Client(client, &tls.Config{
		ServerName: site,
		RootCAs:    pool,
		NextProtos: []string{"http/1.1", "h2"},
		MinVersion: tls.VersionTLS12,
	})
	if err = tlsClient.HandshakeContext(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+site+"/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sing-box-mitm-capture-test/1.0")
	if err = req.Write(tlsClient); err != nil {
		return err
	}
	_, _ = http.ReadResponse(bufio.NewReader(tlsClient), req)

	deadline := time.After(15 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Host == site && event.Method == http.MethodGet {
				t.Logf("captured %s %s %s status=%d alpn=%s", event.Host, event.Method, event.Path, event.Status, event.ALPN)
				_ = tlsClient.Close()
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return io.ErrUnexpectedEOF
		}
	}
}
