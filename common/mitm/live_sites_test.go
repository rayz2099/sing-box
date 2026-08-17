package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type copiedHTTPOutbound struct {
	Tag        string `json:"tag"`
	Type       string `json:"type"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

type copiedHTTPFile struct {
	Outbounds []copiedHTTPOutbound `json:"outbounds"`
}

// httpCONNECTDialer 按 macos-tun 里 type=http 出站的方式打 CONNECT.
// 为什么: 测试只要抄出站形态, 不能把订阅密码写进仓.
type httpCONNECTDialer struct {
	proxy string
}

func (d httpCONNECTDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var nd net.Dialer
	nd.Timeout = 8 * time.Second
	conn, err := nd.DialContext(ctx, "tcp", d.proxy)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", destination.String(), destination.AddrString())
	if _, err = io.WriteString(conn, req); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connect %s via %s: %s", destination, d.proxy, resp.Status)
	}
	ok = true
	return conn, nil
}

func (d httpCONNECTDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

var _ N.Dialer = httpCONNECTDialer{}

func loadCopiedHTTPOutbounds(t *testing.T) []copiedHTTPOutbound {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "copied-http-outbound.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file copiedHTTPFile
	if err = json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	// 若本机有 macos-tun.json, 用里面的 m-dt-http 覆盖地址, 仍不读密码字段.
	if overlay := overlayDTHTTPFromMacosTun(); overlay != nil {
		for i, item := range file.Outbounds {
			if item.Tag == "m-dt-http" {
				file.Outbounds[i] = *overlay
			}
		}
	}
	return file.Outbounds
}

func overlayDTHTTPFromMacosTun() *copiedHTTPOutbound {
	candidates := []string{
		filepath.Join("..", "..", "macos-tun.json"),
		"macos-tun.json",
	}
	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var root struct {
			Outbounds []copiedHTTPOutbound `json:"outbounds"`
		}
		if err = json.Unmarshal(raw, &root); err != nil {
			continue
		}
		for _, item := range root.Outbounds {
			if item.Tag == "m-dt-http" && item.Type == "http" && item.Server != "" {
				return &copiedHTTPOutbound{
					Tag:        item.Tag,
					Type:       item.Type,
					Server:     item.Server,
					ServerPort: item.ServerPort,
				}
			}
		}
	}
	return nil
}

func pickLiveDialer(t *testing.T, outbounds []copiedHTTPOutbound) httpCONNECTDialer {
	t.Helper()
	var last error
	for _, item := range outbounds {
		if item.Type != "http" || item.Server == "" || item.ServerPort == 0 {
			continue
		}
		proxy := net.JoinHostPort(item.Server, fmt.Sprintf("%d", item.ServerPort))
		d := httpCONNECTDialer{proxy: proxy}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := d.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("example.com", 443))
		cancel()
		if err != nil {
			last = err
			t.Logf("outbound %s (%s) probe failed: %v", item.Tag, proxy, err)
			continue
		}
		_ = conn.Close()
		t.Logf("using copied http outbound %s -> %s", item.Tag, proxy)
		return d
	}
	if last != nil {
		t.Skipf("no copied http outbound reachable: %v", last)
	}
	t.Skip("no copied http outbound")
	return httpCONNECTDialer{}
}

// TestLiveCaptureSitesByName 对外网站点按名抓包.
// 为什么: 走复制的 HTTP 出站, 不拉 TUN; 单站失败只记错, 避免外网抖动把整包打红到不可用.
func TestLiveCaptureSitesByName(t *testing.T) {
	if testing.Short() {
		t.Skip("live capture skipped in short mode")
	}
	outbounds := loadCopiedHTTPOutbounds(t)
	dialer := pickLiveDialer(t, outbounds)

	engine := newTestEngine(t)
	requireEnabled(t, engine)
	sites := uniqueSites([]string{"www.google.com", "example.com", "www.cloudflare.com"})
	if err := engine.AddScope(adapter.MITMScope{ID: "live", Domain: sites}); err != nil {
		t.Fatal(err)
	}

	var failed int
	for _, site := range sites {
		err := captureOneLive(engine, dialer, site)
		if err != nil {
			t.Logf("LIVE-FAIL %s: %v", site, err)
			failed++
			continue
		}
		t.Logf("LIVE-OK %s", site)
	}
	ok := len(sites) - failed
	t.Logf("live captured ok=%d fail=%d total=%d", ok, failed, len(sites))
	if ok == 0 {
		t.Fatal("no live site produced a capture event")
	}
	if failed > len(sites)/2 {
		t.Fatalf("too many live failures: %d/%d", failed, len(sites))
	}
}

func requireEnabled(t *testing.T, engine *Engine) {
	t.Helper()
	if err := engine.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
}

func uniqueSites(sites []string) []string {
	seen := make(map[string]struct{}, len(sites))
	var out []string
	for _, site := range sites {
		if _, ok := seen[site]; ok {
			continue
		}
		seen[site] = struct{}{}
		out = append(out, site)
	}
	return out
}

func captureOneLive(engine *Engine, dialer N.Dialer, site string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
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
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("ca pem")
	}
	tlsClient := tls.Client(client, &tls.Config{
		ServerName: site,
		RootCAs:    pool,
		NextProtos: []string{"http/1.1", "h2"},
		MinVersion: tls.VersionTLS12,
	})
	if err = tlsClient.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("client handshake: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+site+"/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sing-box-mitm-capture-test/1.0")
	if err = req.Write(tlsClient); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Host == site && event.Method != "" {
				_ = tlsClient.Close()
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("no capture event")
		}
	}
}
