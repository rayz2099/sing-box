package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type staticDialer struct {
	addr string
}

func (d staticDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.addr)
}

func (d staticDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestInterceptHTTP1SeesRequestLine(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Debug") != "1" {
			t.Errorf("missing injected header")
		}
		w.Header().Set("X-Origin", "yes")
		_, _ = w.Write([]byte("ok"))
	}))
	origin.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	origin.StartTLS()
	defer origin.Close()

	engine := newTestEngine(t)
	engine.options.Insecure = true
	if err := engine.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := engine.AddScope(adapter.MITMScope{ID: "ex", Domain: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := engine.AddFilter(adapter.MITMFilter{
		ID:   "hdr",
		Type: "header",
		Request: &adapter.MITMHeaderPatch{
			Set: map[string]string{"X-Debug": "1"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	events, cancel := engine.SubscribeCapture()
	defer cancel()

	client, server := net.Pipe()
	defer client.Close()
	go engine.Intercept(
		context.Background(),
		server,
		adapter.InboundContext{
			Domain:      "example.com",
			Destination: M.ParseSocksaddr(origin.Listener.Addr().String()),
		},
		staticDialer{addr: origin.Listener.Addr().String()},
		nil,
	)

	tlsClient := handshakeClient(t, engine, client, "example.com")
	req, err := http.NewRequest(http.MethodGet, "https://example.com/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Origin") != "yes" {
		t.Fatalf("missing origin header")
	}

	select {
	case event := <-events:
		if event.Method != http.MethodGet || event.Path != "/v1" {
			t.Fatalf("event=%+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no capture event")
	}
}

func TestInterceptBlockDoesNotDial(t *testing.T) {
	engine := newTestEngine(t)
	engine.options.Insecure = true
	_ = engine.SetEnabled(true)
	_ = engine.AddScope(adapter.MITMScope{ID: "ex", Domain: []string{"blocked.example"}})
	_ = engine.AddFilter(adapter.MITMFilter{ID: "deny", Type: "block", Status: 204})

	client, server := net.Pipe()
	defer client.Close()
	go engine.Intercept(
		context.Background(),
		server,
		adapter.InboundContext{
			Domain:      "blocked.example",
			Destination: M.ParseSocksaddr("127.0.0.1:1"),
		},
		staticDialer{addr: "127.0.0.1:1"},
		nil,
	)
	tlsClient := handshakeClient(t, engine, client, "blocked.example")
	req, _ := http.NewRequest(http.MethodGet, "https://blocked.example/", nil)
	if err := req.Write(tlsClient); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func handshakeClient(t *testing.T, engine *Engine, conn net.Conn, sni string) *tls.Conn {
	t.Helper()
	pem, err := engine.CACertificatePEM()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("ca pem")
	}
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: sni,
		RootCAs:    pool,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err = tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tlsClient
}
