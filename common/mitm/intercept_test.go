package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/http2"
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

func TestInterceptBypassesNonHTTPALPN(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	origin.TLS = &tls.Config{NextProtos: []string{"dot"}}
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

	tlsClient := tls.Client(client, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"dot"},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := tlsClient.ConnectionState().NegotiatedProtocol; got != "dot" {
		t.Fatalf("alpn=%s", got)
	}
	select {
	case event := <-events:
		if event.Warning == "" {
			t.Fatalf("expected bypass warning, event=%+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no bypass event")
	}
}

func TestInterceptHTTP1RedialsAfterOriginClose(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Connection", "close")
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
	reader := bufio.NewReader(tlsClient)
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, "https://example.com/v1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = req.Write(tlsClient); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "ok" {
			t.Fatalf("request %d status=%d body=%s", i, resp.StatusCode, body)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

func handshakeClientWithALPN(t *testing.T, engine *Engine, conn net.Conn, sni string, alpns []string) *tls.Conn {
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
		NextProtos: alpns,
		MinVersion: tls.VersionTLS12,
	})
	if err = tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tlsClient
}

func TestPeekClientHelloKeepsSNI(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		hello, replay, err := PeekClientHello(context.Background(), server)
		if hello == nil {
			done <- fmt.Errorf("peek err=%v", err)
			return
		}
		if hello.ServerName != "example.com" {
			done <- fmt.Errorf("sni=%s", hello.ServerName)
			return
		}
		_ = replay.Close()
		done <- nil
	}()
	tlsClient := tls.Client(client, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	_ = tlsClient.Handshake()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPeekClientHelloReplayAllowsHandshake(t *testing.T) {
	engine := newTestEngine(t)
	leaf, err := engine.ca.leafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		hello, replay, err := PeekClientHello(context.Background(), server)
		if hello == nil {
			done <- fmt.Errorf("peek1 err=%v", err)
			return
		}
		hello, replay, err = PeekClientHello(context.Background(), replay)
		if hello == nil || hello.ServerName != "example.com" {
			done <- fmt.Errorf("peek2 hello=%v err=%v", hello, err)
			return
		}
		tlsServer := tls.Server(replay, &tls.Config{
			Certificates: []tls.Certificate{*leaf},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   tls.VersionTLS12,
		})
		done <- tlsServer.Handshake()
	}()
	tlsClient := tls.Client(client, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInterceptHTTP2RedialsAfterOriginClose(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	origin.EnableHTTP2 = true
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
	tlsClient := handshakeClientWithALPN(t, engine, client, "example.com", []string{"h2"})
	transport := &http2.Transport{}
	cc, err := transport.NewClientConn(tlsClient)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	for i := 0; i < 2; i++ {
		if i == 1 {
			origin.CloseClientConnections()
		}
		req, err := http.NewRequest(http.MethodGet, "https://example.com/v"+fmt.Sprint(i), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "ok" {
			t.Fatalf("request %d status=%d body=%s", i, resp.StatusCode, body)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

func TestClientHandshakeFailMarksLaterBypass(t *testing.T) {
	engine := newTestEngine(t)
	engine.options.Insecure = true
	if err := engine.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := engine.AddScope(adapter.MITMScope{
		ID:          "curl",
		ProcessName: []string{"^curl$"},
	}); err != nil {
		t.Fatal(err)
	}
	meta := adapter.InboundContext{
		Domain:      "x.com",
		ProcessInfo: &adapter.ConnectionOwner{ProcessPath: "/usr/bin/curl", ProcessID: 7},
	}
	if !engine.Match(&meta) {
		t.Fatal("scope must match before handshake")
	}

	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		engine.Intercept(context.Background(), server, meta, staticDialer{addr: "127.0.0.1:1"}, nil)
		close(done)
	}()

	tlsClient := tls.Client(client, &tls.Config{
		ServerName: "x.com",
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err == nil {
		t.Fatal("untrusted client must reject Capture CA")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("intercept did not return")
	}
	if engine.Match(&meta) {
		t.Fatal("same curl+x.com must Bypass after Client Leg fail")
	}
}
