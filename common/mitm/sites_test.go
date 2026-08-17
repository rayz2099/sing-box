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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// TestCaptureSitesByName 对虚拟站点表逐个拆 Client Leg, 断言按名抓到请求行.
// 为什么: 名单大、不走外网, 用来压 Scope 匹配和 h1 明文事件, 不会打到真实站.
func TestCaptureSitesByName(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Host", r.Host)
		_, _ = fmt.Fprintf(w, "ok:%s", r.URL.Path)
	}))
	origin.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	origin.StartTLS()
	t.Cleanup(origin.Close)

	engine := newTestEngine(t)
	engine.options.Insecure = true
	require.NoError(t, engine.SetEnabled(true))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:     "batch",
		Domain: append([]string{}, captureSites...),
	}))

	var (
		ok    atomic.Int64
		failN atomic.Int64
	)
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, site := range captureSites {
		site := site
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := captureOneLocal(engine, origin.Listener.Addr().String(), site); err != nil {
				t.Errorf("%s: %v", site, err)
				failN.Add(1)
				return
			}
			ok.Add(1)
		}()
	}
	wg.Wait()
	if failN.Load() > 0 {
		t.Fatalf("capture batch failed=%d ok=%d total=%d", failN.Load(), ok.Load(), len(captureSites))
	}
	t.Logf("captured %d sites", ok.Load())
}

func captureOneLocal(engine *Engine, originAddr string, site string) error {
	events, cancel := engine.SubscribeCapture()
	defer cancel()

	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		engine.Intercept(
			context.Background(),
			server,
			adapter.InboundContext{
				Domain:      site,
				Destination: M.ParseSocksaddr(originAddr),
			},
			staticDialer{addr: originAddr},
			func(error) { close(done) },
		)
	}()

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
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err = tlsClient.Handshake(); err != nil {
		return fmt.Errorf("client handshake: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+site+"/mitm-probe", nil)
	if err != nil {
		return err
	}
	if err = req.Write(tlsClient); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-events:
			if event.Host == site && event.Method == http.MethodGet && event.Path == "/mitm-probe" {
				_ = tlsClient.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				return nil
			}
		case <-deadline:
			return fmt.Errorf("no capture event")
		}
	}
}
