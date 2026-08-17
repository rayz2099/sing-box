package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// TestAutoGenerateSignsLeafAndClientVerifies 证明内存 CA 能签 SNI leaf, 且客户端只信这份 CA 就能过校验.
func TestAutoGenerateSignsLeafAndClientVerifies(t *testing.T) {
	const serverName = "capture.example"

	ca, err := newAuthority(context.Background(), option.MITMOptions{AutoGenerate: true})
	require.NoError(t, err)

	leaf, err := ca.leafFor(serverName)
	require.NoError(t, err)
	require.NotEmpty(t, leaf.Certificate)

	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, []string{serverName}, leafCert.DNSNames)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certificatePEM()))
	_, err = leafCert.Verify(x509.VerifyOptions{
		DNSName: serverName,
		Roots:   roots,
	})
	require.NoError(t, err)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ln.Close()
	})

	done := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		done <- nil
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
	})
	require.Equal(t, serverName, client.ConnectionState().PeerCertificates[0].DNSNames[0])
	_, _ = client.Write([]byte{0})
	require.NoError(t, <-done)
}

// TestEngineCACertificatePEMAutoGenerate 走 Engine 公开面, 确认 auto_generate 能导出可解析 CA.
func TestEngineCACertificatePEMAutoGenerate(t *testing.T) {
	engine := newTestEngine(t)
	pemBytes, err := engine.CACertificatePEM()
	require.NoError(t, err)
	require.Contains(t, string(pemBytes), "BEGIN CERTIFICATE")
	blockParsed := x509.NewCertPool()
	require.True(t, blockParsed.AppendCertsFromPEM(pemBytes))
}
