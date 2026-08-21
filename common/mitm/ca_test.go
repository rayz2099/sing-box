package mitm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// TestRSAPathSignsLeaf 证明系统已信任的 RSA Capture CA 也能签 Client Leg, 避免再强制 ECDSA 根.
func TestRSAPathSignsLeaf(t *testing.T) {
	const serverName = "curl.example"

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sing-box-mitm", Organization: []string{"ray"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))

	ca, err := newAuthority(context.Background(), option.MITMOptions{
		CertificatePath: certPath,
		KeyPath:         keyPath,
	})
	require.NoError(t, err)

	leaf, err := ca.leafFor(serverName)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certificatePEM()))
	_, err = leafCert.Verify(x509.VerifyOptions{
		DNSName: serverName,
		Roots:   roots,
	})
	require.NoError(t, err)
}
