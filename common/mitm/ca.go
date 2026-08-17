package mitm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ntp"
)

// authority 只为 Client Leg 签 leaf. 和 outbound CertificateStore 不是同一份信任锚.
type authority struct {
	options    option.MITMOptions
	timeFunc   func() time.Time
	access     sync.Mutex
	cert       *x509.Certificate
	key        *ecdsa.PrivateKey
	certPEM    []byte
	leafCache  map[string]*tls.Certificate
}

func newAuthority(ctx context.Context, options option.MITMOptions) (*authority, error) {
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	return &authority{
		options:   options,
		timeFunc:  timeFunc,
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

func (a *authority) ensure() error {
	a.access.Lock()
	defer a.access.Unlock()
	if a.cert != nil && a.key != nil {
		return nil
	}
	certPEM, keyPEM, err := a.loadOrCreate()
	if err != nil {
		return err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return E.Cause(err, "parse mitm ca")
	}
	if tlsCert.Leaf == nil {
		tlsCert.Leaf, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return E.Cause(err, "parse mitm ca leaf")
		}
	}
	priv, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return E.New("mitm ca key must be ecdsa")
	}
	a.cert = tlsCert.Leaf
	a.key = priv
	a.certPEM = certPEM
	return nil
}

func (a *authority) certificatePEM() []byte {
	a.access.Lock()
	defer a.access.Unlock()
	return append([]byte{}, a.certPEM...)
}

func (a *authority) leafFor(serverName string) (*tls.Certificate, error) {
	if err := a.ensure(); err != nil {
		return nil, err
	}
	if serverName == "" {
		return nil, E.New("mitm leaf requires server name")
	}
	a.access.Lock()
	defer a.access.Unlock()
	if leaf, loaded := a.leafCache[serverName]; loaded {
		return leaf, nil
	}
	leaf, err := signLeaf(a.cert, a.key, a.timeFunc, serverName)
	if err != nil {
		return nil, err
	}
	a.leafCache[serverName] = leaf
	return leaf, nil
}

func (a *authority) loadOrCreate() (certPEM []byte, keyPEM []byte, err error) {
	if a.options.Certificate != "" {
		certPEM = []byte(a.options.Certificate)
	} else if a.options.CertificatePath != "" {
		certPEM, err = os.ReadFile(a.options.CertificatePath)
		if err != nil && !a.options.AutoGenerate {
			return nil, nil, E.Cause(err, "read mitm certificate")
		}
		if err != nil {
			certPEM = nil
			err = nil
		}
	}
	if a.options.Key != "" {
		keyPEM = []byte(a.options.Key)
	} else if a.options.KeyPath != "" {
		keyPEM, err = os.ReadFile(a.options.KeyPath)
		if err != nil && !a.options.AutoGenerate {
			return nil, nil, E.Cause(err, "read mitm key")
		}
		if err != nil {
			keyPEM = nil
			err = nil
		}
	}
	if len(certPEM) > 0 && len(keyPEM) > 0 {
		return certPEM, keyPEM, nil
	}
	if !a.options.AutoGenerate {
		return nil, nil, E.New("missing mitm ca, enable auto_generate or provide certificate/key")
	}
	certPEM, keyPEM, err = generateCA(a.timeFunc)
	if err != nil {
		return nil, nil, err
	}
	if a.options.CertificatePath != "" {
		if err = os.WriteFile(a.options.CertificatePath, certPEM, 0o644); err != nil {
			return nil, nil, E.Cause(err, "write mitm certificate")
		}
	}
	if a.options.KeyPath != "" {
		if err = os.WriteFile(a.options.KeyPath, keyPEM, 0o600); err != nil {
			return nil, nil, E.Cause(err, "write mitm key")
		}
	}
	return certPEM, keyPEM, nil
}

func generateCA(timeFunc func() time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := timeFunc()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sing-box Capture CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		nil
}

func signLeaf(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, timeFunc func() time.Time, serverName string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := timeFunc()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour * 24 * 30),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, parent.Raw},
		PrivateKey:  key,
		Leaf:        nil,
	}, nil
}
