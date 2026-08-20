package route

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestMITMTCPCandidate(t *testing.T) {
	if !mitmTCPCandidate("") {
		t.Fatal("empty protocol must still peek")
	}
	if !mitmTCPCandidate(C.ProtocolTLS) {
		t.Fatal("tls must intercept")
	}
	if mitmTCPCandidate(C.ProtocolHTTP) {
		t.Fatal("plaintext http must not intercept")
	}
	if mitmTCPCandidate(C.ProtocolQUIC) {
		t.Fatal("quic is udp bypass")
	}
}
