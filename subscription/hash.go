package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// normalizeHash 统一 pin 格式; 有 hash 即钉死内容, 与自动漂更新互斥.
func normalizeHash(hash string) string {
	hash = strings.TrimSpace(hash)
	hash = strings.TrimPrefix(hash, "sha256:")
	hash = strings.TrimPrefix(hash, "sha256-")
	return strings.ToLower(hash)
}

func contentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func verifyHash(content []byte, expected string) error {
	if expected == "" {
		return nil
	}
	want := normalizeHash(expected)
	got := contentHash(content)
	if got != want {
		return E.New("subscription hash mismatch: want ", want, ", got ", got)
	}
	return nil
}
