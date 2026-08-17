package mitm

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// newTestEngine 给单测一个内存 CA, 避免依赖磁盘证书路径.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(context.Background(), log.NewNOPFactory().Logger(), option.MITMOptions{
		AutoGenerate: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, engine.Close())
	})
	return engine
}

// TestAddScopeRejectsEmptyDomain 保证白名单不能变成 "拦一切".
func TestAddScopeRejectsEmptyDomain(t *testing.T) {
	engine := newTestEngine(t)

	err := engine.AddScope(adapter.MITMScope{ID: "empty"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "domain")

	err = engine.AddScope(adapter.MITMScope{
		ID:           "empty-slices",
		Domain:       []string{},
		DomainSuffix: []string{},
	})
	require.Error(t, err)
	require.Empty(t, engine.Scopes())
}

// TestMatchRequiresCaptureAndHost 覆盖 Capture 开关, domain/suffix 命中, 以及无 host 不中.
func TestMatchRequiresCaptureAndHost(t *testing.T) {
	engine := newTestEngine(t)
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:           "corp",
		Domain:       []string{"api.example.com"},
		DomainSuffix: []string{"corp.example"},
	}))

	exact := &adapter.InboundContext{Domain: "api.example.com"}
	suffix := &adapter.InboundContext{Domain: "svc.corp.example"}
	viaFqdn := &adapter.InboundContext{
		Destination: M.Socksaddr{Fqdn: "api.example.com"},
	}
	noHost := &adapter.InboundContext{}

	require.False(t, engine.Enabled())
	require.False(t, engine.Match(exact), "capture off must not match")
	require.False(t, engine.Match(suffix), "capture off must not match suffix")

	require.NoError(t, engine.SetEnabled(true))
	require.True(t, engine.Match(exact), "exact domain must match")
	require.True(t, engine.Match(suffix), "domain suffix must match")
	require.True(t, engine.Match(viaFqdn), "destination fqdn must match when Domain empty")
	require.False(t, engine.Match(noHost), "missing host must not match")
	require.False(t, engine.Match(nil), "nil metadata must not match")
	require.False(t, engine.Match(&adapter.InboundContext{Domain: "other.example"}), "outside scope must not match")
}
