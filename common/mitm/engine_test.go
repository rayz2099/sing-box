package mitm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// newTestEngine 给单测一个内存 CA, sidecar 落到 TempDir, 避免污染真实 CA 目录.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(context.Background(), log.NewNOPFactory().Logger(), option.MITMOptions{
		AutoGenerate: true,
		StatePath:    filepath.Join(t.TempDir(), "capture-state.json"),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, engine.Close())
	})
	return engine
}

// TestAddScopeRejectsEmptyMatcher 保证白名单不能变成 "拦一切".
func TestAddScopeRejectsEmptyMatcher(t *testing.T) {
	engine := newTestEngine(t)

	err := engine.AddScope(adapter.MITMScope{ID: "empty"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "matcher")

	err = engine.AddScope(adapter.MITMScope{
		ID:           "empty-slices",
		Domain:       []string{},
		DomainSuffix: []string{},
		ProcessName:  []string{},
		ProcessID:    []uint32{},
	})
	require.Error(t, err)
	require.Empty(t, engine.Scopes())
}

func TestAddScopeAcceptsProcessOnly(t *testing.T) {
	engine := newTestEngine(t)
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:          "chrome",
		ProcessName: []string{"Google Chrome"},
	}))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:        "pid",
		ProcessID: []uint32{4242},
	}))
	require.Len(t, engine.Scopes(), 2)
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

func chromeMeta(host string, pid uint32) *adapter.InboundContext {
	return &adapter.InboundContext{
		Domain: host,
		ProcessInfo: &adapter.ConnectionOwner{
			ProcessID:   pid,
			ProcessPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		},
	}
}

func chromeHelperMeta(host string, pid uint32) *adapter.InboundContext {
	return &adapter.InboundContext{
		Domain: host,
		ProcessInfo: &adapter.ConnectionOwner{
			ProcessID:   pid,
			ProcessPath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Helpers/Google Chrome Helper",
		},
	}
}

func TestMatchProcessNameRegex(t *testing.T) {
	engine := newTestEngine(t)
	require.NoError(t, engine.SetEnabled(true))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:          "chrome",
		ProcessName: []string{"Chrome"},
	}))

	hit := chromeMeta("www.google.com", 4242)
	helper := chromeHelperMeta("www.google.com", 4243)
	missName := &adapter.InboundContext{
		Domain: "www.google.com",
		ProcessInfo: &adapter.ConnectionOwner{
			ProcessPath: "/Applications/Safari.app/Contents/MacOS/Safari",
		},
	}
	noOwner := &adapter.InboundContext{Domain: "www.google.com"}
	noHost := chromeMeta("", 4242)

	require.True(t, engine.Match(hit), "substring regex must match basename")
	require.True(t, engine.Match(helper), "substring regex must match helper")
	require.False(t, engine.Match(missName), "other process must not match")
	require.False(t, engine.Match(noOwner), "lookup miss must not match process scope")
	require.False(t, engine.Match(noHost), "process-only still needs SNI/Fqdn")
}

func TestMatchProcessNameAnchored(t *testing.T) {
	engine := newTestEngine(t)
	require.NoError(t, engine.SetEnabled(true))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:          "chrome-exact",
		ProcessName: []string{"^Google Chrome$"},
	}))
	require.True(t, engine.Match(chromeMeta("www.google.com", 4242)))
	require.False(t, engine.Match(chromeHelperMeta("www.google.com", 4243)), "anchored regex must not match helper")
}

func TestAddScopeRejectsBadProcessNameRE(t *testing.T) {
	engine := newTestEngine(t)
	err := engine.AddScope(adapter.MITMScope{
		ID:          "bad",
		ProcessName: []string{"Chrome("},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "process_name")
	require.Empty(t, engine.Scopes())
}

func TestMatchDomainAndProcessAND(t *testing.T) {
	engine := newTestEngine(t)
	require.NoError(t, engine.SetEnabled(true))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:          "google-chrome",
		Domain:      []string{"www.google.com"},
		ProcessName: []string{"Google Chrome"},
		ProcessID:   []uint32{4242},
	}))

	require.True(t, engine.Match(chromeMeta("www.google.com", 4242)))
	require.False(t, engine.Match(chromeMeta("www.google.com", 1)), "pid miss")
	require.False(t, engine.Match(chromeMeta("x.com", 4242)), "domain miss")
	require.False(t, engine.Match(&adapter.InboundContext{Domain: "www.google.com"}), "no owner")
}

func TestMatchDomainOnlyIgnoresOwner(t *testing.T) {
	engine := newTestEngine(t)
	require.NoError(t, engine.SetEnabled(true))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:     "google",
		Domain: []string{"www.google.com"},
	}))
	require.True(t, engine.Match(&adapter.InboundContext{Domain: "www.google.com"}))
	require.True(t, engine.Match(chromeMeta("www.google.com", 4242)))
}

func TestNeedFindProcessFromSeedAndRuntime(t *testing.T) {
	engine, err := NewEngine(context.Background(), log.NewNOPFactory().Logger(), option.MITMOptions{
		AutoGenerate: true,
		Scopes: []option.MITMScope{{
			ID:          "chrome",
			ProcessName: []string{"Chrome"},
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, engine.Close()) })
	require.True(t, engine.NeedFindProcess(), "config seed must be visible before Start")

	plain := newTestEngine(t)
	require.False(t, plain.NeedFindProcess())
	require.NoError(t, plain.AddScope(adapter.MITMScope{
		ID:        "pid",
		ProcessID: []uint32{1},
	}))
	require.True(t, plain.NeedFindProcess())
}

func TestAddScopeRejectsGlobalWildcard(t *testing.T) {
	engine := newTestEngine(t)
	err := engine.AddScope(adapter.MITMScope{ID: "star", Domain: []string{"*.*"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "wildcard")
	err = engine.AddScope(adapter.MITMScope{ID: "all", DomainSuffix: []string{"*"}})
	require.Error(t, err)
	require.Empty(t, engine.Scopes())
}

func TestMatchAndroidPackageName(t *testing.T) {
	engine := newTestEngine(t)
	require.NoError(t, engine.SetEnabled(true))
	require.NoError(t, engine.AddScope(adapter.MITMScope{
		ID:          "chrome",
		ProcessName: []string{"com.android.chrome"},
	}))
	hit := &adapter.InboundContext{
		Domain: "www.google.com",
		ProcessInfo: &adapter.ConnectionOwner{
			AndroidPackageName: "com.android.chrome",
		},
	}
	require.True(t, engine.Match(hit), "process_name must match Android package")
}

func TestPublishAfterUnsubscribeDoesNotPanic(t *testing.T) {
	engine := newTestEngine(t)
	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		events, cancel := engine.SubscribeCapture()
		go func() {
			for range events {
			}
		}()
		go func() {
			engine.publish(adapter.MITMCaptureEvent{Host: "www.google.com"})
			cancel()
			engine.publish(adapter.MITMCaptureEvent{Host: "www.google.com"})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 32; i++ {
		<-done
	}
}

func TestAddScopeRejectsZeroProcessID(t *testing.T) {
	engine := newTestEngine(t)
	err := engine.AddScope(adapter.MITMScope{ID: "pid0", ProcessID: []uint32{0}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "zero")
	require.Empty(t, engine.Scopes())
}

func TestPublishBypassEmitsCapture(t *testing.T) {
	engine := newTestEngine(t)
	events, cancel := engine.SubscribeCapture()
	defer cancel()
	engine.PublishBypass(context.Background(), adapter.InboundContext{Domain: "www.google.com"}, "quic")
	select {
	case event := <-events:
		require.Equal(t, "www.google.com", event.Host)
		require.Contains(t, event.Warning, "quic")
	default:
		t.Fatal("no bypass capture event")
	}
}
