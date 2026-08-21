package mitm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func newStateEngine(t *testing.T, options option.MITMOptions) *Engine {
	t.Helper()
	engine, err := NewEngine(context.Background(), log.NewNOPFactory().Logger(), options)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, engine.Close())
	})
	return engine
}

func TestStateFileDerivedFromCertificatePath(t *testing.T) {
	dir := t.TempDir()
	engine := newStateEngine(t, option.MITMOptions{
		AutoGenerate:    true,
		CertificatePath: filepath.Join(dir, "ca.crt"),
	})
	path, err := engine.stateFile()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "capture-state.json"), path)
}

func TestPersistRoundTripAndSidecarWinsSeed(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "capture-state.json")
	first := newStateEngine(t, option.MITMOptions{
		AutoGenerate: true,
		StatePath:    statePath,
		Enabled:      false,
		Scopes: []option.MITMScope{{
			ID:     "google",
			Domain: []string{"www.google.com"},
		}},
	})
	require.NoError(t, first.AddScope(adapter.MITMScope{
		ID:          "curl",
		ProcessName: []string{"^curl$"},
	}))
	require.NoError(t, first.AddFilter(adapter.MITMFilter{
		ID:   "block-ua",
		Type: "header",
		Request: &adapter.MITMHeaderPatch{
			Remove: []string{"User-Agent"},
		},
	}))
	require.NoError(t, first.SetEnabled(true))

	second := newStateEngine(t, option.MITMOptions{
		AutoGenerate: true,
		StatePath:    statePath,
		Enabled:      false,
		Scopes: []option.MITMScope{{
			ID:     "google",
			Domain: []string{"www.google.com"},
		}},
	})
	require.True(t, second.NeedFindProcess(), "sidecar process Scope must be visible before Start")
	require.NoError(t, second.Start(adapter.StartStateStart))
	require.True(t, second.Enabled())
	require.Equal(t, []adapter.MITMScope{{
		ID:          "curl",
		ProcessName: []string{"^curl$"},
	}}, second.Scopes())
	require.Len(t, second.Filters(), 1)
	require.Equal(t, "block-ua", second.Filters()[0].ID)
}

func TestStartSeedsWhenSidecarMissing(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "capture-state.json")
	engine := newStateEngine(t, option.MITMOptions{
		AutoGenerate: true,
		StatePath:    statePath,
		Enabled:      true,
		Scopes: []option.MITMScope{{
			ID:     "x",
			Domain: []string{"x.com"},
		}},
	})
	require.NoError(t, engine.Start(adapter.StartStateStart))
	require.True(t, engine.Enabled())
	require.Equal(t, []adapter.MITMScope{{
		ID:     "x",
		Domain: []string{"x.com"},
	}}, engine.Scopes())
	_, err := os.Stat(statePath)
	require.NoError(t, err)
}

func TestCorruptSidecarRejectsNewEngine(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "capture-state.json")
	require.NoError(t, os.WriteFile(statePath, []byte("{not-json"), 0o644))
	_, err := NewEngine(context.Background(), log.NewNOPFactory().Logger(), option.MITMOptions{
		AutoGenerate: true,
		StatePath:    statePath,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse mitm capture state")
}

func TestStartRequiresStatePath(t *testing.T) {
	engine := newStateEngine(t, option.MITMOptions{AutoGenerate: true})
	err := engine.Start(adapter.StartStateStart)
	require.Error(t, err)
	require.Contains(t, err.Error(), "state_path")
}
