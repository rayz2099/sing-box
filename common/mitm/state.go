package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

const captureStateName = "capture-state.json"

// captureStateFile 是 CaptureState 的 sidecar.
// 为什么: 订阅 rebuild 会换掉整份 profile 和 Engine, 这份表不能写进订阅 JSON / cache.db.
type captureStateFile struct {
	Enabled bool                 `json:"enabled"`
	Scopes  []adapter.MITMScope  `json:"scopes"`
	Filters []adapter.MITMFilter `json:"filters"`
}

func (e *Engine) stateFile() (string, error) {
	if e.options.StatePath != "" {
		return e.options.StatePath, nil
	}
	if e.options.CertificatePath != "" {
		return filepath.Join(filepath.Dir(e.options.CertificatePath), captureStateName), nil
	}
	if e.options.KeyPath != "" {
		return filepath.Join(filepath.Dir(e.options.KeyPath), captureStateName), nil
	}
	return "", E.New("mitm state_path is required when certificate_path and key_path are empty")
}

func (e *Engine) persistNow() error {
	e.access.Lock()
	defer e.access.Unlock()
	return e.writeLocked()
}

func (e *Engine) writeLocked() error {
	if e.skipPersist {
		return nil
	}
	path, err := e.stateFile()
	if err != nil {
		return err
	}
	scopes := make([]adapter.MITMScope, 0, len(e.scopes))
	for _, item := range e.scopes {
		scopes = append(scopes, item.pub)
	}
	return writeStateFile(path, captureStateFile{
		Enabled: e.enabled.Load(),
		Scopes:  scopes,
		Filters: append([]adapter.MITMFilter{}, e.filters...),
	})
}

func (e *Engine) applyState(state captureStateFile) error {
	for _, scope := range state.Scopes {
		if err := e.AddScope(scope); err != nil {
			return err
		}
	}
	for _, filter := range state.Filters {
		if err := e.AddFilter(filter); err != nil {
			return err
		}
	}
	return e.SetEnabled(state.Enabled)
}

func readStateFile(path string) (*captureStateFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, E.Cause(err, "read mitm capture state")
	}
	var state captureStateFile
	if err = json.Unmarshal(raw, &state); err != nil {
		return nil, E.Cause(err, "parse mitm capture state")
	}
	return &state, nil
}

func writeStateFile(path string, state captureStateFile) error {
	if state.Scopes == nil {
		state.Scopes = []adapter.MITMScope{}
	}
	if state.Filters == nil {
		state.Filters = []adapter.MITMFilter{}
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return E.Cause(err, "encode mitm capture state")
	}
	raw = append(raw, '\n')
	tmpPath := path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return E.Cause(err, "write mitm capture state")
	}
	if _, err = file.Write(raw); err != nil {
		_ = file.Close()
		return E.Cause(err, "write mitm capture state")
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return E.Cause(err, "sync mitm capture state")
	}
	if err = file.Close(); err != nil {
		return E.Cause(err, "close mitm capture state")
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return E.Cause(err, "replace mitm capture state")
	}
	return nil
}
