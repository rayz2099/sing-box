package subscription

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// cacheState 把 etag 等运行时状态与 profile 字节分开存, 避免污染完整配置语义.
type cacheState struct {
	Etag        string    `json:"etag,omitempty"`
	LastUpdated time.Time `json:"last_updated,omitempty"`
}

type cacheStore struct {
	dir string
}

func newCacheStore(dir string) (*cacheStore, error) {
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return nil, E.Cause(err, "create cache dir")
	}
	return &cacheStore{dir: dir}, nil
}

func (s *cacheStore) contentPath(tag string) string {
	return filepath.Join(s.dir, tag+".json")
}

func (s *cacheStore) statePath(tag string) string {
	return filepath.Join(s.dir, tag+".state.json")
}

func (s *cacheStore) Load(tag string) ([]byte, string, error) {
	content, err := os.ReadFile(s.contentPath(tag))
	if err != nil {
		return nil, "", err
	}
	stateContent, err := os.ReadFile(s.statePath(tag))
	if err != nil {
		if os.IsNotExist(err) {
			return content, "", nil
		}
		return nil, "", err
	}
	var state cacheState
	err = json.Unmarshal(stateContent, &state)
	if err != nil {
		return content, "", nil
	}
	return content, state.Etag, nil
}

func (s *cacheStore) Save(tag string, content []byte, etag string) error {
	tmp := s.contentPath(tag) + ".tmp"
	err := os.WriteFile(tmp, content, 0o644)
	if err != nil {
		return err
	}
	err = os.Rename(tmp, s.contentPath(tag))
	if err != nil {
		return err
	}
	state := cacheState{
		Etag:        etag,
		LastUpdated: time.Now(),
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	stateTmp := s.statePath(tag) + ".tmp"
	err = os.WriteFile(stateTmp, encoded, 0o644)
	if err != nil {
		return err
	}
	return os.Rename(stateTmp, s.statePath(tag))
}

func (s *cacheStore) Exists(tag string) bool {
	_, err := os.Stat(s.contentPath(tag))
	return err == nil
}
