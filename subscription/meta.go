package subscription

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

const defaultUpdInterval = 24 * time.Hour

// Meta 是磁盘上的薄控制器配置, 与完整 profile 生命周期解耦.
type Meta = option.SubscriptionMetaOptions

type Entry = option.SubscriptionEntryOptions

var activeFieldPattern = regexp.MustCompile(`("active"\s*:\s*)"(?:\\.|[^"\\])*"`)

// LoadMeta 读取并校验 meta; 缺省值就地补齐, 保证冷启动路径确定.
func LoadMeta(path string) (*Meta, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, E.Cause(err, "read subscription meta")
	}
	var meta Meta
	err = json.Unmarshal(content, &meta)
	if err != nil {
		return nil, E.Cause(err, "decode subscription meta")
	}
	err = normalizeMeta(&meta, path)
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

func normalizeMeta(meta *Meta, metaPath string) error {
	if len(meta.Subscriptions) == 0 {
		return E.New("subscriptions is empty")
	}
	if meta.Active == "" {
		return E.New("active is required")
	}
	metaDir := filepath.Dir(metaPath)
	if meta.CacheDir == "" {
		meta.CacheDir = filepath.Join(metaDir, "subscription-cache")
	} else if !filepath.IsAbs(meta.CacheDir) {
		meta.CacheDir = filepath.Join(metaDir, meta.CacheDir)
	}
	if meta.Listen == "" {
		meta.Listen = filepath.Join(metaDir, "subscription.sock")
	}
	if meta.UpdateInterval.Build() <= 0 {
		meta.UpdateInterval = badoption.Duration(defaultUpdInterval)
	}
	seen := make(map[string]bool)
	activeFound := false
	for i := range meta.Subscriptions {
		entry := &meta.Subscriptions[i]
		if entry.Tag == "" {
			return E.New("subscription tag is required")
		}
		if seen[entry.Tag] {
			return E.New("duplicate subscription tag: ", entry.Tag)
		}
		seen[entry.Tag] = true
		if entry.Builtin == "" && entry.URL == "" && entry.Path == "" {
			return E.New("subscription ", entry.Tag, ": builtin, url or path is required")
		}
		if entry.Builtin != "" {
			if _, err := LoadBuiltin(entry.Builtin); err != nil {
				return E.Cause(err, "subscription ", entry.Tag)
			}
		}
		if entry.Path != "" && !filepath.IsAbs(entry.Path) {
			entry.Path = filepath.Join(metaDir, entry.Path)
		}
		if entry.Tag == meta.Active {
			activeFound = true
		}
	}
	if !activeFound {
		return E.New("active subscription not found: ", meta.Active)
	}
	return nil
}

func sockPath(listen string) (string, error) {
	if listen == "" {
		return "", E.New("listen is empty")
	}
	if strings.HasPrefix(listen, "unix://") {
		u, err := url.Parse(listen)
		if err != nil {
			return "", E.Cause(err, "parse listen")
		}
		path := u.Path
		if path == "" {
			path = u.Host
		}
		if path == "" {
			return "", E.New("invalid unix listen: ", listen)
		}
		return path, nil
	}
	if strings.HasPrefix(listen, "unix:") {
		return strings.TrimPrefix(listen, "unix:"), nil
	}
	return listen, nil
}

// SaveActive 只替换 meta 中的 active 字段, 避免重排其它配置或改写相对路径.
func SaveActive(metaPath string, active string) error {
	content, err := os.ReadFile(metaPath)
	if err != nil {
		return E.Cause(err, "read subscription meta")
	}
	var meta Meta
	err = json.Unmarshal(content, &meta)
	if err != nil {
		return E.Cause(err, "decode subscription meta")
	}
	found := false
	for _, entry := range meta.Subscriptions {
		if entry.Tag == active {
			found = true
			break
		}
	}
	if !found {
		return E.New("active subscription not found: ", active)
	}
	activeJSON, err := json.Marshal(active)
	if err != nil {
		return err
	}
	if !activeFieldPattern.Match(content) {
		return E.New("active field not found in meta file")
	}
	encoded := activeFieldPattern.ReplaceAll(content, []byte(`${1}`+string(activeJSON)))
	tmp := metaPath + ".tmp"
	err = os.WriteFile(tmp, encoded, 0o644)
	if err != nil {
		return err
	}
	return os.Rename(tmp, metaPath)
}
