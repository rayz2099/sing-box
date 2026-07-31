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
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	// 若是 symlink, 仍用调用方路径的 Dir 作为 home (etc), 不用 resolve 到 develop
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
	// listen / cache_dir / update_interval 未配置时相对 meta 所在 home 补齐
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
	}
	if meta.Active == "" {
		if seen["default"] {
			meta.Active = "default"
		} else {
			meta.Active = meta.Subscriptions[0].Tag
		}
	} else if !seen[meta.Active] {
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

// metaWritePath 解析 active 写盘目标; symlink 写 target, 避免 rename 把 link 顶成普通文件.
func metaWritePath(metaPath string) (string, error) {
	info, err := os.Lstat(metaPath)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return metaPath, nil
	}
	target, err := filepath.EvalSymlinks(metaPath)
	if err != nil {
		return "", E.Cause(err, "resolve subscription meta symlink")
	}
	return target, nil
}

// insertActiveField 在缺省 active 的 meta 中补字段, 让 switch 后冷启动可恢复.
func insertActiveField(content []byte, activeJSON string) ([]byte, error) {
	idx := strings.IndexByte(string(content), '{')
	if idx < 0 {
		return nil, E.New("invalid meta json: missing object")
	}
	var b strings.Builder
	b.Grow(len(content) + len(activeJSON) + 16)
	b.Write(content[:idx+1])
	b.WriteString("\n  \"active\": ")
	b.WriteString(activeJSON)
	b.WriteByte(',')
	b.Write(content[idx+1:])
	return []byte(b.String()), nil
}

// SaveActive 只改 meta 中的 active: 有则替换, 无则插入; 不重排其它配置或改写相对路径.
func SaveActive(metaPath string, active string) error {
	writePath, err := metaWritePath(metaPath)
	if err != nil {
		return E.Cause(err, "resolve subscription meta path")
	}
	content, err := os.ReadFile(writePath)
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
	var encoded []byte
	if activeFieldPattern.Match(content) {
		encoded = activeFieldPattern.ReplaceAll(content, []byte(`${1}`+string(activeJSON)))
	} else {
		encoded, err = insertActiveField(content, string(activeJSON))
		if err != nil {
			return err
		}
	}
	// 校验补丁后仍是合法 meta, 避免脏写
	var check Meta
	if err = json.Unmarshal(encoded, &check); err != nil {
		return E.Cause(err, "encode active field")
	}
	if check.Active != active {
		return E.New("active field patch mismatch: ", check.Active)
	}
	tmp := writePath + ".tmp"
	err = os.WriteFile(tmp, encoded, 0o644)
	if err != nil {
		return err
	}
	return os.Rename(tmp, writePath)
}
