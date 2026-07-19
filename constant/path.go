package constant

import (
	"os"
	"path/filepath"

	"github.com/sagernet/sing/common/rw"
)

const dirName = "sing-box"

var resourcePaths []string

func FindPath(name string) (string, bool) {
	name = os.ExpandEnv(name)
	if rw.IsFile(name) {
		return name, true
	}
	for _, dir := range resourcePaths {
		if path := filepath.Join(dir, dirName, name); rw.IsFile(path) {
			return path, true
		}
		if path := filepath.Join(dir, name); rw.IsFile(path) {
			return path, true
		}
	}
	return name, false
}

// DefaultSubscriptionHome 订阅/配置默认 home (与 plist WorkingDirectory 对齐).
const DefaultSubscriptionHome = "/usr/local/etc/" + dirName

// DefaultSubscriptionMetaPath 订阅 meta 默认路径.
// 固定优先配置 home, 避免在 ~/develop/sing-box 等目录执行 CLI 时误用 cwd 下的同名文件,
// 导致 listen socket 与 daemon 不一致.
func DefaultSubscriptionMetaPath() string {
	preferred := filepath.Join(DefaultSubscriptionHome, "subscriptions.json")
	if rw.IsFile(preferred) {
		return preferred
	}
	if path, ok := FindPath("subscriptions.json"); ok {
		if abs, err := filepath.Abs(path); err == nil {
			return abs
		}
		return path
	}
	return preferred
}

func init() {
	resourcePaths = append(resourcePaths, ".")
	if home := os.Getenv("HOME"); home != "" {
		resourcePaths = append(resourcePaths, home)
	}
	if userConfigDir, err := os.UserConfigDir(); err == nil {
		resourcePaths = append(resourcePaths, userConfigDir)
	}
	if userCacheDir, err := os.UserCacheDir(); err == nil {
		resourcePaths = append(resourcePaths, userCacheDir)
	}
}
