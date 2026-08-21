package mitm

import (
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/adapter"
)

// skipPair 是 Client Leg 失败后的粘性 Bypass 键.
// 为什么: 本连接已发出 ServerHello, 不能再改成 Bypass; 后续同进程同 host 必须放行, 否则 curl 会一直 error 60.
type skipPair struct {
	owner string
	host  string
}

func skipOwner(owner *adapter.ConnectionOwner) string {
	if owner == nil {
		return ""
	}
	if owner.ProcessPath != "" {
		return filepath.Base(owner.ProcessPath)
	}
	return owner.AndroidPackageName
}

func skipHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (e *Engine) markSkip(metadata adapter.InboundContext) {
	owner := skipOwner(metadata.ProcessInfo)
	if owner == "" {
		// 没有 ConnectionOwner 就标记会连坐所有进程, 宁可不粘.
		return
	}
	host := skipHost(leafHint(metadata))
	if host == "" {
		return
	}
	e.access.Lock()
	defer e.access.Unlock()
	if e.skips == nil {
		e.skips = make(map[skipPair]struct{})
	}
	e.skips[skipPair{owner: owner, host: host}] = struct{}{}
}

func (e *Engine) hasSkipLocked(owner *adapter.ConnectionOwner, host string) bool {
	if len(e.skips) == 0 {
		return false
	}
	name := skipOwner(owner)
	if name == "" {
		return false
	}
	_, ok := e.skips[skipPair{owner: name, host: skipHost(host)}]
	return ok
}
