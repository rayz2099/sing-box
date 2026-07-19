package subscription

import C "github.com/sagernet/sing-box/constant"

// DefaultMetaPath 未显式指定时的订阅 meta 路径 (绝对, 优先 /usr/local/etc/sing-box).
func DefaultMetaPath() string {
	return C.DefaultSubscriptionMetaPath()
}
