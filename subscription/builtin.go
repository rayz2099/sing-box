package subscription

import (
	_ "embed"

	E "github.com/sagernet/sing/common/exceptions"
)

// 内置 default: 无种子/无网络时也能拉起进程, 再 CLI 切到远端 tun profile.
//
//go:embed embed/default.json
var builtinDefault []byte

// LoadBuiltin 按名加载嵌入 profile; 目前仅支持 default.
func LoadBuiltin(name string) ([]byte, error) {
	switch name {
	case "default":
		if len(builtinDefault) == 0 {
			return nil, E.New("builtin default profile is empty")
		}
		return append([]byte(nil), builtinDefault...), nil
	default:
		return nil, E.New("unknown builtin profile: ", name)
	}
}
