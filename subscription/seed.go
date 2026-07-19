package subscription

import (
	"errors"
	"os"
	"path/filepath"
)

// writeSeedIfMissing 仅在 path 不存在时落盘种子.
// 有意不覆盖已有 path, 避免冲掉手工/编排管理的文件; 缺失则从 url/cache 补齐.
func writeSeedIfMissing(path string, content []byte) error {
	if path == "" || len(content) == 0 {
		return nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err = os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, content, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
