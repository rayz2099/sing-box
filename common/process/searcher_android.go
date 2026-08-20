package process

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
)

var _ Searcher = (*androidSearcher)(nil)

type androidSearcher struct {
	packageManager tun.PackageManager
}

func NewSearcher(config Config) (Searcher, error) {
	return &androidSearcher{config.PackageManager}, nil
}

func (s *androidSearcher) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	inode, uid, err := resolveSocketByNetlink(network, source, destination)
	if err != nil {
		return nil, err
	}
	owner := &adapter.ConnectionOwner{UserId: int32(uid)}
	// 为什么: libbox 已能映射 ProcessID, 这里不填则 Android process_id Scope 恒 miss.
	if _, pid, procErr := resolveProcessNameByProcSearch(inode, uid); procErr == nil {
		owner.ProcessID = pid
	}
	if sharedPackage, loaded := s.packageManager.SharedPackageByID(uid % 100000); loaded {
		owner.AndroidPackageName = sharedPackage
		return owner, nil
	}
	if packageName, loaded := s.packageManager.PackageByID(uid % 100000); loaded {
		owner.AndroidPackageName = packageName
		return owner, nil
	}
	return owner, nil
}
