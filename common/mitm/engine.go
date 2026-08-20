package mitm

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

var _ adapter.MITMEngine = (*Engine)(nil)

// Engine 持有 CaptureState. 热路径只读 snapshot, 注册走 COW.
type Engine struct {
	ctx     context.Context
	logger  log.ContextLogger
	options option.MITMOptions
	ca      *authority
	enabled atomic.Bool
	access  sync.Mutex
	scopes  []storedScope
	filters []adapter.MITMFilter
	subs    []chan adapter.MITMCaptureEvent
}

// storedScope 把 process_name 正则编进 Scope, 避免热路径 Compile.
type storedScope struct {
	pub    adapter.MITMScope
	nameRE []*regexp.Regexp
}

func NewEngine(ctx context.Context, logger log.ContextLogger, options option.MITMOptions) (*Engine, error) {
	ca, err := newAuthority(ctx, options)
	if err != nil {
		return nil, err
	}
	return &Engine{
		ctx:     ctx,
		logger:  logger,
		options: options,
		ca:      ca,
	}, nil
}

func (e *Engine) Name() string {
	return "mitm"
}

func (e *Engine) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := e.ca.ensure(); err != nil {
		return err
	}
	// 配置里的 scopes/enabled 只在启动灌进内存, 之后仍走 API, 不回写磁盘.
	for _, scope := range e.options.Scopes {
		err := e.AddScope(adapter.MITMScope{
			ID:           scope.ID,
			Domain:       scope.Domain,
			DomainSuffix: scope.DomainSuffix,
			ProcessName:  scope.ProcessName,
			ProcessID:    scope.ProcessID,
		})
		if err != nil {
			return err
		}
	}
	if e.options.Enabled {
		return e.SetEnabled(true)
	}
	return nil
}

func (e *Engine) Close() error {
	e.access.Lock()
	defer e.access.Unlock()
	for _, sub := range e.subs {
		close(sub)
	}
	e.subs = nil
	return nil
}

func (e *Engine) Enabled() bool {
	return e.enabled.Load()
}

func (e *Engine) SetEnabled(enabled bool) error {
	if enabled {
		if err := e.ca.ensure(); err != nil {
			return err
		}
	}
	e.enabled.Store(enabled)
	return nil
}

func (e *Engine) CACertificatePEM() ([]byte, error) {
	if err := e.ca.ensure(); err != nil {
		return nil, err
	}
	return e.ca.certificatePEM(), nil
}

func (e *Engine) AddScope(scope adapter.MITMScope) error {
	if scope.ID == "" {
		return E.New("mitm scope id is required")
	}
	if len(scope.Domain) == 0 && len(scope.DomainSuffix) == 0 && len(scope.ProcessName) == 0 && len(scope.ProcessID) == 0 {
		return E.New("mitm scope matcher is required")
	}
	if err := rejectGlobalWildcard(scope.Domain, scope.DomainSuffix); err != nil {
		return err
	}
	if err := rejectZeroProcessID(scope.ProcessID); err != nil {
		return err
	}
	nameRE, err := compileProcessNameRE(scope.ProcessName)
	if err != nil {
		return err
	}
	// 为什么: 先开 searcher 再暴露 Scope, 避免中间几毫秒 lookup miss 漏拦.
	if hasProcessConstraint(scope) {
		if router := service.FromContext[adapter.Router](e.ctx); router != nil {
			router.EnsureFindProcess()
		}
	}
	e.access.Lock()
	defer e.access.Unlock()
	for _, item := range e.scopes {
		if item.pub.ID == scope.ID {
			return E.New("mitm scope already exists: ", scope.ID)
		}
	}
	e.scopes = append(append([]storedScope{}, e.scopes...), storedScope{
		pub:    scope,
		nameRE: nameRE,
	})
	return nil
}

func (e *Engine) RemoveScope(id string) error {
	e.access.Lock()
	defer e.access.Unlock()
	for i, item := range e.scopes {
		if item.pub.ID == id {
			next := append([]storedScope{}, e.scopes[:i]...)
			e.scopes = append(next, e.scopes[i+1:]...)
			return nil
		}
	}
	return E.New("mitm scope not found: ", id)
}

func (e *Engine) Scopes() []adapter.MITMScope {
	e.access.Lock()
	defer e.access.Unlock()
	out := make([]adapter.MITMScope, 0, len(e.scopes))
	for _, item := range e.scopes {
		out = append(out, item.pub)
	}
	return out
}

func (e *Engine) AddFilter(filter adapter.MITMFilter) error {
	if filter.ID == "" {
		return E.New("mitm filter id is required")
	}
	switch filter.Type {
	case "header", "block":
	default:
		return E.New("unknown mitm filter type: ", filter.Type)
	}
	e.access.Lock()
	defer e.access.Unlock()
	for _, item := range e.filters {
		if item.ID == filter.ID {
			return E.New("mitm filter already exists: ", filter.ID)
		}
	}
	e.filters = append(append([]adapter.MITMFilter{}, e.filters...), filter)
	return nil
}

func (e *Engine) RemoveFilter(id string) error {
	e.access.Lock()
	defer e.access.Unlock()
	for i, item := range e.filters {
		if item.ID == id {
			next := append([]adapter.MITMFilter{}, e.filters[:i]...)
			e.filters = append(next, e.filters[i+1:]...)
			return nil
		}
	}
	return E.New("mitm filter not found: ", id)
}

func (e *Engine) Filters() []adapter.MITMFilter {
	e.access.Lock()
	defer e.access.Unlock()
	return append([]adapter.MITMFilter{}, e.filters...)
}

func (e *Engine) Match(metadata *adapter.InboundContext) bool {
	if metadata == nil || !e.enabled.Load() {
		return false
	}
	host := metadata.Domain
	if host == "" {
		host = metadata.Destination.Fqdn
	}
	// 无 SNI/Fqdn 不能签 leaf, 进程 Scope 也不能按 IP 乱拆.
	if host == "" {
		return false
	}
	e.access.Lock()
	scopes := e.scopes
	e.access.Unlock()
	for _, scope := range scopes {
		if matchScope(scope, host, metadata.ProcessInfo) {
			return true
		}
	}
	return false
}

func (e *Engine) NeedFindProcess() bool {
	for _, scope := range e.options.Scopes {
		if len(scope.ProcessName) > 0 || len(scope.ProcessID) > 0 {
			return true
		}
	}
	e.access.Lock()
	defer e.access.Unlock()
	for _, scope := range e.scopes {
		if hasProcessConstraint(scope.pub) {
			return true
		}
	}
	return false
}

func matchScope(scope storedScope, host string, owner *adapter.ConnectionOwner) bool {
	return matchDomain(scope.pub, host) && matchProcess(scope, owner)
}

func matchDomain(scope adapter.MITMScope, host string) bool {
	if len(scope.Domain) == 0 && len(scope.DomainSuffix) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range scope.Domain {
		if host == strings.ToLower(strings.TrimSuffix(domain, ".")) {
			return true
		}
	}
	for _, suffix := range scope.DomainSuffix {
		suf := strings.ToLower(strings.TrimSuffix(suffix, "."))
		if suf == "" {
			continue
		}
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

func matchProcess(scope storedScope, owner *adapter.ConnectionOwner) bool {
	if !hasProcessConstraint(scope.pub) {
		return true
	}
	if owner == nil {
		return false
	}
	if len(scope.nameRE) > 0 {
		if !matchOwnerNames(scope.nameRE, owner) {
			return false
		}
	}
	if len(scope.pub.ProcessID) > 0 {
		if owner.ProcessID == 0 || !containsPID(scope.pub.ProcessID, owner.ProcessID) {
			return false
		}
	}
	return true
}

func hasProcessConstraint(scope adapter.MITMScope) bool {
	return len(scope.ProcessName) > 0 || len(scope.ProcessID) > 0
}

func compileProcessNameRE(exprs []string) ([]*regexp.Regexp, error) {
	if len(exprs) == 0 {
		return nil, nil
	}
	out := make([]*regexp.Regexp, 0, len(exprs))
	for i, expr := range exprs {
		if expr == "" {
			return nil, E.New("mitm scope process_name[", i, "] is empty")
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, E.Cause(err, "mitm scope process_name[", i, "]")
		}
		out = append(out, re)
	}
	return out, nil
}

func matchAnyRE(list []*regexp.Regexp, value string) bool {
	for _, re := range list {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func containsPID(list []uint32, value uint32) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func (e *Engine) SubscribeCapture() (<-chan adapter.MITMCaptureEvent, func()) {
	ch := make(chan adapter.MITMCaptureEvent, 64)
	e.access.Lock()
	e.subs = append(e.subs, ch)
	e.access.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			e.access.Lock()
			defer e.access.Unlock()
			for i, item := range e.subs {
				if item == ch {
					e.subs = append(e.subs[:i], e.subs[i+1:]...)
					close(ch)
					return
				}
			}
		})
	}
	return ch, cancel
}

func (e *Engine) publish(event adapter.MITMCaptureEvent) {
	// 为什么: cancel/Close 会 close(ch), 拷贝后再 send 会和 close 竞态 panic.
	e.access.Lock()
	defer e.access.Unlock()
	for _, sub := range e.subs {
		select {
		case sub <- event:
		default:
		}
	}
}

func (e *Engine) snapshotFilters() []adapter.MITMFilter {
	e.access.Lock()
	defer e.access.Unlock()
	out := append([]adapter.MITMFilter{}, e.filters...)
	return out
}

func fillOwner(event *adapter.MITMCaptureEvent, owner *adapter.ConnectionOwner) {
	if owner == nil {
		return
	}
	switch {
	case owner.ProcessPath != "":
		event.ProcessName = filepath.Base(owner.ProcessPath)
	case owner.AndroidPackageName != "":
		event.ProcessName = owner.AndroidPackageName
	}
	event.ProcessID = owner.ProcessID
}

func matchOwnerNames(list []*regexp.Regexp, owner *adapter.ConnectionOwner) bool {
	for _, name := range ownerNames(owner) {
		if matchAnyRE(list, name) {
			return true
		}
	}
	return false
}

func ownerNames(owner *adapter.ConnectionOwner) []string {
	var names []string
	if owner.ProcessPath != "" {
		names = append(names, filepath.Base(owner.ProcessPath))
	}
	if owner.AndroidPackageName != "" {
		names = append(names, owner.AndroidPackageName)
	}
	return names
}

func rejectGlobalWildcard(domain []string, suffix []string) error {
	for i, item := range domain {
		if isGlobalWildcard(item) {
			return E.New("mitm scope domain[", i, "] wildcard is forbidden")
		}
	}
	for i, item := range suffix {
		if isGlobalWildcard(item) {
			return E.New("mitm scope domain_suffix[", i, "] wildcard is forbidden")
		}
	}
	return nil
}

func isGlobalWildcard(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return host == "*" || host == "*.*"
}

func rejectZeroProcessID(ids []uint32) error {
	for i, pid := range ids {
		if pid == 0 {
			return E.New("mitm scope process_id[", i, "] is zero")
		}
	}
	return nil
}

func (e *Engine) PublishBypass(ctx context.Context, metadata adapter.InboundContext, reason string) {
	host := leafHint(metadata)
	e.logger.WarnContext(ctx, "mitm bypass ", reason, " host=", host)
	e.publish(captureEvent(metadata, adapter.MITMCaptureEvent{
		Host:    host,
		Warning: "mitm bypass: " + reason,
	}))
}

func captureEvent(metadata adapter.InboundContext, event adapter.MITMCaptureEvent) adapter.MITMCaptureEvent {
	fillOwner(&event, metadata.ProcessInfo)
	return event
}
