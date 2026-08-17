package mitm

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.MITMEngine = (*Engine)(nil)

// Engine 持有 CaptureState. 热路径只读 snapshot, 注册走 COW.
type Engine struct {
	ctx      context.Context
	logger   log.ContextLogger
	options  option.MITMOptions
	ca       *authority
	enabled  atomic.Bool
	access   sync.Mutex
	scopes   []adapter.MITMScope
	filters  []adapter.MITMFilter
	subs     []chan adapter.MITMCaptureEvent
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
	if len(scope.Domain) == 0 && len(scope.DomainSuffix) == 0 {
		return E.New("mitm scope domain is required")
	}
	e.access.Lock()
	defer e.access.Unlock()
	for _, item := range e.scopes {
		if item.ID == scope.ID {
			return E.New("mitm scope already exists: ", scope.ID)
		}
	}
	e.scopes = append(append([]adapter.MITMScope{}, e.scopes...), scope)
	return nil
}

func (e *Engine) RemoveScope(id string) error {
	e.access.Lock()
	defer e.access.Unlock()
	for i, item := range e.scopes {
		if item.ID == id {
			next := append([]adapter.MITMScope{}, e.scopes[:i]...)
			e.scopes = append(next, e.scopes[i+1:]...)
			return nil
		}
	}
	return E.New("mitm scope not found: ", id)
}

func (e *Engine) Scopes() []adapter.MITMScope {
	e.access.Lock()
	defer e.access.Unlock()
	return append([]adapter.MITMScope{}, e.scopes...)
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
	return e.MatchHost(host)
}

func (e *Engine) MatchHost(host string) bool {
	if host == "" {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	e.access.Lock()
	scopes := e.scopes
	e.access.Unlock()
	for _, scope := range scopes {
		if matchScope(scope, host) {
			return true
		}
	}
	return false
}

func matchScope(scope adapter.MITMScope, host string) bool {
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
	e.access.Lock()
	subs := append([]chan adapter.MITMCaptureEvent{}, e.subs...)
	e.access.Unlock()
	for _, sub := range subs {
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
