package subscription

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
)

// Controller 外置订阅控制器: 跨 Box teardown/rebuild 常驻, 避免控制面随 profile 一起被拆掉.
type Controller struct {
	ctx          context.Context
	cancel       context.CancelFunc
	metaPath     string
	disableColor bool
	logger       log.ContextLogger

	access     sync.Mutex
	meta       *Meta
	cache      *cacheStore
	instance   *box.Box
	instCancel context.CancelFunc
	lastGood   []byte
	activeTag  string
	server     *Server
	updTicker  *time.Ticker
}

type Status struct {
	Active        string        `json:"active"`
	Subscriptions []StatusEntry `json:"subscriptions"`
	CacheDir      string        `json:"cache_dir"`
	Listen        string        `json:"listen"`
}

type StatusEntry struct {
	Tag      string `json:"tag"`
	Builtin  string `json:"builtin,omitempty"`
	HasURL   bool   `json:"has_url"`
	HasPath  bool   `json:"has_path"`
	HasCache bool   `json:"has_cache"`
	HasHash  bool   `json:"has_hash"`
	IsActive bool   `json:"is_active"`
}

// Done 在 last-good 回滚也失败等致命场景关闭, 让 launchd 侧感知进程该退.
func (c *Controller) Done() <-chan struct{} {
	return c.ctx.Done()
}

func NewController(ctx context.Context, metaPath string, disableColor bool) (*Controller, error) {
	meta, err := LoadMeta(metaPath)
	if err != nil {
		return nil, err
	}
	store, err := newCacheStore(meta.CacheDir)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Controller{
		ctx:          ctx,
		cancel:       cancel,
		metaPath:     metaPath,
		disableColor: disableColor,
		logger:       log.StdLogger(),
		meta:         meta,
		cache:        store,
		activeTag:    meta.Active,
	}, nil
}

// Start 冷启动 active profile, 再挂控制面与定时刷新.
func (c *Controller) Start() error {
	c.access.Lock()
	defer c.access.Unlock()

	entry, err := c.findEntry(c.meta.Active)
	if err != nil {
		return err
	}
	content, err := resolveProfile(c.ctx, *entry, c.cache, nil, true)
	if err != nil {
		return E.Cause(err, "resolve active subscription")
	}
	err = c.startBoxLocked(content)
	if err != nil {
		return err
	}
	c.lastGood = append([]byte(nil), content...)
	c.activeTag = entry.Tag

	server, err := NewServer(c.meta.Listen, c)
	if err != nil {
		c.closeBoxLocked()
		return err
	}
	c.server = server
	err = c.server.Start()
	if err != nil {
		c.closeBoxLocked()
		return err
	}

	c.updTicker = time.NewTicker(c.meta.UpdateInterval.Build())
	go c.loopUpdate()
	c.logger.Info("subscription controller started, active=", c.activeTag)
	return nil
}

func (c *Controller) Close() error {
	c.cancel()
	c.access.Lock()
	defer c.access.Unlock()
	if c.updTicker != nil {
		c.updTicker.Stop()
	}
	var err error
	if c.server != nil {
		err = E.Append(err, c.server.Close(), func(e error) error {
			return E.Cause(e, "close subscription server")
		})
	}
	err = E.Append(err, c.closeBoxLocked(), func(e error) error {
		return E.Cause(e, "close box")
	})
	return err
}

func (c *Controller) loopUpdate() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.updTicker.C:
			err := c.Update("")
			if err != nil {
				c.logger.Error("subscription update: ", err)
			}
		}
	}
}

// Status 供控制面查询当前互斥激活态与各源就绪情况.
func (c *Controller) Status() Status {
	c.access.Lock()
	defer c.access.Unlock()
	entries := make([]StatusEntry, 0, len(c.meta.Subscriptions))
	for _, entry := range c.meta.Subscriptions {
		entries = append(entries, StatusEntry{
			Tag:      entry.Tag,
			Builtin:  entry.Builtin,
			HasURL:   entry.URL != "",
			HasPath:  entry.Path != "",
			HasCache: entry.Builtin == "" && c.cache.Exists(entry.Tag),
			HasHash:  entry.Hash != "",
			IsActive: entry.Tag == c.activeTag,
		})
	}
	return Status{
		Active:        c.activeTag,
		Subscriptions: entries,
		CacheDir:      c.meta.CacheDir,
		Listen:        c.meta.Listen,
	}
}

// Switch 互斥切换完整 profile; 失败时 active 与运行实例都不变.
func (c *Controller) Switch(tag string) error {
	c.access.Lock()
	defer c.access.Unlock()
	if tag == c.activeTag {
		return nil
	}
	entry, err := c.findEntry(tag)
	if err != nil {
		return err
	}
	dialer, err := c.downloadDialerLocked()
	if err != nil {
		return err
	}
	content, err := resolveProfile(c.ctx, *entry, c.cache, dialer, true)
	if err != nil {
		return err
	}
	err = c.rebuildLocked(content)
	if err != nil {
		return err
	}
	c.activeTag = tag
	c.meta.Active = tag
	saveErr := SaveActive(c.metaPath, tag)
	if saveErr != nil {
		// 运行态已切换; meta 写盘失败不回滚实例, 避免为了磁盘再断流
		c.logger.Error("save active to meta: ", saveErr)
	}
	c.logger.Info("switched subscription to ", tag)
	return nil
}

// Update 刷新订阅 cache; tag 为空则刷全部, 仅 active 内容变化时 rebuild.
func (c *Controller) Update(tag string) error {
	c.access.Lock()
	defer c.access.Unlock()
	if tag != "" {
		entry, err := c.findEntry(tag)
		if err != nil {
			return err
		}
		return c.updateEntryLocked(entry)
	}
	var firstErr error
	for i := range c.meta.Subscriptions {
		entry := &c.meta.Subscriptions[i]
		err := c.updateEntryLocked(entry)
		if err != nil {
			c.logger.Error("update ", entry.Tag, ": ", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// ReloadMeta 在 SIGHUP 等场景重读 meta, 支持改文件切换 active.
func (c *Controller) ReloadMeta() error {
	meta, err := LoadMeta(c.metaPath)
	if err != nil {
		return err
	}
	store, err := newCacheStore(meta.CacheDir)
	if err != nil {
		return err
	}
	c.access.Lock()
	oldInterval := c.meta.UpdateInterval.Build()
	oldActive := c.activeTag
	c.meta = meta
	c.cache = store
	ticker := c.updTicker
	c.access.Unlock()
	if meta.UpdateInterval.Build() != oldInterval && ticker != nil {
		ticker.Reset(meta.UpdateInterval.Build())
	}
	if meta.Active != oldActive {
		return c.Switch(meta.Active)
	}
	return nil
}

func (c *Controller) updateEntryLocked(entry *Entry) error {
	if entry.Builtin != "" || entry.URL == "" {
		return nil
	}
	if entry.Hash != "" {
		c.logger.Info("skip auto update for pinned subscription ", entry.Tag)
		return nil
	}
	oldContent, etag, _ := c.cache.Load(entry.Tag)
	dialer, err := c.downloadDialerLocked()
	if err != nil {
		return err
	}
	result, err := fetchHTTP(c.ctx, entry.URL, etag, dialer)
	if err != nil {
		return err
	}
	if result.notMod {
		c.logger.Info("subscription ", entry.Tag, ": not modified")
		return nil
	}
	if err = verifyHash(result.content, entry.Hash); err != nil {
		return err
	}
	if err = c.checkProfile(result.content); err != nil {
		return E.Cause(err, "invalid profile")
	}
	changed := !bytes.Equal(oldContent, result.content)
	err = c.cache.Save(entry.Tag, result.content, result.etag)
	if err != nil {
		return err
	}
	if !changed {
		c.logger.Info("subscription ", entry.Tag, ": content unchanged")
		return nil
	}
	c.logger.Info("subscription ", entry.Tag, ": cache updated")
	if entry.Tag != c.activeTag {
		return nil
	}
	return c.rebuildLocked(result.content)
}

func (c *Controller) downloadDialerLocked() (N.Dialer, error) {
	detour := c.meta.DownloadDetour
	if detour == "" {
		return nil, nil
	}
	if c.instance == nil {
		return nil, E.New("download_detour requires running instance: ", detour)
	}
	outbound, loaded := c.instance.Outbound().Outbound(detour)
	if !loaded {
		return nil, E.New("download detour not found: ", detour)
	}
	return outbound, nil
}

func (c *Controller) findEntry(tag string) (*Entry, error) {
	for i := range c.meta.Subscriptions {
		if c.meta.Subscriptions[i].Tag == tag {
			return &c.meta.Subscriptions[i], nil
		}
	}
	return nil, E.New("subscription not found: ", tag)
}

func (c *Controller) checkProfile(content []byte) error {
	_, err := json.UnmarshalExtendedContext[option.Options](c.ctx, content)
	return err
}

func (c *Controller) startBoxLocked(content []byte) error {
	options, err := json.UnmarshalExtendedContext[option.Options](c.ctx, content)
	if err != nil {
		return E.Cause(err, "decode profile")
	}
	if c.disableColor {
		if options.Log == nil {
			options.Log = &option.LogOptions{}
		}
		options.Log.DisableColor = true
	}
	ctx, cancel := context.WithCancel(c.ctx)
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		cancel()
		return E.Cause(err, "create service")
	}
	err = instance.Start()
	if err != nil {
		cancel()
		return E.Cause(err, "start service")
	}
	c.instance = instance
	c.instCancel = cancel
	return nil
}

func (c *Controller) closeBoxLocked() error {
	if c.instance == nil {
		return nil
	}
	if c.instCancel != nil {
		c.instCancel()
	}
	err := c.instance.Close()
	c.instance = nil
	c.instCancel = nil
	return err
}

// rebuildLocked 同进程 teardown + rebuild; Start 失败则 last-good 回滚, 再失败由调用方决定退出.
func (c *Controller) rebuildLocked(content []byte) error {
	if err := c.checkProfile(content); err != nil {
		return E.Cause(err, "invalid profile")
	}
	prevGood := append([]byte(nil), c.lastGood...)
	_ = c.closeBoxLocked()
	err := c.startBoxLocked(content)
	if err == nil {
		c.lastGood = append([]byte(nil), content...)
		return nil
	}
	c.logger.Error("start new profile failed: ", err)
	if len(prevGood) == 0 {
		return err
	}
	rollbackErr := c.startBoxLocked(prevGood)
	if rollbackErr != nil {
		// last-good 也起不来则结束进程, 交给 launchd 拉起
		c.cancel()
		return E.Cause(rollbackErr, "rollback last-good after start failure: ", err)
	}
	c.lastGood = prevGood
	return E.Cause(err, "applied profile failed, rolled back")
}
