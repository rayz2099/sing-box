package subscription

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fetchResult struct {
	content []byte
	etag    string
	notMod  bool
}

// fetchHTTP 拉取远端完整 profile; dialer 为空时走系统 direct.
func fetchHTTP(ctx context.Context, rawURL string, etag string, dialer N.Dialer) (*fetchResult, error) {
	client := &http.Client{
		Timeout: C.TCPTimeout * 4,
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	if dialer != nil {
		client.Transport = &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return &fetchResult{notMod: true, etag: etag}, nil
	default:
		return nil, E.New("unexpected status: ", response.Status)
	}
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return &fetchResult{
		content: content,
		etag:    response.Header.Get("Etag"),
	}, nil
}

func readPath(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, E.Cause(err, "read subscription path")
	}
	return content, nil
}

// resolveProfile 取数顺序: builtin → cache → path(缺失则跳过) → url(direct).
// path 不存在不致命, 保证无种子仅靠 url 也能冷启动.
func resolveProfile(
	ctx context.Context,
	entry Entry,
	store *cacheStore,
	dialer N.Dialer,
	allowFetch bool,
) ([]byte, error) {
	if entry.Builtin != "" {
		content, err := LoadBuiltin(entry.Builtin)
		if err != nil {
			return nil, err
		}
		if err = verifyHash(content, entry.Hash); err != nil {
			return nil, E.Cause(err, "builtin")
		}
		return content, nil
	}
	if content, _, err := store.Load(entry.Tag); err == nil {
		if err = verifyHash(content, entry.Hash); err != nil {
			return nil, E.Cause(err, "cache")
		}
		return content, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, E.Cause(err, "load cache")
	}
	if entry.Path != "" {
		content, err := readPath(entry.Path)
		if err == nil {
			if err = verifyHash(content, entry.Hash); err != nil {
				return nil, E.Cause(err, "path")
			}
			_ = store.Save(entry.Tag, content, "")
			return content, nil
		}
		// 种子缺失时继续走 url, 不阻断冷启动
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if !allowFetch || entry.URL == "" {
		return nil, E.New("subscription ", entry.Tag, ": no cache, path or url")
	}
	result, err := fetchHTTP(ctx, entry.URL, "", dialer)
	if err != nil {
		return nil, E.Cause(err, "fetch ", entry.Tag)
	}
	if err = verifyHash(result.content, entry.Hash); err != nil {
		return nil, E.Cause(err, "url")
	}
	err = store.Save(entry.Tag, result.content, result.etag)
	if err != nil {
		return nil, err
	}
	return result.content, nil
}
