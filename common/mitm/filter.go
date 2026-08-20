package mitm

import (
	"net"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/adapter"
)

// applyRequestFilters 在明文请求上跑 Filter 链.
// 为什么: Filter 只认识 HTTP 消息, 必须在两段 TLS 之间执行, block 要能阻止打 Origin Leg.
func applyRequestFilters(
	filters []adapter.MITMFilter,
	req *http.Request,
) (blocked bool, status int) {
	for _, filter := range sortedFilters(filters) {
		if !matchFilterWhen(filter.When, req.Host, req.Method, req.URL.RequestURI()) {
			continue
		}
		switch filter.Type {
		case "block":
			status = filter.Status
			if status == 0 {
				status = http.StatusForbidden
			}
			return true, status
		case "header":
			if filter.Request != nil {
				applyHeaderPatch(req.Header, filter.Request)
			}
		}
	}
	return false, 0
}

func applyResponseFilters(
	filters []adapter.MITMFilter,
	req *http.Request,
	resp *http.Response,
) {
	for _, filter := range sortedFilters(filters) {
		if !matchFilterWhen(filter.When, req.Host, req.Method, req.URL.RequestURI()) {
			continue
		}
		if filter.Type == "header" && filter.Response != nil {
			applyHeaderPatch(resp.Header, filter.Response)
		}
	}
}

func matchFilterWhen(
	when adapter.MITMFilterWhen,
	host string,
	method string,
	path string,
) bool {
	if len(when.Host) > 0 && !containsHost(when.Host, host) {
		return false
	}
	if len(when.Method) > 0 && !containsFold(when.Method, method) {
		return false
	}
	if len(when.PathPrefix) > 0 {
		ok := false
		for _, prefix := range when.PathPrefix {
			if strings.HasPrefix(path, prefix) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func applyHeaderPatch(header http.Header, patch *adapter.MITMHeaderPatch) {
	for _, key := range patch.Remove {
		header.Del(key)
	}
	for key, value := range patch.Set {
		header.Set(key, value)
	}
}

func sortedFilters(filters []adapter.MITMFilter) []adapter.MITMFilter {
	out := append([]adapter.MITMFilter{}, filters...)
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1].Priority > out[j].Priority {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

func containsFold(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func containsHost(list []string, value string) bool {
	host := hostName(value)
	for _, item := range list {
		if strings.EqualFold(hostName(item), host) {
			return true
		}
	}
	return false
}

func hostName(host string) string {
	name, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return name
}

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	"Proxy-Connection",
}

func stripHopHeaders(header http.Header) {
	for _, key := range hopHeaders {
		header.Del(key)
	}
}
