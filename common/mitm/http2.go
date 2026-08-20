package mitm

import (
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/net/http2"
)

func (s *sess) serveH2() error {
	server := &http2.Server{}
	server.ServeConn(s.cli, &http2.ServeConnOpts{
		Context: s.ctx,
		Handler: http.HandlerFunc(s.roundH2),
	})
	return nil
}

func (s *sess) roundH2(writer http.ResponseWriter, req *http.Request) {
	if req.Host == "" {
		req.Host = s.host
	}
	path := req.URL.RequestURI()
	rawReq := cloneHeader(req.Header)
	blocked, status := applyRequestFilters(s.filters, req)
	if blocked {
		writer.WriteHeader(status)
		s.emit(req, &http.Response{StatusCode: status, Header: writer.Header()}, path, rawReq, nil)
		return
	}
	if err := rewindableBody(req); err != nil {
		http.Error(writer, err.Error(), http.StatusBadGateway)
		s.engine.publish(s.event(adapter.MITMCaptureEvent{
			Method:  req.Method,
			Path:    path,
			Warning: err.Error(),
		}))
		return
	}
	outReq := req.Clone(s.ctx)
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "https"
	}
	outReq.URL.Host = s.host
	stripHopHeaders(outReq.Header)
	resp, err := s.roundTripH2(outReq)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadGateway)
		s.engine.publish(s.event(adapter.MITMCaptureEvent{
			Method:  req.Method,
			Path:    path,
			Warning: err.Error(),
		}))
		return
	}
	defer resp.Body.Close()
	rawResp := cloneHeader(resp.Header)
	applyResponseFilters(s.filters, outReq, resp)
	stripHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.WriteHeader(resp.StatusCode)
	s.emit(outReq, resp, path, rawReq, rawResp)
	_ = drainCopy(writer, resp.Body)
}

func (s *sess) roundTripH2(req *http.Request) (*http.Response, error) {
	cc, err := s.h2Client()
	if err != nil {
		return nil, err
	}
	if err = resetBody(req); err != nil {
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	s.retireH2(cc)
	cc, err = s.h2Client()
	if err != nil {
		return nil, err
	}
	if err = resetBody(req); err != nil {
		return nil, err
	}
	return cc.RoundTrip(req)
}

// retireH2 只关自己拿到的那条 Origin.
// 为什么: H2 stream 并发, closeOrig 会把别人正在用的 conn 一起掐死.
func (s *sess) retireH2(dead *http2.ClientConn) {
	s.origMu.Lock()
	defer s.origMu.Unlock()
	if s.h2cc != dead {
		return
	}
	_ = s.h2cc.Close()
	s.h2cc = nil
	if s.orig != nil {
		_ = s.orig.Close()
		s.orig = nil
	}
	s.origR = nil
}

func (s *sess) h2Client() (*http2.ClientConn, error) {
	s.origMu.Lock()
	defer s.origMu.Unlock()
	if s.h2cc != nil {
		return s.h2cc, nil
	}
	next := []string{nextH2}
	orig, err := s.engine.hsOrigin(
		s.ctx,
		s.dialer,
		s.meta,
		s.host,
		next,
	)
	if err != nil {
		return nil, err
	}
	neg := orig.ConnectionState().NegotiatedProtocol
	if neg != "" && neg != nextH2 {
		_ = orig.Close()
		return nil, E.New("mitm origin alpn is not h2")
	}
	transport := &http2.Transport{}
	client, err := transport.NewClientConn(orig)
	if err != nil {
		_ = orig.Close()
		return nil, E.Cause(err, "mitm origin h2")
	}
	s.orig = orig
	s.h2cc = client
	return client, nil
}
