package mitm

import (
	"bufio"
	"io"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

func (s *sess) serveH1(br *bufio.Reader) error {
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if isNormalClose(err) {
				return nil
			}
			return E.Cause(err, "mitm read http1 request")
		}
		err = s.roundH1(req)
		_ = req.Body.Close()
		if err != nil {
			return err
		}
	}
}

func (s *sess) roundH1(req *http.Request) error {
	if req.Host == "" {
		req.Host = s.host
	}
	path := req.URL.RequestURI()
	blocked, status := applyRequestFilters(s.filters, req)
	if blocked {
		resp := &http.Response{
			StatusCode: status,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Close:      false,
		}
		s.emit(req, resp, path)
		return resp.Write(s.cli)
	}
	orig, err := s.ensureOrig(nextH1)
	if err != nil {
		return err
	}
	stripHopHeaders(req.Header)
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	req.URL.Host = s.host
	err = req.Write(orig)
	if err != nil {
		return E.Cause(err, "mitm write origin http1")
	}
	if s.origR == nil {
		s.origR = bufio.NewReader(orig)
	}
	resp, err := http.ReadResponse(s.origR, req)
	if err != nil {
		return E.Cause(err, "mitm read origin http1")
	}
	applyResponseFilters(s.filters, req, resp)
	stripHopHeaders(resp.Header)
	s.emit(req, resp, path)
	err = resp.Write(s.cli)
	_ = resp.Body.Close()
	return err
}

func (s *sess) emit(
	req *http.Request,
	resp *http.Response,
	path string,
) {
	event := adapter.MITMCaptureEvent{
		SessionID:      s.sid,
		Host:           s.host,
		ALPN:           s.neg,
		Method:         req.Method,
		Path:           path,
		RequestHeaders: cloneHeader(req.Header),
	}
	if resp != nil {
		event.Status = resp.StatusCode
		event.ResponseHeaders = cloneHeader(resp.Header)
	}
	s.engine.publish(event)
}

func cloneHeader(header http.Header) map[string][]string {
	if header == nil {
		return nil
	}
	out := make(map[string][]string, len(header))
	for key, values := range header {
		out[key] = append([]string{}, values...)
	}
	return out
}

func drainCopy(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}
