package mitm

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	sbufio "github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
)

func (s *sess) serveH1(br *bufio.Reader) error {
	s.cliR = br
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
	rawReq := cloneHeader(req.Header)
	upgrade := isH1WebSocket(req)
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
		s.emit(req, resp, path, rawReq, nil)
		return resp.Write(s.cli)
	}
	if err := rewindableBody(req); err != nil {
		return err
	}
	if !upgrade {
		stripHopHeaders(req.Header)
	}
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	req.URL.Host = s.host
	orig, err := s.writeOrigH1(req)
	if err != nil {
		return err
	}
	if s.origR == nil {
		s.origR = bufio.NewReader(orig)
	}
	resp, err := http.ReadResponse(s.origR, req)
	if err != nil {
		s.closeOrig()
		return E.Cause(err, "mitm read origin http1")
	}
	rawResp := cloneHeader(resp.Header)
	applyResponseFilters(s.filters, req, resp)
	if !upgrade {
		stripHopHeaders(resp.Header)
	}
	s.emit(req, resp, path, rawReq, rawResp)
	err = resp.Write(s.cli)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if upgrade && resp.StatusCode == http.StatusSwitchingProtocols {
		cliR := s.cliR
		if cliR == nil {
			cliR = bufio.NewReader(s.cli)
		}
		return sbufio.CopyConn(s.ctx, &bufConn{Conn: s.cli, r: cliR}, &bufConn{Conn: orig, r: s.origR})
	}
	if resp.Close {
		s.closeOrig()
	}
	return nil
}

func (s *sess) writeOrigH1(req *http.Request) (net.Conn, error) {
	orig, err := s.ensureOrig(nextH1)
	if err != nil {
		return nil, err
	}
	if err = resetBody(req); err != nil {
		return nil, err
	}
	err = req.Write(orig)
	if err == nil {
		return orig, nil
	}
	s.closeOrig()
	orig, err = s.ensureOrig(nextH1)
	if err != nil {
		return nil, err
	}
	if err = resetBody(req); err != nil {
		return nil, err
	}
	err = req.Write(orig)
	if err != nil {
		s.closeOrig()
		return nil, E.Cause(err, "mitm write origin http1")
	}
	return orig, nil
}

func (s *sess) emit(
	req *http.Request,
	resp *http.Response,
	path string,
	rawReq map[string][]string,
	rawResp map[string][]string,
) {
	event := s.event(adapter.MITMCaptureEvent{
		Method:         req.Method,
		Path:           path,
		RequestHeaders: rawReq,
	})
	if resp != nil {
		event.Status = resp.StatusCode
		if rawResp != nil {
			event.ResponseHeaders = rawResp
		} else {
			event.ResponseHeaders = cloneHeader(resp.Header)
		}
	}
	s.engine.publish(event)
}

func isH1WebSocket(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

func rewindableBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody || req.GetBody != nil {
		return nil
	}
	payload, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return E.Cause(err, "mitm buffer http1 body")
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(payload)), nil
	}
	req.Body = io.NopCloser(bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	return nil
}

func resetBody(req *http.Request) error {
	if req.GetBody == nil {
		return nil
	}
	body, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	return nil
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
