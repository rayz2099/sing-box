package subscription

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Server 用专用 unix socket 暴露控制面, 不寄生 Clash API.
type Server struct {
	listen string
	path   string
	ctrl   *Controller
	ln     net.Listener
}

type Request struct {
	Method string `json:"method"`
	Tag    string `json:"tag,omitempty"`
}

type Response struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
}

func NewServer(listen string, ctrl *Controller) (*Server, error) {
	path, err := sockPath(listen)
	if err != nil {
		return nil, err
	}
	return &Server{
		listen: listen,
		path:   path,
		ctrl:   ctrl,
	}, nil
}

func (s *Server) Start() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return E.Cause(err, "mkdir socket dir")
	}
	_ = os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return E.Cause(err, "listen ", s.path)
	}
	if err = os.Chmod(s.path, 0o600); err != nil {
		ln.Close()
		_ = os.Remove(s.path)
		return E.Cause(err, "chmod socket")
	}
	s.ln = ln
	go s.serve()
	return nil
}

func (s *Server) Close() error {
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	_ = os.Remove(s.path)
	return err
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	var req Request
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		s.write(conn, Response{OK: false, Error: err.Error()})
		return
	}
	var resp Response
	switch req.Method {
	case "status":
		status := s.ctrl.Status()
		resp = Response{OK: true, Status: &status}
	case "switch":
		if req.Tag == "" {
			resp = Response{OK: false, Error: "tag is required"}
			break
		}
		err := s.ctrl.Switch(req.Tag)
		if err != nil {
			resp = Response{OK: false, Error: err.Error()}
			break
		}
		status := s.ctrl.Status()
		resp = Response{OK: true, Status: &status}
	case "update":
		err := s.ctrl.Update(req.Tag)
		if err != nil {
			resp = Response{OK: false, Error: err.Error()}
			break
		}
		status := s.ctrl.Status()
		resp = Response{OK: true, Status: &status}
	default:
		resp = Response{OK: false, Error: "unknown method: " + req.Method}
	}
	s.write(conn, resp)
}

func (s *Server) write(conn net.Conn, resp Response) {
	encoder := json.NewEncoder(conn)
	_ = encoder.Encode(resp)
}
