package subscription

import (
	"encoding/json"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

// DialRequest 供 CLI 打进常驻 controller, 不依赖 Clash API.
func DialRequest(listen string, req Request) (*Response, error) {
	path, err := sockPath(listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, E.Cause(err, "dial subscription socket")
	}
	defer conn.Close()
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(req)
	if err != nil {
		return nil, err
	}
	var resp Response
	decoder := json.NewDecoder(conn)
	err = decoder.Decode(&resp)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error == "" {
			return &resp, E.New("subscription request failed")
		}
		return &resp, E.New(resp.Error)
	}
	return &resp, nil
}

// ListenFromMeta 让 CLI 只依赖 meta 文件定位 socket.
func ListenFromMeta(metaPath string) (string, error) {
	meta, err := LoadMeta(metaPath)
	if err != nil {
		return "", err
	}
	return meta.Listen, nil
}
