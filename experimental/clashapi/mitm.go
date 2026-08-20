package clashapi

import (
	"bytes"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// mitmRouter 把 MITM 控制面挂到现有鉴权 group.
// Engine 可能为 nil (配置没开 MITM), 仍注册路由, 由中间件统一 404, 避免调用方因缺路由误判.
func mitmRouter(engine adapter.MITMEngine) http.Handler {
	r := chi.NewRouter()
	r.Use(requireMITM(engine))
	r.Get("/", getMITM(engine))
	r.Patch("/", patchMITM(engine))
	r.Get("/ca", getMITMCA(engine))
	r.Post("/scopes", postMITMScope(engine))
	r.Delete("/scopes/{id}", deleteMITMScope(engine))
	r.Post("/filters", postMITMFilter(engine))
	r.Delete("/filters/{id}", deleteMITMFilter(engine))
	r.Get("/sessions", getMITMSessions)
	r.Get("/capture", getMITMCapture(engine))
	return r
}

// requireMITM 把 "没注入 Engine" 收敛成 404 JSON, 禁止对 nil 解引用.
func requireMITM(engine adapter.MITMEngine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if engine == nil {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type mitmStatus struct {
	Enabled bool                 `json:"enabled"`
	Scopes  []adapter.MITMScope  `json:"scopes"`
	Filters []adapter.MITMFilter `json:"filters"`
}

type mitmPatchRequest struct {
	Enabled *bool `json:"enabled"`
}

func getMITM(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, currentMITM(engine))
	}
}

func patchMITM(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req mitmPatchRequest
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if req.Enabled != nil {
			if err := engine.SetEnabled(*req.Enabled); err != nil {
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, newError(err.Error()))
				return
			}
		}
		render.NoContent(w, r)
	}
}

func getMITMCA(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		pem, err := engine.CACertificatePEM()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pem)
	}
}

// postMITMScope 不在控制面预判空 matcher, 让 Engine.AddScope 自己拒绝, 避免两套规则.
func postMITMScope(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var scope adapter.MITMScope
		if err := render.DecodeJSON(r.Body, &scope); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if err := engine.AddScope(scope); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func deleteMITMScope(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := getEscapeParam(r, "id")
		if err := engine.RemoveScope(id); err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func postMITMFilter(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var filter adapter.MITMFilter
		if err := render.DecodeJSON(r.Body, &filter); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		if err := engine.AddFilter(filter); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func deleteMITMFilter(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := getEscapeParam(r, "id")
		if err := engine.RemoveFilter(id); err != nil {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

// getMITMSessions 不持有历史会话索引: SubscribeCapture 只能推增量, 枚举只能先空.
func getMITMSessions(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, []adapter.MITMCaptureEvent{})
}

// getMITMCapture 用 SubscribeCapture 把明文切片推到 websocket, 不落盘.
func getMITMCapture(engine adapter.MITMEngine) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()

		events, cancel := engine.SubscribeCapture()
		defer cancel()

		buf := &bytes.Buffer{}
		for event := range events {
			buf.Reset()
			if err := json.NewEncoder(buf).Encode(event); err != nil {
				return
			}
			if err := wsutil.WriteServerText(conn, buf.Bytes()); err != nil {
				return
			}
		}
	}
}

func currentMITM(engine adapter.MITMEngine) mitmStatus {
	return mitmStatus{
		Enabled: engine.Enabled(),
		Scopes:  engine.Scopes(),
		Filters: engine.Filters(),
	}
}
