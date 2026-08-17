package mitm

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// TestAddFilterAcceptsHeaderAndBlock 只覆盖已落地的注册面. 解密后 header/block 应用还没接到 Intercept.
func TestAddFilterAcceptsHeaderAndBlock(t *testing.T) {
	engine := newTestEngine(t)

	require.NoError(t, engine.AddFilter(adapter.MITMFilter{
		ID:     "block-login",
		Type:   "block",
		When:   adapter.MITMFilterWhen{PathPrefix: []string{"/login"}},
		Status: 403,
	}))
	require.NoError(t, engine.AddFilter(adapter.MITMFilter{
		ID:   "rewrite-ua",
		Type: "header",
		Request: &adapter.MITMHeaderPatch{
			Set:    map[string]string{"User-Agent": "mitm-test"},
			Remove: []string{"Cookie"},
		},
	}))
	require.Error(t, engine.AddFilter(adapter.MITMFilter{
		ID:   "rewrite",
		Type: "rewrite-body",
	}))

	filters := engine.Filters()
	require.Len(t, filters, 2)
	require.Equal(t, "block", filters[0].Type)
	require.Equal(t, "header", filters[1].Type)
	require.Equal(t, "mitm-test", filters[1].Request.Set["User-Agent"])
	require.Equal(t, []string{"Cookie"}, filters[1].Request.Remove)
}
