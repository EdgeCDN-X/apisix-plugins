package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {}

func init() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewPluginContext(uint32) types.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	types.DefaultPluginContext
	allowed map[string]struct{}
}

func (ctx *pluginContext) OnPluginStart(int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		proxywasm.LogCriticalf("query-param-filter: read configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	ctx.allowed, err = parseAllowlist(data)
	if err != nil {
		proxywasm.LogCriticalf("query-param-filter: invalid configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	return types.OnPluginStartStatusOK
}

func parseAllowlist(data []byte) (map[string]struct{}, error) {
	var values []any
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("expected a JSON array of strings: %w", err)
	}
	if values == nil {
		return nil, errors.New("expected a JSON array of strings, not null")
	}

	allowed := make(map[string]struct{}, len(values))
	for _, value := range values {
		name, ok := value.(string)
		if !ok {
			return nil, errors.New("query parameter names must be strings")
		}
		allowed[name] = struct{}{}
	}
	return allowed, nil
}

func (ctx *pluginContext) NewHttpContext(uint32) types.HttpContext {
	return &httpContext{allowed: ctx.allowed}
}

type httpContext struct {
	types.DefaultHttpContext
	allowed map[string]struct{}
}

func (ctx *httpContext) OnHttpRequestHeaders(int, bool) types.Action {
	args, err := proxywasm.GetProperty([]string{"args"})
	if errors.Is(err, types.ErrorStatusNotFound) {
		return types.ActionContinue
	}
	if err != nil {
		return failRequest(500, "read query arguments", err)
	}

	filtered := filterQuery(string(args), ctx.allowed)
	if filtered == string(args) {
		return types.ActionContinue
	}

	if filtered == "" {
		err = clearQueryArgs()
	} else {
		err = proxywasm.SetProperty([]string{"args"}, []byte(filtered))
	}
	if err != nil {
		return failRequest(500, "set query arguments", err)
	}
	return types.ActionContinue
}

func filterQuery(query string, allowed map[string]struct{}) string {
	var kept []string
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		key, _, _ := strings.Cut(part, "=")
		name := decodeQueryName(key)
		if _, ok := allowed[name]; ok && name != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "&")
}

func decodeQueryName(key string) string {
	var decoded strings.Builder
	decoded.Grow(len(key))
	for i := 0; i < len(key); i++ {
		if key[i] == '%' && i+2 < len(key) {
			high, highOK := hexValue(key[i+1])
			low, lowOK := hexValue(key[i+2])
			if highOK && lowOK {
				decoded.WriteByte(high<<4 | low)
				i += 2
				continue
			}
		}
		if key[i] == '+' {
			decoded.WriteByte(' ')
		} else {
			decoded.WriteByte(key[i])
		}
	}
	return decoded.String()
}

func hexValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func failRequest(status uint32, operation string, err error) types.Action {
	proxywasm.LogErrorf("query-param-filter: %s: %v", operation, err)
	if err := proxywasm.SendHttpResponse(status, nil, nil, -1); err != nil {
		proxywasm.LogErrorf("query-param-filter: send error response: %v", err)
		panic("query-param-filter: failed to send error response")
	}
	return types.ActionPause
}
