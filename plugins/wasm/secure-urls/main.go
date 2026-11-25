package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

const cookieName = "ex-sec-session"

type secureKey struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type config struct {
	SecureKeys      []secureKey `json:"secure_keys"`
	DisablePrefixes bool        `json:"disable_prefixes"`
	BindClientIP    bool        `json:"bind_client_ip"`
	TrustedProxies  []string    `json:"trusted_proxies"`
}

type settings struct {
	config
	keys    map[string]string
	proxies []netip.Prefix
}

type cookieBody struct {
	KeyName   string `json:"keyName"`
	Expires   int64  `json:"expires"`
	Service   string `json:"service"`
	URLPrefix string `json:"url,omitempty"`
	IP        string `json:"ip,omitempty"`
}

func main() {}

func init() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct{ types.DefaultVMContext }

func (*vmContext) NewPluginContext(uint32) types.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	types.DefaultPluginContext
	settings *settings
}

func (ctx *pluginContext) OnPluginStart(int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err == nil {
		ctx.settings, err = parseConfig(data)
	}
	if err != nil {
		proxywasm.LogCriticalf("secure-urls: invalid configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	return types.OnPluginStartStatusOK
}

func parseConfig(data []byte) (*settings, error) {
	var c config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, errors.New("configuration must be a JSON object")
	}
	if len(c.SecureKeys) == 0 {
		return nil, errors.New("at least one secure key is required")
	}
	s := &settings{config: c, keys: make(map[string]string, len(c.SecureKeys))}
	for _, key := range c.SecureKeys {
		if key.Name == "" || key.Value == "" {
			return nil, errors.New("secure key name and value must be nonempty")
		}
		if _, exists := s.keys[key.Name]; exists {
			return nil, errors.New("secure key names must be unique")
		}
		s.keys[key.Name] = key.Value
	}
	for _, raw := range c.TrustedProxies {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q", raw)
		}
		s.proxies = append(s.proxies, prefix.Masked())
	}
	return s, nil
}

func (ctx *pluginContext) NewHttpContext(uint32) types.HttpContext {
	return &httpContext{settings: ctx.settings}
}

type httpContext struct {
	types.DefaultHttpContext
	settings *settings
	cookie   string
}

func (ctx *httpContext) OnHttpRequestHeaders(int, bool) types.Action {
	scheme, err := proxywasm.GetProperty([]string{"scheme"})
	if err != nil {
		return failRequest(500, "read request scheme", err)
	}
	host, err := proxywasm.GetHttpRequestHeader(":authority")
	if err != nil {
		return failRequest(500, "read request host", err)
	}
	path, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		return failRequest(500, "read request URI", err)
	}
	incoming, err := url.ParseRequestURI(path)
	if err != nil || incoming.IsAbs() || incoming.Host != "" {
		return denyRequest()
	}
	incoming.Scheme = string(scheme)
	incoming.Host = host
	if incoming.Scheme != "http" && incoming.Scheme != "https" || incoming.Host == "" {
		return denyRequest()
	}
	ip := ""
	if ctx.settings.BindClientIP {
		peer, err := proxywasm.GetProperty([]string{"realip_remote_addr"})
		if errors.Is(err, types.ErrorStatusNotFound) {
			peer, err = proxywasm.GetProperty([]string{"remote_addr"})
		}
		if err != nil {
			return failRequest(500, "read peer IP", err)
		}
		realIP, err := optionalHeader("x-real-ip")
		if err != nil {
			return failRequest(500, "read X-Real-IP", err)
		}
		forwarded, err := optionalHeader("x-forwarded-for")
		if err != nil {
			return failRequest(500, "read X-Forwarded-For", err)
		}
		ip, err = ctx.settings.clientIP(string(peer), realIP, forwarded)
		if err != nil {
			return denyRequest()
		}
	}
	cookieHeader, err := optionalHeader("cookie")
	if err != nil {
		return failRequest(500, "read cookie", err)
	}
	ctx.cookie, err = ctx.settings.authorize(incoming, cookieHeader, ip, time.Now())
	if err != nil {
		return denyRequest()
	}
	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseHeaders(int, bool) types.Action {
	if ctx.cookie != "" {
		if err := proxywasm.AddHttpResponseHeader("set-cookie", ctx.cookie); err != nil {
			proxywasm.LogErrorf("secure-urls: add session cookie: %v", err)
		}
	}
	return types.ActionContinue
}

func optionalHeader(name string) (string, error) {
	value, err := proxywasm.GetHttpRequestHeader(name)
	if errors.Is(err, types.ErrorStatusNotFound) {
		return "", nil
	}
	return value, err
}

func denyRequest() types.Action {
	if err := proxywasm.SendHttpResponse(401, nil, nil, -1); err != nil {
		proxywasm.LogErrorf("secure-urls: send rejection: %v", err)
		panic("secure-urls: failed to send rejection")
	}
	return types.ActionPause
}

func failRequest(status uint32, operation string, err error) types.Action {
	proxywasm.LogErrorf("secure-urls: %s: %v", operation, err)
	if err := proxywasm.SendHttpResponse(status, nil, nil, -1); err != nil {
		proxywasm.LogErrorf("secure-urls: send error response: %v", err)
		panic("secure-urls: failed to send error response")
	}
	return types.ActionPause
}

func (s *settings) clientIP(peer, realIP, forwarded string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(peer))
	if err != nil || addr.Zone() != "" {
		return "", errors.New("invalid peer IP")
	}
	addr = addr.Unmap()
	if !s.trusted(addr) {
		return addr.String(), nil
	}
	if realIP != "" {
		addr, err = netip.ParseAddr(strings.TrimSpace(realIP))
		if err != nil || addr.Zone() != "" {
			return "", errors.New("invalid X-Real-IP")
		}
		return addr.Unmap().String(), nil
	}
	if forwarded != "" {
		chain := strings.Split(forwarded, ",")
		for i := len(chain) - 1; i >= 0; i-- {
			addr, err = netip.ParseAddr(strings.TrimSpace(chain[i]))
			if err != nil || addr.Zone() != "" {
				return "", errors.New("invalid X-Forwarded-For")
			}
			addr = addr.Unmap()
			if !s.trusted(addr) || i == 0 {
				return addr.String(), nil
			}
		}
	}
	return addr.String(), nil
}

func (s *settings) trusted(addr netip.Addr) bool {
	for _, prefix := range s.proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

var errUnauthorized = errors.New("unauthorized")

func (s *settings) authorize(incoming *url.URL, cookieHeader, ip string, now time.Time) (string, error) {
	query, err := url.ParseQuery(incoming.RawQuery)
	if err != nil {
		return "", errUnauthorized
	}
	for _, name := range []string{"EX-Expires", "EX-KeyName", "EX-Sign", "EX-UrlPrefix", "EX-Client-IP"} {
		if len(query[name]) > 1 {
			return "", errUnauthorized
		}
	}
	expiry, name, signature := query.Get("EX-Expires"), query.Get("EX-KeyName"), query.Get("EX-Sign")
	if expiry == "" || name == "" || signature == "" {
		request := http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
		cookie, err := request.Cookie(cookieName)
		if err != nil {
			return "", errUnauthorized
		}
		return s.authorizeCookie(incoming, cookie.Value, ip, now)
	}
	key, ok := s.keys[name]
	if !ok {
		return "", errUnauthorized
	}
	expires, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || now.Unix() > expires {
		return "", errUnauthorized
	}
	prefix := query.Get("EX-UrlPrefix")
	if prefix != "" {
		if s.DisablePrefixes || !validPrefix(incoming, prefix) {
			return "", errUnauthorized
		}
		for name := range query {
			switch name {
			case "EX-Expires", "EX-KeyName", "EX-Sign", "EX-UrlPrefix", "EX-Client-IP":
			default:
				return "", errUnauthorized
			}
		}
	}
	if s.BindClientIP {
		requestIP, err := netip.ParseAddr(query.Get("EX-Client-IP"))
		if err != nil || requestIP.Zone() != "" || requestIP.Unmap().String() != ip {
			return "", errUnauthorized
		}
	}
	legacy := *incoming
	if prefix != "" {
		legacy.RawQuery = "EX-UrlPrefix=" + prefix + "&"
	} else {
		legacy.RawQuery = ""
	}
	legacy.RawQuery += "EX-Expires=" + expiry + "&EX-KeyName=" + name
	if s.BindClientIP {
		legacy.RawQuery += "&EX-Client-IP=" + query.Get("EX-Client-IP")
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return "", errUnauthorized
	}
	valid := false
	if prefix == "" {
		signed := *incoming
		signed.RawQuery, err = withoutSignature(incoming.RawQuery)
		if err != nil {
			return "", errUnauthorized
		}
		valid = hmac.Equal(sig, sign([]byte(signed.String()), key))
	}
	if !valid {
		// Legacy signatures may omit query parameters, so use them only when
		// every parameter is part of the legacy payload.
		onlySignedParams := true
		for name := range query {
			switch name {
			case "EX-Expires", "EX-KeyName", "EX-Sign":
			case "EX-UrlPrefix":
				onlySignedParams = onlySignedParams && prefix != ""
			case "EX-Client-IP":
				onlySignedParams = onlySignedParams && s.BindClientIP
			default:
				onlySignedParams = false
			}
		}
		valid = onlySignedParams && hmac.Equal(sig, sign([]byte(legacy.String()), key))
	}
	if !valid {
		return "", errUnauthorized
	}
	if prefix == "" {
		return "", nil
	}
	body := cookieBody{KeyName: name, Expires: now.Unix() + 3600, Service: incoming.Host, URLPrefix: prefix}
	if s.BindClientIP {
		body.IP = ip
	}
	return makeCookie(body, key, now)
}

func withoutSignature(raw string) (string, error) {
	parts := strings.Split(raw, "&")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(name)
		if err != nil {
			return "", err
		}
		if name != "EX-Sign" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "&"), nil
}

func (s *settings) authorizeCookie(incoming *url.URL, value, ip string, now time.Time) (string, error) {
	if s.DisablePrefixes {
		return "", errUnauthorized
	}
	encoded, encodedSig, ok := strings.Cut(value, ".")
	if !ok {
		return "", errUnauthorized
	}
	payload, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", errUnauthorized
	}
	sig, err := base64.URLEncoding.DecodeString(encodedSig)
	if err != nil {
		return "", errUnauthorized
	}
	var body cookieBody
	if err := json.Unmarshal(payload, &body); err != nil {
		return "", errUnauthorized
	}
	key, ok := s.keys[body.KeyName]
	if !ok || body.Service != incoming.Host || now.Unix() > body.Expires ||
		!validPrefix(incoming, body.URLPrefix) || s.BindClientIP && body.IP != ip {
		return "", errUnauthorized
	}
	// The existing service verifies the re-marshaled payload, not the raw JSON.
	payload, err = json.Marshal(body)
	if err != nil || !hmac.Equal(sig, sign(payload, key)) {
		return "", errUnauthorized
	}
	if time.Unix(body.Expires, 0).Sub(now) < 20*time.Minute {
		body.Expires = now.Unix() + 3600
		return makeCookie(body, key, now)
	}
	return "", nil
}

func validPrefix(incoming *url.URL, encoded string) bool {
	raw, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return false
	}
	prefix, err := url.Parse(string(raw))
	if err != nil || prefix.Host == "" || prefix.User != nil || prefix.RawQuery != "" || prefix.Fragment != "" {
		return false
	}
	if prefix.Scheme != incoming.Scheme || prefix.Host != incoming.Host {
		return false
	}
	return strings.HasPrefix(incoming.Scheme+"://"+incoming.Host+incoming.Path, string(raw))
}

func sign(payload []byte, key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func makeCookie(body cookieBody, key string, now time.Time) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	rawPrefix, err := base64.URLEncoding.DecodeString(body.URLPrefix)
	if err != nil {
		return "", err
	}
	prefix, err := url.Parse(string(rawPrefix))
	if err != nil {
		return "", err
	}
	host := body.Service
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	value := base64.URLEncoding.EncodeToString(payload) + "." + base64.URLEncoding.EncodeToString(sign(payload, key))
	cookie := http.Cookie{
		Name: cookieName, Value: value, Path: prefix.Path, Domain: host,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
		Expires: time.Unix(body.Expires, 0), MaxAge: int(time.Unix(body.Expires, 0).Sub(now).Seconds()),
	}
	return cookie.String(), nil
}
