package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

var testNow = time.Unix(1700000000, 0)

func testSettings(t *testing.T, binding bool) *settings {
	t.Helper()
	data := fmt.Sprintf(`{"secure_keys":[{"name":"old","value":"old-secret"},{"name":"new","value":"new-secret"}],"bind_client_ip":%t,"trusted_proxies":["10.0.0.0/8","2001:db8::/32"]}`, binding)
	s, err := parseConfig([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signedURL(t *testing.T, rawURL, signedPayload, key string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL + "&EX-Sign=" + hex.EncodeToString(sign([]byte(signedPayload), key)))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestConfiguration(t *testing.T) {
	for _, input := range []string{
		`null`,
		`{"secure_keys":[{"name":"","value":"secret"}]}`,
		`{"secure_keys":[{"name":"key","value":"secret"},{"name":"key","value":"other"}]}`,
		`{"secure_keys":[{"name":"key","value":"secret"}],"trusted_proxies":["not-a-cidr"]}`,
	} {
		if _, err := parseConfig([]byte(input)); err == nil {
			t.Errorf("accepted invalid configuration: %s", input)
		}
	}
}

func TestSingleURLSignature(t *testing.T) {
	s := testSettings(t, false)
	payload := "https://cdn.example/file?quality=high&EX-Expires=1700000100&EX-KeyName=old"
	u := signedURL(t, payload, payload, "old-secret")
	if cookie, err := s.authorize(u, "", "", testNow); err != nil || cookie != "" {
		t.Fatalf("valid signed URL: cookie=%q err=%v", cookie, err)
	}
	for _, raw := range []string{
		strings.Replace(u.String(), "quality=high", "quality=low", 1),
		u.String() + "&extra=unsigned",
		u.String() + "&EX-KeyName=new",
		strings.Replace(u.String(), "old", "new", 1),
	} {
		changed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.authorize(changed, "", "", testNow); err == nil {
			t.Errorf("accepted changed URL %s", raw)
		}
	}
	if _, err := s.authorize(u, "", "", testNow.Add(101*time.Second)); err == nil {
		t.Fatal("accepted expired URL")
	}
	delete(s.keys, "old")
	if _, err := s.authorize(u, "", "", testNow); err == nil {
		t.Fatal("accepted removed key")
	}
}

func TestPrefixCookieAndRotation(t *testing.T) {
	s := testSettings(t, false)
	prefix := base64.URLEncoding.EncodeToString([]byte("https://cdn.example/media/"))
	payload := "https://cdn.example/media/index?EX-UrlPrefix=" + prefix + "&EX-Expires=1700000100&EX-KeyName=old"
	u := signedURL(t, payload, payload, "old-secret")
	cookie, err := s.authorize(u, "", "", testNow)
	if err != nil || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "SameSite=None") {
		t.Fatalf("valid prefix cookie: %q, %v", cookie, err)
	}
	header := strings.SplitN(cookie, ";", 2)[0]
	segment, _ := url.Parse("https://cdn.example/media/segment.ts")
	if refreshed, err := s.authorize(segment, header, "", testNow); err != nil || refreshed != "" {
		t.Fatalf("valid session: refresh=%q err=%v", refreshed, err)
	}
	if refreshed, err := s.authorize(segment, header, "", testNow.Add(41*time.Minute)); err != nil || refreshed == "" {
		t.Fatalf("near-expiry session should refresh: %q, %v", refreshed, err)
	}
	for _, raw := range []string{"https://cdn.example/other", "https://cdn.example.evil/media/segment.ts"} {
		other, _ := url.Parse(raw)
		if _, err := s.authorize(other, header, "", testNow); err == nil {
			t.Errorf("accepted cookie for %s", raw)
		}
	}
	changed, _ := url.Parse(u.String() + "&quality=unsigned")
	if _, err := s.authorize(changed, "", "", testNow); err == nil {
		t.Fatal("accepted unsigned prefix query parameter")
	}
	s.DisablePrefixes = true
	if _, err := s.authorize(segment, header, "", testNow); err == nil {
		t.Fatal("accepted prefix cookie when prefixes are disabled")
	}
	s.DisablePrefixes = false
	delete(s.keys, "old")
	if _, err := s.authorize(segment, header, "", testNow); err == nil {
		t.Fatal("accepted cookie signed with a removed key")
	}
}

func TestClientIP(t *testing.T) {
	s := testSettings(t, true)
	tests := []struct {
		peer, real, forwarded, want string
		fail                        bool
	}{
		{"192.0.2.1", "198.51.100.1", "198.51.100.2", "192.0.2.1", false},
		{"10.0.0.1", "198.51.100.1", "198.51.100.2", "198.51.100.1", false},
		{"10.0.0.1", "", "198.51.100.1, 10.1.1.1", "198.51.100.1", false},
		{"10.0.0.1", "", "203.0.113.1, 198.51.100.1", "198.51.100.1", false},
		{"10.0.0.1", "", "", "10.0.0.1", false},
		{"2001:db8::1", "2001:db8:1::1", "", "2001:db8:1::1", false},
		{"10.0.0.1", "bad", "198.51.100.1", "", true},
		{"10.0.0.1", "", "198.51.100.1, bad", "", true},
	}
	for _, tc := range tests {
		got, err := s.clientIP(tc.peer, tc.real, tc.forwarded)
		if (err != nil) != tc.fail || got != tc.want {
			t.Errorf("clientIP(%q, %q, %q) = %q, %v; want %q (error=%t)", tc.peer, tc.real, tc.forwarded, got, err, tc.want, tc.fail)
		}
	}
}

func TestIPBoundSignaturesAndCookies(t *testing.T) {
	s := testSettings(t, true)
	prefix := base64.URLEncoding.EncodeToString([]byte("https://cdn.example/media/"))
	payload := "https://cdn.example/media/index?EX-UrlPrefix=" + prefix + "&EX-Expires=1700000100&EX-KeyName=new&EX-Client-IP=198.51.100.1"
	u := signedURL(t, payload, payload, "new-secret")
	cookie, err := s.authorize(u, "", "198.51.100.1", testNow)
	if err != nil || cookie == "" {
		t.Fatalf("IP-bound URL: cookie=%q err=%v", cookie, err)
	}
	if _, err := s.authorize(u, "", "198.51.100.2", testNow); err == nil {
		t.Fatal("accepted URL from wrong IP")
	}
	header := strings.SplitN(cookie, ";", 2)[0]
	segment, _ := url.Parse("https://cdn.example/media/segment.ts")
	if _, err := s.authorize(segment, header, "198.51.100.1", testNow); err != nil {
		t.Fatalf("valid IP-bound cookie: %v", err)
	}
	if _, err := s.authorize(segment, header, "198.51.100.2", testNow); err == nil {
		t.Fatal("accepted cookie from wrong IP")
	}
	old := testSettings(t, false)
	oldPayload := "https://cdn.example/media/index?EX-UrlPrefix=" + prefix + "&EX-Expires=1700000100&EX-KeyName=new"
	oldCookie, err := old.authorize(signedURL(t, oldPayload, oldPayload, "new-secret"), "", "", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.authorize(segment, strings.SplitN(oldCookie, ";", 2)[0], "198.51.100.1", testNow); err == nil {
		t.Fatal("accepted unbound cookie while binding is enabled")
	}
}
