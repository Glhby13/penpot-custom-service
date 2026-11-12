package authservice

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCustomizationInjectionIsLimitedToStockHTML(t *testing.T) {
	for _, tc := range []struct {
		name, path, ctype, encoding string
		status                      int
		want                        bool
	}{
		{"SPA", "/", "text/html; charset=utf-8", "", 200, true},
		{"RPC", "/api/rpc/command/get-profile", "application/json", "", 200, false},
		{"asset", "/js/main.js", "text/javascript", "", 200, false},
		{"upstream error", "/", "text/html", "", 502, false},
		{"compressed body", "/", "text/html", "gzip", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "<html><head></head><body>Penpot</body></html>"
			resp := &http.Response{
				StatusCode: tc.status,
				Header:     http.Header{"Content-Type": {tc.ctype}, "Content-Encoding": {tc.encoding}},
				Request:    &http.Request{URL: &url.URL{Path: tc.path}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}
			if err := injectRedirect(resp); err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(got), customizeTag) != tc.want {
				t.Fatalf("injected=%v want=%v", strings.Contains(string(got), customizeTag), tc.want)
			}
			if !tc.want && string(got) != body {
				t.Fatal("non-SPA response changed")
			}
		})
	}
}

func TestCustomizationAssetsAreEmbeddedAndRevalidated(t *testing.T) {
	s := newTestServer(&fakeKC{}, &fakePenpot{})
	for _, asset := range []string{"customize.css", "customize.js", "logo.png", "logo-dark.png", "icon.png", "favicon.png", "mark.png"} {
		rec := get(s, "/auth-ui/assets/"+asset, "")
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("asset %s unavailable: %d", asset, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-cache" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("asset %s has incorrect caching/type guards", asset)
		}
	}
	for _, favRoute := range []string{"/favicon.ico", "/images/favicon.png"} {
		rec := get(s, favRoute, "")
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("route %s unavailable: %d", favRoute, rec.Code)
		}
	}
}
