package config

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// TestSignCloudFrontUpstream is the end-to-end config wiring test: a
// `sign cloudfront …` upstream loaded via config.Load must build an origin that,
// when fetched, reaches the backend with CloudFront canned-policy signature params.
func TestSignCloudFrontUpstream(t *testing.T) {
	// Backend that records the signed request it receives.
	var got *url.URL
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	// A throwaway CloudFront private key PEM.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(t.TempDir(), "cf.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	cadishfile := "example.com {\n" +
		"  upstream cf {\n" +
		"    to   " + srv.URL + "\n" +
		"    sign cloudfront K-CFG key " + pemPath + " ttl 5m\n" +
		"  }\n" +
		"}\n"
	cfgPath := filepath.Join(t.TempDir(), "Cadishfile")
	if err := os.WriteFile(cfgPath, []byte(cadishfile), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Close()

	site := cfg.Sites[0]
	o := site.Origins["cf"]
	if o == nil {
		t.Fatal("no `cf` origin built")
	}

	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "media/clip.mp4"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resp.Body.Close()

	if got == nil {
		t.Fatal("backend never received the request")
	}
	if got.Path != "/media/clip.mp4" {
		t.Errorf("path = %q, want /media/clip.mp4", got.Path)
	}
	q := got.Query()
	if q.Get("Key-Pair-Id") != "K-CFG" {
		t.Errorf("Key-Pair-Id = %q, want K-CFG", q.Get("Key-Pair-Id"))
	}
	for _, p := range []string{"Expires", "Signature"} {
		if q.Get(p) == "" {
			t.Errorf("missing %s in signed request (query=%q)", p, got.RawQuery)
		}
	}
}

// TestSignEmptyKeyPairIDCaughtByCheck verifies the CHECK path (ValidateStructure)
// rejects an empty key-pair id — e.g. an unset `{$CF_KEYPAIR_ID}` — so `cadish check`
// no longer passes a config that `cadish run` would crash on (check<->run parity).
func TestSignEmptyKeyPairIDCaughtByCheck(t *testing.T) {
	cases := map[string]string{
		"empty literal": "example.com {\n upstream cf { to https://d.cloudfront.net\n sign cloudfront \"\" key /x.pem }\n}\n",
		"unset env var": "example.com {\n upstream cf { to https://d.cloudfront.net\n sign cloudfront {$CADISH_TEST_UNSET_KPID} key /x.pem }\n}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateStructure("test.Cadishfile", src, t.TempDir()); err == nil {
				t.Error("ValidateStructure should reject an empty key-pair id (check<->run divergence)")
			}
		})
	}
}

// TestSignCloudFrontErrors verifies bad `sign` directives fail to load with a
// positioned error.
func TestSignCloudFrontErrors(t *testing.T) {
	cases := map[string]string{
		"missing key":      "example.com {\n upstream cf { to https://d.cloudfront.net\n sign cloudfront K }\n}\n",
		"bad provider":     "example.com {\n upstream cf { to https://d.cloudfront.net\n sign akamai K key /x.pem }\n}\n",
		"missing pem file": "example.com {\n upstream cf { to https://d.cloudfront.net\n sign cloudfront K key /nonexistent/x.pem }\n}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "Cadishfile")
			if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Error("expected Load to fail")
			}
		})
	}
}
