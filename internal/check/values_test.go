package check

import (
	"strings"
	"testing"
)

// TestValueValidation: `cadish check` must catch invalid VALUES (bad byte-size units,
// malformed bind addresses) at lint time — the gap where they used to pass clean and
// only fail at startup/bind.
func TestValueValidation(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
		code    string // expected diagnostic code when wantErr
	}{
		{
			name:    "bad ram size unit",
			src:     "site.local {\n  cache { ram 256MiBi }\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: true,
			code:    "invalid-size",
		},
		{
			name:    "bad disk size",
			src:     "site.local {\n  cache { disk /tmp/c 10XB }\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: true,
			code:    "invalid-size",
		},
		{
			name:    "malformed listen IP",
			src:     "{\n  admin { listen 0.0.0.0.1:9090\n    auth_token sekret }\n}\nsite.local {\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: true,
			code:    "invalid-listen",
		},
		{
			name:    "valid sizes and listen",
			src:     "{\n  admin { listen 127.0.0.1:9090\n    auth_token sekret }\n}\nsite.local {\n  cache { ram 256MiB }\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: false,
		},
		{
			name:    "valid hostname listen (not an IP attempt)",
			src:     "{\n  admin { listen localhost:9090\n    auth_token sekret }\n}\nsite.local {\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := CheckSource("Cadishfile", []byte(tc.src))
			if err != nil {
				t.Fatalf("CheckSource parse error: %v", err)
			}
			errs, _ := rep.Counts()
			if tc.wantErr && errs == 0 {
				t.Fatalf("expected a value-validation error, got none (exit=%d)", rep.ExitCode(false))
			}
			if !tc.wantErr && errs != 0 {
				t.Fatalf("expected no errors, got %d: %+v", errs, rep.Diagnostics)
			}
			if tc.wantErr {
				if rep.ExitCode(false) != 1 {
					t.Errorf("ExitCode = 0, want 1 for an error")
				}
				found := false
				for _, d := range rep.Diagnostics {
					if d.Code == tc.code {
						found = true
						if d.Position == "" {
							t.Errorf("diagnostic %q has no position", tc.code)
						}
					}
				}
				if !found {
					t.Errorf("no diagnostic with code %q; got %+v", tc.code, rep.Diagnostics)
				}
			}
		})
	}
}

// TestDurationValidation: `cadish check` must catch invalid DURATION values
// (cache_ttl ttl/grace/hit_for_miss, health interval, timeout, sign ttl) at lint
// time, mirroring the size/addr validation. Valid durations — including the
// cadish "d"/"w" extensions — pass.
func TestDurationValidation(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
		code    string
	}{
		{
			name:    "bogus ttl",
			src:     "site.local {\n  cache_ttl default ttl 5xz\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: true,
			code:    "invalid-duration",
		},
		{
			name:    "bogus grace",
			src:     "site.local {\n  cache_ttl default ttl 1h grace 1banana\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: true,
			code:    "invalid-duration",
		},
		{
			name:    "bogus hit_for_miss",
			src:     "site.local {\n  cache_ttl @x hit_for_miss nope\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: true,
			code:    "invalid-duration",
		},
		{
			name:    "bogus max_stale",
			src:     "site.local {\n  cache_ttl default ttl 1h grace 5m max_stale 1banana\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: true,
			code:    "invalid-duration",
		},
		{
			name:    "valid max_stale (third tier)",
			src:     "site.local {\n  cache_ttl default ttl 60s grace 5m max_stale 24h\n  upstream b { to http://127.0.0.1:8080 }\n}\n",
			wantErr: false,
		},
		{
			name:    "bogus health interval",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 200 interval 5zz window 3 threshold 2\n  }\n}\n",
			wantErr: true,
			code:    "invalid-duration",
		},
		{
			name:    "bogus timeout duration",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    timeout connect 5banana\n  }\n}\n",
			wantErr: true,
			code:    "invalid-duration",
		},
		{
			name:    "valid durations incl d and w units",
			src:     "site.local {\n  @images path /img/*\n  cache_ttl @images ttl 24h grace 365d\n  cache_ttl default ttl 2s grace 1w\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 200 interval 1s window 3 threshold 2\n    timeout connect 5s first_byte 600s\n  }\n}\n",
			wantErr: false,
		},
	}
	runValueCases(t, cases)
}

// TestUpstreamURLValidation: `cadish check` must catch a bogus `to …` backend
// target (bad URL, empty, unsupported scheme, missing host) at lint time.
func TestUpstreamURLValidation(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
		code    string
	}{
		{
			name:    "garbage scheme/host",
			src:     "site.local {\n  upstream b { to ht!tp://[::bad }\n}\n",
			wantErr: true,
			code:    "invalid-upstream-url",
		},
		{
			name:    "unsupported scheme",
			src:     "site.local {\n  upstream b { to ftp://example.com }\n}\n",
			wantErr: true,
			code:    "invalid-upstream-url",
		},
		{
			name:    "valid http and dns targets",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    to dns://backend.svc:8080\n  }\n}\n",
			wantErr: false,
		},
		{
			name:    "valid bare host:port (implies http)",
			src:     "site.local {\n  upstream b { to 127.0.0.1:8080 }\n}\n",
			wantErr: false,
		},
		{
			name:    "valid cluster to target",
			src:     "site.local {\n  cluster c {\n    to http://10.0.0.1:80\n    shard_by url\n  }\n}\n",
			wantErr: false,
		},
		{
			name:    "bogus cluster to target",
			src:     "site.local {\n  cluster c {\n    to ht!tp://[::bad\n    shard_by url\n  }\n}\n",
			wantErr: true,
			code:    "invalid-upstream-url",
		},
	}
	runValueCases(t, cases)
}

// TestHealthExpectValidation: a malformed `health … expect` token must be a
// `cadish check` error (check≡run), since `cadish run` rejects it at load. Valid
// list/class/single forms stay clean.
func TestHealthExpectValidation(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
		code    string
	}{
		{
			name:    "bad class 6xx",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 6xx interval 5s\n  }\n}\n",
			wantErr: true,
			code:    "invalid-health-expect",
		},
		{
			name:    "bad code 999",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 999 interval 5s\n  }\n}\n",
			wantErr: true,
			code:    "invalid-health-expect",
		},
		{
			name:    "non-numeric foo",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect foo interval 5s\n  }\n}\n",
			wantErr: true,
			code:    "invalid-health-expect",
		},
		{
			name:    "valid single 200",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 200 interval 5s\n  }\n}\n",
			wantErr: false,
		},
		{
			name:    "valid code list 200 301",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 200 301 interval 5s\n  }\n}\n",
			wantErr: false,
		},
		{
			name:    "valid class list 2xx 3xx",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 2xx 3xx interval 5s\n  }\n}\n",
			wantErr: false,
		},
	}
	runValueCases(t, cases)
}

// TestHealthWindowValidation (Fix 4, check≡run): an absurd `health … window N` must be a
// `cadish check` error with the SAME bound the runtime enforces — otherwise check passes
// a config that would drive a ~2GB-per-backend allocation and fail at `cadish run`. A
// sane window stays clean.
func TestHealthWindowValidation(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
		code    string
	}{
		{
			name:    "absurd window",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 200 interval 5s window 2000000000\n  }\n}\n",
			wantErr: true,
			code:    "invalid-health-window",
		},
		{
			name:    "sane window",
			src:     "site.local {\n  upstream b {\n    to http://127.0.0.1:8080\n    health GET / expect 200 interval 5s window 5\n  }\n}\n",
			wantErr: false,
		},
	}
	runValueCases(t, cases)
}

// runValueCases is the shared assertion harness: every case parses, then either
// produces >=1 error with the expected code (and a non-empty position + exit 1),
// or produces zero errors.
func runValueCases(t *testing.T, cases []struct {
	name    string
	src     string
	wantErr bool
	code    string
}) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := CheckSource("Cadishfile", []byte(tc.src))
			if err != nil {
				t.Fatalf("CheckSource parse error: %v", err)
			}
			errs, _ := rep.Counts()
			if tc.wantErr && errs == 0 {
				t.Fatalf("expected a value-validation error, got none: %+v", rep.Diagnostics)
			}
			if !tc.wantErr && errs != 0 {
				t.Fatalf("expected no errors, got %d: %+v", errs, rep.Diagnostics)
			}
			if tc.wantErr {
				if rep.ExitCode(false) != 1 {
					t.Errorf("ExitCode = 0, want 1 for an error")
				}
				found := false
				for _, d := range rep.Diagnostics {
					if d.Code == tc.code {
						found = true
						if d.Position == "" {
							t.Errorf("diagnostic %q has no position", tc.code)
						}
					}
				}
				if !found {
					t.Errorf("no diagnostic with code %q; got %+v", tc.code, rep.Diagnostics)
				}
			}
		})
	}
}

// TestValueValidation_PositionPointsAtValue: the diagnostic position should point at the
// offending value's line, not the block.
func TestValueValidation_PositionPointsAtValue(t *testing.T) {
	rep, err := CheckSource("Cadishfile", []byte("site.local {\n  cache { ram 256MiBi }\n  upstream b { to http://127.0.0.1:8080 }\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Diagnostics) == 0 {
		t.Fatal("expected a diagnostic")
	}
	if !strings.Contains(rep.Diagnostics[0].Position, ":2:") {
		t.Errorf("position = %q, want it on line 2 (the ram directive)", rep.Diagnostics[0].Position)
	}
}
