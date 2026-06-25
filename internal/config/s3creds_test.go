package config

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// upstreamDir returns the first `upstream` directive in a parsed site body.
func upstreamDir(t *testing.T, site *cadishfile.Site) *cadishfile.Directive {
	t.Helper()
	for _, n := range site.Body {
		if d, ok := n.(*cadishfile.Directive); ok && d.Name == "upstream" {
			return d
		}
	}
	t.Fatal("no upstream directive")
	return nil
}

func TestParseS3Creds(t *testing.T) {
	t.Run("explicit creds + region", func(t *testing.T) {
		site := parseSite(t, "s.local {\n  upstream s3 { to http://m:9000; bucket b; access_key AK; secret_key SK; region eu-west }\n}\n")
		c := parseS3Creds(upstreamDir(t, site))
		if c.access != "AK" || c.secret != "SK" || c.region != "eu-west" {
			t.Fatalf("creds = %+v, want AK/SK/eu-west", c)
		}
		if c.anonymous {
			t.Error("anonymous should be false when creds are given")
		}
	})

	t.Run("anonymous flag", func(t *testing.T) {
		site := parseSite(t, "s.local {\n  upstream s3 { to http://m:9000; bucket b; anonymous }\n}\n")
		c := parseS3Creds(upstreamDir(t, site))
		if !c.anonymous {
			t.Error("anonymous flag not parsed")
		}
		if c.access != "" || c.secret != "" {
			t.Errorf("expected no creds, got %+v", c)
		}
	})

	t.Run("no creds => empty (implies anonymous downstream)", func(t *testing.T) {
		site := parseSite(t, "s.local {\n  upstream s3 { to http://m:9000; bucket b }\n}\n")
		c := parseS3Creds(upstreamDir(t, site))
		if c.access != "" || c.secret != "" || c.anonymous {
			t.Fatalf("creds = %+v, want all empty", c)
		}
	})
}
