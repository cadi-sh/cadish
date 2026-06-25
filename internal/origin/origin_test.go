package origin

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestStatusOf(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"not found", ErrNotFound, http.StatusNotFound},
		{"wrapped not found", fmt.Errorf("x: %w", ErrNotFound), http.StatusNotFound},
		{"status error", &StatusError{Status: 503}, 503},
		{"wrapped status error", fmt.Errorf("x: %w", &StatusError{Status: 502}), 502},
		{"plain error", errors.New("dial refused"), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := StatusOf(c.err); got != c.want {
				t.Fatalf("StatusOf(%v) = %d want %d", c.err, got, c.want)
			}
		})
	}
}

func TestStatusError_Error(t *testing.T) {
	if got := (&StatusError{Status: 500}).Error(); got != "origin: upstream status 500" {
		t.Fatalf("Error() = %q", got)
	}
	if got := (&StatusError{Status: 502, Origin: "httporigin"}).Error(); got != "origin: httporigin upstream status 502" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestRequest_RangeHeaderAndMethod(t *testing.T) {
	var r Request
	if r.RangeHeader() != "" {
		t.Fatalf("RangeHeader on nil header = %q want empty", r.RangeHeader())
	}
	if r.method() != http.MethodGet {
		t.Fatalf("method default = %q want GET", r.method())
	}
	r.Header = http.Header{"Range": {"bytes=0-9"}}
	if r.RangeHeader() != "bytes=0-9" {
		t.Fatalf("RangeHeader = %q", r.RangeHeader())
	}
	r.Method = http.MethodHead
	if r.method() != http.MethodHead {
		t.Fatalf("method = %q want HEAD", r.method())
	}
}
