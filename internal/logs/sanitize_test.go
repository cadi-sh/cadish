package logs

import (
	"strings"
	"testing"
)

// TestLogRenderStripsControlBytes: an attacker-controlled Host/Path carrying CR/LF/ESC must not
// forge log lines or inject ANSI escapes into the text/NCSA `cadish logs` renderers.
func TestLogRenderStripsControlBytes(t *testing.T) {
	rec := Record{
		Method: "GET",
		Host:   "evil\r\nFAKE: line",
		Path:   "/p\x1b[31mRED\r\n200 injected",
		Status: 200,
	}
	for _, out := range []string{renderText(rec), renderNCSA(rec)} {
		if strings.ContainsAny(out, "\r\n\x1b") {
			t.Errorf("rendered log line carries a control byte (forgeable): %q", out)
		}
	}
}
