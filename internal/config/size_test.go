package config

import (
	"strings"
	"testing"
)

// TestParseSizeErrorMessage: a bad size value should produce an actionable error
// message, not expose Go internals (strconv.ParseFloat).
func TestParseSizeErrorMessage(t *testing.T) {
	_, err := ParseSize("256mibi")
	if err == nil {
		t.Fatal("expected an error for bad size")
	}
	msg := err.Error()
	if strings.Contains(msg, "strconv") || strings.Contains(msg, "ParseFloat") {
		t.Errorf("error message leaks Go internals: %q", msg)
	}
	if !strings.Contains(msg, "MiB") && !strings.Contains(msg, "GiB") {
		t.Errorf("error message is not actionable (no example sizes): %q", msg)
	}
}
