package check

import (
	"testing"
)

// TestTransformNoOpWarning: a config using `transform { … }` must produce a
// no-op-directive warning; one without it must not.
func TestTransformNoOpWarning(t *testing.T) {
	t.Run("with_transform", func(t *testing.T) {
		src := `example.com {
    upstream app { to http://127.0.0.1:8080 }
    transform {
        replace /foo /bar
    }
}`
		rep, err := CheckSource("t.cadish", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(rep)["no-op-directive"]; n != 1 {
			t.Errorf("no-op-directive count = %d, want 1", n)
		}
	})

	t.Run("without_transform", func(t *testing.T) {
		src := `example.com {
    upstream app { to http://127.0.0.1:8080 }
    replace /foo /bar
}`
		rep, err := CheckSource("t.cadish", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(rep)["no-op-directive"]; n != 0 {
			t.Errorf("no-op-directive count = %d, want 0", n)
		}
	})
}
