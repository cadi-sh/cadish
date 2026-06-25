package edgeir

import "testing"

// TestServerOnlyDirectivesAreDelegated: rewrite / encode are server-only in edge v1.
// The projector must record each in Delegate[] (with a reason) so the coverage report
// and `--strict` surface them — not silently drop them, which would break the
// projector's "never silently dropped" contract (audit 2026-06-24). NOTE: `respond
// on_error` became EDGE-NATIVE in D76 (Response.OnError) and `replace` in D75
// (Response.Transforms), so they are no longer in this delegated set — see
// TestProjectOnErrorIsEdgeNative / TestProjectReplaceIsEdgeNative.
func TestServerOnlyDirectivesAreDelegated(t *testing.T) {
	src := `example.com {
    @html content_type text/html
    rewrite path /old/(.*) /new/$1
    encode
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	for _, want := range []string{"rewrite", "encode"} {
		found := false
		for _, d := range ir.Delegate {
			if d.Directive == want {
				found = true
				if d.Reason == "" {
					t.Errorf("delegate %q has empty reason", want)
				}
			}
		}
		if !found {
			t.Errorf("%q not delegated; delegate = %+v", want, ir.Delegate)
		}
	}
	if rep.Delegated == 0 {
		t.Error("coverage report should record delegated directives")
	}
}
