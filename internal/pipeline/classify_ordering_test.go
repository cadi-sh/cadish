package pipeline

import (
	"net/http"
	"strings"
	"testing"
)

// classifyTokenOf compiles a site whose cache_key ends in {TOKEN} and returns the
// derived value for a request carrying the given headers/cookies. The token is the
// last \x1f-separated component of the cache key.
func classifyTokenOf(t *testing.T, p *Pipeline, h http.Header) string {
	t.Helper()
	key := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/p", Header: h}).CacheKey
	parts := splitKey(key)
	return parts[len(parts)-1]
}

// TestClassifyMatcherFeedsClassifier is acceptance #1: a classify-type matcher
// (@regulated = classify {regulated}==1) feeds another classifier (ageverify). The
// natural layered form must compile AND resolve correctly at runtime.
func TestClassifyMatcherFeedsClassifier(t *testing.T) {
	const src = `example.com {
		@isRegulated  header X-Region gated
		classify {regulated} {
			when @isRegulated -> 1
			default           -> 0
		}
		@regulated  classify {regulated}==1
		@verified   cookie verified_prod
		classify {ageverify} {
			when @regulated @verified -> 0
			when @regulated           -> 1
			default                   -> 0
		}
		cache_key method host path {ageverify}
	}`
	p := compileSrc(t, src)

	// Not regulated -> ageverify default 0.
	if got := classifyTokenOf(t, p, http.Header{}); got != "0" {
		t.Errorf("not regulated => ageverify 0, got %q", got)
	}

	// Regulated, not verified -> 1 (gate).
	reg := http.Header{}
	reg.Set("X-Region", "gated")
	if got := classifyTokenOf(t, p, reg); got != "1" {
		t.Errorf("regulated, unverified => ageverify 1, got %q", got)
	}

	// Regulated AND verified -> 0 (first row).
	both := http.Header{}
	both.Set("X-Region", "gated")
	both.Set("Cookie", "verified_prod=1")
	if got := classifyTokenOf(t, p, both); got != "0" {
		t.Errorf("regulated+verified => ageverify 0, got %q", got)
	}
}

// TestClassifyCycleDetected is acceptance #2: a 2-cycle (classify a references
// @b(=classify b==1); classify b references @a(=classify a==1)) must be a clear
// CompileError naming BOTH tokens, not a hang/stack overflow.
func TestClassifyCycleDetected(t *testing.T) {
	const src = `example.com {
		@a  classify {a}==1
		@b  classify {b}==1
		classify {a} {
			when @b -> 1
			default -> 0
		}
		classify {b} {
			when @a -> 1
			default -> 0
		}
		cache_key path {a} {b}
	}`
	ce := compileErr(t, src)
	msg := strings.ToLower(ce.Error())
	if !strings.Contains(msg, "cycle") {
		t.Fatalf("cycle error must say %q, got %q", "cycle", ce.Error())
	}
	// Must name BOTH participants so the operator can find the loop.
	if !strings.Contains(msg, "{a}") || !strings.Contains(msg, "{b}") {
		t.Errorf("cycle error must name both {a} and {b}, got %q", ce.Error())
	}
}

// TestClassifyUndefinedMatcherStillErrors is acceptance #3: a classify referencing
// a genuinely-undefined matcher still errors `undefined matcher @x` (the fixpoint
// must not mask a real undefined reference behind "made no progress").
func TestClassifyUndefinedMatcherStillErrors(t *testing.T) {
	const src = `example.com {
		classify {age} {
			when @nope -> 1
			default    -> 0
		}
		cache_key path {age}
	}`
	ce := compileErr(t, src)
	if !strings.Contains(ce.Error(), "undefined matcher @nope") {
		t.Errorf("want `undefined matcher @nope`, got %q", ce.Error())
	}
}

// TestClassifyDeepChain is acceptance #4: a 3+ level chain
// plain -> classifyA -> @a -> classifyB -> @b -> classifyC compiles and resolves.
func TestClassifyDeepChain(t *testing.T) {
	const src = `example.com {
		@plain  header X-In yes
		classify {ca} {
			when @plain -> 1
			default     -> 0
		}
		@a  classify {ca}==1
		classify {cb} {
			when @a -> 1
			default -> 0
		}
		@b  classify {cb}==1
		classify {cc} {
			when @b -> hit
			default -> miss
		}
		cache_key path {cc}
	}`
	p := compileSrc(t, src)

	if got := classifyTokenOf(t, p, http.Header{}); got != "miss" {
		t.Errorf("no X-In => cc miss, got %q", got)
	}
	in := http.Header{}
	in.Set("X-In", "yes")
	if got := classifyTokenOf(t, p, in); got != "hit" {
		t.Errorf("X-In => cc hit (propagated through 3 levels), got %q", got)
	}
}

// TestClassifyUnknownTokenStillErrors guards the other genuine-undefined case: a
// classify-matcher referencing a token that has no classify {} definition must
// still error clearly, not be deferred forever.
func TestClassifyUnknownTokenStillErrors(t *testing.T) {
	const src = `example.com {
		@x  classify {ghost}==1
		pass @x
		cache_key path
	}`
	ce := compileErr(t, src)
	if !strings.Contains(ce.Error(), "{ghost}") {
		t.Errorf("want unknown-token error naming {ghost}, got %q", ce.Error())
	}
}
