package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/cadi-sh/cadish/internal/tlsacme"
	corelisters "k8s.io/client-go/listers/core/v1"
)

// TLSInjector is the OPTIONAL typed side-channel for BYO TLS Secret certs referenced by a
// Gateway HTTPS listener's certificateRefs. *server.Server satisfies it via SetDynamicCerts
// — the SAME hot-swap dynamic-cert mechanism the Ingress controller uses, so a Gateway BYO
// cert is registered exactly like an Ingress spec.tls Secret cert (one TLS manager, keyed by
// SNI host). A bare-Applier test fake that does not implement it simply disables BYO-Secret
// TLS for Gateway listeners (the listener is then acknowledged-but-not-programmed).
type TLSInjector interface {
	SetDynamicCerts([]tlsacme.DynamicCert) error
}

// certPEM is a validated BYO keypair (raw Secret bytes) plus the parsed leaf, threaded from
// the per-reconcile validation gate to injection so the keypair is parsed once.
type certPEM struct {
	cert, key []byte
	leaf      *x509.Certificate
}

// tlsSecretGate validates each referenced kubernetes.io/tls Secret once per reconcile, the
// same shape as the Ingress controller's gate: usable() parses tls.crt/tls.key and reports
// whether it is a usable keypair; covers() answers per-host SAN coverage (F10) from the
// cached leaf. The validated PEM is cached so injection re-uses it without a re-read.
type tlsSecretGate struct {
	sec  corelisters.SecretLister
	good map[string]certPEM
	bad  map[string]string
}

func newTLSSecretGate(sec corelisters.SecretLister) *tlsSecretGate {
	return &tlsSecretGate{sec: sec, good: map[string]certPEM{}, bad: map[string]string{}}
}

// usable reports whether ns/name is an existing Secret carrying a PARSEABLE TLS keypair
// (memoized). A missing, non-TLS, or corrupt Secret reports false.
func (g *tlsSecretGate) usable(ns, name string) bool {
	if g == nil || g.sec == nil {
		return false
	}
	k := ns + "/" + name
	if _, ok := g.good[k]; ok {
		return true
	}
	if _, ok := g.bad[k]; ok {
		return false
	}
	s, err := g.sec.Secrets(ns).Get(name)
	if err != nil || s == nil {
		return false
	}
	crt, key := s.Data["tls.crt"], s.Data["tls.key"]
	if len(crt) == 0 || len(key) == 0 {
		return false
	}
	pair, perr := tls.X509KeyPair(crt, key)
	if perr != nil {
		g.bad[k] = perr.Error()
		return false
	}
	var leaf *x509.Certificate
	if len(pair.Certificate) > 0 {
		if lf, lerr := x509.ParseCertificate(pair.Certificate[0]); lerr == nil {
			leaf = lf
		}
	}
	g.good[k] = certPEM{cert: crt, key: key, leaf: leaf}
	return true
}

// covers reports whether the Secret ns/name's certificate SANs cover host (F10). Consulted
// only for a Secret already classified usable; a cache miss reports false (treated as not
// covered → the listener is not programmed).
func (g *tlsSecretGate) covers(ns, name, host string) bool {
	if g == nil {
		return false
	}
	pem, ok := g.good[ns+"/"+name]
	if !ok || pem.leaf == nil {
		return false
	}
	return pem.leaf.VerifyHostname(strings.ToLower(strings.TrimSpace(host))) == nil
}
