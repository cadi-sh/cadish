package admin

import (
	"embed"
	"io/fs"
	"net/http"
)

// uiFS embeds the single-page dashboard assets. No external runtime dependency and
// no JS build step — plain HTML/CSS/JS shipped in the binary.
//
//go:embed ui
var uiFS embed.FS

// uiRoot is the embedded ui/ subtree as a root filesystem.
var uiRoot, _ = fs.Sub(uiFS, "ui")

// handleIndex serves the embedded dashboard. Any path that is not an API route
// falls here; unknown paths serve index.html (SPA-style) so a deep link works.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path
	if name == "/" || name == "" {
		name = "/index.html"
	}
	f, err := uiRoot.Open(name[1:])
	if err != nil {
		// Unknown asset: fall back to the SPA shell.
		s.serveAsset(w, "index.html")
		return
	}
	_ = f.Close()
	s.serveAsset(w, name[1:])
}

func (s *Server) serveAsset(w http.ResponseWriter, name string) {
	b, err := fs.ReadFile(uiRoot, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	switch {
	case hasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case hasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case hasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}
	_, _ = w.Write(b)
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}
