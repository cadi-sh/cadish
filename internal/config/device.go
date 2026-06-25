package config

import (
	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/classify"
)

// buildClassifier compiles a site's `device_detect { … }` block into the device
// classifier. The compilation logic is the single source of truth in
// internal/classify.FromSite (shared with the pipeline, which projects the same
// ruleset into the Edge IR — D70). This thin wrapper is retained for the config
// layer's tests and any direct caller.
func buildClassifier(site *cadishfile.Site) (*classify.Classifier, error) {
	return classify.FromSite(site)
}
