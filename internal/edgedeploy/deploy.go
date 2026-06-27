// Package edgedeploy is the Cadish Edge management plane's Cloudflare API client.
// It uploads the worker bundle + bindings, ensures the (opt-in) KV namespace, and
// attaches/detaches the worker routes — the three operations behind
// `cadish edge deploy / enable / disable` (design §7).
//
// Auth is a Cloudflare API token (env CF_API_TOKEN), never in the Cadishfile. The
// client speaks the Cloudflare v4 REST API and is fully unit-testable against an
// httptest server (BaseURL is overridable).
//
// Separation of concerns (design §9, kill switch): deploy uploads the script with
// NO routes (testable via the *.workers.dev URL, no production traffic); enable
// attaches the routes (go-live); disable detaches them (instant bypass to the
// cadish server behind).
package edgedeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the Cloudflare v4 API root.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// compatibilityDate pins the Workers runtime compatibility date for uploaded
// scripts. Bump deliberately (a runtime behavior change is a deploy-visible event).
const compatibilityDate = "2024-09-23"

// mainModule is the module filename inside the uploaded bundle (ES module format).
const mainModule = "worker.mjs"

// Config is the resolved deploy target + the worker's runtime bindings. Identity
// (account/zone/worker/routes/kv) comes from the `edge {}` block; OriginURL (and
// the optional Upstreams map) are deploy-time bindings — the IR carries upstream
// NAMES only, the concrete URL lives here (D34).
type Config struct {
	AccountID   string
	Zone        string // zone name (e.g. example.com) or zone id (32-hex)
	WorkerName  string
	Routes      []string
	KVNamespace string            // "" => no L2, no namespace bound
	OriginURL   string            // CADISH_ORIGIN binding (the cadish server behind)
	Upstreams   map[string]string // optional CADISH_UPSTREAMS binding (name -> url)
}

// Client talks to the Cloudflare API. BaseURL and HTTP are overridable for tests.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	token   string
}

// New returns a Client authenticated with the given API token.
func New(token string) *Client {
	return &Client{
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		token:   token,
	}
}

// apiResponse is the Cloudflare v4 envelope.
type apiResponse struct {
	Success  bool              `json:"success"`
	Errors   []apiError        `json:"errors"`
	Messages []json.RawMessage `json:"messages"`
	Result   json.RawMessage   `json:"result"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e apiError) String() string { return fmt.Sprintf("%d: %s", e.Code, e.Message) }

// do issues an authenticated request and decodes the CF envelope, returning the
// raw result on success or an error carrying the CF error messages.
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var env apiResponse
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%s %s: status %d: non-JSON response: %s", method, path, resp.StatusCode, snippet(data))
	}
	if !env.Success {
		return nil, fmt.Errorf("%s %s: cloudflare API error: %s", method, path, joinErrors(env.Errors))
	}
	return env.Result, nil
}

func snippet(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

func joinErrors(errs []apiError) string {
	if len(errs) == 0 {
		return "(no error detail)"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, e.String())
	}
	return strings.Join(parts, "; ")
}

// binding is one worker binding entry in the upload metadata.
type binding struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Text        string `json:"text,omitempty"`         // plain_text
	NamespaceID string `json:"namespace_id,omitempty"` // kv_namespace
}

// scriptMetadata is the multipart "metadata" part for an ES-module upload.
type scriptMetadata struct {
	MainModule        string    `json:"main_module"`
	CompatibilityDate string    `json:"compatibility_date"`
	Bindings          []binding `json:"bindings"`
}

// Deploy uploads the worker script + bindings WITHOUT attaching any route. It
// first ensures the KV namespace (only when the config uses one) so the binding
// can reference its id. After Deploy the worker is reachable at its *.workers.dev
// URL but receives no production traffic until Enable.
func (c *Client) Deploy(ctx context.Context, cfg Config, scriptSource string) error {
	if cfg.AccountID == "" || cfg.WorkerName == "" {
		return fmt.Errorf("deploy: account and worker are required (set them in the edge {} block or via flags)")
	}
	// Fail closed on an account id or worker name that would alter the REST path it
	// is interpolated into: a `/`, whitespace, query/fragment, or percent would
	// retarget the PUT at an UNRELATED resource (a different account or script), so a
	// mis-derived target is rejected BEFORE any upload rather than clobbering it.
	if err := validateDeployTarget(cfg.AccountID, cfg.WorkerName); err != nil {
		return err
	}
	bindings := []binding{}
	if cfg.OriginURL != "" {
		bindings = append(bindings, binding{Type: "plain_text", Name: "CADISH_ORIGIN", Text: cfg.OriginURL})
	}
	if len(cfg.Upstreams) > 0 {
		j, err := json.Marshal(cfg.Upstreams)
		if err != nil {
			return err
		}
		bindings = append(bindings, binding{Type: "plain_text", Name: "CADISH_UPSTREAMS", Text: string(j)})
	}
	if cfg.KVNamespace != "" {
		nsID, err := c.ensureKVNamespace(ctx, cfg.AccountID, cfg.KVNamespace)
		if err != nil {
			return err
		}
		bindings = append(bindings, binding{Type: "kv_namespace", Name: "CADISH_KV", NamespaceID: nsID})
	}

	meta := scriptMetadata{MainModule: mainModule, CompatibilityDate: compatibilityDate, Bindings: bindings}
	body, contentType, err := buildUpload(meta, scriptSource)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/accounts/%s/workers/scripts/%s", cfg.AccountID, cfg.WorkerName)
	_, err = c.do(ctx, http.MethodPut, path, body, contentType)
	return err
}

// validateDeployTarget rejects an account id or worker name that is empty or carries
// a character that would change the Cloudflare REST path it is interpolated into
// (path separator, whitespace, query/fragment, or percent). CF identifiers never
// contain these; rejecting fail-closes a mis-derived or malicious target before the
// script PUT (and the KV calls keyed on the account) can hit the wrong resource.
func validateDeployTarget(accountID, worker string) error {
	if err := safePathSegment("account", accountID); err != nil {
		return err
	}
	return safePathSegment("worker", worker)
}

func safePathSegment(field, s string) error {
	if s == "" {
		return fmt.Errorf("deploy: %s is empty", field)
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || r == '/' || r == '?' || r == '#' || r == '%' {
			return fmt.Errorf("deploy: %s %q contains an invalid character (would retarget the Cloudflare API path)", field, s)
		}
	}
	return nil
}

// buildUpload assembles the multipart body for an ES-module worker upload: a
// "metadata" JSON part + the module file part (named mainModule, content-type
// application/javascript+module).
func buildUpload(meta scriptMetadata, scriptSource string) (io.Reader, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, "", err
	}
	mh := textproto.MIMEHeader{}
	mh.Set("Content-Disposition", `form-data; name="metadata"`)
	mh.Set("Content-Type", "application/json")
	mp, err := w.CreatePart(mh)
	if err != nil {
		return nil, "", err
	}
	if _, err := mp.Write(metaJSON); err != nil {
		return nil, "", err
	}

	sh := textproto.MIMEHeader{}
	sh.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, mainModule, mainModule))
	sh.Set("Content-Type", "application/javascript+module")
	sp, err := w.CreatePart(sh)
	if err != nil {
		return nil, "", err
	}
	if _, err := io.WriteString(sp, scriptSource); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return &buf, w.FormDataContentType(), nil
}

// kvNamespace is one entry in the KV namespaces list / create result.
type kvNamespace struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// kvPerPage is the KV-namespace list page size. ensureKVNamespace pages through
// the full list so it never misses (and re-creates) a namespace that already
// exists past the first page on an account with many namespaces.
const kvPerPage = 100

// ensureKVNamespace returns the id of the namespace titled name, creating it if it
// does not exist (idempotent — safe to call on every deploy). It paginates the
// list so a target beyond the first page is found, not duplicated.
func (c *Client) ensureKVNamespace(ctx context.Context, accountID, name string) (string, error) {
	for page := 1; ; page++ {
		res, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/accounts/%s/storage/kv/namespaces?per_page=%d&page=%d", accountID, kvPerPage, page), nil, "")
		if err != nil {
			return "", err
		}
		var batch []kvNamespace
		if err := json.Unmarshal(res, &batch); err != nil {
			return "", err
		}
		for _, ns := range batch {
			if ns.Title == name {
				return ns.ID, nil
			}
		}
		if len(batch) < kvPerPage {
			break // last page reached
		}
	}
	bodyJSON, _ := json.Marshal(map[string]string{"title": name})
	res, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/accounts/%s/storage/kv/namespaces", accountID), bytes.NewReader(bodyJSON), "application/json")
	if err != nil {
		return "", err
	}
	var created kvNamespace
	if err := json.Unmarshal(res, &created); err != nil {
		return "", err
	}
	if created.ID == "" {
		return "", fmt.Errorf("create KV namespace %q: empty id in response", name)
	}
	return created.ID, nil
}

// zone is a CF zone list entry.
type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// resolveZoneID returns the zone id for cfg.Zone, which may already be a 32-hex
// id (used as-is) or a zone name (resolved via the API).
func (c *Client) resolveZoneID(ctx context.Context, zoneRef string) (string, error) {
	if isZoneID(zoneRef) {
		return zoneRef, nil
	}
	res, err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(zoneRef), nil, "")
	if err != nil {
		return "", err
	}
	var zones []zone
	if err := json.Unmarshal(res, &zones); err != nil {
		return "", err
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("zone %q not found", zoneRef)
	}
	return zones[0].ID, nil
}

// isZoneID reports whether s looks like a Cloudflare zone id (32 lowercase hex).
func isZoneID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// workerRoute is a CF worker-route entry.
type workerRoute struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Script  string `json:"script"`
}

// Enable attaches the configured routes to the worker (go-live). It is idempotent:
// a route whose pattern already points at the worker is left as-is.
func (c *Client) Enable(ctx context.Context, cfg Config) error {
	if cfg.Zone == "" || len(cfg.Routes) == 0 {
		return fmt.Errorf("enable: a zone and at least one route are required")
	}
	zoneID, err := c.resolveZoneID(ctx, cfg.Zone)
	if err != nil {
		return err
	}
	existing, err := c.listRoutes(ctx, zoneID)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, r := range existing {
		if r.Script == cfg.WorkerName {
			have[r.Pattern] = true
		}
	}
	for _, pattern := range cfg.Routes {
		if have[pattern] {
			continue
		}
		bodyJSON, _ := json.Marshal(map[string]string{"pattern": pattern, "script": cfg.WorkerName})
		if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/workers/routes", zoneID), bytes.NewReader(bodyJSON), "application/json"); err != nil {
			return err
		}
	}
	return nil
}

// Disable detaches every route pointing at the worker (instant bypass / kill
// switch). Idempotent: with no such routes it is a no-op.
func (c *Client) Disable(ctx context.Context, cfg Config) error {
	if cfg.Zone == "" {
		return fmt.Errorf("disable: a zone is required")
	}
	zoneID, err := c.resolveZoneID(ctx, cfg.Zone)
	if err != nil {
		return err
	}
	existing, err := c.listRoutes(ctx, zoneID)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if r.Script != cfg.WorkerName {
			continue
		}
		if _, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/workers/routes/%s", zoneID, r.ID), nil, ""); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) listRoutes(ctx context.Context, zoneID string) ([]workerRoute, error) {
	res, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/zones/%s/workers/routes", zoneID), nil, "")
	if err != nil {
		return nil, err
	}
	var routes []workerRoute
	if err := json.Unmarshal(res, &routes); err != nil {
		return nil, err
	}
	return routes, nil
}
