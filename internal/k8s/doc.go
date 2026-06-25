// Package k8s resolves cadish `k8s://service.namespace:port` upstream targets to
// the live set of ready pod IP:port endpoints via the Kubernetes API
// (EndpointSlices), using a client-go SharedInformer with a warm local cache and
// event-driven re-resolution. It is built lazily — only when a loaded Cadishfile
// actually contains a k8s:// target — so a non-Kubernetes cadish pays nothing.
package k8s
