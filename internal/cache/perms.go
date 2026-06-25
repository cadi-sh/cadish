package cache

import (
	"errors"
	"fmt"
	"os"
)

// nonrootUID is the uid/gid the published distroless-nonroot image runs as
// (gcr.io/distroless/static-debian12:nonroot). A fresh persistent/named volume is
// created root-owned, so this uid cannot create the cache directory inside it —
// the classic first-run crash (backlog #12 / D23).
const nonrootUID = 65532

// hintPermission wraps a cache-directory creation error. When the failure is a
// permission error (the root-owned-volume case), it prepends an actionable message
// naming the uid and the two standard fixes (a chown one-liner for docker/compose,
// fsGroup/initContainer for Kubernetes) — instead of letting cadish crash-loop on a
// bare "mkdir …: permission denied". The original error is still wrapped, so
// errors.Is(err, os.ErrPermission) keeps working for callers.
func hintPermission(dir string, err error) error {
	if err == nil || !errors.Is(err, os.ErrPermission) {
		return err
	}
	return fmt.Errorf("cannot create cache directory %s: %w\n"+
		"cadish runs as uid %d (distroless-nonroot) and a fresh volume is root-owned. Make the volume writable by that uid:\n"+
		"  docker/compose: docker run --rm -v <volume>:/data busybox chown -R %d:%d /data\n"+
		"  kubernetes:     set the pod securityContext fsGroup: %d (or enable the chown initContainer in the Helm chart)",
		dir, err, nonrootUID, nonrootUID, nonrootUID, nonrootUID)
}
