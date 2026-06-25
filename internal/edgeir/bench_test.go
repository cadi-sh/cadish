package edgeir

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// BenchmarkProject records the cost of `cadish edge build`'s core projection on the
// realistic storefront site. This is an OFFLINE, per-reload operation (not on the
// request hot path) — the benchmark exists only to confirm it is not pathological
// (it is a single linear walk of the compiled rule lists, no per-request work).
func BenchmarkProject(b *testing.B) {
	f, err := cadishfile.Parse("bench.cadish", []byte(storefrontSrc))
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	p, err := pipeline.Compile(f.Sites[0])
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, perr := Project(p); perr != nil {
			b.Fatalf("project: %v", perr)
		}
	}
}

// BenchmarkProjectLargeConfig stresses Project with a synthetically large site
// (many cache_ttl status rows + header rules), to confirm the projection scales
// linearly and does not blow up on a big config.
func BenchmarkProjectLargeConfig(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("big.example.com {\n")
	for i := 0; i < 200; i++ {
		// A path-matched header rule + a status cache_ttl row per iteration.
		sb.WriteString("    @m")
		writeInt(&sb, i)
		sb.WriteString(" path /seg")
		writeInt(&sb, i)
		sb.WriteString("/*\n")
		sb.WriteString("    header @m")
		writeInt(&sb, i)
		sb.WriteString(" +X-Seg ")
		writeInt(&sb, i)
		sb.WriteByte('\n')
	}
	sb.WriteString("    cache_ttl default ttl 60s\n")
	sb.WriteString("}\n")

	f, err := cadishfile.Parse("big.cadish", []byte(sb.String()))
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	p, err := pipeline.Compile(f.Sites[0])
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, perr := Project(p); perr != nil {
			b.Fatalf("project: %v", perr)
		}
	}
}

func writeInt(sb *strings.Builder, n int) {
	if n == 0 {
		sb.WriteByte('0')
		return
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	sb.Write(buf[i:])
}
