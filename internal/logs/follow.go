package logs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// maxLineBytes bounds a single access-log line (a defensive cap; cadish access
// lines are small, but a corrupt/huge line must not OOM the reader).
const maxLineBytes = 1 << 20 // 1 MiB

// lineScanner wraps bufio.Scanner with a raised line cap, so a long (but bounded)
// JSON access line is not silently truncated the way the default 64 KiB cap would.
type lineScanner struct{ sc *bufio.Scanner }

func newLineScanner(r io.Reader) *lineScanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	return &lineScanner{sc: sc}
}

func (l *lineScanner) Scan() bool    { return l.sc.Scan() }
func (l *lineScanner) Bytes() []byte { return l.sc.Bytes() }
func (l *lineScanner) Text() string  { return l.sc.Text() }
func (l *lineScanner) Err() error    { return l.sc.Err() }

// FollowOptions tunes the file-tail follow loop.
type FollowOptions struct {
	// FromStart, when true, emits the whole file before tailing (like `tail -n +1
	// -f`); otherwise only lines appended after start are emitted (like `tail -f`).
	FromStart bool
	// PollInterval is how often the loop checks for appended data. Defaults to 200ms.
	PollInterval time.Duration
}

func (o FollowOptions) withDefaults() FollowOptions {
	if o.PollInterval <= 0 {
		o.PollInterval = 200 * time.Millisecond
	}
	return o
}

// Follow tails the file at path, parsing/filtering/rendering each appended NDJSON
// access line until ctx is cancelled. It uses simple polling (no fsnotify
// dependency — honors the no-new-deps invariant) and handles truncation/rotation:
// if the file shrinks below the read offset, it seeks back to the start. It returns
// nil on ctx cancellation, or the first non-recoverable I/O error.
func Follow(ctx context.Context, path string, out, errOut io.Writer, filter Filter, format Format, opts FollowOptions) error {
	opts = opts.withDefaults()
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if !opts.FromStart {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return fmt.Errorf("seek %s: %w", path, err)
		}
	}

	reader := bufio.NewReader(f)
	var carry []byte // partial trailing line not yet newline-terminated
	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()

	for {
		// Drain everything currently available, emitting each complete line.
		for {
			chunk, rerr := reader.ReadBytes('\n')
			if len(chunk) > 0 {
				carry = append(carry, chunk...)
				if carry[len(carry)-1] == '\n' {
					emitLine(carry, out, errOut, filter, format)
					carry = carry[:0]
				}
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return fmt.Errorf("read %s: %w", path, rerr)
			}
		}

		// Handle truncation/rotation: if the file is now shorter than our offset,
		// seek back to the start and resume.
		if shrunk, serr := fileShrank(f); serr == nil && shrunk {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek %s: %w", path, err)
			}
			reader.Reset(f)
			carry = carry[:0]
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// emitLine parses/filters/renders one buffered line, writing warnings for bad lines
// to errOut and skipping them (a single corrupt line never aborts the tail).
func emitLine(line []byte, out, errOut io.Writer, filter Filter, format Format) {
	rec, ok, err := ParseLine(line)
	if err != nil {
		if errOut != nil {
			fmt.Fprintf(errOut, "cadish logs: %v\n", err)
		}
		return
	}
	if !ok || !filter.Matches(rec) {
		return
	}
	_, _ = io.WriteString(out, Render(rec, format)+"\n")
}

// fileShrank reports whether the file's current size is less than the reader's
// current offset (i.e. it was truncated or rotated under us).
func fileShrank(f *os.File) (bool, error) {
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, err
	}
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	return info.Size() < offset, nil
}
