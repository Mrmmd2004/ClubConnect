// Package bundle carries the helper programs inside the clubconnect executable. Aether (the
// MASQUE / gool / mim / noize engine) is written in Rust, so it cannot be compiled into this Go
// program; instead the release build embeds its binary here and clubconnect unpacks it on
// start. The result is one file to ship and one program to run.
package bundle

import (
	"crypto/sha256"
	"embed"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

//go:embed all:bin
var embedded embed.FS

const root = "bin"

// Extract unpacks the embedded programs into dst and returns the names it wrote (files that are
// already there and identical are left alone, so a normal start touches nothing).
func Extract(dst string) ([]string, error) { return ExtractFS(embedded, root, dst) }

// Names lists the embedded programs.
func Names() []string {
	var out []string
	entries, _ := fs.ReadDir(embedded, root)
	for _, e := range entries {
		if wanted(e) {
			out = append(out, e.Name())
		}
	}
	return out
}

func wanted(e fs.DirEntry) bool {
	n := e.Name()
	return !e.IsDir() && !strings.HasPrefix(n, ".") && !strings.EqualFold(n, "README.txt")
}

// ExtractFS is Extract for any file system (the tests use an in-memory one).
func ExtractFS(fsys fs.FS, dir, dst string) ([]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var written []string
	var firstErr error
	for _, e := range entries {
		if !wanted(e) {
			continue
		}
		wrote, err := extractOne(fsys, path.Join(dir, e.Name()), filepath.Join(dst, e.Name()))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if wrote {
			written = append(written, e.Name())
		}
	}
	return written, firstErr
}

func extractOne(fsys fs.FS, src, dst string) (bool, error) {
	data, err := fs.ReadFile(fsys, src)
	if err != nil {
		return false, err
	}
	if same(dst, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return false, err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return false, err
	}
	os.Chmod(tmp, 0o755)
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp) // for instance a running copy on Windows: keep using the one that is there
		return false, err
	}
	return true, nil
}

func same(dst string, data []byte) bool {
	st, err := os.Stat(dst)
	if err != nil || st.Size() != int64(len(data)) {
		return false
	}
	f, err := os.Open(dst)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return string(h.Sum(nil)) == string(sum(data))
}

func sum(data []byte) []byte { s := sha256.Sum256(data); return s[:] }
