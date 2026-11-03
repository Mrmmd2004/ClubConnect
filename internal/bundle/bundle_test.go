package bundle

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
	"time"
)

func TestExtractWritesNewFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"bin/aether":              {Data: []byte("rust program")},
		"bin/psiphon-tunnel-core": {Data: []byte("go program")},
		"bin/README.txt":          {Data: []byte("docs")},
		"bin/.keep":               {Data: []byte("x")},
	}
	dst := filepath.Join(t.TempDir(), "bin")
	got, err := ExtractFS(fsys, "bin", dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("extracted %v, want the two programs only", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "aether")); string(b) != "rust program" {
		t.Errorf("content %q", b)
	}
	for _, skipped := range []string{"README.txt", ".keep"} {
		if _, err := os.Stat(filepath.Join(dst, skipped)); err == nil {
			t.Errorf("%s was extracted", skipped)
		}
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dst, "aether"))
		if st.Mode().Perm()&0o100 == 0 {
			t.Error("the program is not executable")
		}
	}
}

func TestExtractLeavesIdenticalFilesAlone(t *testing.T) {
	fsys := fstest.MapFS{"bin/aether": {Data: []byte("v1")}}
	dst := t.TempDir()
	ExtractFS(fsys, "bin", dst)
	p := filepath.Join(dst, "aether")
	old := time.Now().Add(-time.Hour)
	os.Chtimes(p, old, old)
	got, err := ExtractFS(fsys, "bin", dst)
	if err != nil || len(got) != 0 {
		t.Errorf("second extract wrote %v (%v)", got, err)
	}
	if st, _ := os.Stat(p); !st.ModTime().Equal(old.Truncate(time.Second)) && st.ModTime().After(old.Add(time.Minute)) {
		t.Error("an identical file was rewritten")
	}
}

func TestExtractReplacesChangedFilesAndLeavesNoTempFile(t *testing.T) {
	dst := t.TempDir()
	ExtractFS(fstest.MapFS{"bin/aether": {Data: []byte("v1")}}, "bin", dst)
	got, err := ExtractFS(fstest.MapFS{"bin/aether": {Data: []byte("v2-longer")}}, "bin", dst)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v %v", got, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "aether")); string(b) != "v2-longer" {
		t.Errorf("content %q", b)
	}
	// same size, different content must still be replaced
	got, _ = ExtractFS(fstest.MapFS{"bin/aether": {Data: []byte("v2-LONGER")}}, "bin", dst)
	if len(got) != 1 {
		t.Error("same-size change not detected")
	}
	if _, err := os.Stat(filepath.Join(dst, "aether.new")); err == nil {
		t.Error("temporary file left behind")
	}
}

func TestMissingOrEmptyBundleIsFine(t *testing.T) {
	got, err := ExtractFS(fstest.MapFS{}, "bin", t.TempDir())
	if err != nil || len(got) != 0 {
		t.Errorf("empty file system: %v %v", got, err)
	}
	got, err = ExtractFS(fstest.MapFS{"bin/README.txt": {Data: []byte("x")}}, "bin", t.TempDir())
	if err != nil || len(got) != 0 {
		t.Errorf("only a README: %v %v", got, err)
	}
}

// The repository ships bin/ with only a README, so a plain `go build` unpacks nothing.
func TestShippedBundleIsEmptyUntilTheReleaseBuildFillsIt(t *testing.T) {
	if len(Names()) != 0 {
		t.Skipf("this build embeds: %v", Names())
	}
	got, err := Extract(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Errorf("Extract: %v %v", got, err)
	}
}
