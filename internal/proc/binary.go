package proc

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ExeSuffix is ".exe" on Windows and empty elsewhere.
func ExeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// FindBinary looks for a helper: explicit path, next to our executable, ./bin, then PATH.
// It returns "" when nothing is found.
func FindBinary(explicit string, names ...string) string {
	return FindBinaryIn(explicit, nil, names...)
}

// FindBinaryIn is FindBinary with extra directories searched before PATH.
func FindBinaryIn(explicit string, extra []string, names ...string) string {
	if explicit != "" {
		if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
			return explicit
		}
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		dirs = append(dirs, d, filepath.Join(d, "bin"))
	}
	dirs = append(dirs, ".", "bin")
	dirs = append(dirs, extra...)
	for _, n := range names {
		n += ExeSuffix()
		for _, d := range dirs {
			p := filepath.Join(d, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				abs, _ := filepath.Abs(p)
				return abs
			}
		}
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}
