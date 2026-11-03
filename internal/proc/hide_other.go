//go:build !windows

package proc

import "os/exec"

// HideWindow keeps a helper program from opening a console window (Windows only).
func HideWindow(c *exec.Cmd) {}
