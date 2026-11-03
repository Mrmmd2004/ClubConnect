// Package backends holds the engines Club Connect can send traffic through: the built-in
// WireGuard WARP, Aether (MASQUE, gool, mim, noize), Psiphon, Tor, and the chains that run
// Psiphon or Tor through WARP. Every one of them is a core.Backend.
package backends

import (
	"path/filepath"
	"strings"

	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/proc"
)

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// unpackedDir is where the helper programs embedded in the executable are unpacked.
func unpackedDir(cfg *config.Config) []string {
	return []string{filepath.Join(cfg.DataDir, "bin")}
}

// AetherBin finds the Aether program ("" when there is none): the path from Settings, then next
// to clubconnect, then the copy unpacked from the executable, then PATH.
func AetherBin(cfg *config.Config) string {
	return proc.FindBinaryIn(cfg.Aether.Bin, unpackedDir(cfg), "aether")
}

// PsiphonBin finds the Psiphon tunnel-core program ("" when there is none).
func PsiphonBin(cfg *config.Config) string {
	return proc.FindBinaryIn(cfg.Psiphon.Bin, unpackedDir(cfg), "psiphon-tunnel-core", "psiphon")
}

// VariantAvailable tells whether a WARP variant can run here (the non-built-in ones need Aether).
func VariantAvailable(cfg *config.Config, v string) bool {
	return !config.VariantNeedsAether(v) || AetherBin(cfg) != ""
}

// NewWarpBackend builds the WARP engine for a variant.
func NewWarpBackend(cfg *config.Config, variant string) core.Backend {
	switch variant {
	case "wg":
		return NewWarp(cfg)
	case "auto", "":
		return NewAutoWarp(cfg)
	}
	return NewAetherWarp(cfg, variant)
}
