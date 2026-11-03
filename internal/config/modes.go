package config

import "strings"

// The modes. Nothing runs until one of them is started (menu, -mode flag or the API).
var AllModes = []string{"auto", "warp", "psiphon", "tor", "warp+psiphon", "warp+tor"}

var modeLabels = map[string]string{
	"auto":         "Auto (best of WARP / Psiphon / Tor)",
	"warp":         "WARP only",
	"psiphon":      "Psiphon only",
	"tor":          "Tor only",
	"warp+psiphon": "WARP -> Psiphon",
	"warp+tor":     "WARP -> Tor",
}

// ModeLabel is the human name of a mode (unknown values pass through).
func ModeLabel(m string) string {
	if l, ok := modeLabels[m]; ok {
		return l
	}
	return m
}

// SplitMode separates an optional WARP variant: "warp@masque" -> ("warp", "masque").
func SplitMode(s string) (mode, variant string) {
	if i := strings.IndexByte(s, '@'); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return strings.TrimSpace(s), ""
}

// ModeUsesWarp tells whether a mode has a WARP engine whose variant can be chosen.
func ModeUsesWarp(mode string) bool {
	return mode == "auto" || mode == "warp" || mode == "warp+psiphon" || mode == "warp+tor"
}

// NormMode accepts a few spellings ("Cloudflare-Tor", "cf->psiphon") and returns "" if unknown.
func NormMode(s string) string {
	s = strings.NewReplacer("cloudflare", "warp", "cf", "warp", " ", "", "->", "+", ">", "+", "-", "+", "_", "+").
		Replace(strings.ToLower(strings.TrimSpace(s)))
	for _, m := range AllModes {
		if s == m {
			return m
		}
	}
	return ""
}
