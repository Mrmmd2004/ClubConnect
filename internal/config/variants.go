package config

import "strings"

// WARP is not one thing. Aether can reach Cloudflare in several ways, and a network that blocks
// one of them usually lets another through. Club Connect offers all of them as "variants" of the
// WARP engine; every mode that contains WARP (warp, warp+psiphon, warp+tor, and the WARP part of
// auto) can use any variant, chosen per mode.
var WarpVariants = []string{"auto", "wg", "masque", "masque-h2", "gool", "gool-classic", "mim", "wg-noize"}

var VariantLabels = map[string]string{
	"auto":         "Auto            tries them in waves, keeps the first that really carries traffic",
	"wg":           "WireGuard       built in, nothing else needed (UDP 2408 and fallbacks)",
	"masque":       "MASQUE HTTP/3   Cloudflare's main protocol, looks like HTTPS (UDP 443)  [aether]",
	"masque-h2":    "MASQUE HTTP/2   same tunnel over TCP 443, survives QUIC blocking  [aether]",
	"gool":         "Gool            WireGuard inside MASQUE, a different exit address  [aether]",
	"gool-classic": "WARP-in-WARP     WireGuard inside WireGuard  [aether]",
	"mim":          "MASQUE-in-MASQUE two MASQUE hops, a different exit address  [aether]",
	"wg-noize":     "WireGuard+noize WireGuard with a disguised handshake, for strict networks  [aether]",
}

var VariantShort = map[string]string{
	"auto":         "Auto",
	"wg":           "WireGuard",
	"masque":       "MASQUE HTTP/3",
	"masque-h2":    "MASQUE HTTP/2",
	"gool":         "Gool (WireGuard in MASQUE)",
	"gool-classic": "WARP-in-WARP",
	"mim":          "MASQUE-in-MASQUE",
	"wg-noize":     "WireGuard + noize",
}

// VariantName is the short human name of a variant ("auto: wg" style values pass through).
func VariantName(v string) string {
	if n, ok := VariantShort[v]; ok {
		return n
	}
	return v
}

// NormVariant accepts the canonical names and a few spellings; "" means unknown or empty.
func NormVariant(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("_", "-", " ", "-", "+", "-").Replace(s)
	switch s {
	case "wireguard", "warp", "classic", "wireguard-only":
		return "wg"
	case "h3", "quic", "masque-h3", "masque-quic", "http3":
		return "masque"
	case "h2", "http2", "masque-http2":
		return "masque-h2"
	case "warp-in-warp", "wiw-classic":
		return "gool-classic"
	case "masque-in-masque":
		return "mim"
	case "noize", "wg-obfs", "wireguard-noize":
		return "wg-noize"
	}
	for _, v := range WarpVariants {
		if s == v {
			return v
		}
	}
	return ""
}

// VariantNeedsAether: every variant except the built-in WireGuard (and auto, which falls back
// to it) is carried by the Aether program.
func VariantNeedsAether(v string) bool { return v != "wg" && v != "auto" && v != "" }

// VariantFor returns the WARP variant a mode uses (the setting made in the menu or config).
func (c *Config) VariantFor(mode string) string {
	var v string
	switch mode {
	case "warp+psiphon":
		v = c.Warp.PsiphonVariant
	case "warp+tor":
		v = c.Warp.TorVariant
	default:
		v = c.Warp.Variant
	}
	if v = NormVariant(v); v == "" {
		v = "auto"
	}
	return v
}

// SetVariant stores the WARP variant of one mode.
func (c *Config) SetVariant(mode, v string) {
	switch mode {
	case "warp+psiphon":
		c.Warp.PsiphonVariant = v
	case "warp+tor":
		c.Warp.TorVariant = v
	default:
		c.Warp.Variant = v
	}
}
