package inbound

import (
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// Auth is the optional username/password that protects both the SOCKS5 and the HTTP side.
// An empty Username means no authentication.
type Auth struct {
	Username string
	Password string
}

// Enabled reports whether credentials are required.
func (a Auth) Enabled() bool { return a.Username != "" }

// Check compares the credentials in constant time.
func (a Auth) Check(user, pass string) bool {
	if !a.Enabled() {
		return true
	}
	u := subtle.ConstantTimeCompare([]byte(user), []byte(a.Username))
	p := subtle.ConstantTimeCompare([]byte(pass), []byte(a.Password))
	return u&p == 1
}

// CheckProxyAuthorization checks an HTTP "Proxy-Authorization: Basic ..." header value.
func (a Auth) CheckProxyAuthorization(h string) bool {
	if !a.Enabled() {
		return true
	}
	enc := strings.TrimPrefix(h, "Basic ")
	if enc == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	u, p, _ := strings.Cut(string(raw), ":")
	return a.Check(u, p)
}

// proxyAuthRequired is the answer to an HTTP proxy request without valid credentials.
var proxyAuthRequired = []byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Club Connect\"\r\nContent-Length: 0\r\n\r\n")
