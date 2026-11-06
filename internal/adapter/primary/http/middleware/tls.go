package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// TLSConfig controls the transport enforcement applied to every request.
type TLSConfig struct {
	// Required redirects plaintext requests to HTTPS. It is true whenever TLS
	// is enabled, which production always requires.
	Required bool
	// Direct means this server terminates TLS itself. In that mode the request
	// TLS state is authoritative and X-Forwarded-Proto is ignored.
	Direct bool
	// TrustedProxies are the peers allowed to assert X-Forwarded-Proto. Without
	// one of them the header is treated as a client-supplied value and ignored.
	TrustedProxies []string
	// HSTSMaxAge, when positive, emits Strict-Transport-Security on every
	// secure response.
	HSTSMaxAge time.Duration
	// HSTSIncludeSubDomains extends the HSTS policy to subdomains.
	HSTSIncludeSubDomains bool
}

// HTTPS redirects plaintext requests to the same URL over HTTPS and stamps
// HSTS on secure responses. The /health endpoint is exempt so container probes
// (which speak plaintext when TLS terminates at the proxy) keep working.
func RequireHTTPS(cfg TLSConfig) gin.HandlerFunc {
	trusted := parseTrustedProxies(cfg.TrustedProxies)
	hsts := hstsHeader(cfg.HSTSMaxAge, cfg.HSTSIncludeSubDomains)

	return func(ctx *gin.Context) {
		if !cfg.Required {
			ctx.Next()
			return
		}

		if requestIsSecure(ctx.Request, cfg.Direct, trusted) {
			if hsts != "" {
				ctx.Header("Strict-Transport-Security", hsts)
			}
			ctx.Next()
			return
		}

		// The health probe must remain reachable over the internal plaintext
		// listener, otherwise the container is marked unhealthy in proxy mode.
		if ctx.Request.URL.Path == "/health" {
			ctx.Next()
			return
		}

		target, ok := httpsURL(ctx.Request)
		if !ok {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}

		// Keep the redirect out of shared caches: its Location is derived from
		// the client-supplied Host header.
		ctx.Header("Cache-Control", "no-store")

		// 308 keeps the method and body intact for API clients that do not use
		// GET, unlike the default 301/302 behaviour.
		ctx.Redirect(http.StatusPermanentRedirect, target)
		ctx.Abort()
	}
}

// parseTrustedProxies converts the IP/CIDR strings into networks. Entries that
// cannot be parsed are ignored: LoadConfig already rejects them at boot, and
// the middleware must not trust a malformed entry by accident.
func parseTrustedProxies(entries []string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(entries))

	for _, entry := range entries {
		if ip := net.ParseIP(entry); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				networks = append(networks, &net.IPNet{IP: ipv4, Mask: net.CIDRMask(32, 32)})
				continue
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			continue
		}

		if _, network, err := net.ParseCIDR(entry); err == nil {
			networks = append(networks, network)
		}
	}

	return networks
}

// hstsHeader generates the value of the HTTP Strict-Transport-Security (HSTS)
// response header based on the parameters provided.
func hstsHeader(maxAge time.Duration, includeSubDomains bool) string {
	if maxAge <= 0 {
		return ""
	}

	seconds := int64(maxAge / time.Second)
	if seconds <= 0 {
		return ""
	}

	header := fmt.Sprintf("max-age=%d", seconds)
	if includeSubDomains {
		header += "; includeSubDomains"
	}

	return header
}

// requestIsSecure decides whether the request reached the API over TLS. A
// direct TLS handshake is trusted unconditionally; otherwise the forwarded
// scheme is only honoured when the immediate peer is a configured proxy.
func requestIsSecure(r *http.Request, direct bool, trusted []*net.IPNet) bool {
	if r.TLS != nil {
		return true
	}

	if direct {
		return false
	}

	if !isTrustedPeer(r.RemoteAddr, trusted) {
		return false
	}

	return strings.EqualFold(lastForwardedProto(r.Header.Get("X-Forwarded-Proto")), "https")
}

// isTrustedPeer reports whether the socket address belongs to one of the
// trusted proxy networks.
func isTrustedPeer(remoteAddr string, trusted []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// lastForwardedProto returns the rightmost non-empty value of the
// X-Forwarded-Proto list. Proxies append the scheme they observed, so the last
// entry is the closest one and cannot be forged by the client, unlike the
// leftmost value.
func lastForwardedProto(value string) string {
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if proto := strings.TrimSpace(parts[i]); proto != "" {
			return proto
		}
	}

	return ""
}

// httpsURL builds the redirect target from the request itself. The default
// HTTP port is dropped because https://host:80 would target the wrong port.
func httpsURL(r *http.Request) (string, bool) {
	host := r.Host
	if host == "" {
		return "", false
	}

	host = strings.TrimSuffix(host, ":80")
	if host == "" {
		return "", false
	}

	return "https://" + host + r.URL.RequestURI(), true
}
