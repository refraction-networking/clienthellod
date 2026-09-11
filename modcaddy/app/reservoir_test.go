package app

import (
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// TestTLSVisitorSNIScoping verifies the serveTLS fallback can never cross
// origins: a same client IP that opens a tls.* connection and then a quic.*
// connection (recorded most recently) must still resolve the tls.* fallback to
// the tls.* connection — otherwise the tls.* card would show a quic.* SNI.
func TestTLSVisitorSNIScoping(t *testing.T) {
	r := &Reservoir{
		TlsTTL:                 caddy.Duration(time.Minute),
		mapLastTLSVisitorPerIP: new(sync.Map),
	}

	const ip = "203.0.113.7"
	r.NewTLSVisitor(ip, "tls.tlsfingerprint.io", ip+":40001")
	r.NewTLSVisitor(ip, "quic.tlsfingerprint.io", ip+":40002") // most recent

	if got, ok := r.GetLastTLSVisitor(ip, "tls.tlsfingerprint.io"); !ok || got != ip+":40001" {
		t.Fatalf("tls.* fallback = (%q,%v), want (%q,true)", got, ok, ip+":40001")
	}
	if got, ok := r.GetLastTLSVisitor(ip, "quic.tlsfingerprint.io"); !ok || got != ip+":40002" {
		t.Fatalf("quic.* fallback = (%q,%v), want (%q,true)", got, ok, ip+":40002")
	}
	// Browsers may vary host/SNI case; the match must be case-insensitive.
	if got, ok := r.GetLastTLSVisitor(ip, "TLS.TLSFingerprint.IO"); !ok || got != ip+":40001" {
		t.Fatalf("case-insensitive fallback = (%q,%v), want (%q,true)", got, ok, ip+":40001")
	}
	// An unrelated host must not resolve to any captured connection.
	if _, ok := r.GetLastTLSVisitor(ip, "evil.example.com"); ok {
		t.Fatalf("unexpected fallback for unrelated host")
	}
}
