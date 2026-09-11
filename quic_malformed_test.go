package clienthellod_test

import (
	"testing"

	. "github.com/refraction-networking/clienthellod"
)

// quicInitialPrefix returns the fixed prefix of a QUIC v1 long-header Initial
// packet up to (but not including) the token-length field: first byte with the
// long-header + fixed bits and the Initial type, version = 1, a 4-byte DCID,
// and an empty SCID. Callers append a token-length VLI (and more) to it.
func quicInitialPrefix() []byte {
	return []byte{
		0xc0,                   // long header (0x80) + fixed bit (0x40), Initial type (0x30 bits clear)
		0x00, 0x00, 0x00, 0x01, // version = QUIC v1 (only supported version)
		0x04, 0xde, 0xad, 0xbe, 0xef, // DCID length = 4, then the DCID
		0x00, // SCID length = 0
	}
}

// hugeVLI is a maximal 8-byte QUIC variable-length integer: 0x3fffffffffffffff
// once the two length-encoding bits are cleared. It is vastly larger than any
// real datagram, so make([]byte, n) with it panics "makeslice: len out of
// range" unless the length is bounded first.
var hugeVLI = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// TestUnmarshalMalformedInitialNoPanic feeds Initial packets whose token-length
// and packet-length fields declare an absurd size. These once panicked inside
// DecodeQUICHeaderAndFrames and took down the whole Caddy process (five multi-
// hour outages, Jul–Sep 2026). They must now return an error, never panic.
func TestUnmarshalMalformedInitialNoPanic(t *testing.T) {
	hugeToken := append(quicInitialPrefix(), hugeVLI...) // token length = huge

	hugePayload := append(quicInitialPrefix(), 0x00) // token length = 0
	hugePayload = append(hugePayload, hugeVLI...)    // packet length = huge

	cases := map[string][]byte{
		"huge token length":  hugeToken,
		"huge packet length": hugePayload,
	}

	for name, p := range cases {
		p := p
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("UnmarshalQUICClientInitialPacket panicked on %q: %v", name, r)
				}
			}()
			if _, err := UnmarshalQUICClientInitialPacket(p); err == nil {
				t.Fatalf("expected an error for %q, got nil", name)
			}
		})
	}
}

// TestHandlePacketMalformedRecovers confirms the fingerprinter's packet entry
// point never propagates a panic to its raw-socket goroutine caller, no matter
// how malformed the input — the backstop that keeps the listener alive.
func TestHandlePacketMalformedRecovers(t *testing.T) {
	qfp := NewQUICFingerprinter()

	hugeToken := append(quicInitialPrefix(), hugeVLI...)
	hugePayload := append(quicInitialPrefix(), 0x00)
	hugePayload = append(hugePayload, hugeVLI...)

	inputs := [][]byte{
		hugeToken,
		hugePayload,
		{},                             // empty
		{0x00},                         // not a long header
		{0xc0, 0x00, 0x00, 0x00, 0x01}, // long header, v1, but truncated
	}
	for i, p := range inputs {
		p := p
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("HandlePacket panicked on input %d: %v", i, r)
				}
			}()
			_ = qfp.HandlePacket("203.0.113.9:443", p)
		}()
	}
}
