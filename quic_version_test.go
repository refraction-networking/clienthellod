package clienthellod_test

import (
	"errors"
	"testing"

	. "github.com/refraction-networking/clienthellod"
)

// DecodeQUICHeaderAndFrames must reject non-v1 Initials before deriving keys.
// A GREASE-version probe (e.g. quiche's 0xbabababa) reuses the real
// connection's DCID; clienthellod can only decrypt QUIC v1, and feeding a
// non-v1 Initial decrypted with v1 keys corrupts ClientHello reconstruction
// under the shared DCID — which previously suppressed the fingerprint entirely.
func TestDecodeQUICHeaderRejectsNonV1Version(t *testing.T) {
	// Sanity: the unmodified vector is QUIC v1 and decodes cleanly.
	if _, _, err := DecodeQUICHeaderAndFrames(quicIETFData_Chrome125_PKN1); err != nil {
		t.Fatalf("v1 Initial should decode, got %v", err)
	}

	for name, version := range map[string][4]byte{
		"GREASE_babababa": {0xba, 0xba, 0xba, 0xba},
		"QUICv2":          {0x6b, 0x33, 0x43, 0xcf},
		"version_zero":    {0x00, 0x00, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			pkt := append([]byte(nil), quicIETFData_Chrome125_PKN1...)
			copy(pkt[1:5], version[:])
			if _, _, err := DecodeQUICHeaderAndFrames(pkt); !errors.Is(err, ErrUnsupportedQUICVersion) {
				t.Fatalf("expected ErrUnsupportedQUICVersion, got %v", err)
			}
		})
	}
}
