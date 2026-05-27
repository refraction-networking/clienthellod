package clienthellod

import (
	"crypto/sha1" // skipcq: GSC-G505
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"

	"github.com/refraction-networking/clienthellod/internal/utils"
)

// updateU32 writes a u32 as 4 big-endian bytes.
func updateU32(h hash.Hash, i uint32) {
	binary.Write(h, binary.BigEndian, i)
}

// updateU64 writes a u64 as 8 big-endian bytes.
func updateU64(h hash.Hash, i uint64) {
	binary.Write(h, binary.BigEndian, i)
}

// vliToU64 decodes a variable-length integer byte slice (after unsetVLIBits)
// to a u64 by treating the bytes as a big-endian integer.
func vliToU64(arr utils.Uint8Arr) uint64 {
	var val uint64
	for _, b := range arr {
		val = val<<8 | uint64(b)
	}
	return val
}

// FingerprintID is the type of fingerprint ID.
type FingerprintID int64

// AsHex returns the hex representation of this fingerprint ID.
func (id FingerprintID) AsHex() string {
	hid := make([]byte, 8)
	binary.BigEndian.PutUint64(hid, uint64(id))
	return hex.EncodeToString(hid)
}

// isGREASEU16 returns true if v is a GREASE value (0xXAXA pattern).
func isGREASEU16(v uint16) bool {
	high := (v >> 8) & 0xFF
	low := v & 0xFF
	return high == low && (low&0x0F) == 0x0A
}

// ungreaseU16 replaces a GREASE u16 value with the canonical 0x0A0A placeholder.
func ungreaseU16(v uint16) uint16 {
	if isGREASEU16(v) {
		return 0x0A0A
	}
	return v
}

// pskGREASE is the set of PSK exchange mode GREASE byte values (RFC 8701).
var pskGREASE = [8]byte{0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4}

// ungreasePSK replaces a PSK exchange mode GREASE byte with 0x0B.
func ungreasePSK(v byte) byte {
	for _, g := range pskGREASE {
		if v == g {
			return 0x0B
		}
	}
	return v
}

// isGREASEALPN returns true if a 2-char ALPN string is a GREASE value.
func isGREASEALPN(s string) bool {
	if len(s) != 2 {
		return false
	}
	return s[0] == s[1] && (s[0]&0x0F) == 0x0A
}

// calcNumericID computes both the original and normalized TLS fingerprint IDs.
//
// Algorithm matches retina_quic_fp's TlsFingerprint::fingerprint():
//   - SHA-1 over: version(u32), cipher_suites(ungreased), compression_algs,
//     extensions(ungreased, sorted if normalized), named_groups(ungreased),
//     ec_point_formats, signature_algs(ungreased), alpn(per-string u8-length-prefixed,
//     GREASE→"\x0a\x0a"), key_share(ungreased group IDs), psk_exchange_modes(ungreased),
//     supported_versions(ungreased), compress_certificate(raw wire bytes),
//     record_size_limit(always 2 bytes)
//   - No array-level length prefixes anywhere.
func (ch *ClientHello) calcNumericID() (orig, norm int64) {
	for _, normalized := range []bool{false, true} {
		h := sha1.New() // skipcq: GO-S1025, GSC-G401

		// TLS handshake version as u32 (record version excluded)
		binary.Write(h, binary.BigEndian, uint32(ch.TLSHandshakeVersion))

		// Cipher suites — ungreased, flat big-endian u16 bytes
		for _, cs := range ch.CipherSuites {
			binary.Write(h, binary.BigEndian, ungreaseU16(cs))
		}

		// Compression methods — flat bytes
		h.Write(ch.CompressionMethods)

		// Extensions — ungreased (already handled by clienthellod), sorted if normalized
		exts := ch.Extensions
		if normalized {
			exts = ch.ExtensionsNormalized
		}
		for _, ext := range exts {
			binary.Write(h, binary.BigEndian, ungreaseU16(ext))
		}

		// Named groups — ungreased, flat big-endian u16 bytes
		for _, ng := range ch.NamedGroupList {
			binary.Write(h, binary.BigEndian, ungreaseU16(ng))
		}

		// EC point formats — flat bytes
		h.Write(ch.ECPointFormatList)

		// Signature algorithms — ungreased, flat big-endian u16 bytes
		for _, sa := range ch.SignatureSchemeList {
			binary.Write(h, binary.BigEndian, ungreaseU16(sa))
		}

		// ALPN — per-string u8 length prefix + bytes; GREASE strings → "\x0a\x0a"
		for _, proto := range ch.ALPN {
			if isGREASEALPN(proto) {
				proto = "\x0a\x0a"
			}
			h.Write([]byte{uint8(len(proto))})
			h.Write([]byte(proto))
		}

		// Key share — ungreased (already handled by clienthellod), flat big-endian u16
		for _, ks := range ch.KeyShare {
			binary.Write(h, binary.BigEndian, ungreaseU16(ks))
		}

		// PSK exchange modes — ungreased, flat bytes
		for _, mode := range ch.PSKKeyExchangeModes {
			h.Write([]byte{ungreasePSK(mode)})
		}

		// Supported versions — ungreased, flat big-endian u16 bytes
		for _, sv := range ch.SupportedVersions {
			binary.Write(h, binary.BigEndian, ungreaseU16(sv))
		}

		// Compress certificate — 1-byte list-byte-count + 2 bytes per algo.
		// DB stores e.g. [2, 0, 2] for brotli: count=2 (byte length), then 0x0002.
		if len(ch.CertCompressAlgo) > 0 {
			h.Write([]byte{uint8(2 * len(ch.CertCompressAlgo))})
			for _, algo := range ch.CertCompressAlgo {
				binary.Write(h, binary.BigEndian, algo)
			}
		}

		// Record size limit — always exactly 2 bytes (value or [0, 0])
		if len(ch.RecordSizeLimit) >= 2 {
			h.Write(ch.RecordSizeLimit[:2])
		} else {
			h.Write([]byte{0, 0})
		}

		if normalized {
			norm = int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
		} else {
			orig = int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
		}
	}
	return
}

// calcNumericID computes the QUIC header fingerprint ID for the gathered initials.
//
// Algorithm matches retina_quic_fp's QuicHeaderFingerprint::fingerprint():
//   - SHA-1 over: version(4 raw bytes), dcid_len(u32), scid_len(u32),
//     packet_number_length(u32), sorted_unique_frame_types(first packet only),
//     token_presence(u8)
//   - No length prefixes.
func (gci *GatheredClientInitials) calcNumericID() uint64 {
	h := sha1.New() // skipcq: GO-S1025, GSC-G401

	// Version — 4 raw bytes, no length prefix
	h.Write(gci.Packets[0].Header.Version)

	// DCID and SCID lengths as u32
	updateU32(h, gci.Packets[0].Header.DCIDLength)
	updateU32(h, gci.Packets[0].Header.SCIDLength)

	// Packet number field length as u32 (not the packet number value)
	updateU32(h, gci.Packets[0].Header.initialPacketNumberLength)

	// Sorted unique frame types from first packet only
	firstFrameTypes := gci.Packets[0].frames.FrameTypesUint8()
	sort.Slice(firstFrameTypes, func(i, j int) bool { return firstFrameTypes[i] < firstFrameTypes[j] })
	firstFrameTypes = dedupUint8(firstFrameTypes)
	h.Write(firstFrameTypes)

	// Token presence as u8
	if gci.Packets[0].Header.HasToken {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	return binary.BigEndian.Uint64(h.Sum(nil)[0:8])
}

// calcNumericID computes the QUIC transport parameters fingerprint ID.
//
// Algorithm matches retina_quic_fp's QtpFingerprint::fingerprint():
//   - SHA-1 over: sorted parameter IDs (each as u64), then each transport
//     parameter value decoded to u64. No length prefixes.
func (qtp *QUICTransportParameters) calcNumericID() uint64 {
	h := sha1.New() // skipcq: GO-S1025, GSC-G401

	// Parameter IDs first — sorted, each as u64, no count or length prefix
	for _, id := range qtp.QTPIDs {
		updateU64(h, id)
	}

	// Transport parameter values as decoded u64s, in fixed order
	updateU64(h, vliToU64(qtp.MaxIdleTimeout))
	updateU64(h, vliToU64(qtp.MaxUDPPayloadSize))
	updateU64(h, vliToU64(qtp.InitialMaxData))
	updateU64(h, vliToU64(qtp.InitialMaxStreamDataBidiLocal))
	updateU64(h, vliToU64(qtp.InitialMaxStreamDataBidiRemote))
	updateU64(h, vliToU64(qtp.InitialMaxStreamDataUni))
	updateU64(h, vliToU64(qtp.InitialMaxStreamsBidi))
	updateU64(h, vliToU64(qtp.InitialMaxStreamsUni))
	updateU64(h, vliToU64(qtp.AckDelayExponent))
	updateU64(h, vliToU64(qtp.MaxAckDelay))
	updateU64(h, vliToU64(qtp.ActiveConnectionIDLimit))

	return binary.BigEndian.Uint64(h.Sum(nil))
}

// dedupUint8 removes consecutive duplicates from a sorted []uint8 slice.
func dedupUint8(s []uint8) []uint8 {
	if len(s) == 0 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
