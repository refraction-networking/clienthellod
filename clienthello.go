package clienthellod

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"

	"github.com/refraction-networking/clienthellod/internal/utils"
	tls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
	"golang.org/x/crypto/cryptobyte"
)

// ClientHello represents a captured ClientHello message with all fingerprintable fields.
type ClientHello struct {
	raw []byte

	TLSRecordVersion    uint16 `json:"tls_record_version"`    // TLS record version (major, minor)
	TLSHandshakeVersion uint16 `json:"tls_handshake_version"` // TLS handshake version (major, minor)

	CipherSuites         []uint16       `json:"cipher_suites"`
	CompressionMethods   utils.Uint8Arr `json:"compression_methods"`
	Extensions           []uint16       `json:"extensions"`            // extension IDs in original order
	ExtensionsNormalized []uint16       `json:"extensions_normalized"` // sorted extension IDs

	ServerName          string         `json:"server_name"`            // server_name(0)
	NamedGroupList      []uint16       `json:"supported_groups"`       // supported_groups(10) a.k.a elliptic_curves
	ECPointFormatList   utils.Uint8Arr `json:"ec_point_formats"`       // ec_point_formats(11)
	SignatureSchemeList []uint16       `json:"signature_algorithms"`   // signature_algorithms(13)
	ALPN                []string       `json:"alpn"`                   // alpn(16)
	CertCompressAlgo    []uint16       `json:"compress_certificate"`   // compress_certificate(27)
	RecordSizeLimit     utils.Uint8Arr `json:"record_size_limit"`      // record_size_limit(28)
	SupportedVersions   []uint16       `json:"supported_versions"`     // supported_versions(43)
	PSKKeyExchangeModes utils.Uint8Arr `json:"psk_key_exchange_modes"` // psk_key_exchange_modes(45)
	KeyShare            []uint16       `json:"key_share"`              // key_share(51)
	ApplicationSettings []string       `json:"application_settings"`   // application_settings(17513) a.k.a ALPS

	UserAgent string `json:"user_agent,omitempty"` // User-Agent header, set by the caller

	NumID     int64  `json:"num_id,omitempty"`      // NID of the fingerprint
	NormNumID int64  `json:"norm_num_id,omitempty"` // Normalized NID of the fingerprint
	HexID     string `json:"hex_id,omitempty"`      // ID of the fingerprint (hex string)
	NormHexID string `json:"norm_hex_id,omitempty"` // Normalized ID of the fingerprint (hex string)

	// below are ONLY used for calculating the fingerprint (hash)
	lengthPrefixedSupportedGroups   []uint16
	lengthPrefixedEcPointFormats    []uint8
	lengthPrefixedSignatureAlgos    []uint16
	alpnWithLengths                 []uint8
	lengthPrefixedCertCompressAlgos []uint8
	keyshareGroupsWithLengths       []uint16

	// QUIC-only, nil if not QUIC
	qtp *QUICTransportParameters
}

// ReadClientHello reads a ClientHello from a connection (io.Reader)
// and returns a ClientHello struct.
//
// It will return an error if the reader does not give a stream of bytes
// representing a valid ClientHello. But all bytes read from the reader
// will be stored in the ClientHello struct to be rewinded by the caller
// if ever needed.
//
// This function does not automatically call [ClientHello.ParseClientHello].
func ReadClientHello(r io.Reader) (ch *ClientHello, err error) {
	ch = new(ClientHello)
	// Read a TLS record
	// Read exactly 5 bytes from the reader
	ch.raw = make([]byte, 5)
	if _, err = io.ReadFull(r, ch.raw); err != nil {
		return
	}

	// Check if the first byte is 0x16 (TLS Handshake)
	if ch.raw[0] != 0x16 {
		err = errors.New("not a TLS handshake record")
		return
	}

	// Read exactly length bytes from the reader
	ch.raw = append(ch.raw, make([]byte, binary.BigEndian.Uint16(ch.raw[3:5]))...)
	_, err = io.ReadFull(r, ch.raw[5:])
	return
}

// UnmarshalClientHello unmarshals a ClientHello from a byte slice
// and returns a ClientHello struct. Any extra bytes after the ClientHello
// message will be ignored.
//
// This function automatically calls [ClientHello.ParseClientHello].
func UnmarshalClientHello(p []byte) (ch *ClientHello, err error) {
	r := bytes.NewReader(p)
	ch, err = ReadClientHello(r)
	if err != nil {
		return
	}

	err = ch.ParseClientHello()
	return
}

func (ch *ClientHello) Raw() []byte {
	return ch.raw
}

// ParseClientHello parses the raw bytes of a ClientHello into a ClientHello struct.
func (ch *ClientHello) ParseClientHello() error {
	// Call uTLS to parse the raw bytes into ClientHelloSpec
	fingerprinter := tls.Fingerprinter{
		AllowBluntMimicry: true, // we will need all the extensions even when not recognized
	}
	chs, err := fingerprinter.RawClientHello(ch.raw)
	if err != nil {
		return fmt.Errorf("failed to parse ClientHello, (*tls.Fingerprinter).RawClientHello(): %w", err)
	}

	// ch.TLSRecordVersion = chs.TLSVersMin    // won't work for TLS 1.3
	// ch.TLSHandshakeVersion = chs.TLSVersMax // won't work for TLS 1.3
	ch.CipherSuites = chs.CipherSuites
	ch.CompressionMethods = chs.CompressionMethods

	// parse extensions
	ch.parseExtensions(chs)

	// Call uTLS to parse the raw bytes into ClientHelloMsg
	chm := tls.UnmarshalClientHello(ch.raw[5:])
	if chm == nil {
		return errors.New("failed to parse ClientHello, (*tls.ClientHelloInfo).Unmarshal(): nil")
	}
	ch.ServerName = chm.ServerName

	runtime.SetFinalizer(ch, func(c *ClientHello) {
		c.qtp = nil // other trivial types are easy to GC
	})

	// In the end parse extra information from raw
	return ch.parseExtra()
}

func (ch *ClientHello) parseExtensions(chs *tls.ClientHelloSpec) { // skipcq: GO-R1005
	for _, ext := range chs.Extensions {
		switch ext := ext.(type) {
		case *tls.SupportedCurvesExtension:
			for _, curve := range ext.Curves {
				ch.NamedGroupList = append(ch.NamedGroupList, uint16(curve))
			}
			ch.lengthPrefixedSupportedGroups = append(ch.lengthPrefixedSupportedGroups, 2*uint16(len(ch.NamedGroupList)))
			ch.lengthPrefixedSupportedGroups = append(ch.lengthPrefixedSupportedGroups, ch.NamedGroupList...)
		case *tls.SupportedPointsExtension:
			ch.ECPointFormatList = ext.SupportedPoints
			ch.lengthPrefixedEcPointFormats = append(ch.lengthPrefixedEcPointFormats, uint8(len(ext.SupportedPoints)))
			ch.lengthPrefixedEcPointFormats = append(ch.lengthPrefixedEcPointFormats, ext.SupportedPoints...)
		case *tls.SignatureAlgorithmsExtension:
			for _, sig := range ext.SupportedSignatureAlgorithms {
				ch.SignatureSchemeList = append(ch.SignatureSchemeList, uint16(sig))
			}
			ch.lengthPrefixedSignatureAlgos = append(ch.lengthPrefixedSignatureAlgos, 2*uint16(len(ch.SignatureSchemeList)))
			ch.lengthPrefixedSignatureAlgos = append(ch.lengthPrefixedSignatureAlgos, ch.SignatureSchemeList...)
		case *tls.ALPNExtension:
			ch.ALPN = ext.AlpnProtocols
			// we will get alpnWithLengths from raw
		case *tls.UtlsCompressCertExtension:
			for _, algo := range ext.Algorithms {
				ch.CertCompressAlgo = append(ch.CertCompressAlgo, uint16(algo))
			}
			ch.lengthPrefixedCertCompressAlgos = append(ch.lengthPrefixedCertCompressAlgos, 2*uint8(len(ch.CertCompressAlgo)))
			ch.lengthPrefixedCertCompressAlgos = append(
				ch.lengthPrefixedCertCompressAlgos,
				utils.Uint16ToUint8(ch.CertCompressAlgo)...,
			)
		case *tls.FakeRecordSizeLimitExtension:
			ch.RecordSizeLimit = append(ch.RecordSizeLimit, uint8(ext.Limit>>8), uint8(ext.Limit))
		case *tls.SupportedVersionsExtension:
			for _, ver := range ext.Versions {
				ch.SupportedVersions = append(ch.SupportedVersions, uint16(ver))
			}
		case *tls.PSKKeyExchangeModesExtension:
			ch.PSKKeyExchangeModes = ext.Modes
		case *tls.KeyShareExtension:
			for _, ks := range ext.KeyShares {
				ch.KeyShare = append(ch.KeyShare, uint16(ks.Group))
				// get below from raw instead
				// ch.keyshareGroupsWithLengths = append(ch.keyshareGroupsWithLengths, uint16(ks.Group))
				// ch.keyshareGroupsWithLengths = append(ch.keyshareGroupsWithLengths, uint16(len(ks.Data)))
			}
		case *tls.ApplicationSettingsExtension:
			ch.ApplicationSettings = ext.SupportedProtocols
		case *tls.GenericExtension:
			if ext.Id == dicttls.ExtType_quic_transport_parameters {
				ch.qtp = ParseQUICTransportParameters(ext.Data)
			}
		}
	}
}

// parseExtra parses extra information from raw bytes which couldn't be parsed by uTLS.
func (ch *ClientHello) parseExtra() error {
	// parse alpnWithLengths and Extensions
	s := cryptobyte.String(ch.raw)
	var recordVersion uint16
	if !s.Skip(1) || !s.ReadUint16(&recordVersion) || !s.Skip(2) { // skip TLS record header
		return errors.New("failed to parse TLS header, cryptobyte.String().Skip(): false")
	}
	ch.TLSRecordVersion = recordVersion
	var handshakeVersion uint16
	if !s.Skip(1) || // skip Handshake type
		!s.Skip(3) || // skip Handshake length
		!s.ReadUint16(&handshakeVersion) || // parse ClientHello version
		!s.Skip(32) { // skip ClientHello random
		return errors.New("failed to parse ClientHello, cryptobyte.String().Skip(): false")
	}
	ch.TLSHandshakeVersion = handshakeVersion

	var ignoredSessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&ignoredSessionID) {
		return errors.New("unable to read session id")
	}

	var ignoredCipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ignoredCipherSuites) {
		return errors.New("unable to read ciphersuites")
	}

	var ignoredCompressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&ignoredCompressionMethods) {
		return errors.New("unable to read compression methods")
	}

	if s.Empty() {
		return nil // no extensions
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return errors.New("unable to read extensions data")
	}

	err := ch.parseExtensionsExtra(extensions)
	if err != nil {
		return fmt.Errorf("failed to parse extensions, parseExtensionsExtra(): %w", err)
	}

	// sort ch.Extensions and put result to ch.ExtensionsNormalized
	ch.ExtensionsNormalized = make([]uint16, len(ch.Extensions))
	copy(ch.ExtensionsNormalized, ch.Extensions)
	sort.Slice(ch.ExtensionsNormalized, func(i, j int) bool {
		return ch.ExtensionsNormalized[i] < ch.ExtensionsNormalized[j]
	})

	// calculate fingerprint
	ch.NumID, ch.NormNumID = ch.calcNumericID()
	ch.HexID = FingerprintID(ch.NumID).AsHex()
	ch.NormHexID = FingerprintID(ch.NormNumID).AsHex()

	return nil
}

func (ch *ClientHello) parseExtensionsExtra(extensions cryptobyte.String) error {
	var extensionIDs []uint16
	for !extensions.Empty() {
		var extensionID uint16
		var extensionData cryptobyte.String
		if !extensions.ReadUint16(&extensionID) {
			return errors.New("unable to read extension ID")
		}
		if !extensions.ReadUint16LengthPrefixed(&extensionData) {
			return errors.New("unable to read extension data")
		}

		extensionID, err := ch.parseExtensionExtra(extensionID, extensionData)
		if err != nil {
			return fmt.Errorf("failed to parse extension, parseExtensionExtra(): %w", err)
		}
		extensionIDs = append(extensionIDs, extensionID) // extension ID might need to be overridden by parseExtensionExtra() in case of GREASE
	}
	ch.Extensions = extensionIDs

	return nil
}

func (ch *ClientHello) parseExtensionExtra(extensionID uint16, extensionData cryptobyte.String) (uint16, error) {
	switch extensionID {
	case 16: // ALPN
		ch.alpnWithLengths = extensionData
	case 51: // keyshare
		if !extensionData.Skip(2) {
			return 0, errors.New("unable to skip keyshare total length")
		}
		for !extensionData.Empty() {
			var group uint16
			var length uint16
			if !extensionData.ReadUint16(&group) || !extensionData.ReadUint16(&length) {
				return 0, errors.New("unable to read keyshare group")
			}
			if utils.IsGREASEUint16(group) {
				group = tls.GREASE_PLACEHOLDER
			}
			ch.keyshareGroupsWithLengths = append(ch.keyshareGroupsWithLengths, group, length)

			if !extensionData.Skip(int(length)) {
				return 0, errors.New("unable to skip keyshare data")
			}
		}
	default:
		if utils.IsGREASEUint16(extensionID) {
			return tls.GREASE_PLACEHOLDER, nil
		}
	}

	return extensionID, nil
}
