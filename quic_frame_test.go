package clienthellod_test

import (
	"bytes"
	"math/rand"
	"testing"

	. "github.com/refraction-networking/clienthellod"
)

func TestPADDING(t *testing.T) {
	var randLen int = rand.Int() % 512 // skipcq: GSC-G404
	var rdBuf []byte = make([]byte, randLen+5)
	copy(rdBuf[randLen:], "hello")

	var padding PADDING
	if padding.FrameType() != QUICFrame_PADDING {
		t.Errorf("padding.FrameType() = %d, want %d", padding.FrameType(), QUICFrame_PADDING)
	}

	r, err := padding.ReadReader(bytes.NewReader(rdBuf))
	if err != nil {
		t.Errorf("padding.ReadReader() error = %v", err)
	}

	if padding.Length != uint64(randLen)+1 {
		t.Errorf("padding.Length = %d, want %d", padding.Length, randLen+1)
	}

	// check what's left in the Reader
	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if err != nil {
		t.Errorf("padding.ReadReader() error = %v", err)
	}

	if n != 5 || string(buf[:n]) != "hello" {
		t.Errorf("padding.ReadReader() = %d, %s, want 5, hello", n, string(buf[:n]))
	}
}

func TestCRYPTO(t *testing.T) {
	var cryptoRaw []byte = []byte{
		/* 0x06, */ // Frame Type, to be read by ReadAllFrames()
		0x40, 0x9e, 0x1a, 0x33, 0x00, 0x26, 0x00,
		0x24, 0x00, 0x1d, 0x00, 0x20, 0xf8, 0x82, 0xf6,
		0x48, 0x2b, 0x20, 0x0c, 0xa0, 0x60, 0x79, 0x1c,
		0x45, 0xa5, 0xb8, 0x43, 0x58, 0x11,
		'h', 'e', 'l', 'l', 'o', // extra bytes shouldn't be read
	}

	var crypto CRYPTO
	if crypto.FrameType() != QUICFrame_CRYPTO {
		t.Errorf("crypto.FrameType() = %d, want %d", crypto.FrameType(), QUICFrame_CRYPTO)
	}

	r, err := crypto.ReadReader(bytes.NewReader(cryptoRaw))
	if err != nil {
		t.Errorf("crypto.ReadReader() error = %v", err)
	}

	if crypto.Offset != 158 {
		t.Errorf("crypto.Offset = %d, want %d", crypto.Offset, 158)
	}

	if crypto.Length != 26 {
		t.Errorf("crypto.Length = %d, want %d", crypto.Length, 26)
	}

	var cryptoDataTruth []byte = []byte{
		0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00,
		0x20, 0xf8, 0x82, 0xf6, 0x48, 0x2b, 0x20, 0x0c,
		0xa0, 0x60, 0x79, 0x1c, 0x45, 0xa5, 0xb8, 0x43,
		0x58, 0x11,
	}
	if !bytes.Equal(crypto.Data(), cryptoDataTruth) {
		t.Errorf("crypto.Data = %v, want %v", crypto.Data(), cryptoDataTruth)
	}

	// check what's left in the Reader
	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if err != nil {
		t.Errorf("crypto.ReadReader() error = %v", err)
	}

	if n != 5 || string(buf[:n]) != "hello" {
		t.Errorf("crypto.ReadReader() = %d, %s, want 5, hello", n, string(buf[:n]))
	}
}

func TestReadAllFramesAndReassemble(t *testing.T) {
	frames, err := ReadAllFrames(bytes.NewReader(allFramesRaw))
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 13 {
		t.Fatalf("len(frames) = %d, want 13", len(frames))
	}

	var frameTypesTruth []uint64 = []uint64{
		0x01, 0x00, 0x06, 0x00, 0x01, 0x06, 0x00, 0x06,
		0x01, 0x01, 0x01, 0x01, 0x01,
	}

	var paddingLengthTruth []uint64 = []uint64{
		627, 135, 119,
	}

	var cryptoOffsetTruth []uint64 = []uint64{
		184, 158, 0,
	}
	var cryptoLengthTruth []uint64 = []uint64{
		110, 26, 158,
	}

	var idxPadding int
	var idxCrypto int
	for i, frame := range frames {
		if frame.FrameType() != frameTypesTruth[i] {
			t.Fatalf("frame#%d type mismatch: %d != %d", i, frame.FrameType(), frameTypesTruth[i])
		}

		if frame.FrameType() == QUICFrame_PADDING {
			if frame.(*PADDING).Length != paddingLengthTruth[idxPadding] {
				t.Fatalf("frame#%d padding length mismatch: %d != %d", i, frame.(*PADDING).Length, paddingLengthTruth[idxPadding])
			}
			idxPadding++
		}

		if frame.FrameType() == QUICFrame_CRYPTO {
			if frame.(*CRYPTO).Offset != cryptoOffsetTruth[idxCrypto] {
				t.Fatalf("frame#%d crypto offset mismatch: %d != %d", i, frame.(*CRYPTO).Offset, cryptoOffsetTruth[idxCrypto])
			}
			if frame.(*CRYPTO).Length != cryptoLengthTruth[idxCrypto] {
				t.Fatalf("frame#%d crypto length mismatch: %d != %d", i, frame.(*CRYPTO).Length, cryptoLengthTruth[idxCrypto])
			}
			idxCrypto++
		}
	}

	crypto, err := ReassembleCRYPTOFrames(frames)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(crypto, reassembledCryptoTruth) {
		t.Fatalf("crypto mismatch: expected %v, got %v", reassembledCryptoTruth, crypto)
	}
}

var (
	reassembledCryptoTruth = []byte{
		0x01, 0x00, 0x01, 0x22, 0x03, 0x03, 0xe3, 0x1b,
		0x6b, 0x88, 0xce, 0x0e, 0xff, 0x48, 0x08, 0x52,
		0xa6, 0x21, 0x03, 0x90, 0x84, 0x92, 0x5d, 0xf6,
		0x8a, 0xcb, 0xad, 0x66, 0xdb, 0x9f, 0x3c, 0x94,
		0x3f, 0x0e, 0xba, 0xf2, 0x4a, 0x3c, 0x00, 0x00,
		0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x01,
		0x00, 0x00, 0xf3, 0x44, 0x69, 0x00, 0x05, 0x00,
		0x03, 0x02, 0x68, 0x33, 0x00, 0x39, 0x00, 0x5d,
		0x09, 0x02, 0x40, 0x67, 0x0f, 0x00, 0x01, 0x04,
		0x80, 0x00, 0x75, 0x30, 0x05, 0x04, 0x80, 0x60,
		0x00, 0x00, 0xe2, 0xd0, 0x11, 0x38, 0x87, 0x0c,
		0x6f, 0x9f, 0x01, 0x96, 0x07, 0x04, 0x80, 0x60,
		0x00, 0x00, 0x71, 0x28, 0x04, 0x52, 0x56, 0x43,
		0x4d, 0x03, 0x02, 0x45, 0xc0, 0x20, 0x04, 0x80,
		0x01, 0x00, 0x00, 0x08, 0x02, 0x40, 0x64, 0x80,
		0xff, 0x73, 0xdb, 0x0c, 0x00, 0x00, 0x00, 0x01,
		0xba, 0xca, 0x5a, 0x5a, 0x00, 0x00, 0x00, 0x01,
		0x80, 0x00, 0x47, 0x52, 0x04, 0x00, 0x00, 0x00,
		0x01, 0x06, 0x04, 0x80, 0x60, 0x00, 0x00, 0x04,
		0x04, 0x80, 0xf0, 0x00, 0x00, 0x00, 0x33, 0x00,
		0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xf8,
		0x82, 0xf6, 0x48, 0x2b, 0x20, 0x0c, 0xa0, 0x60,
		0x79, 0x1c, 0x45, 0xa5, 0xb8, 0x43, 0x58, 0x11,
		0x26, 0x64, 0xec, 0x4f, 0xf7, 0xd6, 0xea, 0x10,
		0x30, 0xf6, 0x9f, 0x36, 0x80, 0x49, 0x43, 0x00,
		0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08,
		0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
		0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00,
		0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33,
		0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d,
		0x00, 0x17, 0x00, 0x18, 0x00, 0x00, 0x00, 0x1a,
		0x00, 0x18, 0x00, 0x00, 0x15, 0x71, 0x2e, 0x63,
		0x6c, 0x69, 0x65, 0x6e, 0x74, 0x68, 0x65, 0x6c,
		0x6c, 0x6f, 0x2e, 0x67, 0x61, 0x75, 0x6b, 0x2e,
		0x61, 0x73, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03,
		0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,
		0x1b, 0x00, 0x03, 0x02, 0x00, 0x02,
	}

	allFramesRaw = []byte{
		// PING
		0x01,
		// PADDING
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
		// CRYPTO
		0x06, 0x40, 0xb8, 0x40, 0x6e, 0x26, 0x64, 0xec,
		0x4f, 0xf7, 0xd6, 0xea, 0x10, 0x30, 0xf6, 0x9f,
		0x36, 0x80, 0x49, 0x43, 0x00, 0x0d, 0x00, 0x14,
		0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
		0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06,
		0x06, 0x01, 0x02, 0x01, 0x00, 0x10, 0x00, 0x05,
		0x00, 0x03, 0x02, 0x68, 0x33, 0x00, 0x0a, 0x00,
		0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00,
		0x18, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00,
		0x00, 0x15, 0x71, 0x2e, 0x63, 0x6c, 0x69, 0x65,
		0x6e, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e,
		0x67, 0x61, 0x75, 0x6b, 0x2e, 0x61, 0x73, 0x00,
		0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x2d,
		0x00, 0x02, 0x01, 0x01, 0x00, 0x1b, 0x00, 0x03,
		0x02, 0x00, 0x02,
		// PADDING
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// PING
		0x01,
		// CRYPTO
		0x06, 0x40, 0x9e, 0x1a, 0x33, 0x00, 0x26, 0x00,
		0x24, 0x00, 0x1d, 0x00, 0x20, 0xf8, 0x82, 0xf6,
		0x48, 0x2b, 0x20, 0x0c, 0xa0, 0x60, 0x79, 0x1c,
		0x45, 0xa5, 0xb8, 0x43, 0x58, 0x11,
		// PADDING
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// CRYPTO
		0x06, 0x00, 0x40, 0x9e, 0x01, 0x00, 0x01, 0x22,
		0x03, 0x03, 0xe3, 0x1b, 0x6b, 0x88, 0xce, 0x0e,
		0xff, 0x48, 0x08, 0x52, 0xa6, 0x21, 0x03, 0x90,
		0x84, 0x92, 0x5d, 0xf6, 0x8a, 0xcb, 0xad, 0x66,
		0xdb, 0x9f, 0x3c, 0x94, 0x3f, 0x0e, 0xba, 0xf2,
		0x4a, 0x3c, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13,
		0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0xf3, 0x44,
		0x69, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33,
		0x00, 0x39, 0x00, 0x5d, 0x09, 0x02, 0x40, 0x67,
		0x0f, 0x00, 0x01, 0x04, 0x80, 0x00, 0x75, 0x30,
		0x05, 0x04, 0x80, 0x60, 0x00, 0x00, 0xe2, 0xd0,
		0x11, 0x38, 0x87, 0x0c, 0x6f, 0x9f, 0x01, 0x96,
		0x07, 0x04, 0x80, 0x60, 0x00, 0x00, 0x71, 0x28,
		0x04, 0x52, 0x56, 0x43, 0x4d, 0x03, 0x02, 0x45,
		0xc0, 0x20, 0x04, 0x80, 0x01, 0x00, 0x00, 0x08,
		0x02, 0x40, 0x64, 0x80, 0xff, 0x73, 0xdb, 0x0c,
		0x00, 0x00, 0x00, 0x01, 0xba, 0xca, 0x5a, 0x5a,
		0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x47, 0x52,
		0x04, 0x00, 0x00, 0x00, 0x01, 0x06, 0x04, 0x80,
		0x60, 0x00, 0x00, 0x04, 0x04, 0x80, 0xf0, 0x00,
		0x00, 0x00,
		// PING * 5
		0x01, 0x01, 0x01, 0x01, 0x01,
	}
)

var (
	quicFramesTruth_Chrome125_PKN1 = QUICFrames{
		&CRYPTO{Offset: 0, Length: 1211},
	}
	quicFramesTruth_Chrome125_PKN2 = QUICFrames{
		&CRYPTO{Offset: 1211, Length: 8},
		&PADDING{Length: 80},
		&CRYPTO{Offset: 1720, Length: 35},
		&CRYPTO{Offset: 1677, Length: 43},
		&PADDING{Length: 2},
		&PING{},
		&PADDING{Length: 235},
		&CRYPTO{Offset: 1755, Length: 21},
		&CRYPTO{Offset: 1219, Length: 238},
		&PADDING{Length: 305},
		&CRYPTO{Offset: 1457, Length: 220},
		&PING{},
	}
	quicFramesTruth_Firefox126 = QUICFrames{
		&CRYPTO{Offset: 0, Length: 633},
	}
	quicFramesTruth_Firefox126_0_RTT = QUICFrames{
		&CRYPTO{Offset: 0, Length: 594},
	}
)

func testQUICFramesEqualsTruth(t *testing.T, frames, truths QUICFrames) {
	if len(frames) != len(truths) {
		t.Fatalf("Expected %d frames, got %d", len(truths), len(frames))
	}

	for i, truth := range truths {
		switch truth := truth.(type) {
		case *CRYPTO:
			if frame, ok := frames[i].(*CRYPTO); ok {
				if frame.Offset != truth.Offset || frame.Length != truth.Length {
					t.Errorf("Frame %d: expected %+v, got %+v", i, truth, frame)
				}
			} else {
				t.Errorf("Frame %d: expected CRYPTO, got %T", i, frames[i])
			}
		case *PADDING:
			if frame, ok := frames[i].(*PADDING); ok {
				if frame.Length != truth.Length {
					t.Errorf("Frame %d: expected %+v, got %+v", i, truth, frame)
				}
			} else {
				t.Errorf("Frame %d: expected PADDING, got %T", i, frames[i])
			}
		case *PING:
			if _, ok := frames[i].(*PING); !ok {
				t.Errorf("Frame %d: expected PING, got %T", i, frames[i])
			}
		default:
			t.Fatalf("Unknown frame type: %T", truth)
		}
	}
}
