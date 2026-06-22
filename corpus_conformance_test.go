package clienthellod_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	. "github.com/refraction-networking/clienthellod"
)

// corpusDir is the conformance corpus, pinned as a submodule (see
// .github/workflows/conformance.yml). Initialize it with:
//
//	git submodule update --init testdata/conformance
const corpusDir = "testdata/conformance/corpus"

// TestConformanceCorpus checks clienthellod against the shared conformance
// contract natively, so it runs in the normal `go test` loop during development
// (no Python harness needed). For every corpus case it groups client Initials by
// DCID and feeds each group to clienthellod exactly as the conformance go_runner
// does, then asserts the four fingerprint hashes match the committed golden.
//
// This verifies the contract's essence — that clienthellod still produces the
// agreed hashes for every corpus connection. The authoritative full check (every
// canonical feature field, plus the known-issue framework) remains the Python
// harness `harness.check --impl go`, run in CI. Skips cleanly if the submodule
// has not been initialized.
func TestConformanceCorpus(t *testing.T) {
	if _, err := os.Stat(corpusDir); os.IsNotExist(err) {
		t.Skipf("conformance corpus not initialized (%s); run: git submodule update --init testdata/conformance", corpusDir)
	}

	dirs, err := filepath.Glob(filepath.Join(corpusDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	cases := dirs[:0]
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, "expected.json")); err == nil {
			cases = append(cases, d)
		}
	}
	if len(cases) == 0 {
		t.Skipf("no corpus cases with expected.json under %s", corpusDir)
	}

	for _, dir := range cases {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			want := loadCorpusGolden(t, filepath.Join(dir, "expected.json"))

			pcaps, _ := filepath.Glob(filepath.Join(dir, "input.pcap*"))
			if len(pcaps) == 0 {
				t.Fatalf("no input.pcap* in %s", dir)
			}
			got := fingerprintCorpusPcap(t, pcaps[0])

			if len(got) != len(want) {
				t.Errorf("connection count: got %d, want %d", len(got), len(want))
			}
			for key, w := range want {
				g, ok := got[key]
				if !ok {
					t.Errorf("conn %s: missing (clienthellod produced no fingerprint)", key)
					continue
				}
				for _, f := range []struct{ name, got, want string }{
					{"quic_header_fp", g.QUICHeaderFP, w.QUICHeaderFP},
					{"tls_fp", g.TLSFP, w.TLSFP},
					{"qtp_fp", g.QTPFP, w.QTPFP},
					{"super_fp", g.SuperFP, w.SuperFP},
				} {
					if f.got != f.want {
						t.Errorf("conn %s %s: got %s, want %s", key, f.name, f.got, f.want)
					}
				}
			}
			for key := range got {
				if _, ok := want[key]; !ok {
					t.Errorf("conn %s: unexpected extra connection (super_fp %s)", key, got[key].SuperFP)
				}
			}
		})
	}
}

// fingerprintHashes is the subset of the conformance canonical record this test
// asserts: the four hashes, keyed by conn_key (DCID hex).
type fingerprintHashes struct {
	QUICHeaderFP string `json:"quic_header_fp"`
	TLSFP        string `json:"tls_fp"`
	QTPFP        string `json:"qtp_fp"`
	SuperFP      string `json:"super_fp"`
}

func loadCorpusGolden(t *testing.T, path string) map[string]fingerprintHashes {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []struct {
		ConnKey string `json:"conn_key"`
		fingerprintHashes
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	m := make(map[string]fingerprintHashes, len(recs))
	for _, r := range recs {
		m[r.ConnKey] = r.fingerprintHashes
	}
	return m
}

// fingerprintCorpusPcap mirrors the conformance go_runner: it groups client
// Initials by DCID and feeds each group to clienthellod, returning the four
// hashes per completed connection keyed by conn_key (DCID hex).
func fingerprintCorpusPcap(t *testing.T, path string) map[string]fingerprintHashes {
	t.Helper()
	src, f := openCorpusPcap(t, path)
	defer f.Close()

	type group struct {
		gci  *GatheredClientInitials
		done bool
	}
	groups := map[string]*group{}
	deadline := time.Now().Add(time.Hour)

	for pkt := range src.Packets() {
		udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if udp == nil || len(udp.Payload) == 0 {
			continue
		}
		cip, err := UnmarshalQUICClientInitialPacket(udp.Payload)
		if err != nil {
			continue // not a decryptable QUIC v1 client Initial (e.g. GREASE version)
		}
		dcid := corpusDCID(udp.Payload)
		if dcid == nil {
			continue
		}
		key := hex.EncodeToString(dcid)
		g := groups[key]
		if g == nil {
			g = &group{gci: GatherClientInitialsWithDeadline(deadline)}
			groups[key] = g
		}
		if g.done {
			continue
		}
		_ = g.gci.AddPacket(cip) // accept/dedup/reassembly logic lives in clienthellod
		if g.gci.Completed() {
			g.done = true
		}
	}

	out := make(map[string]fingerprintHashes)
	for key, g := range groups {
		if !g.gci.Completed() {
			continue
		}
		qfp, err := GenerateQUICFingerprint(g.gci)
		if err != nil {
			t.Errorf("conn %s: GenerateQUICFingerprint: %v", key, err)
			continue
		}
		out[key] = fingerprintHashes{
			QUICHeaderFP: hashHex(g.gci.NumID),
			TLSFP:        hashHex(uint64(g.gci.ClientHello.NormNumID)),
			QTPFP:        hashHex(g.gci.TransportParameters.NumID),
			SuperFP:      hashHex(qfp.NumID),
		}
	}
	return out
}

// openCorpusPcap opens a pcap or pcapng file (detected by magic) with pure-Go
// gopacket, mirroring the conformance go_runner.
func openCorpusPcap(t *testing.T, path string) (*gopacket.PacketSource, *os.File) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		ng, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		return gopacket.NewPacketSource(ng, ng.LinkType()), f
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	return gopacket.NewPacketSource(r, r.LinkType()), f
}

// corpusDCID extracts the DCID from a QUIC long-header packet, or nil.
func corpusDCID(p []byte) []byte {
	if len(p) < 6 || p[0]&0xC0 != 0xC0 {
		return nil
	}
	dcidLen := int(p[5])
	if 6+dcidLen > len(p) {
		return nil
	}
	out := make([]byte, dcidLen)
	copy(out, p[6:6+dcidLen])
	return out
}

func hashHex(v uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return hex.EncodeToString(b[:])
}
