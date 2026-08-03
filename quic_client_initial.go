package clienthellod

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ClientInitial represents a QUIC Initial Packet sent by the Client.
type ClientInitial struct {
	Header     *QUICHeader `json:"header,omitempty"` // QUIC header
	FrameTypes []uint64    `json:"frames,omitempty"` // frames ID in order
	frames     QUICFrames  // frames in order
	raw        []byte
}

// UnmarshalQUICClientInitialPacket is similar to ParseQUICCIP, but on error
// such as ClientHello cannot be parsed, it returns a partially completed
// ClientInitialPacket instead of nil.
func UnmarshalQUICClientInitialPacket(p []byte) (ci *ClientInitial, err error) {
	ci = &ClientInitial{
		raw: p,
	}

	ci.Header, ci.frames, err = DecodeQUICHeaderAndFrames(p)
	if err != nil {
		return
	}

	ci.FrameTypes = ci.frames.FrameTypes()

	// Make sure first GC completely releases all resources as possible
	runtime.SetFinalizer(ci, func(c *ClientInitial) {
		c.Header = nil
		c.FrameTypes = nil
		c.frames = nil
		c.raw = nil
	})

	return ci, nil
}

// GatheredClientInitials represents a series of Initial Packets sent by the Client to initiate
// the QUIC handshake.
type GatheredClientInitials struct {
	Packets         []*ClientInitial `json:"packets,omitempty"` // sorted by ClientInitial.PacketNumber
	maxPacketNumber uint64           // if a packet lies more than this many packet numbers from pnBase, will reject the packet
	maxPacketCount  uint64           // if len(Packets) >= maxPacketCount, will reject any new packets
	pnBase          uint64           // packet number of the first Initial seen; anchors maxPacketNumber
	pnBaseSet       bool             // whether pnBase has been recorded yet
	pktsMutex       *sync.Mutex

	clientHelloReconstructor *QUICClientHelloReconstructor
	ClientHello              *QUICClientHello         `json:"client_hello,omitempty"`         // TLS ClientHello
	TransportParameters      *QUICTransportParameters `json:"transport_parameters,omitempty"` // QUIC Transport Parameters extracted from the extension in ClientHello

	HexID string `json:"hex_id,omitempty"`
	NumID uint64 `json:"num_id,omitempty"`

	deadline              time.Time
	completed             atomic.Bool
	completeChan          chan struct{}
	completeChanCloseOnce sync.Once
}

const (
	// DEFAULT_MAX_INITIAL_PACKET_NUMBER bounds how far into a connection Client
	// Initials are still gathered. It is measured as a distance from the first
	// Initial observed for the connection, NOT as an absolute packet number:
	// clients are free to start numbering anywhere, and Firefox does -- across a
	// 60-connection sample its first Initial packet number was roughly uniform
	// over 1..32 (median 18) with a tail past 240. Comparing the raw packet
	// number against this dropped such connections entirely, and since Firefox's
	// ClientHello spans two Initials (n and n+1) it also dropped connections
	// starting at exactly the bound: the second packet was rejected and the
	// ClientHello never reassembled.
	DEFAULT_MAX_INITIAL_PACKET_NUMBER uint64 = 32
	DEFAULT_MAX_INITIAL_PACKET_COUNT  uint64 = 4
)

var (
	ErrGatheringExpired                                    = errors.New("ClientInitials gathering has expired")
	ErrPacketRejected                                      = errors.New("packet rejected based upon rules")
	ErrGatheredClientInitialsChannelClosedBeforeCompletion = errors.New("completion notification channel closed before setting completion flag")
)

// GatherClientInitialPackets reads a series of Client Initial Packets from the input channel
// and returns the result of the gathered packets.
func GatherClientInitials() *GatheredClientInitials {
	gci := &GatheredClientInitials{
		Packets:                  make([]*ClientInitial, 0, 4), // expecting 4 packets at max
		maxPacketNumber:          DEFAULT_MAX_INITIAL_PACKET_NUMBER,
		maxPacketCount:           DEFAULT_MAX_INITIAL_PACKET_COUNT,
		pktsMutex:                &sync.Mutex{},
		clientHelloReconstructor: NewQUICClientHelloReconstructor(),
		completed:                atomic.Bool{},
		completeChan:             make(chan struct{}),
		completeChanCloseOnce:    sync.Once{},
	}

	// Make sure first GC completely releases all resources as possible
	runtime.SetFinalizer(gci, func(g *GatheredClientInitials) {
		g.Packets = nil

		g.clientHelloReconstructor = nil
		g.ClientHello = nil
		g.TransportParameters = nil

		g.completeChanCloseOnce.Do(func() {
			close(g.completeChan)
		})
		g.completeChan = nil
	})

	return gci
}

// GatherClientInitialsWithDeadline is a helper function to create a GatheredClientInitials with a deadline.
func GatherClientInitialsWithDeadline(deadline time.Time) *GatheredClientInitials {
	gci := GatherClientInitials()
	gci.SetDeadline(deadline)
	return gci
}

func (gci *GatheredClientInitials) AddPacket(cip *ClientInitial) error {
	gci.pktsMutex.Lock()
	defer gci.pktsMutex.Unlock()

	if gci.Expired() { // not allowing new packets after expiry
		return ErrGatheringExpired
	}

	if gci.ClientHello != nil { // parse complete, new packet likely to be an ACK-only frame, ignore
		return nil
	}

	// Anchor the packet-number bound on this connection's first Initial. See
	// DEFAULT_MAX_INITIAL_PACKET_NUMBER: the bound is a distance, not a ceiling,
	// so it does not assume the client started numbering at zero.
	if !gci.pnBaseSet {
		gci.pnBase = cip.Header.initialPacketNumber
		gci.pnBaseSet = true
	}

	// check if packet needs to be rejected based upon set maxPacketNumber and maxPacketCount
	if pnDistance(cip.Header.initialPacketNumber, gci.pnBase) > atomic.LoadUint64(&gci.maxPacketNumber) ||
		uint64(len(gci.Packets)) >= atomic.LoadUint64(&gci.maxPacketCount) {
		return ErrPacketRejected
	}

	// check if duplicate packet number was received, if so, discard
	for _, p := range gci.Packets {
		if p.Header.initialPacketNumber == cip.Header.initialPacketNumber {
			return nil
		}
	}

	gci.Packets = append(gci.Packets, cip)

	// sort by initialPacketNumber
	sort.Slice(gci.Packets, func(i, j int) bool {
		return gci.Packets[i].Header.initialPacketNumber < gci.Packets[j].Header.initialPacketNumber
	})

	if err := gci.clientHelloReconstructor.FromFrames(cip.frames); err != nil {
		if errors.Is(err, ErrNeedMoreFrames) {
			return nil // abort early, need more frames before ClientHello can be reconstructed
		} else {
			return fmt.Errorf("failed to reassemble ClientHello: %w", err)
		}
	}

	return gci.lockedGatherComplete()
}

// Completed returns true if the GatheredClientInitials is complete.
func (gci *GatheredClientInitials) Completed() bool {
	return gci.completed.Load()
}

// Expired returns true if the GatheredClientInitials has expired.
func (gci *GatheredClientInitials) Expired() bool {
	return time.Now().After(gci.deadline)
}

func (gci *GatheredClientInitials) lockedGatherComplete() error {
	var err error
	// First, reconstruct the ClientHello
	gci.ClientHello, err = gci.clientHelloReconstructor.Reconstruct()
	if err != nil {
		return fmt.Errorf("failed to reconstruct ClientHello: %w", err)
	}

	// Next, point the TransportParameters to the ClientHello's qtp
	gci.TransportParameters = gci.ClientHello.qtp

	// Then calculate the NumericID
	numericID := gci.calcNumericID()
	atomic.StoreUint64(&gci.NumID, numericID)
	gci.HexID = FingerprintID(numericID).AsHex()

	// Finally, mark the completion
	gci.completed.Store(true)
	gci.completeChanCloseOnce.Do(func() {
		close(gci.completeChan)
	})

	return nil
}

// SetDeadline sets the deadline for the GatheredClientInitials to complete.
func (gci *GatheredClientInitials) SetDeadline(deadline time.Time) {
	gci.deadline = deadline
}

// SetMaxPacketNumber sets how far, in packet numbers, a Client Initial may lie
// from the first Initial observed for this connection and still be gathered.
// Packets beyond that distance are rejected.
//
// It is a distance rather than an absolute ceiling because clients may start
// numbering their Initials anywhere; see DEFAULT_MAX_INITIAL_PACKET_NUMBER.
//
// This function can be used as a precaution against memory exhaustion attacks.
func (gci *GatheredClientInitials) SetMaxPacketNumber(maxPacketNumber uint64) {
	atomic.StoreUint64(&gci.maxPacketNumber, maxPacketNumber)
}

// pnDistance returns the absolute difference between two packet numbers, so a
// reordered capture -- where a lower packet number arrives second -- is not
// penalised by the span guard.
func pnDistance(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// SetMaxPacketCount sets the maximum number of packets to be gathered.
// If more Client Initial packets are received, they will be rejected.
//
// This function can be used as a precaution against memory exhaustion attacks.
func (gci *GatheredClientInitials) SetMaxPacketCount(maxPacketCount uint64) {
	atomic.StoreUint64(&gci.maxPacketCount, maxPacketCount)
}

// Wait blocks until the GatheredClientInitials is complete or expired.
func (gci *GatheredClientInitials) Wait() error {
	if gci.completed.Load() {
		return nil
	}

	select {
	case <-time.After(time.Until(gci.deadline)):
		return ErrGatheringExpired
	case <-gci.completeChan:
		if gci.completed.Load() {
			return nil
		}
		return ErrGatheredClientInitialsChannelClosedBeforeCompletion // divergent state, only possible reason is GC
	}
}
