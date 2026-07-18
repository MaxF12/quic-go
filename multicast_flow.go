package quic

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
)

const (
	multicastDuplicateWindow  = 4096
	maxQueuedMulticastPackets = 64
)

// multicastFlow contains receive state that is deliberately independent from
// the connection's unicast packet number and recovery state.
type multicastFlow struct {
	id                protocol.ConnectionID
	sourceAddress     net.IP
	groupAddress      net.IP
	udpPort           uint16
	cipherSuite       uint16
	firstPacketNumber protocol.PacketNumber
	secretHash        [sha256.Size]byte

	opener   handshake.MulticastOpener
	unpacker *packetUnpacker
	receiver multicastReceiver
	history  multicastPacketHistory

	closed    chan struct{}
	closeOnce sync.Once
	readWG    sync.WaitGroup
}

type multicastPacketHistory struct {
	largest protocol.PacketNumber
	seen    map[protocol.PacketNumber]struct{}
}

func newMulticastPacketHistory() multicastPacketHistory {
	return multicastPacketHistory{
		largest: protocol.InvalidPacketNumber,
		seen:    make(map[protocol.PacketNumber]struct{}),
	}
}

func (h *multicastPacketHistory) add(pn protocol.PacketNumber) bool {
	if pn < 0 {
		return false
	}
	if _, ok := h.seen[pn]; ok {
		return false
	}
	if h.largest >= multicastDuplicateWindow {
		cutoff := h.largest - multicastDuplicateWindow
		if pn <= cutoff {
			return false
		}
	}
	h.seen[pn] = struct{}{}
	if pn <= h.largest {
		return true
	}
	h.largest = pn
	if h.largest < multicastDuplicateWindow {
		return true
	}
	cutoff := h.largest - multicastDuplicateWindow
	for seenPN := range h.seen {
		if seenPN <= cutoff {
			delete(h.seen, seenPN)
		}
	}
	return true
}

func (f *multicastFlow) matches(frame *wire.MCFlowFrame) bool {
	if f.id != frame.FlowID ||
		!f.sourceAddress.Equal(frame.SourceAddress.AsSlice()) ||
		!f.groupAddress.Equal(frame.GroupAddress.AsSlice()) ||
		f.udpPort != frame.UDPPort ||
		f.cipherSuite != frame.CipherSuite ||
		f.firstPacketNumber != frame.FirstPacketNumber {
		return false
	}
	hash := sha256.Sum256(frame.Secret)
	return subtle.ConstantTimeCompare(f.secretHash[:], hash[:]) == 1
}

func (f *multicastFlow) close() {
	f.closeOnce.Do(func() {
		close(f.closed)
		_ = f.receiver.Close()
		f.readWG.Wait()
		f.opener = nil
		f.receiver = nil
	})
}

func (c *Conn) multicastDebugf(format string, args ...any) {
	if c.qlogger == nil {
		return
	}
	c.qlogger.RecordEvent(qlog.DebugEvent{
		EventName: "multicast",
		Message:   fmt.Sprintf(format, args...),
	})
}

func (c *Conn) handleMCFlowFrame(frame *wire.MCFlowFrame) error {
	c.multicastDebugf(
		"received MC_FLOW flow_id=%s ip_version=%d source=%s group=%s port=%d cipher_suite=%#x first_packet_number=%d secret_length=%d",
		frame.FlowID,
		frame.IPVersion,
		frame.SourceAddress,
		frame.GroupAddress,
		frame.UDPPort,
		frame.CipherSuite,
		frame.FirstPacketNumber,
		len(frame.Secret),
	)
	if c.perspective != protocol.PerspectiveClient || !c.config.EnableMulticast {
		c.multicastDebugf("rejected MC_FLOW reason=multicast_not_enabled_for_client")
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			FrameType:    uint64(wire.FrameTypeMCFlow),
			ErrorMessage: "received MC_FLOW without multicast support",
		}
	}

	if len(frame.Secret) == 0 {
		if c.multicastFlow != nil && c.multicastFlow.id == frame.FlowID {
			c.multicastDebugf("withdrawing multicast flow flow_id=%s", frame.FlowID)
			c.closeMulticastFlow()
		} else {
			c.multicastDebugf("ignored multicast withdrawal flow_id=%s reason=flow_not_active", frame.FlowID)
		}
		return nil
	}

	if frame.IPVersion != 4 && frame.IPVersion != 6 {
		c.multicastDebugf("rejected MC_FLOW reason=unsupported_ip_version value=%d", frame.IPVersion)
		return multicastFlowProtocolError("unsupported multicast IP version")
	}
	if frame.CipherSuite != tls.TLS_AES_128_GCM_SHA256 {
		c.multicastDebugf("rejected MC_FLOW reason=unsupported_cipher_suite value=%#x", frame.CipherSuite)
		return multicastFlowProtocolError("unsupported multicast cipher suite")
	}
	if len(frame.Secret) != sha256.Size {
		c.multicastDebugf("rejected MC_FLOW reason=invalid_secret_length value=%d", len(frame.Secret))
		return multicastFlowProtocolError("invalid multicast traffic secret length")
	}
	if frame.UDPPort == 0 {
		c.multicastDebugf("rejected MC_FLOW reason=invalid_udp_port")
		return multicastFlowProtocolError("invalid multicast UDP port")
	}
	if c.multicastFlow != nil {
		if c.multicastFlow.matches(frame) {
			c.multicastDebugf("ignored retransmitted MC_FLOW flow_id=%s reason=already_active", frame.FlowID)
			return nil
		}
		c.multicastDebugf(
			"rejected MC_FLOW reason=second_distinct_flow active_flow_id=%s new_flow_id=%s",
			c.multicastFlow.id,
			frame.FlowID,
		)
		return multicastFlowProtocolError("received a second distinct multicast flow")
	}

	c.multicastDebugf("deriving multicast packet protection flow_id=%s", frame.FlowID)
	opener, err := handshake.NewMulticastOpener(
		frame.CipherSuite,
		frame.Secret,
		frame.FirstPacketNumber,
		c.version,
	)
	if err != nil {
		c.multicastDebugf("rejected MC_FLOW reason=packet_protection_setup error=%v", err)
		return multicastFlowProtocolError(err.Error())
	}
	mode := "ASM"
	if isIPv4SSMGroup(frame.GroupAddress) || isIPv6SSMGroup(frame.GroupAddress) {
		mode = "SSM"
	}
	c.multicastDebugf(
		"opening multicast receiver flow_id=%s mode=%s source=%s group=%s port=%d interface=%q",
		frame.FlowID,
		mode,
		frame.SourceAddress,
		frame.GroupAddress,
		frame.UDPPort,
		c.config.MulticastInterface,
	)
	receiver, err := multicastReceiverFactory(
		frame.SourceAddress,
		frame.GroupAddress,
		frame.UDPPort,
		c.config.MulticastInterface,
		multicastDebugFunc(c.multicastDebugf),
	)
	if err != nil {
		c.multicastDebugf("multicast receiver setup failed flow_id=%s error=%v", frame.FlowID, err)
		return fmt.Errorf("joining multicast flow: %w", err)
	}

	flow := &multicastFlow{
		id:                frame.FlowID,
		sourceAddress:     net.IP(frame.SourceAddress.AsSlice()),
		groupAddress:      net.IP(frame.GroupAddress.AsSlice()),
		udpPort:           frame.UDPPort,
		cipherSuite:       frame.CipherSuite,
		firstPacketNumber: frame.FirstPacketNumber,
		secretHash:        sha256.Sum256(frame.Secret),
		opener:            opener,
		unpacker:          &packetUnpacker{shortHdrConnIDLen: frame.FlowID.Len()},
		receiver:          receiver,
		history:           newMulticastPacketHistory(),
		closed:            make(chan struct{}),
	}
	c.multicastFlow = flow
	c.multicastDebugf("installed multicast flow flow_id=%s; starting receive loop", frame.FlowID)
	flow.readWG.Add(1)
	go c.readMulticastPackets(flow)
	return nil
}

func multicastFlowProtocolError(message string) error {
	return &qerr.TransportError{
		ErrorCode:    qerr.ProtocolViolation,
		FrameType:    uint64(wire.FrameTypeMCFlow),
		ErrorMessage: message,
	}
}

func (c *Conn) closeMulticastFlow() {
	if c.multicastFlow == nil {
		return
	}
	flow := c.multicastFlow
	c.multicastFlow = nil
	c.multicastDebugf("closing multicast flow flow_id=%s", flow.id)
	flow.close()
	c.multicastDebugf("closed multicast flow flow_id=%s", flow.id)
}

func (c *Conn) readMulticastPackets(flow *multicastFlow) {
	defer flow.readWG.Done()
	c.multicastDebugf("multicast receive loop started flow_id=%s", flow.id)
	for {
		buffer := getPacketBuffer()
		buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
		n, remoteAddr, err := flow.receiver.Read(buffer.Data)
		if err != nil {
			buffer.Release()
			select {
			case <-flow.closed:
				c.multicastDebugf("multicast receive loop stopped flow_id=%s", flow.id)
				return
			default:
			}
			//nolint:staticcheck // Match the transport receive loop for this PoC.
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				c.multicastDebugf("temporary multicast receive error flow_id=%s error=%v", flow.id, err)
				continue
			}
			c.multicastDebugf("disabling multicast receiver flow_id=%s error=%v", flow.id, err)
			if c.logger != nil {
				c.logger.Errorf("Disabling multicast flow after receive error: %s", err)
			}
			_ = flow.receiver.Close()
			return
		}
		if n == 0 {
			c.multicastDebugf("ignored empty multicast UDP packet flow_id=%s source=%s", flow.id, remoteAddr)
			buffer.Release()
			continue
		}
		c.multicastDebugf(
			"queued multicast UDP packet flow_id=%s bytes=%d source=%s",
			flow.id,
			n,
			remoteAddr,
		)
		buffer.Data = buffer.Data[:n]
		c.queueMulticastPacket(receivedPacket{
			buffer:     buffer,
			remoteAddr: remoteAddr,
			rcvTime:    monotime.Now(),
			data:       buffer.Data,
			multicast:  true,
		})
	}
}

func (c *Conn) queueMulticastPacket(p receivedPacket) {
	c.receivedPacketMx.Lock()
	if c.multicastPackets.Len() >= maxQueuedMulticastPackets {
		c.receivedPacketMx.Unlock()
		c.multicastDebugf(
			"dropped multicast UDP packet reason=connection_queue_full bytes=%d source=%s",
			len(p.data),
			p.remoteAddr,
		)
		p.buffer.Decrement()
		p.buffer.MaybeRelease()
		return
	}
	c.multicastPackets.PushBack(p)
	c.receivedPacketMx.Unlock()

	select {
	case c.notifyReceivedPacket <- struct{}{}:
	default:
	}
}

// handleMulticastPacket runs on the connection event loop. It intentionally
// doesn't call any ACK, loss recovery, path migration, RTT or idle-time code.
func (c *Conn) handleMulticastPacket(p receivedPacket) {
	defer func() {
		p.buffer.Decrement()
		p.buffer.MaybeRelease()
	}()

	flow := c.multicastFlow
	if flow == nil {
		c.multicastDebugf("dropped multicast QUIC packet reason=no_active_flow bytes=%d", len(p.data))
		return
	}
	if len(p.data) == 0 {
		c.multicastDebugf("dropped multicast QUIC packet flow_id=%s reason=empty_packet", flow.id)
		return
	}
	if wire.IsLongHeaderPacket(p.data[0]) {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s reason=long_header bytes=%d",
			flow.id,
			len(p.data),
		)
		return
	}
	destConnID, err := wire.ParseConnectionID(p.data, flow.id.Len())
	if err != nil {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s reason=connection_id_parse error=%v",
			flow.id,
			err,
		)
		return
	}
	if destConnID != flow.id {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s reason=connection_id_mismatch got=%s",
			flow.id,
			destConnID,
		)
		return
	}
	headerLen, pn, pnLen, keyPhase, parseErr := flow.unpacker.unpackShortHeader(flow.opener, p.data)
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s reason=header_protection error=%v",
			flow.id,
			parseErr,
		)
		return
	}
	pn = flow.opener.DecodePacketNumber(pn, pnLen)
	data, err := flow.opener.Open(
		p.data[headerLen:headerLen],
		p.data[headerLen:],
		p.rcvTime,
		pn,
		keyPhase,
		p.data[:headerLen],
	)
	if err != nil {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s packet_number=%d reason=authentication_failed error=%v",
			flow.id,
			pn,
			err,
		)
		return
	}
	if parseErr != nil {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s packet_number=%d reason=invalid_reserved_bits",
			flow.id,
			pn,
		)
		return
	}
	if keyPhase != protocol.KeyPhaseZero {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s packet_number=%d reason=key_phase got=%s",
			flow.id,
			pn,
			keyPhase,
		)
		return
	}
	if len(data) == 0 {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s packet_number=%d reason=empty_plaintext",
			flow.id,
			pn,
		)
		return
	}
	flow.opener.CommitPacketNumber(pn)
	if !flow.history.add(pn) {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s packet_number=%d reason=duplicate_or_stale",
			flow.id,
			pn,
		)
		return
	}
	frames, reason := c.parseMulticastFrames(data)
	if reason != "" {
		c.multicastDebugf(
			"dropped multicast QUIC packet flow_id=%s packet_number=%d reason=%s",
			flow.id,
			pn,
			reason,
		)
		return
	}
	queued := 0
	for _, frame := range frames {
		if c.datagramQueue.HandleDatagramFrame(frame) {
			queued++
		} else {
			c.multicastDebugf(
				"dropped multicast DATAGRAM flow_id=%s packet_number=%d reason=application_queue_full payload_bytes=%d",
				flow.id,
				pn,
				len(frame.Data),
			)
		}
	}
	c.multicastDebugf(
		"accepted multicast QUIC packet flow_id=%s packet_number=%d packet_number_length=%d datagrams=%d queued=%d plaintext_bytes=%d",
		flow.id,
		pn,
		pnLen,
		len(frames),
		queued,
		len(data),
	)
}

func (c *Conn) parseMulticastFrames(data []byte) ([]*wire.DatagramFrame, string) {
	var datagrams []*wire.DatagramFrame
	for len(data) > 0 {
		frameType, n, err := c.frameParser.ParseType(data, protocol.Encryption1RTT)
		if errors.Is(err, io.EOF) {
			return datagrams, ""
		}
		if err != nil {
			return nil, "frame_type_parse"
		}
		data = data[n:]
		switch {
		case frameType == wire.FrameTypePing:
			continue
		case frameType.IsDatagramFrameType():
			frame, n, err := c.frameParser.ParseDatagramFrame(frameType, data, c.version)
			if err != nil {
				return nil, "datagram_frame_parse"
			}
			if frame.Length(c.version) > wire.MaxDatagramSize {
				return nil, "datagram_frame_too_large"
			}
			data = data[n:]
			datagrams = append(datagrams, frame)
		default:
			// Multicast input must never turn a prohibited frame into a
			// connection error or mutate unicast transport state.
			return nil, fmt.Sprintf("prohibited_frame_type_%#x", uint64(frameType))
		}
	}
	return datagrams, ""
}
