package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// debugStatus keeps the final diagnostic useful even when dialing fails before
// the caller receives a connection.
type debugStatus struct {
	packetsSent              atomic.Uint64
	packetsReceived          atomic.Uint64
	multicastFlowFrames      atomic.Uint64
	multicastEvents          atomic.Uint64
	multicastPacketsAccepted atomic.Uint64
}

func (s *debugStatus) String() string {
	return fmt.Sprintf(
		"packets_sent=%d packets_received=%d mc_flow_frames=%d multicast_events=%d multicast_packets_accepted=%d",
		s.packetsSent.Load(),
		s.packetsReceived.Load(),
		s.multicastFlowFrames.Load(),
		s.multicastEvents.Load(),
		s.multicastPacketsAccepted.Load(),
	)
}

func newDebugConnectionTracer(
	logger *log.Logger,
	status *debugStatus,
) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	return func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		role := "server"
		if isClient {
			role = "client"
		}
		trace := &debugTrace{
			logger: logger,
			status: status,
			start:  time.Now(),
		}
		trace.logf("trace started role=%s connection_id=%s", role, connID)
		return trace
	}
}

type debugTrace struct {
	logger *log.Logger
	status *debugStatus
	start  time.Time
}

var _ qlogwriter.Trace = (*debugTrace)(nil)

func (t *debugTrace) AddProducer() qlogwriter.Recorder {
	return &debugRecorder{trace: t}
}

func (t *debugTrace) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema
}

func (t *debugTrace) logf(format string, args ...any) {
	elapsed := time.Since(t.start).Round(time.Microsecond)
	t.logger.Printf("[+%s] %s", elapsed, fmt.Sprintf(format, args...))
}

type debugRecorder struct {
	trace *debugTrace
}

var _ qlogwriter.Recorder = (*debugRecorder)(nil)

func (r *debugRecorder) Close() error { return nil }

func (r *debugRecorder) RecordEvent(event qlogwriter.Event) {
	switch event := event.(type) {
	case qlog.StartedConnection:
		r.recordStartedConnection(event)
	case *qlog.StartedConnection:
		r.recordStartedConnection(*event)
	case qlog.VersionInformation:
		r.recordVersionInformation(event)
	case *qlog.VersionInformation:
		r.recordVersionInformation(*event)
	case qlog.PacketSent:
		r.recordPacketSent(event)
	case *qlog.PacketSent:
		r.recordPacketSent(*event)
	case qlog.PacketReceived:
		r.recordPacketReceived(event)
	case *qlog.PacketReceived:
		r.recordPacketReceived(*event)
	case qlog.PacketDropped:
		r.recordPacketDropped(event)
	case *qlog.PacketDropped:
		r.recordPacketDropped(*event)
	case qlog.ParametersSet:
		r.recordParametersSet(event)
	case *qlog.ParametersSet:
		r.recordParametersSet(*event)
	case qlog.ALPNInformation:
		r.trace.logf("TLS ALPN negotiated protocol=%q", event.ChosenALPN)
	case *qlog.ALPNInformation:
		r.trace.logf("TLS ALPN negotiated protocol=%q", event.ChosenALPN)
	case qlog.PTOCountUpdated:
		r.trace.logf("loss recovery PTO count=%d", event.PTOCount)
	case *qlog.PTOCountUpdated:
		r.trace.logf("loss recovery PTO count=%d", event.PTOCount)
	case qlog.PacketLost:
		r.recordPacketLost(event)
	case *qlog.PacketLost:
		r.recordPacketLost(*event)
	case qlog.KeyUpdated:
		r.trace.logf(
			"TLS key updated type=%s phase=%d trigger=%s",
			event.KeyType,
			event.KeyPhase,
			event.Trigger,
		)
	case *qlog.KeyUpdated:
		r.trace.logf(
			"TLS key updated type=%s phase=%d trigger=%s",
			event.KeyType,
			event.KeyPhase,
			event.Trigger,
		)
	case qlog.KeyDiscarded:
		r.trace.logf("TLS key discarded type=%s phase=%d", event.KeyType, event.KeyPhase)
	case *qlog.KeyDiscarded:
		r.trace.logf("TLS key discarded type=%s phase=%d", event.KeyType, event.KeyPhase)
	case qlog.ConnectionClosed:
		r.recordConnectionClosed(event)
	case *qlog.ConnectionClosed:
		r.recordConnectionClosed(*event)
	case qlog.DebugEvent:
		r.recordDebugEvent(event)
	case *qlog.DebugEvent:
		r.recordDebugEvent(*event)
	}
}

func (r *debugRecorder) recordStartedConnection(event qlog.StartedConnection) {
	r.trace.logf(
		"connection started local=%s remote=%s",
		formatPathEndpoint(event.Local),
		formatPathEndpoint(event.Remote),
	)
}

func (r *debugRecorder) recordVersionInformation(event qlog.VersionInformation) {
	r.trace.logf(
		"version information client=%s server=%s chosen=%x",
		formatVersions(event.ClientVersions),
		formatVersions(event.ServerVersions),
		uint32(event.ChosenVersion),
	)
}

func (r *debugRecorder) recordPacketSent(event qlog.PacketSent) {
	r.trace.status.packetsSent.Add(1)
	r.trace.logf(
		"sent %s bytes=%d payload_bytes=%d frames=%s trigger=%q",
		formatPacketHeader(event.Header),
		event.Raw.Length,
		event.Raw.PayloadLength,
		r.formatFrames(event.Frames),
		event.Trigger,
	)
}

func (r *debugRecorder) recordPacketReceived(event qlog.PacketReceived) {
	r.trace.status.packetsReceived.Add(1)
	r.trace.logf(
		"received %s bytes=%d payload_bytes=%d frames=%s trigger=%q",
		formatPacketHeader(event.Header),
		event.Raw.Length,
		event.Raw.PayloadLength,
		r.formatFrames(event.Frames),
		event.Trigger,
	)
}

func (r *debugRecorder) recordPacketDropped(event qlog.PacketDropped) {
	r.trace.logf(
		"dropped unicast packet %s bytes=%d trigger=%s",
		formatPacketHeader(event.Header),
		event.Raw.Length,
		event.Trigger,
	)
}

func (r *debugRecorder) recordParametersSet(event qlog.ParametersSet) {
	r.trace.logf(
		"transport parameters restore=%t initiator=%s idle_timeout=%s max_udp_payload=%d max_datagram_frame=%d",
		event.Restore,
		event.Initiator,
		event.MaxIdleTimeout,
		event.MaxUDPPayloadSize,
		event.MaxDatagramFrameSize,
	)
}

func (r *debugRecorder) recordPacketLost(event qlog.PacketLost) {
	r.trace.logf(
		"lost %s trigger=%s",
		formatPacketHeader(event.Header),
		event.Trigger,
	)
}

func (r *debugRecorder) recordConnectionClosed(event qlog.ConnectionClosed) {
	connectionCode := "none"
	if event.ConnectionError != nil {
		connectionCode = fmt.Sprintf("%#x", uint64(*event.ConnectionError))
	}
	applicationCode := "none"
	if event.ApplicationError != nil {
		applicationCode = fmt.Sprintf("%#x", uint64(*event.ApplicationError))
	}
	// The reason is deliberately omitted: it can be arbitrary peer or
	// application text. The normal client error still prints it.
	r.trace.logf(
		"connection closed initiator=%s transport_code=%s application_code=%s trigger=%s",
		event.Initiator,
		connectionCode,
		applicationCode,
		event.Trigger,
	)
}

func (r *debugRecorder) recordDebugEvent(event qlog.DebugEvent) {
	// Only multicast messages emitted by this fork are part of the safe
	// diagnostic surface. Ignore arbitrary DebugEvents from other producers.
	if event.EventName != "multicast" {
		return
	}
	r.trace.status.multicastEvents.Add(1)
	if strings.HasPrefix(event.Message, "accepted multicast QUIC packet") {
		r.trace.status.multicastPacketsAccepted.Add(1)
	}
	r.trace.logf("multicast: %s", event.Message)
}

func (r *debugRecorder) formatFrames(frames []qlog.Frame) string {
	if len(frames) == 0 {
		return "[]"
	}
	formatted := make([]string, 0, len(frames))
	for _, wrapped := range frames {
		switch frame := wrapped.Frame.(type) {
		case *qlog.MulticastFlowFrame:
			r.trace.status.multicastFlowFrames.Add(1)
			formatted = append(formatted, formatMulticastFlowFrame(frame))
		case qlog.MulticastFlowFrame:
			r.trace.status.multicastFlowFrames.Add(1)
			formatted = append(formatted, formatMulticastFlowFrame(&frame))
		case *qlog.CryptoFrame:
			formatted = append(formatted, fmt.Sprintf("CRYPTO(offset=%d,length=%d)", frame.Offset, frame.Length))
		case *qlog.StreamFrame:
			formatted = append(
				formatted,
				fmt.Sprintf(
					"STREAM(id=%d,offset=%d,length=%d,fin=%t)",
					frame.StreamID,
					frame.Offset,
					frame.Length,
					frame.Fin,
				),
			)
		case *qlog.DatagramFrame:
			formatted = append(formatted, fmt.Sprintf("DATAGRAM(length=%d)", frame.Length))
		case *qlog.PingFrame:
			formatted = append(formatted, "PING")
		case *qlog.AckFrame:
			formatted = append(formatted, "ACK")
		case *qlog.HandshakeDoneFrame:
			formatted = append(formatted, "HANDSHAKE_DONE")
		default:
			// Some QUIC frames carry tokens or opaque challenge data. Print
			// only their Go type, never their values.
			formatted = append(formatted, safeTypeName(wrapped.Frame))
		}
	}
	return "[" + strings.Join(formatted, ",") + "]"
}

func formatMulticastFlowFrame(frame *qlog.MulticastFlowFrame) string {
	return fmt.Sprintf(
		"MC_FLOW(flow_id=%s,ip_version=%d,source=%s,group=%s,port=%d,cipher_suite=%#x,first_packet_number=%d,secret_length=%d)",
		frame.FlowID,
		frame.IPVersion,
		frame.SourceAddress,
		frame.GroupAddress,
		frame.UDPPort,
		frame.CipherSuite,
		frame.FirstPacketNumber,
		frame.SecretLength,
	)
}

func formatPacketHeader(header qlog.PacketHeader) string {
	fields := []string{fmt.Sprintf("packet_type=%s", header.PacketType)}
	if int64(header.PacketNumber) >= 0 {
		fields = append(fields, fmt.Sprintf("packet_number=%d", header.PacketNumber))
	}
	if header.Version != 0 {
		fields = append(fields, fmt.Sprintf("version=%x", uint32(header.Version)))
	}
	return strings.Join(fields, " ")
}

func formatPathEndpoint(endpoint qlog.PathEndpointInfo) string {
	var addresses []string
	for _, address := range []netip.AddrPort{endpoint.IPv4, endpoint.IPv6} {
		if address.IsValid() {
			addresses = append(addresses, address.String())
		}
	}
	if len(addresses) == 0 {
		return "<unknown>"
	}
	return strings.Join(addresses, ",")
}

func formatVersions(versions []qlog.Version) string {
	if len(versions) == 0 {
		return "[]"
	}
	formatted := make([]string, 0, len(versions))
	for _, version := range versions {
		formatted = append(formatted, fmt.Sprintf("%x", uint32(version)))
	}
	return "[" + strings.Join(formatted, ",") + "]"
}

func safeTypeName(value any) string {
	if value == nil {
		return "<nil>"
	}
	valueType := reflect.TypeOf(value)
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if valueType.Name() != "" {
		return valueType.Name()
	}
	return valueType.String()
}
