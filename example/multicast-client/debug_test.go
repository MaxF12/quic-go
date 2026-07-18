package main

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

func TestDebugTraceReportsMulticastMetadataWithoutSecrets(t *testing.T) {
	var output bytes.Buffer
	status := &debugStatus{}
	newTrace := newDebugConnectionTracer(log.New(&output, "", 0), status)
	trace := newTrace(
		context.Background(),
		true,
		quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4}),
	)
	recorder := trace.AddProducer()

	const secret = "do-not-print-this-token"
	recorder.RecordEvent(qlog.PacketReceived{
		Header: qlog.PacketHeader{
			PacketType:   qlog.PacketType1RTT,
			PacketNumber: 42,
		},
		Raw: qlog.RawInfo{Length: 1200, PayloadLength: 1180},
		Frames: []qlog.Frame{
			{Frame: &qlog.MulticastFlowFrame{
				FlowID:            "deadbeef",
				IPVersion:         6,
				SourceAddress:     "2001:db8::1",
				GroupAddress:      "ff3e:30:3ffe:ffff:1::4",
				UDPPort:           5000,
				CipherSuite:       0x1301,
				FirstPacketNumber: 7,
				SecretLength:      32,
			}},
			{Frame: &qlog.NewTokenFrame{Token: []byte(secret)}},
		},
	})
	recorder.RecordEvent(qlog.DebugEvent{
		EventName: "untrusted",
		Message:   secret,
	})
	recorder.RecordEvent(qlog.DebugEvent{
		EventName: "multicast",
		Message:   "joined IPv6 ASM channel=(*,ff3e:30:3ffe:ffff:1::4)",
	})

	logged := output.String()
	for _, expected := range []string{
		"MC_FLOW(",
		"source=2001:db8::1",
		"group=ff3e:30:3ffe:ffff:1::4",
		"secret_length=32",
		"NewTokenFrame",
		"joined IPv6 ASM",
	} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("debug output missing %q:\n%s", expected, logged)
		}
	}
	if strings.Contains(logged, secret) {
		t.Fatalf("debug output leaked secret %q:\n%s", secret, logged)
	}
	if got := status.packetsReceived.Load(); got != 1 {
		t.Fatalf("received packet count = %d, want 1", got)
	}
	if got := status.multicastFlowFrames.Load(); got != 1 {
		t.Fatalf("MC_FLOW count = %d, want 1", got)
	}
	if got := status.multicastEvents.Load(); got != 1 {
		t.Fatalf("multicast event count = %d, want 1", got)
	}
}
