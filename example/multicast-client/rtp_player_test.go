package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildH264SDP(t *testing.T) {
	sdp, err := buildH264SDP(22222, 96, "Z2QAH6zZQFAFuhAAAAMAEAAAAwPA8YMZYA==,aOvjyyLA")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"c=IN IP4 127.0.0.1",
		"m=video 22222 RTP/AVP 96",
		"a=rtpmap:96 H264/90000",
		"a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z2QAH6zZQFAFuhAAAAMAEAAAAwPA8YMZYA==,aOvjyyLA",
		"a=recvonly",
	} {
		if !strings.Contains(sdp, expected) {
			t.Fatalf("SDP missing %q:\n%s", expected, sdp)
		}
	}

	withoutSprop, err := buildH264SDP(11111, 96, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withoutSprop, "sprop-parameter-sets") {
		t.Fatalf("SDP unexpectedly contains sprop-parameter-sets:\n%s", withoutSprop)
	}
}

func TestBuildH264SDPRejectsInvalidInput(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, err := buildH264SDP(port, 96, ""); err == nil {
			t.Fatalf("expected port %d to fail", port)
		}
	}
	if _, err := buildH264SDP(1234, 96, "sps,pps\ninjected"); err == nil {
		t.Fatal("expected newline in sprop-parameter-sets to fail")
	}
}

func TestParseRTPPacketFromCapture(t *testing.T) {
	packet, err := hex.DecodeString("80600df3221a4b914f4284c27c45")
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseRTPPacket(packet, 96)
	if err != nil {
		t.Fatal(err)
	}
	if info.PayloadType != 96 ||
		info.Marker ||
		info.Sequence != 3571 ||
		info.Timestamp != 0x221a4b91 ||
		info.SSRC != 0x4f4284c2 ||
		!bytes.Equal(info.Payload, []byte{0x7c, 0x45}) {
		t.Fatalf("unexpected RTP info: %+v", info)
	}
}

func TestParseRTPPacketWithCSRCsExtensionAndPadding(t *testing.T) {
	packet := []byte{
		0xb1, 0xe0, 0, 42,
		0, 0, 0, 1,
		0, 0, 0, 2,
		0, 0, 0, 3, // one CSRC
		0xbe, 0xde, 0, 1,
		1, 2, 3, 4, // one extension word
		0x65, 0xaa, // H.264 payload
		0, 2, // two bytes of padding
	}
	info, err := parseRTPPacket(packet, 96)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Marker || info.Sequence != 42 {
		t.Fatalf("unexpected RTP header: %+v", info)
	}
	if !bytes.Equal(info.Payload, []byte{0x65, 0xaa}) {
		t.Fatalf("payload = %x, want 65aa", info.Payload)
	}
}

func TestParseRTPPacketRejectsMalformedPackets(t *testing.T) {
	testCases := []struct {
		name   string
		packet []byte
		pt     uint8
	}{
		{name: "short", packet: []byte{0x80}, pt: 96},
		{name: "version", packet: append([]byte{0x40, 0x60}, make([]byte, 11)...), pt: 96},
		{name: "payload type", packet: append([]byte{0x80, 97}, make([]byte, 11)...), pt: 96},
		{name: "CSRC", packet: append([]byte{0x81, 96}, make([]byte, 11)...), pt: 96},
		{name: "extension", packet: append([]byte{0x90, 96}, make([]byte, 11)...), pt: 96},
		{name: "zero padding", packet: append([]byte{0xa0, 96}, make([]byte, 11)...), pt: 96},
		{name: "no payload", packet: append([]byte{0x80, 96}, make([]byte, 10)...), pt: 96},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := parseRTPPacket(testCase.packet, testCase.pt); err == nil {
				t.Fatalf("expected packet %x to fail", testCase.packet)
			}
		})
	}
}

func TestH264NALTypes(t *testing.T) {
	testCases := []struct {
		name     string
		payload  []byte
		expected []uint8
	}{
		{name: "single IDR", payload: []byte{0x65, 1}, expected: []uint8{5}},
		{name: "FU-A IDR", payload: []byte{0x7c, 0x85, 1}, expected: []uint8{5}},
		{
			name:     "STAP-A",
			payload:  []byte{0x18, 0, 2, 0x09, 0x30, 0, 1, 0x41},
			expected: []uint8{9, 1},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			types, err := h264NALTypes(testCase.payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(types, testCase.expected) {
				t.Fatalf("NAL types = %v, want %v", types, testCase.expected)
			}
		})
	}

	for _, payload := range [][]byte{nil, {0x7c}, {0x18, 0}, {0x18, 0, 2, 0x09}} {
		if _, err := h264NALTypes(payload); err == nil {
			t.Fatalf("expected malformed payload %x to fail", payload)
		}
	}
}

type recordingPacketWriter struct {
	data   []byte
	err    error
	closed bool
}

func (w *recordingPacketWriter) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.data = append(w.data[:0], data...)
	return len(data), nil
}

func (w *recordingPacketWriter) Close() error {
	w.closed = true
	return nil
}

func TestRTPPlayerForwardsPacketUnchanged(t *testing.T) {
	writer := &recordingPacketWriter{}
	player := &rtpPlayer{conn: writer}
	packet := []byte{0x80, 0x60, 1, 2, 3, 4}
	if err := player.WriteRTP(packet); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.data, packet) {
		t.Fatalf("forwarded packet = %x, want %x", writer.data, packet)
	}

	sentinel := errors.New("write failed")
	writer.err = sentinel
	if err := player.WriteRTP(packet); !errors.Is(err, sentinel) {
		t.Fatalf("WriteRTP error = %v, want %v", err, sentinel)
	}
}

func TestUDPPacketWriterForwardsPacketUnchanged(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	writer := &udpPacketWriter{
		conn:   sender,
		target: receiver.LocalAddr().(*net.UDPAddr),
	}
	packet := []byte{0x80, 0x60, 1, 2, 3, 4}
	if _, err := writer.Write(packet); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, 64)
	n, _, err := receiver.ReadFromUDP(received)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received[:n], packet) {
		t.Fatalf("received packet = %x, want %x", received[:n], packet)
	}
}

func TestWaitForLoopbackUDPListener(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	done := make(chan struct{})
	if err := waitForLoopbackUDPListener(
		context.Background(),
		listener.LocalAddr().(*net.UDPAddr),
		done,
		time.Second,
	); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForLoopbackUDPListenerReportsEarlyExit(t *testing.T) {
	port, err := availableLoopbackUDPPort()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)

	err = waitForLoopbackUDPListener(
		context.Background(),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
		done,
		time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "ffplay exited") {
		t.Fatalf("error = %v, want ffplay exit error", err)
	}
}

func TestFFplayArgumentsConfigureRTPJitter(t *testing.T) {
	arguments := strings.Join(ffplayArguments(), " ")
	for _, expected := range []string{
		"-protocol_whitelist pipe,udp,rtp",
		"-reorder_queue_size 64",
		"-max_delay 100000",
		"-f sdp -i pipe:0",
		"-framedrop",
	} {
		if !strings.Contains(arguments, expected) {
			t.Fatalf("ffplay arguments missing %q: %s", expected, arguments)
		}
	}
}
