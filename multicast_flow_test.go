package quic

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

type blockingMulticastReceiver struct {
	closed chan struct{}
	once   sync.Once
}

type failingMulticastReceiver struct {
	closed bool
}

func (r *failingMulticastReceiver) Read([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("multicast receive failed")
}

func (r *failingMulticastReceiver) Close() error {
	r.closed = true
	return nil
}

func newBlockingMulticastReceiver() *blockingMulticastReceiver {
	return &blockingMulticastReceiver{closed: make(chan struct{})}
}

func (r *blockingMulticastReceiver) Read([]byte) (int, net.Addr, error) {
	<-r.closed
	return 0, nil, net.ErrClosed
}

func (r *blockingMulticastReceiver) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func TestMulticastFlowLifecycleAndDatagramDelivery(t *testing.T) {
	testMulticastFlowLifecycleAndDatagramDelivery(t, 4, "192.0.2.1", "232.1.1.1")
}

func TestASMMulticastFlowLifecycleAndDatagramDelivery(t *testing.T) {
	testMulticastFlowLifecycleAndDatagramDelivery(t, 4, "0.0.0.0", "239.192.74.99")
}

func TestIPv6ASMMulticastFlowLifecycleAndDatagramDelivery(t *testing.T) {
	testMulticastFlowLifecycleAndDatagramDelivery(
		t,
		6,
		"::",
		"ff3e:30:3ffe:ffff:1::4",
	)
}

func testMulticastFlowLifecycleAndDatagramDelivery(
	t *testing.T,
	ipVersion uint8,
	source, group string,
) {
	t.Helper()
	sourceAddress := netip.MustParseAddr(source)
	groupAddress := netip.MustParseAddr(group)
	receiver := newBlockingMulticastReceiver()
	oldFactory := multicastReceiverFactory
	var factoryCalls int
	multicastReceiverFactory = func(
		source, group netip.Addr,
		port uint16,
		interfaceName string,
		_ multicastDebugFunc,
	) (multicastReceiver, error) {
		factoryCalls++
		require.Equal(t, sourceAddress, source)
		require.Equal(t, groupAddress, group)
		require.Equal(t, uint16(5000), port)
		require.Equal(t, "en0", interfaceName)
		return receiver, nil
	}
	t.Cleanup(func() { multicastReceiverFactory = oldFactory })

	conn := &Conn{
		config:                 &Config{EnableMulticast: true, EnableDatagrams: true, MulticastInterface: "en0"},
		perspective:            protocol.PerspectiveClient,
		version:                protocol.Version1,
		frameParser:            *wire.NewFrameParser(true, false, false),
		datagramQueue:          newDatagramQueue(func() {}, nil),
		lastPacketReceivedTime: monotime.Time(1234),
	}
	t.Cleanup(conn.closeMulticastFlow)

	firstPN := protocol.PacketNumber(1<<32 + 7)
	secret := []byte("0123456789abcdef0123456789abcdef")
	frame := &wire.MCFlowFrame{
		FlowID:            protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		IPVersion:         ipVersion,
		SourceAddress:     sourceAddress,
		GroupAddress:      groupAddress,
		UDPPort:           5000,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		FirstPacketNumber: firstPN,
		Secret:            secret,
	}
	require.NoError(t, conn.handleMCFlowFrame(frame))
	require.NotNil(t, conn.multicastFlow)
	require.Equal(t, 1, factoryCalls)

	// MC_FLOW is retransmitted by the normal unicast loss recovery machinery.
	// Reinstalling the same flow must therefore be idempotent.
	require.NoError(t, conn.handleMCFlowFrame(frame))
	require.Equal(t, 1, factoryCalls)

	datagram := &wire.DatagramFrame{DataLenPresent: true, Data: []byte("multicast payload")}
	payload, err := datagram.Append([]byte{0, byte(wire.FrameTypePing)}, protocol.Version1)
	require.NoError(t, err)
	packet := makeProtectedMulticastPacket(t, frame.FlowID, firstPN, secret, payload)
	conn.handleMulticastPacket(multicastReceivedPacket(packet))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := conn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("multicast payload"), data)
	require.Equal(t, monotime.Time(1234), conn.lastPacketReceivedTime)

	// A duplicate packet must not result in duplicate application delivery.
	conn.handleMulticastPacket(multicastReceivedPacket(packet))
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = conn.ReceiveDatagram(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	withdraw := *frame
	withdraw.Secret = nil
	require.NoError(t, conn.handleMCFlowFrame(&withdraw))
	require.Nil(t, conn.multicastFlow)
}

func TestMulticastFlowDropsProhibitedFrames(t *testing.T) {
	conn := &Conn{
		config:        &Config{EnableMulticast: true, EnableDatagrams: true},
		perspective:   protocol.PerspectiveClient,
		version:       protocol.Version1,
		frameParser:   *wire.NewFrameParser(true, false, false),
		datagramQueue: newDatagramQueue(func() {}, nil),
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	flowID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	opener, err := handshake.NewMulticastOpener(
		tls.TLS_AES_128_GCM_SHA256,
		secret,
		10,
		protocol.Version1,
	)
	require.NoError(t, err)
	conn.multicastFlow = &multicastFlow{
		id:       flowID,
		opener:   opener,
		unpacker: &packetUnpacker{shortHdrConnIDLen: flowID.Len()},
		history:  newMulticastPacketHistory(),
	}

	stream := &wire.StreamFrame{StreamID: 0, Data: []byte("not allowed")}
	payload, err := stream.Append(nil, protocol.Version1)
	require.NoError(t, err)
	packet := makeProtectedMulticastPacket(t, flowID, 10, secret, payload)
	conn.handleMulticastPacket(multicastReceivedPacket(packet))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = conn.ReceiveDatagram(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestMulticastFlowAcceptsVariableLengthPacketNumbers(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	flowID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	testCases := []struct {
		name         string
		packetNumber protocol.PacketNumber
		length       protocol.PacketNumberLen
	}{
		{name: "one byte", packetNumber: 0x7f, length: protocol.PacketNumberLen1},
		{name: "two bytes", packetNumber: 0x1234, length: protocol.PacketNumberLen2},
		{name: "three bytes", packetNumber: 37892, length: protocol.PacketNumberLen3},
		{name: "four bytes", packetNumber: 1<<24 + 7, length: protocol.PacketNumberLen4},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			conn := &Conn{
				config:        &Config{EnableMulticast: true, EnableDatagrams: true},
				perspective:   protocol.PerspectiveClient,
				version:       protocol.Version1,
				frameParser:   *wire.NewFrameParser(true, false, false),
				datagramQueue: newDatagramQueue(func() {}, nil),
			}
			opener, err := handshake.NewMulticastOpener(
				tls.TLS_AES_128_GCM_SHA256,
				secret,
				testCase.packetNumber,
				protocol.Version1,
			)
			require.NoError(t, err)
			conn.multicastFlow = &multicastFlow{
				id:       flowID,
				opener:   opener,
				unpacker: &packetUnpacker{shortHdrConnIDLen: flowID.Len()},
				history:  newMulticastPacketHistory(),
			}

			expected := []byte(testCase.name)
			datagram := &wire.DatagramFrame{DataLenPresent: true, Data: expected}
			payload, err := datagram.Append(nil, protocol.Version1)
			require.NoError(t, err)
			packet := makeProtectedMulticastPacketWithPacketNumberLength(
				t,
				flowID,
				testCase.packetNumber,
				testCase.length,
				secret,
				payload,
			)
			conn.handleMulticastPacket(multicastReceivedPacket(packet))

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			data, err := conn.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, expected, data)
		})
	}
}

func TestMulticastQueueIsBoundedSeparatelyFromUnicast(t *testing.T) {
	conn := &Conn{notifyReceivedPacket: make(chan struct{}, 1)}
	conn.receivedPackets.Init(8)
	conn.multicastPackets.Init(8)
	t.Cleanup(func() {
		for !conn.multicastPackets.Empty() {
			conn.multicastPackets.PopFront().buffer.Release()
		}
	})

	for range maxQueuedMulticastPackets {
		conn.queueMulticastPacket(multicastReceivedPacket([]byte{0x40}))
	}
	require.Equal(t, maxQueuedMulticastPackets, conn.multicastPackets.Len())

	dropped := multicastReceivedPacket([]byte{0x40})
	conn.queueMulticastPacket(dropped)
	require.Zero(t, dropped.buffer.refCount)
	require.Equal(t, maxQueuedMulticastPackets, conn.multicastPackets.Len())

	// A full multicast queue doesn't consume the unicast queue's capacity.
	conn.handlePacket(receivedPacket{data: []byte{0x40}})
	require.Equal(t, 1, conn.receivedPackets.Len())
}

func TestMulticastReadFailureDisablesOnlyReceiver(t *testing.T) {
	receiver := &failingMulticastReceiver{}
	flow := &multicastFlow{
		receiver: receiver,
		closed:   make(chan struct{}),
	}
	conn := &Conn{}
	flow.readWG.Add(1)
	go conn.readMulticastPackets(flow)
	flow.readWG.Wait()
	require.True(t, receiver.closed)
	require.Nil(t, conn.closeErr.Load())
}

func TestMCFlowRequiresClientOptIn(t *testing.T) {
	frame := &wire.MCFlowFrame{}
	conn := &Conn{config: &Config{}, perspective: protocol.PerspectiveClient}
	require.Error(t, conn.handleMCFlowFrame(frame))
	conn = &Conn{config: &Config{EnableMulticast: true}, perspective: protocol.PerspectiveServer}
	require.Error(t, conn.handleMCFlowFrame(frame))
}

func multicastReceivedPacket(data []byte) receivedPacket {
	buffer := getPacketBuffer()
	buffer.Data = append(buffer.Data, data...)
	return receivedPacket{
		buffer:    buffer,
		rcvTime:   monotime.Now(),
		data:      buffer.Data,
		multicast: true,
	}
}

func makeProtectedMulticastPacket(
	t *testing.T,
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	secret, payload []byte,
) []byte {
	return makeProtectedMulticastPacketWithPacketNumberLength(
		t,
		connID,
		pn,
		protocol.PacketNumberLen4,
		secret,
		payload,
	)
}

func makeProtectedMulticastPacketWithPacketNumberLength(
	t *testing.T,
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	pnLen protocol.PacketNumberLen,
	secret, payload []byte,
) []byte {
	t.Helper()
	key := expandLabel(t, secret, "quic key", 16)
	iv := expandLabel(t, secret, "quic iv", 12)
	hpKey := expandLabel(t, secret, "quic hp", 16)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)

	header, err := wire.AppendShortHeader(nil, connID, pn, pnLen, protocol.KeyPhaseZero)
	require.NoError(t, err)
	nonce := append([]byte(nil), iv...)
	var packetNumber [8]byte
	binary.BigEndian.PutUint64(packetNumber[:], uint64(pn))
	for i := range packetNumber {
		nonce[len(nonce)-len(packetNumber)+i] ^= packetNumber[i]
	}
	packet := append(header, aead.Seal(nil, nonce, payload, header)...)

	pnOffset := 1 + connID.Len()
	sample := packet[pnOffset+4 : pnOffset+4+aes.BlockSize]
	hpBlock, err := aes.NewCipher(hpKey)
	require.NoError(t, err)
	var mask [aes.BlockSize]byte
	hpBlock.Encrypt(mask[:], sample)
	packet[0] ^= mask[0] & 0x1f
	for i := range int(pnLen) {
		packet[pnOffset+i] ^= mask[i+1]
	}
	return packet
}

func expandLabel(t *testing.T, secret []byte, label string, length int) []byte {
	t.Helper()
	info := make([]byte, 3, 3+6+len(label)+1)
	binary.BigEndian.PutUint16(info, uint16(length))
	info[2] = byte(6 + len(label))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	value, err := hkdf.Expand(sha256.New, secret, string(info), length)
	require.NoError(t, err)
	return value
}
