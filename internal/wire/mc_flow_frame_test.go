package wire

import (
	"io"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func newIPv4MCFlowFrame() *MCFlowFrame {
	return &MCFlowFrame{
		FlowID:            protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		IPVersion:         4,
		SourceAddress:     netip.MustParseAddr("192.0.2.1"),
		GroupAddress:      netip.MustParseAddr("232.1.2.3"),
		UDPPort:           4242,
		CipherSuite:       0x1301,
		FirstPacketNumber: 0x1337,
		Secret:            []byte{1, 2, 3},
	}
}

func TestMCFlowFrameIPv4Encoding(t *testing.T) {
	frame := newIPv4MCFlowFrame()
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, []byte{
		0x80, 0xff, 0x4d, 0x43,
		0x4, 0xde, 0xad, 0xbe, 0xef,
		0x4,
		192, 0, 2, 1,
		232, 1, 2, 3,
		0x10, 0x92,
		0x13, 0x01,
		0x53, 0x37,
		0x3, 1, 2, 3,
	}, b)
	require.Equal(t, protocol.ByteCount(len(b)), frame.Length(protocol.Version1))

	parser := NewFrameParser(false, false, false)
	frameType, typeLen, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeMCFlow, frameType)
	require.Equal(t, quicvarint.Len(uint64(FrameTypeMCFlow)), typeLen)

	parsed, n, err := parser.ParseLessCommonFrame(frameType, b[typeLen:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b)-typeLen, n)
	require.Equal(t, frame, parsed)
}

func TestMCFlowFrameIPv6Withdrawal(t *testing.T) {
	frame := &MCFlowFrame{
		FlowID:            protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		IPVersion:         6,
		SourceAddress:     netip.MustParseAddr("2001:db8::1"),
		GroupAddress:      netip.MustParseAddr("ff3e::8000:1234"),
		UDPPort:           5000,
		CipherSuite:       0x1301,
		FirstPacketNumber: 1 << 30,
	}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(len(b)), frame.Length(protocol.Version1))

	typeLen := quicvarint.Len(uint64(FrameTypeMCFlow))
	parsed, n, err := parseMCFlowFrame(b[typeLen:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b)-typeLen, n)
	require.Equal(t, frame, parsed)
	require.Empty(t, parsed.Secret)
}

func TestMCFlowFrameParsingConsumesExactlyOneFrame(t *testing.T) {
	frame := newIPv4MCFlowFrame()
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	b = append(b, byte(FrameTypePing))

	typeLen := quicvarint.Len(uint64(FrameTypeMCFlow))
	parsed, n, err := parseMCFlowFrame(b[typeLen:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, frame, parsed)
	require.Equal(t, len(b)-typeLen-1, n)
}

func TestMCFlowFrameParsingErrorsOnTruncation(t *testing.T) {
	frame := newIPv4MCFlowFrame()
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	payload := b[quicvarint.Len(uint64(FrameTypeMCFlow)):]

	for i := range len(payload) {
		_, n, err := parseMCFlowFrame(payload[:i], protocol.Version1)
		require.Error(t, err, "expected error at length %d", i)
		require.Zero(t, n)
	}
}

func TestMCFlowFrameSecretLengthErrors(t *testing.T) {
	frame := newIPv4MCFlowFrame()
	frame.Secret = nil
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	payload := b[quicvarint.Len(uint64(FrameTypeMCFlow)):]

	t.Run("truncated varint", func(t *testing.T) {
		data := append([]byte(nil), payload...)
		data[len(data)-1] = 0x40
		_, n, err := parseMCFlowFrame(data, protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
		require.Zero(t, n)
	})

	t.Run("truncated secret", func(t *testing.T) {
		data := append([]byte(nil), payload...)
		data[len(data)-1] = 3
		data = append(data, 1, 2)
		_, n, err := parseMCFlowFrame(data, protocol.Version1)
		require.ErrorIs(t, err, io.EOF)
		require.Zero(t, n)
	})
}

func TestMCFlowFrameRejectsInvalidFlowIDs(t *testing.T) {
	t.Run("parse zero length", func(t *testing.T) {
		_, n, err := parseMCFlowFrame([]byte{0}, protocol.Version1)
		require.EqualError(t, err, "invalid zero-length flow ID")
		require.Zero(t, n)
	})

	t.Run("parse too long", func(t *testing.T) {
		_, n, err := parseMCFlowFrame([]byte{protocol.MaxConnIDLen + 1}, protocol.Version1)
		require.ErrorIs(t, err, protocol.ErrInvalidConnectionIDLen)
		require.Zero(t, n)
	})

	t.Run("append zero length", func(t *testing.T) {
		frame := newIPv4MCFlowFrame()
		frame.FlowID = protocol.ConnectionID{}
		_, err := frame.Append(nil, protocol.Version1)
		require.EqualError(t, err, "invalid zero-length flow ID")
	})
}

func TestMCFlowFrameRejectsInvalidIPVersion(t *testing.T) {
	_, n, err := parseMCFlowFrame([]byte{1, 0x42, 5}, protocol.Version1)
	require.EqualError(t, err, "invalid IP version: 5")
	require.Zero(t, n)

	frame := newIPv4MCFlowFrame()
	frame.IPVersion = 5
	_, err = frame.Append(nil, protocol.Version1)
	require.EqualError(t, err, "invalid IP version: 5")
}

func TestMCFlowFrameValidatesAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ipVersion uint8
		source    string
		group     string
		err       string
	}{
		{
			name:      "IPv4 with IPv6 source",
			ipVersion: 4,
			source:    "2001:db8::1",
			group:     "232.1.2.3",
			err:       "IPv4 flow requires IPv4 source and group addresses",
		},
		{
			name:      "IPv4 with IPv6 group",
			ipVersion: 4,
			source:    "192.0.2.1",
			group:     "ff3e::8000:1234",
			err:       "IPv4 flow requires IPv4 source and group addresses",
		},
		{
			name:      "IPv6 with IPv4 source",
			ipVersion: 6,
			source:    "192.0.2.1",
			group:     "ff3e::8000:1234",
			err:       "IPv6 flow requires IPv6 source and group addresses",
		},
		{
			name:      "IPv6 with IPv4 group",
			ipVersion: 6,
			source:    "2001:db8::1",
			group:     "232.1.2.3",
			err:       "IPv6 flow requires IPv6 source and group addresses",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := newIPv4MCFlowFrame()
			frame.IPVersion = tc.ipVersion
			frame.SourceAddress = netip.MustParseAddr(tc.source)
			frame.GroupAddress = netip.MustParseAddr(tc.group)
			_, err := frame.Append(nil, protocol.Version1)
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestMCFlowFrameRejectsInvalidSourceAddresses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ipVersion uint8
		source    string
		group     string
	}{
		{
			name:      "IPv4 unspecified",
			ipVersion: 4,
			source:    "0.0.0.0",
			group:     "239.192.74.99",
		},
		{
			name:      "IPv4 multicast",
			ipVersion: 4,
			source:    "239.1.2.3",
			group:     "239.192.74.99",
		},
		{
			name:      "IPv4 broadcast",
			ipVersion: 4,
			source:    "255.255.255.255",
			group:     "239.192.74.99",
		},
		{
			name:      "IPv6 unspecified",
			ipVersion: 6,
			source:    "::",
			group:     "ff3e::8000:1234",
		},
		{
			name:      "IPv6 multicast",
			ipVersion: 6,
			source:    "ff02::1",
			group:     "ff3e::8000:1234",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := newIPv4MCFlowFrame()
			frame.IPVersion = tc.ipVersion
			frame.SourceAddress = netip.MustParseAddr(tc.source)
			frame.GroupAddress = netip.MustParseAddr(tc.group)
			_, err := frame.Append(nil, protocol.Version1)
			require.ErrorContains(t, err, "invalid IPv")
		})
	}
}

func TestMCFlowFrameAllowsIPv4ASMGroup(t *testing.T) {
	frame := newIPv4MCFlowFrame()
	frame.GroupAddress = netip.MustParseAddr("239.192.74.99")
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)

	typeLen := quicvarint.Len(uint64(FrameTypeMCFlow))
	parsed, _, err := parseMCFlowFrame(b[typeLen:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, frame.GroupAddress, parsed.GroupAddress)
}

func TestMCFlowFrameAllowsIPv6ASMGroups(t *testing.T) {
	for _, group := range []string{
		"ff3e:30:3ffe:ffff:1::4",
		"ff1e::8000:1234",
		"ff9e::8000:1234",
	} {
		t.Run(group, func(t *testing.T) {
			frame := &MCFlowFrame{
				FlowID:            protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				IPVersion:         6,
				SourceAddress:     netip.MustParseAddr("2001:67c:1232:6004::1"),
				GroupAddress:      netip.MustParseAddr(group),
				UDPPort:           4434,
				CipherSuite:       0x1301,
				FirstPacketNumber: 0x1337,
				Secret:            []byte{1, 2, 3},
			}
			b, err := frame.Append(nil, protocol.Version1)
			require.NoError(t, err)

			typeLen := quicvarint.Len(uint64(FrameTypeMCFlow))
			parsed, n, err := parseMCFlowFrame(b[typeLen:], protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, len(b)-typeLen, n)
			require.Equal(t, frame, parsed)
		})
	}
}

func TestIPv6MulticastGroupMode(t *testing.T) {
	require.True(t, isIPv6SSMGroup(netip.MustParseAddr("ff3e::8000:1234")))
	require.True(t, isIPv6SSMGroup(netip.MustParseAddr("ffbe::8000:1234")))
	require.False(t, isIPv6SSMGroup(netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4")))
	require.False(t, isIPv6SSMGroup(netip.MustParseAddr("ff1e::8000:1234")))
}

func TestMCFlowFrameRejectsInvalidMulticastGroups(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ipVersion uint8
		source    string
		group     string
	}{
		{
			name:      "IPv4 unicast",
			ipVersion: 4,
			source:    "192.0.2.1",
			group:     "192.0.2.2",
		},
		{
			name:      "IPv4 reserved null SSM address",
			ipVersion: 4,
			source:    "192.0.2.1",
			group:     "232.0.0.0",
		},
		{
			name:      "IPv4 reserved base multicast address",
			ipVersion: 4,
			source:    "192.0.2.1",
			group:     "224.0.0.0",
		},
		{
			name:      "IPv6 invalid flags",
			ipVersion: 6,
			source:    "2001:db8::1",
			group:     "ff2e::1234",
		},
		{
			name:      "IPv6 nonzero reserved prefix field",
			ipVersion: 6,
			source:    "2001:db8::1",
			group:     "ff3e:130:3ffe:ffff:1::4",
		},
		{
			name:      "IPv6 invalid low group ID",
			ipVersion: 6,
			source:    "2001:db8::1",
			group:     "ff3e::1234",
		},
		{
			name:      "IPv6 prefix-based zero group ID",
			ipVersion: 6,
			source:    "2001:db8::1",
			group:     "ff3e:30:3ffe:ffff:1::",
		},
		{
			name:      "IPv6 unassigned scope",
			ipVersion: 6,
			source:    "2001:db8::1",
			group:     "ff36::8000:1234",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := newIPv4MCFlowFrame()
			frame.IPVersion = tc.ipVersion
			frame.SourceAddress = netip.MustParseAddr(tc.source)
			frame.GroupAddress = netip.MustParseAddr(tc.group)
			_, err := frame.Append(nil, protocol.Version1)
			require.ErrorContains(t, err, "is not a supported multicast group")
		})
	}
}

func TestMCFlowFrameRejectsNegativeFirstPacketNumber(t *testing.T) {
	frame := newIPv4MCFlowFrame()
	frame.FirstPacketNumber = protocol.InvalidPacketNumber
	_, err := frame.Append(nil, protocol.Version1)
	require.EqualError(t, err, "invalid first packet number: -1")
}

func TestMCFlowFrameOnlyAllowedAt1RTT(t *testing.T) {
	b, err := newIPv4MCFlowFrame().Append(nil, protocol.Version1)
	require.NoError(t, err)

	for _, encLevel := range []protocol.EncryptionLevel{
		protocol.EncryptionInitial,
		protocol.EncryptionHandshake,
		protocol.Encryption0RTT,
		protocol.Encryption1RTT,
	} {
		t.Run(encLevel.String(), func(t *testing.T) {
			parser := NewFrameParser(false, false, false)
			frameType, _, err := parser.ParseType(b, encLevel)
			if encLevel == protocol.Encryption1RTT {
				require.NoError(t, err)
				require.Equal(t, FrameTypeMCFlow, frameType)
				return
			}
			var transportErr *qerr.TransportError
			require.ErrorAs(t, err, &transportErr)
			require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
			require.Equal(t, uint64(FrameTypeMCFlow), transportErr.FrameType)
		})
	}
}
