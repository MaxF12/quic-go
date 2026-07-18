package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// MCFlowFrame announces an experimental multicast QUIC flow.
type MCFlowFrame struct {
	FlowID            protocol.ConnectionID
	IPVersion         uint8
	SourceAddress     netip.Addr
	GroupAddress      netip.Addr
	UDPPort           uint16
	CipherSuite       uint16
	FirstPacketNumber protocol.PacketNumber
	Secret            []byte
}

func parseMCFlowFrame(b []byte, _ protocol.Version) (*MCFlowFrame, int, error) {
	startLen := len(b)
	if len(b) == 0 {
		return nil, 0, io.EOF
	}

	connIDLen := int(b[0])
	b = b[1:]
	if connIDLen == 0 {
		return nil, 0, errors.New("invalid zero-length flow ID")
	}
	if connIDLen > protocol.MaxConnIDLen {
		return nil, 0, protocol.ErrInvalidConnectionIDLen
	}
	if len(b) < connIDLen {
		return nil, 0, io.EOF
	}
	frame := &MCFlowFrame{FlowID: protocol.ParseConnectionID(b[:connIDLen])}
	b = b[connIDLen:]

	if len(b) == 0 {
		return nil, 0, io.EOF
	}
	frame.IPVersion = b[0]
	b = b[1:]

	var addrLen int
	switch frame.IPVersion {
	case 4:
		addrLen = 4
	case 6:
		addrLen = 16
	default:
		return nil, 0, fmt.Errorf("invalid IP version: %d", frame.IPVersion)
	}
	if len(b) < 2*addrLen+4 {
		return nil, 0, io.EOF
	}
	if frame.IPVersion == 4 {
		frame.SourceAddress = netip.AddrFrom4([4]byte(b[:4]))
		b = b[4:]
		frame.GroupAddress = netip.AddrFrom4([4]byte(b[:4]))
		b = b[4:]
	} else {
		frame.SourceAddress = netip.AddrFrom16([16]byte(b[:16]))
		b = b[16:]
		frame.GroupAddress = netip.AddrFrom16([16]byte(b[:16]))
		b = b[16:]
	}
	frame.UDPPort = binary.BigEndian.Uint16(b)
	b = b[2:]
	frame.CipherSuite = binary.BigEndian.Uint16(b)
	b = b[2:]

	firstPacketNumber, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	frame.FirstPacketNumber = protocol.PacketNumber(firstPacketNumber)
	b = b[l:]

	secretLen, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if secretLen > uint64(len(b)) {
		return nil, 0, io.EOF
	}
	if secretLen > 0 {
		frame.Secret = make([]byte, int(secretLen))
		copy(frame.Secret, b[:secretLen])
	}
	b = b[secretLen:]

	if err := frame.validate(); err != nil {
		return nil, 0, err
	}
	return frame, startLen - len(b), nil
}

func (f *MCFlowFrame) validate() error {
	if f.FlowID.Len() == 0 {
		return errors.New("invalid zero-length flow ID")
	}
	if f.FlowID.Len() > protocol.MaxConnIDLen {
		return protocol.ErrInvalidConnectionIDLen
	}
	switch f.IPVersion {
	case 4:
		if !f.SourceAddress.Is4() || !f.GroupAddress.Is4() {
			return errors.New("IPv4 flow requires IPv4 source and group addresses")
		}
		source := f.SourceAddress.As4()
		if f.SourceAddress.IsMulticast() ||
			f.SourceAddress.IsUnspecified() && isIPv4SSMGroup(f.GroupAddress) ||
			source == [4]byte{255, 255, 255, 255} {
			return fmt.Errorf("invalid IPv4 multicast source address: %s", f.SourceAddress)
		}
	case 6:
		if !f.SourceAddress.Is6() || f.SourceAddress.Is4In6() ||
			!f.GroupAddress.Is6() || f.GroupAddress.Is4In6() {
			return errors.New("IPv6 flow requires IPv6 source and group addresses")
		}
		if f.SourceAddress.IsMulticast() ||
			f.SourceAddress.IsUnspecified() && isIPv6SSMGroup(f.GroupAddress) {
			return fmt.Errorf("invalid IPv6 multicast source address: %s", f.SourceAddress)
		}
	default:
		return fmt.Errorf("invalid IP version: %d", f.IPVersion)
	}
	if !isSupportedMulticastGroup(f.GroupAddress) {
		return fmt.Errorf("group address %s is not a supported multicast group", f.GroupAddress)
	}
	if f.FirstPacketNumber < 0 {
		return fmt.Errorf("invalid first packet number: %d", f.FirstPacketNumber)
	}
	return nil
}

func isSupportedMulticastGroup(addr netip.Addr) bool {
	if addr.Is4() {
		group := addr.As4()
		if !addr.IsMulticast() {
			return false
		}
		// 224.0.0.0 is reserved and is not a usable group address.
		if group == [4]byte{224, 0, 0, 0} {
			return false
		}
		// 232.0.0.0 is the reserved null address in the IPv4 SSM range.
		return group != [4]byte{232, 0, 0, 0}
	}
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	bytes := addr.As16()
	if bytes[0] != 0xff {
		return false
	}
	scope := bytes[1] & 0xf
	validScope := scope >= 1 && scope <= 5 || scope == 8 || scope == 0xe
	if !validScope {
		return false
	}

	flags := bytes[1] >> 4
	knownFlags := flags & 0x7 // RFC 7371: X is independent of R, P, and T.
	if knownFlags != 0 && knownFlags != 1 && knownFlags != 3 && knownFlags != 7 {
		return false
	}
	if knownFlags == 3 || knownFlags == 7 {
		// Prefix-based addresses carry a prefix of at most 64 bits. The
		// low nibble is reserved unless R selects the embedded-RP format;
		// RFC 7371 says the independent ff2 bits in the high nibble are
		// ignored on receipt.
		if bytes[3] > 64 || knownFlags == 3 && bytes[2]&0xf != 0 {
			return false
		}
	}
	if isIPv6SSMGroup(addr) {
		// FF3x::4000:0000 is the reserved null SSM address, and lower
		// group IDs are invalid for IPv6 SSM.
		return binary.BigEndian.Uint32(bytes[12:]) > 0x40000000
	}
	if knownFlags == 3 || knownFlags == 7 {
		// RFC 3306's Group ID is the low 32 bits, independent of the
		// embedded prefix and prefix length.
		return binary.BigEndian.Uint32(bytes[12:]) != 0
	}

	// Reject an ordinary multicast address whose identifier is all zero.
	if bytes[2]&0xf != 0 {
		return true
	}
	for _, b := range bytes[3:] {
		if b != 0 {
			return true
		}
	}
	return false
}

func isIPv4SSMGroup(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.Is4() && addr.As4()[0] == 232
}

func isIPv6SSMGroup(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	bytes := addr.As16()
	flags := bytes[1] >> 4
	return bytes[0] == 0xff &&
		flags&0x7 == 3 &&
		bytes[2]&0xf == 0 &&
		bytes[3] == 0
}

// Append appends an MC_FLOW frame.
func (f *MCFlowFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	b = quicvarint.Append(b, uint64(FrameTypeMCFlow))
	b = append(b, uint8(f.FlowID.Len()))
	b = append(b, f.FlowID.Bytes()...)
	b = append(b, f.IPVersion)
	if f.IPVersion == 4 {
		source := f.SourceAddress.As4()
		group := f.GroupAddress.As4()
		b = append(b, source[:]...)
		b = append(b, group[:]...)
	} else {
		source := f.SourceAddress.As16()
		group := f.GroupAddress.As16()
		b = append(b, source[:]...)
		b = append(b, group[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, f.UDPPort)
	b = binary.BigEndian.AppendUint16(b, f.CipherSuite)
	b = quicvarint.Append(b, uint64(f.FirstPacketNumber))
	b = quicvarint.Append(b, uint64(len(f.Secret)))
	b = append(b, f.Secret...)
	return b, nil
}

// Length returns the encoded length of the frame.
func (f *MCFlowFrame) Length(protocol.Version) protocol.ByteCount {
	addrLen := 2 * 16
	if f.IPVersion == 4 {
		addrLen = 2 * 4
	}
	return protocol.ByteCount(
		quicvarint.Len(uint64(FrameTypeMCFlow)) +
			1 + f.FlowID.Len() +
			1 + addrLen +
			2 + 2 +
			quicvarint.Len(uint64(f.FirstPacketNumber)) +
			quicvarint.Len(uint64(len(f.Secret))) + len(f.Secret),
	)
}
