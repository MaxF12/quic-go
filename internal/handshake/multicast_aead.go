package handshake

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// multicastOpener opens multicast packets protected with a fixed traffic
// secret. Multicast flows don't support key updates.
type multicastOpener struct {
	aead            cipher.AEAD
	headerProtector headerProtector
	highestRcvdPN   protocol.PacketNumber
	nonceBuf        [8]byte
}

var _ ShortHeaderOpener = &multicastOpener{}

// MulticastOpener authenticates packets independently from committing the
// packet number used as the reconstruction basis. This lets the multicast
// profile authenticate malformed protected headers before dropping them,
// without allowing those packets to change flow state.
type MulticastOpener interface {
	ShortHeaderOpener
	CommitPacketNumber(protocol.PacketNumber)
}

// NewMulticastOpener creates a fixed-key opener for a multicast flow.
func NewMulticastOpener(
	cipherSuite uint16,
	secret []byte,
	firstPacketNumber protocol.PacketNumber,
	version protocol.Version,
) (MulticastOpener, error) {
	if cipherSuite != tls.TLS_AES_128_GCM_SHA256 {
		return nil, fmt.Errorf("unsupported multicast cipher suite: %#x", cipherSuite)
	}
	if len(secret) != sha256.Size {
		return nil, fmt.Errorf("invalid multicast secret length: %d (expected %d)", len(secret), sha256.Size)
	}
	if firstPacketNumber < 0 || firstPacketNumber > protocol.PacketNumber(protocol.MaxByteCount) {
		return nil, fmt.Errorf("invalid multicast first packet number: %d", firstPacketNumber)
	}

	suite := getCipherSuite(cipherSuite)
	return &multicastOpener{
		aead:            createAEAD(suite, secret, version),
		headerProtector: newHeaderProtector(suite, secret, false, version),
		highestRcvdPN:   firstPacketNumber - 1,
	}, nil
}

func (o *multicastOpener) DecodePacketNumber(
	wirePN protocol.PacketNumber,
	wirePNLen protocol.PacketNumberLen,
) protocol.PacketNumber {
	return protocol.DecodePacketNumber(wirePNLen, o.highestRcvdPN, wirePN)
}

func (o *multicastOpener) Open(
	dst, src []byte,
	_ monotime.Time,
	pn protocol.PacketNumber,
	_ protocol.KeyPhaseBit,
	associatedData []byte,
) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[:], uint64(pn))
	decrypted, err := o.aead.Open(dst, o.nonceBuf[:], src, associatedData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return decrypted, nil
}

// CommitPacketNumber advances the reconstruction basis after the caller has
// accepted all multicast-specific short-header constraints.
func (o *multicastOpener) CommitPacketNumber(pn protocol.PacketNumber) {
	o.highestRcvdPN = max(o.highestRcvdPN, pn)
}

func (o *multicastOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}
