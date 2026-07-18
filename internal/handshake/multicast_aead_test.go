package handshake

import (
	"bytes"
	"crypto/tls"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func newMulticastTestSealer(secret []byte, version protocol.Version) LongHeaderSealer {
	suite := getCipherSuite(tls.TLS_AES_128_GCM_SHA256)
	return newLongHeaderSealer(
		createAEAD(suite, secret, version),
		newHeaderProtector(suite, secret, false, version),
	)
}

func TestMulticastOpener(t *testing.T) {
	secret := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	const firstPacketNumber protocol.PacketNumber = 0x1234fffe

	for _, version := range []protocol.Version{protocol.Version1, protocol.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			opener, err := NewMulticastOpener(
				tls.TLS_AES_128_GCM_SHA256,
				secret,
				firstPacketNumber,
				version,
			)
			require.NoError(t, err)

			// Reconstruct a truncated packet number when joining a flow late.
			require.Equal(
				t,
				firstPacketNumber,
				opener.DecodePacketNumber(firstPacketNumber&0xffff, protocol.PacketNumberLen2),
			)

			sealer := newMulticastTestSealer(secret, version)
			plaintext := []byte("multicast datagram")
			associatedData := []byte{0x43, 0xde, 0xad, 0xbe, 0xef}
			encrypted := sealer.Seal(nil, plaintext, firstPacketNumber, associatedData)
			decrypted, err := opener.Open(
				nil,
				encrypted,
				monotime.Now(),
				firstPacketNumber,
				protocol.KeyPhaseZero,
				associatedData,
			)
			require.NoError(t, err)
			require.Equal(t, firstPacketNumber-1, opener.(*multicastOpener).highestRcvdPN)
			require.Equal(t, plaintext, decrypted)
			// Authentication and state mutation are deliberately separate.
			require.Equal(t, firstPacketNumber-1, opener.(*multicastOpener).highestRcvdPN)
			opener.CommitPacketNumber(firstPacketNumber)
			require.Equal(t, firstPacketNumber, opener.(*multicastOpener).highestRcvdPN)

			// A successful open advances the reconstruction basis across a
			// truncated packet number wrap.
			require.Equal(
				t,
				protocol.PacketNumber(0x12350000),
				opener.DecodePacketNumber(0, protocol.PacketNumberLen1),
			)

			sample := bytes.Repeat([]byte{0xa5}, 16)
			firstByte := byte(0x43)
			packetNumberBytes := []byte{0x12, 0x34, 0xff, 0xfe}
			sealer.EncryptHeader(sample, &firstByte, packetNumberBytes)
			require.NotEqual(t, byte(0x43), firstByte)
			require.NotEqual(t, []byte{0x12, 0x34, 0xff, 0xfe}, packetNumberBytes)
			opener.DecryptHeader(sample, &firstByte, packetNumberBytes)
			require.Equal(t, byte(0x43), firstByte)
			require.Equal(t, []byte{0x12, 0x34, 0xff, 0xfe}, packetNumberBytes)
		})
	}
}

func TestMulticastOpenerFirstPacketNumberZero(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	opener, err := NewMulticastOpener(
		tls.TLS_AES_128_GCM_SHA256,
		secret,
		0,
		protocol.Version1,
	)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0), opener.DecodePacketNumber(0, protocol.PacketNumberLen1))
}

func TestMulticastOpenerRejectsInvalidConfiguration(t *testing.T) {
	validSecret := bytes.Repeat([]byte{0x42}, 32)

	t.Run("cipher suite", func(t *testing.T) {
		_, err := NewMulticastOpener(
			tls.TLS_AES_256_GCM_SHA384,
			validSecret,
			0,
			protocol.Version1,
		)
		require.ErrorContains(t, err, "unsupported multicast cipher suite")
	})

	for _, secretLen := range []int{0, 31, 33} {
		t.Run("secret length", func(t *testing.T) {
			_, err := NewMulticastOpener(
				tls.TLS_AES_128_GCM_SHA256,
				make([]byte, secretLen),
				0,
				protocol.Version1,
			)
			require.ErrorContains(t, err, "invalid multicast secret length")
		})
	}

	for _, firstPacketNumber := range []protocol.PacketNumber{
		protocol.InvalidPacketNumber,
		protocol.PacketNumber(protocol.MaxByteCount) + 1,
	} {
		t.Run("first packet number", func(t *testing.T) {
			_, err := NewMulticastOpener(
				tls.TLS_AES_128_GCM_SHA256,
				validSecret,
				firstPacketNumber,
				protocol.Version1,
			)
			require.ErrorContains(t, err, "invalid multicast first packet number")
		})
	}
}

func TestMulticastOpenerFailuresDontAdvancePacketNumber(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	const firstPacketNumber protocol.PacketNumber = 0x12345678
	const laterPacketNumber = firstPacketNumber + 1<<16
	associatedData := []byte("header")
	sealer := newMulticastTestSealer(secret, protocol.Version1)
	encrypted := sealer.Seal(nil, []byte("payload"), laterPacketNumber, associatedData)

	newOpener := func(t *testing.T) MulticastOpener {
		t.Helper()
		opener, err := NewMulticastOpener(
			tls.TLS_AES_128_GCM_SHA256,
			secret,
			firstPacketNumber,
			protocol.Version1,
		)
		require.NoError(t, err)
		return opener
	}
	assertBasisUnchanged := func(t *testing.T, opener ShortHeaderOpener) {
		t.Helper()
		require.Equal(
			t,
			firstPacketNumber,
			opener.DecodePacketNumber(firstPacketNumber&0xffff, protocol.PacketNumberLen2),
		)
	}

	t.Run("authentication failure", func(t *testing.T) {
		opener := newOpener(t)
		encrypted[len(encrypted)-1] ^= 0xff
		_, err := opener.Open(
			nil,
			encrypted,
			monotime.Now(),
			laterPacketNumber,
			protocol.KeyPhaseZero,
			associatedData,
		)
		require.ErrorIs(t, err, ErrDecryptionFailed)
		assertBasisUnchanged(t, opener)
	})
}
