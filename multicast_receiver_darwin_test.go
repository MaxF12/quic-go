//go:build darwin

package quic

import (
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestDarwinIPv4SourceMembershipRequest(t *testing.T) {
	request := newDarwinIPv4SourceMembershipRequest(
		netip.MustParseAddr("232.1.2.3"),
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("198.51.100.8"),
	)

	require.Equal(t, [4]byte{232, 1, 2, 3}, request.group)
	require.Equal(t, [4]byte{192, 0, 2, 10}, request.source)
	require.Equal(t, [4]byte{198, 51, 100, 8}, request.interfaceAddress)
	require.Equal(t, uintptr(12), unsafe.Sizeof(request))
}

func TestDarwinIPv4MembershipRequest(t *testing.T) {
	request := newDarwinIPv4MembershipRequest(
		netip.MustParseAddr("239.192.74.99"),
		netip.MustParseAddr("198.51.100.8"),
	)

	require.Equal(t, [4]byte{239, 192, 74, 99}, request.Multiaddr)
	require.Equal(t, [4]byte{198, 51, 100, 8}, request.Interface)
	require.Equal(t, uintptr(8), unsafe.Sizeof(request))
}

func TestDarwinIPv6ASMMembership(t *testing.T) {
	ifaces, err := net.Interfaces()
	require.NoError(t, err)
	var iface *net.Interface
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 ||
			ifaces[i].Flags&net.FlagMulticast == 0 ||
			ifaces[i].Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ok := ipFromNetAddr(addr)
			if ok && ip.Is6() && !ip.Is4In6() && !ip.IsUnspecified() {
				iface = &ifaces[i]
				break
			}
		}
		if iface != nil {
			break
		}
	}
	if iface == nil {
		t.Skip("no active multicast interface")
	}

	portProbe, err := net.ListenPacket("udp6", "[::]:0")
	require.NoError(t, err)
	port := portProbe.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, portProbe.Close())

	receiver, err := newNativeMulticastReceiver(
		netip.MustParseAddr("2001:67c:1232:6004:c78:6140:6e37:69ce"),
		netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4"),
		uint16(port),
		iface.Name,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, receiver.Close())
}
