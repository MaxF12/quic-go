package quic

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateIPv4MulticastFlow(t *testing.T) {
	validSource := netip.MustParseAddr("192.0.2.10")
	validGroup := netip.MustParseAddr("232.1.2.3")
	require.NoError(t, validateIPv4MulticastFlow(validSource, validGroup, 5000))
	require.NoError(t, validateIPv4MulticastFlow(
		validSource,
		netip.MustParseAddr("239.192.74.99"),
		5000,
	))
	require.NoError(t, validateIPv4MulticastFlow(
		netip.IPv4Unspecified(),
		netip.MustParseAddr("239.192.74.99"),
		5000,
	))

	testCases := []struct {
		name   string
		source netip.Addr
		group  netip.Addr
		port   uint16
	}{
		{
			name:   "IPv6 source",
			source: netip.MustParseAddr("2001:db8::1"),
			group:  validGroup,
			port:   5000,
		},
		{
			name:   "multicast source",
			source: netip.MustParseAddr("232.0.0.1"),
			group:  validGroup,
			port:   5000,
		},
		{
			name:   "unspecified SSM source",
			source: netip.IPv4Unspecified(),
			group:  validGroup,
			port:   5000,
		},
		{
			name:   "reserved null SSM group",
			source: validSource,
			group:  netip.MustParseAddr("232.0.0.0"),
			port:   5000,
		},
		{
			name:   "reserved base multicast group",
			source: validSource,
			group:  netip.MustParseAddr("224.0.0.0"),
			port:   5000,
		},
		{
			name:   "zero port",
			source: validSource,
			group:  validGroup,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Error(t, validateIPv4MulticastFlow(
				testCase.source,
				testCase.group,
				testCase.port,
			))
		})
	}
}

func TestIPv4MulticastGroupMode(t *testing.T) {
	require.True(t, isIPv4SSMGroup(netip.MustParseAddr("232.1.2.3")))
	require.False(t, isIPv4SSMGroup(netip.MustParseAddr("239.192.74.99")))
	require.False(t, isIPv4SSMGroup(netip.MustParseAddr("192.0.2.1")))
}

func TestValidateIPv6MulticastFlow(t *testing.T) {
	validSource := netip.MustParseAddr("2001:67c:1232:6004::1")
	require.NoError(t, validateIPv6MulticastFlow(
		validSource,
		netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4"),
		4434,
	))
	require.NoError(t, validateIPv6MulticastFlow(
		validSource,
		netip.MustParseAddr("ff3e::8000:1234"),
		4434,
	))
	require.NoError(t, validateIPv6MulticastFlow(
		netip.IPv6Unspecified(),
		netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4"),
		4434,
	))

	testCases := []struct {
		name   string
		source netip.Addr
		group  netip.Addr
		port   uint16
	}{
		{
			name:   "IPv4 source",
			source: netip.MustParseAddr("192.0.2.1"),
			group:  netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4"),
			port:   4434,
		},
		{
			name:   "multicast source",
			source: netip.MustParseAddr("ff1e::1"),
			group:  netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4"),
			port:   4434,
		},
		{
			name:   "unspecified SSM source",
			source: netip.IPv6Unspecified(),
			group:  netip.MustParseAddr("ff3e::8000:1234"),
			port:   4434,
		},
		{
			name:   "invalid SSM group ID",
			source: validSource,
			group:  netip.MustParseAddr("ff3e::1234"),
			port:   4434,
		},
		{
			name:   "invalid flags",
			source: validSource,
			group:  netip.MustParseAddr("ff2e::1234"),
			port:   4434,
		},
		{
			name:   "prefix-based zero group ID",
			source: validSource,
			group:  netip.MustParseAddr("ff3e:30:3ffe:ffff:1::"),
			port:   4434,
		},
		{
			name:   "zero port",
			source: validSource,
			group:  netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Error(t, validateIPv6MulticastFlow(
				testCase.source,
				testCase.group,
				testCase.port,
			))
		})
	}
}

func TestIPv6MulticastGroupMode(t *testing.T) {
	require.True(t, isIPv6SSMGroup(netip.MustParseAddr("ff3e::8000:1234")))
	require.True(t, isIPv6SSMGroup(netip.MustParseAddr("ffbe::8000:1234")))
	require.False(t, isIPv6SSMGroup(netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4")))
	require.False(t, isIPv6SSMGroup(netip.MustParseAddr("ff1e::8000:1234")))
	require.False(t, isIPv6SSMGroup(netip.MustParseAddr("2001:db8::1")))
}

func TestMulticastInterfaceRouteTarget(t *testing.T) {
	ipv4Source := netip.MustParseAddr("192.0.2.1")
	ipv4Group := netip.MustParseAddr("239.192.74.99")
	require.Equal(t, ipv4Source, multicastInterfaceRouteTarget(ipv4Source, ipv4Group))
	require.Equal(t, ipv4Group, multicastInterfaceRouteTarget(netip.IPv4Unspecified(), ipv4Group))

	ipv6Source := netip.MustParseAddr("2001:db8::1")
	ipv6Group := netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4")
	require.Equal(t, ipv6Source, multicastInterfaceRouteTarget(ipv6Source, ipv6Group))
	require.Equal(t, ipv6Group, multicastInterfaceRouteTarget(netip.IPv6Unspecified(), ipv6Group))
}

func TestFindInterfaceByIPv4(t *testing.T) {
	ifaces := []net.Interface{
		{Index: 1, Name: "first"},
		{Index: 7, Name: "multicast0"},
	}
	addrs := map[int][]net.Addr{
		1: {&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)}},
		7: {&net.IPNet{IP: net.ParseIP("198.51.100.8"), Mask: net.CIDRMask(24, 32)}},
	}

	iface, err := findInterfaceByIPv4(
		netip.MustParseAddr("198.51.100.8"),
		func() ([]net.Interface, error) { return ifaces, nil },
		func(iface *net.Interface) ([]net.Addr, error) { return addrs[iface.Index], nil },
	)
	require.NoError(t, err)
	require.Equal(t, 7, iface.Index)

	_, err = findInterfaceByIPv4(
		netip.MustParseAddr("203.0.113.1"),
		func() ([]net.Interface, error) { return ifaces, nil },
		func(iface *net.Interface) ([]net.Addr, error) { return addrs[iface.Index], nil },
	)
	require.Error(t, err)

	sentinel := errors.New("list failed")
	_, err = findInterfaceByIPv4(
		netip.MustParseAddr("198.51.100.8"),
		func() ([]net.Interface, error) { return nil, sentinel },
		func(*net.Interface) ([]net.Addr, error) { return nil, nil },
	)
	require.ErrorIs(t, err, sentinel)
}

func TestFindInterfaceByIPv6(t *testing.T) {
	ifaces := []net.Interface{
		{Index: 1, Name: "first"},
		{Index: 7, Name: "multicast0"},
	}
	addrs := map[int][]net.Addr{
		1: {&net.IPNet{IP: net.ParseIP("2001:db8:1::1"), Mask: net.CIDRMask(64, 128)}},
		7: {&net.IPNet{IP: net.ParseIP("2001:db8:2::8"), Mask: net.CIDRMask(64, 128)}},
	}

	iface, err := findInterfaceByIPv6(
		netip.MustParseAddr("2001:db8:2::8"),
		func() ([]net.Interface, error) { return ifaces, nil },
		func(iface *net.Interface) ([]net.Addr, error) { return addrs[iface.Index], nil },
	)
	require.NoError(t, err)
	require.Equal(t, 7, iface.Index)

	_, err = findInterfaceByIPv6(
		netip.MustParseAddr("2001:db8:3::1"),
		func() ([]net.Interface, error) { return ifaces, nil },
		func(iface *net.Interface) ([]net.Addr, error) { return addrs[iface.Index], nil },
	)
	require.Error(t, err)

	sentinel := errors.New("list failed")
	_, err = findInterfaceByIPv6(
		netip.MustParseAddr("2001:db8:2::8"),
		func() ([]net.Interface, error) { return nil, sentinel },
		func(*net.Interface) ([]net.Addr, error) { return nil, nil },
	)
	require.ErrorIs(t, err, sentinel)
}

func TestFindIPv4InterfaceAddress(t *testing.T) {
	addr, err := findIPv4InterfaceAddress([]net.Addr{
		&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("198.51.100.8"), Mask: net.CIDRMask(24, 32)},
	})
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("198.51.100.8"), addr)

	_, err = findIPv4InterfaceAddress([]net.Addr{
		&net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
	})
	require.Error(t, err)
}

func TestMulticastPacketMatches(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.10")
	group := netip.MustParseAddr("232.1.2.3")
	sourceAddr := &net.UDPAddr{IP: net.ParseIP(source.String()), Port: 4433}

	require.True(t, multicastPacketMatches(
		sourceAddr,
		net.ParseIP(group.String()),
		source,
		group,
		true,
	))
	require.False(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 4433},
		net.ParseIP(group.String()),
		source,
		group,
		true,
	))
	require.False(t, multicastPacketMatches(
		sourceAddr,
		net.ParseIP("232.1.2.4"),
		source,
		group,
		true,
	))
	require.False(t, multicastPacketMatches(sourceAddr, nil, source, group, true))
	require.False(t, multicastPacketMatches(nil, net.ParseIP(group.String()), source, group, true))

	asmGroup := netip.MustParseAddr("239.192.74.99")
	require.True(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 4433},
		net.ParseIP(asmGroup.String()),
		netip.IPv4Unspecified(),
		asmGroup,
		false,
	))
	require.False(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 4433},
		net.ParseIP("239.192.74.100"),
		source,
		asmGroup,
		false,
	))
	require.False(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4433},
		net.ParseIP(asmGroup.String()),
		netip.IPv4Unspecified(),
		asmGroup,
		false,
	))
	require.False(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.IPv4zero, Port: 4433},
		net.ParseIP(asmGroup.String()),
		netip.IPv4Unspecified(),
		asmGroup,
		false,
	))

	ipv6Source := netip.MustParseAddr("2001:67c:1232:6004::1")
	ipv6ASMGroup := netip.MustParseAddr("ff3e:30:3ffe:ffff:1::4")
	require.True(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("2001:67c:1232:6004::2"), Port: 4434},
		net.ParseIP(ipv6ASMGroup.String()),
		ipv6Source,
		ipv6ASMGroup,
		false,
	))
	require.False(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("2001:67c:1232:6004::2"), Port: 4434},
		net.ParseIP("ff3e:30:3ffe:ffff:1::5"),
		ipv6Source,
		ipv6ASMGroup,
		false,
	))

	ipv6SSMGroup := netip.MustParseAddr("ff3e::8000:1234")
	require.True(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP(ipv6Source.String()), Port: 4434},
		net.ParseIP(ipv6SSMGroup.String()),
		ipv6Source,
		ipv6SSMGroup,
		true,
	))
	require.False(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("2001:67c:1232:6004::2"), Port: 4434},
		net.ParseIP(ipv6SSMGroup.String()),
		ipv6Source,
		ipv6SSMGroup,
		true,
	))
	require.False(t, multicastPacketMatches(
		&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4434},
		net.ParseIP(ipv6ASMGroup.String()),
		ipv6Source,
		ipv6ASMGroup,
		false,
	))
}

func TestValidateMulticastInterface(t *testing.T) {
	require.NoError(t, validateMulticastInterface(&net.Interface{
		Name:  "multicast0",
		Flags: net.FlagUp | net.FlagMulticast,
	}))
	require.Error(t, validateMulticastInterface(nil))
	require.Error(t, validateMulticastInterface(&net.Interface{Name: "down"}))
	require.Error(t, validateMulticastInterface(&net.Interface{
		Name:  "point-to-point",
		Flags: net.FlagUp,
	}))
}
