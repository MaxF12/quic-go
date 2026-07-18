//go:build linux

package quic

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

func nativeIPv4MulticastInterfaceAddress(*net.Interface) (netip.Addr, error) {
	// Linux identifies the interface by index for MCAST_JOIN_SOURCE_GROUP.
	return netip.Addr{}, nil
}

func configureNativeIPv4MulticastSocket(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("setting SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0); err != nil {
		return fmt.Errorf("disabling IP_MULTICAST_ALL: %w", err)
	}
	return nil
}

func configureNativeIPv6MulticastSocket(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("setting SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_ALL, 0); err != nil {
		return fmt.Errorf("disabling IPV6_MULTICAST_ALL: %w", err)
	}
	return nil
}

func joinNativeIPv4ASM(
	_ net.PacketConn,
	conn *ipv4.PacketConn,
	iface *net.Interface,
	_ netip.Addr,
	group netip.Addr,
) (func() error, error) {
	groupAddr := &net.UDPAddr{IP: net.IP(group.AsSlice())}
	if err := conn.JoinGroup(iface, groupAddr); err != nil {
		return nil, err
	}
	return func() error { return conn.LeaveGroup(iface, groupAddr) }, nil
}

func joinNativeIPv4SSM(
	_ net.PacketConn,
	conn *ipv4.PacketConn,
	iface *net.Interface,
	_ netip.Addr,
	source, group netip.Addr,
) (func() error, error) {
	sourceAddr := &net.UDPAddr{IP: net.IP(source.AsSlice())}
	groupAddr := &net.UDPAddr{IP: net.IP(group.AsSlice())}
	if err := conn.JoinSourceSpecificGroup(iface, groupAddr, sourceAddr); err != nil {
		return nil, err
	}
	return func() error {
		return conn.LeaveSourceSpecificGroup(iface, groupAddr, sourceAddr)
	}, nil
}
