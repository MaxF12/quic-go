//go:build darwin

package quic

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// darwinIPv4SourceMembershipRequest mirrors Darwin's struct ip_mreq_source.
type darwinIPv4SourceMembershipRequest struct {
	group            [4]byte
	source           [4]byte
	interfaceAddress [4]byte
}

func nativeIPv4MulticastInterfaceAddress(iface *net.Interface) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("listing IPv4 addresses: %w", err)
	}
	return findIPv4InterfaceAddress(addrs)
}

func configureNativeIPv4MulticastSocket(fd int) error {
	return configureNativeDarwinMulticastSocket(fd)
}

func configureNativeIPv6MulticastSocket(fd int) error {
	return configureNativeDarwinMulticastSocket(fd)
}

func configureNativeDarwinMulticastSocket(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("setting SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fmt.Errorf("setting SO_REUSEPORT: %w", err)
	}
	return nil
}

func joinNativeIPv4SSM(
	packetConn net.PacketConn,
	_ *ipv4.PacketConn,
	_ *net.Interface,
	interfaceAddress, source, group netip.Addr,
) (func() error, error) {
	rawConn, err := multicastSyscallConn(packetConn)
	if err != nil {
		return nil, err
	}

	request := newDarwinIPv4SourceMembershipRequest(group, source, interfaceAddress)
	if err := setDarwinIPv4SourceMembership(rawConn, unix.IP_ADD_SOURCE_MEMBERSHIP, &request); err != nil {
		return nil, err
	}
	return func() error {
		return setDarwinIPv4SourceMembership(rawConn, unix.IP_DROP_SOURCE_MEMBERSHIP, &request)
	}, nil
}

func joinNativeIPv4ASM(
	packetConn net.PacketConn,
	_ *ipv4.PacketConn,
	_ *net.Interface,
	interfaceAddress netip.Addr,
	group netip.Addr,
) (func() error, error) {
	rawConn, err := multicastSyscallConn(packetConn)
	if err != nil {
		return nil, err
	}
	request := newDarwinIPv4MembershipRequest(group, interfaceAddress)
	if err := setDarwinIPv4Membership(rawConn, unix.IP_ADD_MEMBERSHIP, request); err != nil {
		return nil, err
	}
	return func() error {
		return setDarwinIPv4Membership(rawConn, unix.IP_DROP_MEMBERSHIP, request)
	}, nil
}

func multicastSyscallConn(packetConn net.PacketConn) (syscall.RawConn, error) {
	syscallConn, ok := packetConn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("UDP packet connection does not expose its system socket")
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("accessing UDP system socket: %w", err)
	}
	return rawConn, nil
}

func setDarwinIPv4Membership(rawConn syscall.RawConn, option int, request unix.IPMreq) error {
	var socketOptionErr error
	if err := rawConn.Control(func(fd uintptr) {
		socketOptionErr = unix.SetsockoptIPMreq(
			int(fd),
			unix.IPPROTO_IP,
			option,
			&request,
		)
	}); err != nil {
		return err
	}
	return socketOptionErr
}

func newDarwinIPv4MembershipRequest(group, interfaceAddress netip.Addr) unix.IPMreq {
	return unix.IPMreq{
		Multiaddr: group.Unmap().As4(),
		Interface: interfaceAddress.Unmap().As4(),
	}
}

func newDarwinIPv4SourceMembershipRequest(
	group, source, interfaceAddress netip.Addr,
) darwinIPv4SourceMembershipRequest {
	return darwinIPv4SourceMembershipRequest{
		group:            group.Unmap().As4(),
		source:           source.Unmap().As4(),
		interfaceAddress: interfaceAddress.Unmap().As4(),
	}
}

func setDarwinIPv4SourceMembership(
	rawConn syscall.RawConn,
	option int,
	request *darwinIPv4SourceMembershipRequest,
) error {
	var socketOptionErr error
	if err := rawConn.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_IP),
			uintptr(option),
			uintptr(unsafe.Pointer(request)),
			unsafe.Sizeof(*request),
			0,
		)
		if errno != 0 {
			socketOptionErr = errno
		}
	}); err != nil {
		return err
	}
	runtime.KeepAlive(request)
	return socketOptionErr
}
