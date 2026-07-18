package quic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// multicastReceiver receives protected QUIC packets from a multicast flow.
type multicastReceiver interface {
	Read([]byte) (int, net.Addr, error)
	Close() error
}

type multicastDebugFunc func(format string, args ...any)

func (f multicastDebugFunc) logf(format string, args ...any) {
	if f != nil {
		f(format, args...)
	}
}

var multicastReceiverFactory func(
	source, group netip.Addr,
	port uint16,
	interfaceName string,
	debugf multicastDebugFunc,
) (multicastReceiver, error) = newNativeMulticastReceiver

func validateMulticastFlow(source, group netip.Addr, port uint16) error {
	source = source.Unmap()
	group = group.Unmap()
	switch {
	case source.Is4() && group.Is4():
		return validateIPv4MulticastFlow(source, group, port)
	case source.Is6() && !source.Is4In6() && group.Is6() && !group.Is4In6():
		return validateIPv6MulticastFlow(source, group, port)
	default:
		return fmt.Errorf("multicast source and group address families must match")
	}
}

func validateIPv4MulticastFlow(source, group netip.Addr, port uint16) error {
	source = source.Unmap()
	group = group.Unmap()

	if !source.IsValid() || !source.Is4() {
		return fmt.Errorf("multicast source must be an IPv4 address")
	}
	if !group.IsValid() || !group.Is4() || !group.IsMulticast() {
		return fmt.Errorf("multicast group must be an IPv4 multicast address")
	}
	if group.As4() == [4]byte{224, 0, 0, 0} {
		return fmt.Errorf("multicast group must not be the reserved address 224.0.0.0")
	}
	if group.As4() == [4]byte{232, 0, 0, 0} {
		return fmt.Errorf("multicast group must not be the reserved address 232.0.0.0")
	}
	if !isUsableMulticastSource(source) &&
		!(source.IsUnspecified() && !isIPv4SSMGroup(group)) {
		return fmt.Errorf("invalid multicast source address: %s", source)
	}
	if port == 0 {
		return fmt.Errorf("multicast UDP port must not be 0")
	}
	return nil
}

func validateIPv6MulticastFlow(source, group netip.Addr, port uint16) error {
	if !source.IsValid() || !source.Is6() || source.Is4In6() {
		return fmt.Errorf("multicast source must be an IPv6 address")
	}
	if !isSupportedIPv6MulticastGroup(group) {
		return fmt.Errorf("multicast group must be a supported IPv6 multicast address")
	}
	if !isUsableMulticastSource(source) &&
		!(source.IsUnspecified() && !isIPv6SSMGroup(group)) {
		return fmt.Errorf("invalid multicast source address: %s", source)
	}
	if port == 0 {
		return fmt.Errorf("multicast UDP port must not be 0")
	}
	return nil
}

func isUsableMulticastSource(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	if addr.Is4() {
		return addr.As4() != [4]byte{255, 255, 255, 255}
	}
	return addr.Is6() && !addr.Is4In6()
}

func isIPv4SSMGroup(group netip.Addr) bool {
	group = group.Unmap()
	return group.Is4() && group.As4()[0] == 232
}

func isIPv6SSMGroup(group netip.Addr) bool {
	group = group.Unmap()
	if !group.Is6() || group.Is4In6() {
		return false
	}
	bytes := group.As16()
	flags := bytes[1] >> 4
	return bytes[0] == 0xff &&
		flags&0x7 == 3 &&
		bytes[2]&0xf == 0 &&
		bytes[3] == 0
}

func isSupportedIPv6MulticastGroup(group netip.Addr) bool {
	group = group.Unmap()
	if !group.Is6() || group.Is4In6() || !group.IsMulticast() {
		return false
	}
	bytes := group.As16()
	scope := bytes[1] & 0xf
	if !(scope >= 1 && scope <= 5 || scope == 8 || scope == 0xe) {
		return false
	}
	flags := bytes[1] >> 4
	knownFlags := flags & 0x7
	if knownFlags != 0 && knownFlags != 1 && knownFlags != 3 && knownFlags != 7 {
		return false
	}
	if (knownFlags == 3 || knownFlags == 7) &&
		(bytes[3] > 64 || knownFlags == 3 && bytes[2]&0xf != 0) {
		return false
	}
	if isIPv6SSMGroup(group) {
		return binary.BigEndian.Uint32(bytes[12:]) > 0x40000000
	}
	if knownFlags == 3 || knownFlags == 7 {
		return binary.BigEndian.Uint32(bytes[12:]) != 0
	}
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

func selectIPv4MulticastInterface(
	source, group netip.Addr,
	interfaceName string,
) (*net.Interface, netip.Addr, error) {
	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return nil, netip.Addr{}, fmt.Errorf("looking up multicast interface %q: %w", interfaceName, err)
		}
		if err := validateMulticastInterface(iface); err != nil {
			return nil, netip.Addr{}, err
		}
		local, err := nativeIPv4MulticastInterfaceAddress(iface)
		if err != nil {
			return nil, netip.Addr{}, fmt.Errorf("multicast interface %q: %w", iface.Name, err)
		}
		return iface, local, nil
	}

	local, err := probeIPv4Route(multicastInterfaceRouteTarget(source, group))
	if err != nil {
		return nil, netip.Addr{}, err
	}
	iface, err := findInterfaceByIPv4(local, net.Interfaces, func(iface *net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	})
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if err := validateMulticastInterface(iface); err != nil {
		return nil, netip.Addr{}, err
	}
	return iface, local, nil
}

func selectIPv6MulticastInterface(
	source, group netip.Addr,
	interfaceName string,
) (*net.Interface, netip.Addr, error) {
	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return nil, netip.Addr{}, fmt.Errorf("looking up multicast interface %q: %w", interfaceName, err)
		}
		if err := validateMulticastInterface(iface); err != nil {
			return nil, netip.Addr{}, err
		}
		return iface, netip.Addr{}, nil
	}

	local, err := probeIPv6Route(multicastInterfaceRouteTarget(source, group))
	if err != nil {
		return nil, netip.Addr{}, err
	}
	iface, err := findInterfaceByIPv6(local, net.Interfaces, func(iface *net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	})
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if err := validateMulticastInterface(iface); err != nil {
		return nil, netip.Addr{}, err
	}
	return iface, local, nil
}

func multicastInterfaceRouteTarget(source, group netip.Addr) netip.Addr {
	if source.IsUnspecified() {
		return group
	}
	return source
}

func validateMulticastInterface(iface *net.Interface) error {
	if iface == nil {
		return errors.New("multicast interface is nil")
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("multicast interface %q is down", iface.Name)
	}
	if iface.Flags&net.FlagMulticast == 0 {
		return fmt.Errorf("interface %q does not support multicast", iface.Name)
	}
	return nil
}

func probeIPv4Route(target netip.Addr) (netip.Addr, error) {
	conn, err := net.DialUDP(
		"udp4",
		nil,
		&net.UDPAddr{IP: net.IP(target.Unmap().AsSlice()), Port: 9},
	)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("probing route to multicast interface hint %s: %w", target, err)
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("route probe returned non-UDP local address %T", conn.LocalAddr())
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok || !addr.Unmap().Is4() || addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("route probe returned invalid IPv4 local address %q", local.IP)
	}
	return addr.Unmap(), nil
}

func probeIPv6Route(target netip.Addr) (netip.Addr, error) {
	target = target.Unmap()
	if !target.Is6() || target.Is4In6() {
		return netip.Addr{}, fmt.Errorf("IPv6 route probe requires an IPv6 interface hint")
	}
	conn, err := net.DialUDP(
		"udp6",
		nil,
		&net.UDPAddr{IP: net.IP(target.AsSlice()), Port: 9},
	)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("probing route to multicast interface hint %s: %w", target, err)
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("route probe returned non-UDP local address %T", conn.LocalAddr())
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok || !addr.Is6() || addr.Is4In6() || addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("route probe returned invalid IPv6 local address %q", local.IP)
	}
	return addr, nil
}

type interfacesFunc func() ([]net.Interface, error)
type interfaceAddrsFunc func(*net.Interface) ([]net.Addr, error)

func findIPv4InterfaceAddress(addrs []net.Addr) (netip.Addr, error) {
	for _, addr := range addrs {
		ip, ok := ipFromNetAddr(addr)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && ip.As4() != [4]byte{255, 255, 255, 255} {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("has no usable IPv4 address")
}

func findInterfaceByIPv4(
	local netip.Addr,
	listInterfaces interfacesFunc,
	interfaceAddrs interfaceAddrsFunc,
) (*net.Interface, error) {
	local = local.Unmap()
	if !local.IsValid() || !local.Is4() {
		return nil, fmt.Errorf("local interface address must be IPv4")
	}

	ifaces, err := listInterfaces()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}
	for i := range ifaces {
		addrs, err := interfaceAddrs(&ifaces[i])
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ok := ipFromNetAddr(addr)
			if ok && ip.Unmap() == local {
				iface := ifaces[i]
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no network interface owns route-selected IPv4 address %s", local)
}

func findInterfaceByIPv6(
	local netip.Addr,
	listInterfaces interfacesFunc,
	interfaceAddrs interfaceAddrsFunc,
) (*net.Interface, error) {
	local = local.Unmap()
	if !local.IsValid() || !local.Is6() || local.Is4In6() {
		return nil, fmt.Errorf("local interface address must be IPv6")
	}

	ifaces, err := listInterfaces()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}
	for i := range ifaces {
		addrs, err := interfaceAddrs(&ifaces[i])
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ok := ipFromNetAddr(addr)
			if ok && ip == local {
				iface := ifaces[i]
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no network interface owns route-selected IPv6 address %s", local)
}

func ipFromNetAddr(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}

	var ip net.IP
	switch addr := addr.(type) {
	case *net.IPAddr:
		ip = addr.IP
	case *net.IPNet:
		ip = addr.IP
	case *net.UDPAddr:
		ip = addr.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		parsed, err := netip.ParseAddr(host)
		return parsed.Unmap(), err == nil
	}
	parsed, ok := netip.AddrFromSlice(ip)
	return parsed.Unmap(), ok
}

func multicastPacketMatches(
	sourceAddr net.Addr,
	destination net.IP,
	expectedSource, expectedGroup netip.Addr,
	sourceSpecific bool,
) bool {
	return multicastPacketMismatch(
		sourceAddr,
		destination,
		expectedSource,
		expectedGroup,
		sourceSpecific,
	) == ""
}

func multicastPacketMismatch(
	sourceAddr net.Addr,
	destination net.IP,
	expectedSource, expectedGroup netip.Addr,
	sourceSpecific bool,
) string {
	source, ok := ipFromNetAddr(sourceAddr)
	if !ok || !isUsableMulticastSource(source) {
		return "invalid_source"
	}
	expectedSource = expectedSource.Unmap()
	expectedGroup = expectedGroup.Unmap()
	if source.Is4() != expectedSource.Is4() {
		return "source_family"
	}
	if sourceSpecific && source != expectedSource {
		return "unexpected_source"
	}
	group, ok := netip.AddrFromSlice(destination)
	if !ok {
		return "missing_destination"
	}
	group = group.Unmap()
	if group.Is4() != expectedGroup.Is4() {
		return "destination_family"
	}
	if group != expectedGroup {
		return "unexpected_destination"
	}
	return ""
}
