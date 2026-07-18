//go:build darwin || linux

package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/net/ipv6"
)

type nativeIPv6MulticastReceiver struct {
	conn           *ipv6.PacketConn
	leave          func() error
	expectedSource netip.Addr
	expectedGroup  netip.Addr
	sourceSpecific bool
	interfaceIndex int
	debugf         multicastDebugFunc

	closeOnce sync.Once
	closeErr  error
}

var _ multicastReceiver = (*nativeIPv6MulticastReceiver)(nil)

func newNativeIPv6MulticastReceiver(
	source, group netip.Addr,
	port uint16,
	interfaceName string,
	debugf multicastDebugFunc,
) (multicastReceiver, error) {
	iface, localAddress, err := selectIPv6MulticastInterface(source, group, interfaceName)
	if err != nil {
		debugf.logf("IPv6 interface selection failed: %v", err)
		return nil, err
	}
	selection := "route"
	if interfaceName != "" {
		selection = "explicit"
	}
	local := "<not-probed>"
	if localAddress.IsValid() {
		local = localAddress.String()
	}
	debugf.logf(
		"selected IPv6 interface mode=%s name=%q index=%d local=%s source_hint=%s route_hint=%s",
		selection,
		iface.Name,
		iface.Index,
		local,
		source,
		multicastInterfaceRouteTarget(source, group),
	)

	listenConfig := net.ListenConfig{
		Control: func(_, _ string, rawConn syscall.RawConn) error {
			var socketOptionErr error
			if err := rawConn.Control(func(fd uintptr) {
				socketOptionErr = configureNativeIPv6MulticastSocket(int(fd))
			}); err != nil {
				return err
			}
			return socketOptionErr
		},
	}
	packetConn, err := listenConfig.ListenPacket(
		context.Background(),
		"udp6",
		net.JoinHostPort("::", strconv.Itoa(int(port))),
	)
	if err != nil {
		debugf.logf("IPv6 socket bind failed port=%d: %v", port, err)
		return nil, fmt.Errorf("binding IPv6 multicast receiver to UDP port %d: %w", port, err)
	}
	debugf.logf("bound IPv6 multicast socket local=%s", packetConn.LocalAddr())

	conn := ipv6.NewPacketConn(packetConn)
	closeOnError := func(err error) (multicastReceiver, error) {
		return nil, errors.Join(err, conn.Close())
	}
	if err := conn.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
		debugf.logf("enabling IPv6 packet metadata failed: %v", err)
		return closeOnError(fmt.Errorf("enabling IPv6 multicast packet metadata: %w", err))
	}
	debugf.logf("enabled IPv6 destination and ingress-interface metadata")

	sourceSpecific := isIPv6SSMGroup(group)
	flowKind := "ASM"
	channel := fmt.Sprintf("(*,%s)", group)
	groupAddr := &net.UDPAddr{IP: net.IP(group.AsSlice())}
	var leave func() error
	if sourceSpecific {
		flowKind = "SSM"
		channel = fmt.Sprintf("(%s,%s)", source, group)
		sourceAddr := &net.UDPAddr{IP: net.IP(source.AsSlice())}
		if err := conn.JoinSourceSpecificGroup(iface, groupAddr, sourceAddr); err != nil {
			debugf.logf(
				"IPv6 %s join failed channel=%s interface=%q index=%d: %v",
				flowKind,
				channel,
				iface.Name,
				iface.Index,
				err,
			)
			return closeOnError(fmt.Errorf(
				"joining IPv6 %s flow %s on interface %q: %w",
				flowKind,
				channel,
				iface.Name,
				err,
			))
		}
		leave = func() error {
			return conn.LeaveSourceSpecificGroup(iface, groupAddr, sourceAddr)
		}
	} else {
		if err := conn.JoinGroup(iface, groupAddr); err != nil {
			debugf.logf(
				"IPv6 %s join failed channel=%s interface=%q index=%d: %v",
				flowKind,
				channel,
				iface.Name,
				iface.Index,
				err,
			)
			return closeOnError(fmt.Errorf(
				"joining IPv6 %s flow %s on interface %q: %w",
				flowKind,
				channel,
				iface.Name,
				err,
			))
		}
		leave = func() error { return conn.LeaveGroup(iface, groupAddr) }
	}
	debugf.logf(
		"joined IPv6 %s channel=%s interface=%q index=%d",
		flowKind,
		channel,
		iface.Name,
		iface.Index,
	)

	return &nativeIPv6MulticastReceiver{
		conn:           conn,
		leave:          leave,
		expectedSource: source,
		expectedGroup:  group,
		sourceSpecific: sourceSpecific,
		interfaceIndex: iface.Index,
		debugf:         debugf,
	}, nil
}

func (r *nativeIPv6MulticastReceiver) Read(buf []byte) (int, net.Addr, error) {
	for {
		n, control, source, err := r.conn.ReadFrom(buf)
		if err != nil {
			r.debugf.logf("IPv6 multicast socket read failed: %v", err)
			return 0, nil, err
		}
		if control == nil {
			r.debugf.logf(
				"dropped IPv6 UDP packet bytes=%d source=%s reason=missing_packet_metadata",
				n,
				source,
			)
			continue
		}
		r.debugf.logf(
			"received IPv6 UDP packet bytes=%d source=%s destination=%s ifindex=%d",
			n,
			source,
			control.Dst,
			control.IfIndex,
		)
		if control.IfIndex != r.interfaceIndex {
			r.debugf.logf(
				"dropped IPv6 UDP packet reason=unexpected_interface got=%d want=%d",
				control.IfIndex,
				r.interfaceIndex,
			)
			continue
		}
		if reason := multicastPacketMismatch(
			source,
			control.Dst,
			r.expectedSource,
			r.expectedGroup,
			r.sourceSpecific,
		); reason != "" {
			r.debugf.logf(
				"dropped IPv6 UDP packet reason=%s expected_source=%s expected_group=%s source_specific=%t",
				reason,
				r.expectedSource,
				r.expectedGroup,
				r.sourceSpecific,
			)
			continue
		}
		r.debugf.logf("accepted IPv6 UDP packet bytes=%d source=%s", n, source)
		return n, source, nil
	}
}

func (r *nativeIPv6MulticastReceiver) Close() error {
	r.closeOnce.Do(func() {
		r.debugf.logf(
			"leaving IPv6 multicast group=%s interface_index=%d",
			r.expectedGroup,
			r.interfaceIndex,
		)
		var leaveErr error
		if r.leave != nil {
			leaveErr = r.leave()
		}
		r.closeErr = errors.Join(
			leaveErr,
			r.conn.Close(),
		)
		if r.closeErr != nil {
			r.debugf.logf("closing IPv6 multicast receiver failed: %v", r.closeErr)
		} else {
			r.debugf.logf("closed IPv6 multicast receiver")
		}
	})
	return r.closeErr
}
