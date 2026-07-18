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

	"golang.org/x/net/ipv4"
)

type nativeIPv4MulticastReceiver struct {
	conn           *ipv4.PacketConn
	leave          func() error
	expectedSource netip.Addr
	expectedGroup  netip.Addr
	sourceSpecific bool
	interfaceIndex int
	debugf         multicastDebugFunc

	closeOnce sync.Once
	closeErr  error
}

var _ multicastReceiver = (*nativeIPv4MulticastReceiver)(nil)

func newNativeMulticastReceiver(
	source, group netip.Addr,
	port uint16,
	interfaceName string,
	debugf multicastDebugFunc,
) (multicastReceiver, error) {
	source = source.Unmap()
	group = group.Unmap()
	if err := validateMulticastFlow(source, group, port); err != nil {
		debugf.logf("receiver validation failed: %v", err)
		return nil, err
	}
	if source.Is4() {
		return newNativeIPv4MulticastReceiver(source, group, port, interfaceName, debugf)
	}
	return newNativeIPv6MulticastReceiver(source, group, port, interfaceName, debugf)
}

func newNativeIPv4MulticastReceiver(
	source, group netip.Addr,
	port uint16,
	interfaceName string,
	debugf multicastDebugFunc,
) (multicastReceiver, error) {
	iface, interfaceAddress, err := selectIPv4MulticastInterface(source, group, interfaceName)
	if err != nil {
		debugf.logf("IPv4 interface selection failed: %v", err)
		return nil, err
	}
	selection := "route"
	if interfaceName != "" {
		selection = "explicit"
	}
	debugf.logf(
		"selected IPv4 interface mode=%s name=%q index=%d local=%s source_hint=%s route_hint=%s",
		selection,
		iface.Name,
		iface.Index,
		interfaceAddress,
		source,
		multicastInterfaceRouteTarget(source, group),
	)

	listenConfig := net.ListenConfig{
		Control: func(_, _ string, rawConn syscall.RawConn) error {
			var socketOptionErr error
			if err := rawConn.Control(func(fd uintptr) {
				socketOptionErr = configureNativeIPv4MulticastSocket(int(fd))
			}); err != nil {
				return err
			}
			return socketOptionErr
		},
	}
	packetConn, err := listenConfig.ListenPacket(
		context.Background(),
		"udp4",
		net.JoinHostPort("0.0.0.0", strconv.Itoa(int(port))),
	)
	if err != nil {
		debugf.logf("IPv4 socket bind failed port=%d: %v", port, err)
		return nil, fmt.Errorf("binding multicast receiver to UDP port %d: %w", port, err)
	}
	debugf.logf("bound IPv4 multicast socket local=%s", packetConn.LocalAddr())

	conn := ipv4.NewPacketConn(packetConn)
	closeOnError := func(err error) (multicastReceiver, error) {
		return nil, errors.Join(err, conn.Close())
	}
	if err := conn.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		debugf.logf("enabling IPv4 packet metadata failed: %v", err)
		return closeOnError(fmt.Errorf("enabling multicast packet metadata: %w", err))
	}
	debugf.logf("enabled IPv4 destination and ingress-interface metadata")

	sourceSpecific := isIPv4SSMGroup(group)
	flowKind := "ASM"
	channel := fmt.Sprintf("(*,%s)", group)
	var leave func() error
	if sourceSpecific {
		flowKind = "SSM"
		channel = fmt.Sprintf("(%s,%s)", source, group)
		leave, err = joinNativeIPv4SSM(packetConn, conn, iface, interfaceAddress, source, group)
	} else {
		leave, err = joinNativeIPv4ASM(packetConn, conn, iface, interfaceAddress, group)
	}
	if err != nil {
		debugf.logf(
			"IPv4 %s join failed channel=%s interface=%q index=%d: %v",
			flowKind,
			channel,
			iface.Name,
			iface.Index,
			err,
		)
		return closeOnError(fmt.Errorf(
			"joining IPv4 %s flow %s on interface %q: %w",
			flowKind,
			channel,
			iface.Name,
			err,
		))
	}
	debugf.logf(
		"joined IPv4 %s channel=%s interface=%q index=%d",
		flowKind,
		channel,
		iface.Name,
		iface.Index,
	)

	return &nativeIPv4MulticastReceiver{
		conn:           conn,
		leave:          leave,
		expectedSource: source,
		expectedGroup:  group,
		sourceSpecific: sourceSpecific,
		interfaceIndex: iface.Index,
		debugf:         debugf,
	}, nil
}

func (r *nativeIPv4MulticastReceiver) Read(buf []byte) (int, net.Addr, error) {
	for {
		n, control, source, err := r.conn.ReadFrom(buf)
		if err != nil {
			r.debugf.logf("IPv4 multicast socket read failed: %v", err)
			return 0, nil, err
		}
		if control == nil {
			r.debugf.logf(
				"dropped IPv4 UDP packet bytes=%d source=%s reason=missing_packet_metadata",
				n,
				source,
			)
			continue
		}
		r.debugf.logf(
			"received IPv4 UDP packet bytes=%d source=%s destination=%s ifindex=%d",
			n,
			source,
			control.Dst,
			control.IfIndex,
		)
		if control.IfIndex != r.interfaceIndex {
			r.debugf.logf(
				"dropped IPv4 UDP packet reason=unexpected_interface got=%d want=%d",
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
				"dropped IPv4 UDP packet reason=%s expected_source=%s expected_group=%s source_specific=%t",
				reason,
				r.expectedSource,
				r.expectedGroup,
				r.sourceSpecific,
			)
			continue
		}
		r.debugf.logf("accepted IPv4 UDP packet bytes=%d source=%s", n, source)
		return n, source, nil
	}
}

func (r *nativeIPv4MulticastReceiver) Close() error {
	r.closeOnce.Do(func() {
		r.debugf.logf(
			"leaving IPv4 multicast group=%s interface_index=%d",
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
			r.debugf.logf("closing IPv4 multicast receiver failed: %v", r.closeErr)
		} else {
			r.debugf.logf("closed IPv4 multicast receiver")
		}
	})
	return r.closeErr
}
