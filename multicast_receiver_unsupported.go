//go:build !darwin && !linux

package quic

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
)

func nativeIPv4MulticastInterfaceAddress(*net.Interface) (netip.Addr, error) {
	return netip.Addr{}, fmt.Errorf("native multicast receive is not supported on %s", runtime.GOOS)
}

func newNativeMulticastReceiver(
	_, _ netip.Addr,
	_ uint16,
	_ string,
	_ multicastDebugFunc,
) (multicastReceiver, error) {
	return nil, fmt.Errorf("native multicast receive is not supported on %s", runtime.GOOS)
}
