// The multicast-client example receives experimental minimal multicast QUIC
// DATAGRAMs and prints them to standard output.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	interfaceName := flag.String("interface", "", "multicast receive interface name (default: route to source)")
	serverName := flag.String("server-name", "", "TLS server name (default: hostname from address)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	raw := flag.Bool("raw", false, "write raw DATAGRAM payloads instead of one hex value per line")
	debug := flag.Bool("debug", false, "print secret-safe QUIC and multicast diagnostics to stderr")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] host:port\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var (
		debugLogger *log.Logger
		status      *debugStatus
	)
	if *debug {
		debugLogger = log.New(os.Stderr, "mc-quic debug: ", log.LstdFlags|log.Lmicroseconds)
		status = &debugStatus{}
		debugLogger.Printf(
			"starting address=%q alpn=%q interface=%q insecure=%t server_name=%q",
			flag.Arg(0),
			"mc-quic",
			*interfaceName,
			*insecure,
			*serverName,
		)
		if resolved, err := net.ResolveUDPAddr("udp", flag.Arg(0)); err != nil {
			debugLogger.Printf("address resolution failed: %v", err)
		} else {
			debugLogger.Printf("resolved remote UDP address=%s network=%s", resolved, resolved.Network())
		}
		if *interfaceName == "" {
			debugLogger.Printf("multicast interface selection=automatic (route to advertised source)")
		} else if iface, err := net.InterfaceByName(*interfaceName); err != nil {
			debugLogger.Printf("multicast interface lookup failed name=%q error=%v", *interfaceName, err)
		} else {
			addresses, addressErr := iface.Addrs()
			debugLogger.Printf(
				"multicast interface name=%q index=%d mtu=%d flags=%s addresses=%v address_error=%v",
				iface.Name,
				iface.Index,
				iface.MTU,
				iface.Flags,
				addresses,
				addressErr,
			)
		}
	}

	tlsConfig := &tls.Config{
		NextProtos:         []string{"mc-quic"},
		ServerName:         *serverName,
		InsecureSkipVerify: *insecure, // explicitly controlled by the demo flag
	}
	quicConfig := &quic.Config{
		EnableMulticast:    true,
		MulticastInterface: *interfaceName,
	}
	if *debug {
		quicConfig.Tracer = newDebugConnectionTracer(debugLogger, status)
	}
	dialStart := time.Now()
	if *debug {
		debugLogger.Printf("dial started")
	}
	conn, err := quic.DialAddr(ctx, flag.Arg(0), tlsConfig, quicConfig)
	if err != nil {
		if *debug {
			debugLogger.Printf(
				"dial failed before handshake completed after=%s status={%s} error=%v",
				time.Since(dialStart).Round(time.Millisecond),
				status,
				err,
			)
		}
		log.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if *debug {
		state := conn.ConnectionState()
		debugLogger.Printf(
			"handshake complete after=%s local=%s remote=%s version=%v alpn=%q datagrams_local=%t datagrams_remote=%t",
			time.Since(dialStart).Round(time.Millisecond),
			conn.LocalAddr(),
			conn.RemoteAddr(),
			state.Version,
			state.TLS.NegotiatedProtocol,
			state.SupportsDatagrams.Local,
			state.SupportsDatagrams.Remote,
		)
		debugLogger.Printf("waiting for MC_FLOW and multicast DATAGRAMs")
	}

	for {
		datagram, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				if *debug {
					debugLogger.Printf("stopped by interrupt status={%s}", status)
				}
				return
			}
			if *debug {
				debugLogger.Printf(
					"connection ended after successful handshake status={%s} error=%v",
					status,
					err,
				)
			}
			log.Fatal(err)
		}
		if *debug {
			debugLogger.Printf("application received multicast DATAGRAM payload_bytes=%d", len(datagram))
		}
		if *raw {
			if _, err := os.Stdout.Write(datagram); err != nil {
				log.Fatal(err)
			}
			continue
		}
		fmt.Println(hex.EncodeToString(datagram))
	}
}
