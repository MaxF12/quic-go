// The multicast-client example receives experimental minimal multicast QUIC
// DATAGRAMs and either prints them or displays RTP/H.264 video using ffplay.
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	interfaceName := flag.String("interface", "", "multicast receive interface name (default: route to source)")
	serverName := flag.String("server-name", "", "TLS server name (default: hostname from address)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	raw := flag.Bool("raw", false, "write raw DATAGRAM payloads instead of one hex value per line")
	debug := flag.Bool("debug", false, "print secret-safe QUIC and multicast diagnostics to stderr")
	display := flag.Bool("display", false, "decode and display RTP/H.264 DATAGRAMs using ffplay")
	ffplayExecutable := flag.String("ffplay", "ffplay", "ffplay executable used by -display")
	rtpPayloadType := flag.Uint("rtp-payload-type", defaultRTPPayloadType, "RTP payload type used by -display")
	spropParameterSets := flag.String(
		"h264-sprop-parameter-sets",
		"",
		"optional base64 SPS,PPS value from SDP sprop-parameter-sets",
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] host:port\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if *display && *raw {
		return errors.New("-display and -raw cannot be used together")
	}
	if *rtpPayloadType > 127 {
		return fmt.Errorf("RTP payload type must be between 0 and 127: %d", *rtpPayloadType)
	}
	keepAlivePeriod := time.Duration(0)
	if *display {
		keepAlivePeriod = displayKeepAlivePeriod
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

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
		debugLogger.Printf(
			"display=%t rtp_payload_type=%d keep_alive=%s",
			*display,
			*rtpPayloadType,
			keepAlivePeriod,
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

	var player *rtpPlayer
	if *display {
		var err error
		player, err = startRTPPlayer(ctx, rtpPlayerOptions{
			Executable:         *ffplayExecutable,
			PayloadType:        uint8(*rtpPayloadType),
			SpropParameterSets: *spropParameterSets,
			FFplayStderr:       os.Stderr,
		})
		if err != nil {
			return err
		}
		defer player.Close()
		log.Printf(
			"displaying RTP/H.264 payload type %d via %s on 127.0.0.1:%d",
			*rtpPayloadType,
			player.executable,
			player.port,
		)
		if *spropParameterSets == "" {
			log.Printf("display is waiting for in-band H.264 SPS/PPS")
		}
		go func() {
			select {
			case <-player.Done():
				cancel()
			case <-ctx.Done():
			}
		}()
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
	if *display {
		quicConfig.KeepAlivePeriod = keepAlivePeriod
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
		if errors.Is(err, context.Canceled) {
			if signalCtx.Err() != nil {
				return nil
			}
			if player != nil {
				select {
				case <-player.Done():
					if playerErr := player.WaitError(); playerErr != nil {
						return fmt.Errorf("ffplay exited before the QUIC handshake completed: %w", playerErr)
					}
					return nil
				default:
				}
			}
		}
		return err
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
				if signalCtx.Err() != nil {
					return nil
				}
				if player != nil {
					select {
					case <-player.Done():
						if playerErr := player.WaitError(); playerErr != nil {
							return fmt.Errorf("ffplay exited: %w", playerErr)
						}
						return nil
					default:
					}
				}
				return nil
			}
			if *debug {
				debugLogger.Printf(
					"connection ended after successful handshake status={%s} error=%v",
					status,
					err,
				)
			}
			return err
		}
		if *debug {
			debugLogger.Printf("application received multicast DATAGRAM payload_bytes=%d", len(datagram))
		}
		if player != nil {
			info, err := parseRTPPacket(datagram, uint8(*rtpPayloadType))
			if err != nil {
				if *debug {
					debugLogger.Printf(
						"display dropped non-RTP DATAGRAM payload_bytes=%d error=%v",
						len(datagram),
						err,
					)
				}
				continue
			}
			if *debug {
				nalTypes, nalErr := h264NALTypes(info.Payload)
				debugLogger.Printf(
					"RTP/H.264 sequence=%d timestamp=%d marker=%t payload_type=%d ssrc=%#x payload_bytes=%d nal_types=%s nal_error=%v",
					info.Sequence,
					info.Timestamp,
					info.Marker,
					info.PayloadType,
					info.SSRC,
					len(info.Payload),
					formatNALTypes(nalTypes),
					nalErr,
				)
			}
			if err := player.WriteRTP(datagram); err != nil {
				return err
			}
			continue
		}
		if *raw {
			if _, err := os.Stdout.Write(datagram); err != nil {
				return err
			}
			continue
		}
		fmt.Println(hex.EncodeToString(datagram))
	}
}
