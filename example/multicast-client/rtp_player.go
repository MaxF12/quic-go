package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultRTPPayloadType  = 96
	h264ClockRate          = 90000
	rtpJitterDelay         = 100 * time.Millisecond
	displayKeepAlivePeriod = 2 * time.Second
	playerStartupTimeout   = 3 * time.Second
	playerStartupPoll      = 10 * time.Millisecond
	playerShutdownTimeout  = 2 * time.Second
)

type rtpPlayerOptions struct {
	Executable         string
	PayloadType        uint8
	SpropParameterSets string
	FFplayStderr       io.Writer
}

type packetWriteCloser interface {
	Write([]byte) (int, error)
	Close() error
}

type udpPacketWriter struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (w *udpPacketWriter) Write(packet []byte) (int, error) {
	return w.conn.WriteToUDP(packet, w.target)
}

func (w *udpPacketWriter) Close() error {
	return w.conn.Close()
}

type rtpPlayer struct {
	conn       packetWriteCloser
	cmd        *exec.Cmd
	executable string
	port       int

	done chan struct{}

	waitMx  sync.Mutex
	waitErr error

	closeOnce sync.Once
}

func startRTPPlayer(ctx context.Context, options rtpPlayerOptions) (*rtpPlayer, error) {
	executable := options.Executable
	if executable == "" {
		executable = "ffplay"
	}
	executable, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf(
			"finding ffplay executable %q: %w (install FFmpeg, for example with `brew install ffmpeg`)",
			options.Executable,
			err,
		)
	}

	port, err := availableLoopbackUDPPort()
	if err != nil {
		return nil, err
	}
	sdp, err := buildH264SDP(port, options.PayloadType, options.SpropParameterSets)
	if err != nil {
		return nil, err
	}

	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	args := ffplayArguments()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = strings.NewReader(sdp)
	cmd.Stdout = io.Discard
	cmd.Stderr = options.FFplayStderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := cmd.Process.Signal(os.Interrupt)
		if errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		return err
	}
	cmd.WaitDelay = playerShutdownTimeout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting ffplay: %w", err)
	}

	player := &rtpPlayer{
		cmd:        cmd,
		executable: executable,
		port:       port,
		done:       make(chan struct{}),
	}
	go func() {
		err := cmd.Wait()
		player.waitMx.Lock()
		player.waitErr = err
		player.waitMx.Unlock()
		close(player.done)
	}()
	if err := waitForLoopbackUDPListener(ctx, target, player.done, playerStartupTimeout); err != nil {
		var waitErr error
		select {
		case <-player.Done():
			waitErr = player.WaitError()
		default:
		}
		player.Close()
		if waitErr != nil {
			return nil, fmt.Errorf("%w (ffplay: %v)", err, waitErr)
		}
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		player.Close()
		return nil, fmt.Errorf("opening RTP loopback sender to %s: %w", target, err)
	}
	player.conn = &udpPacketWriter{conn: conn, target: target}
	return player, nil
}

func (p *rtpPlayer) Done() <-chan struct{} { return p.done }

func (p *rtpPlayer) WaitError() error {
	p.waitMx.Lock()
	defer p.waitMx.Unlock()
	return p.waitErr
}

func (p *rtpPlayer) WriteRTP(packet []byte) error {
	n, err := p.conn.Write(packet)
	if err != nil {
		return fmt.Errorf("forwarding RTP packet to ffplay: %w", err)
	}
	if n != len(packet) {
		return io.ErrShortWrite
	}
	return nil
}

func (p *rtpPlayer) Close() {
	p.closeOnce.Do(func() {
		if p.conn != nil {
			_ = p.conn.Close()
		}
		select {
		case <-p.done:
			return
		default:
		}

		if p.cmd.Process != nil {
			_ = p.cmd.Process.Signal(os.Interrupt)
		}
		select {
		case <-p.done:
		case <-time.After(playerShutdownTimeout):
			if p.cmd.Process != nil {
				_ = p.cmd.Process.Kill()
			}
			<-p.done
		}
	})
}

func availableLoopbackUDPPort() (int, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, fmt.Errorf("allocating an RTP loopback port: %w", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		return 0, fmt.Errorf("releasing the RTP loopback port probe: %w", err)
	}
	return port, nil
}

func waitForLoopbackUDPListener(
	ctx context.Context,
	target *net.UDPAddr,
	processDone <-chan struct{},
	timeout time.Duration,
) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(playerStartupPoll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for ffplay RTP socket: %w", context.Cause(ctx))
		case <-processDone:
			return errors.New("ffplay exited before opening its RTP socket")
		case <-timer.C:
			return fmt.Errorf("timed out waiting %s for ffplay RTP socket %s", timeout, target)
		case <-ticker.C:
		}

		probe, err := net.ListenUDP("udp4", target)
		switch {
		case err == nil:
			if closeErr := probe.Close(); closeErr != nil {
				return fmt.Errorf("closing ffplay RTP readiness probe for %s: %w", target, closeErr)
			}
		case errors.Is(err, syscall.EADDRINUSE):
			select {
			case <-processDone:
				return errors.New("ffplay exited while opening its RTP socket")
			default:
				return nil
			}
		default:
			return fmt.Errorf("probing ffplay RTP socket %s: %w", target, err)
		}
	}
}

func buildH264SDP(port int, payloadType uint8, spropParameterSets string) (string, error) {
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid RTP UDP port: %d", port)
	}
	if payloadType > 127 {
		return "", fmt.Errorf("invalid RTP payload type: %d", payloadType)
	}
	if strings.ContainsAny(spropParameterSets, "\r\n") {
		return "", errors.New("H.264 sprop-parameter-sets must not contain newlines")
	}

	fmtp := "packetization-mode=1"
	if spropParameterSets != "" {
		fmtp += ";sprop-parameter-sets=" + spropParameterSets
	}
	return strings.Join([]string{
		"v=0",
		"o=- 0 0 IN IP4 127.0.0.1",
		"s=MC-QUIC RTP/H.264",
		"c=IN IP4 127.0.0.1",
		"t=0 0",
		"m=video " + strconv.Itoa(port) + " RTP/AVP " + strconv.Itoa(int(payloadType)),
		"a=rtpmap:" + strconv.Itoa(int(payloadType)) + " H264/" + strconv.Itoa(h264ClockRate),
		"a=fmtp:" + strconv.Itoa(int(payloadType)) + " " + fmtp,
		"a=recvonly",
		"",
	}, "\n"), nil
}

func ffplayArguments() []string {
	return []string{
		"-hide_banner",
		"-loglevel", "warning",
		"-protocol_whitelist", "pipe,udp,rtp",
		"-fflags", "nobuffer",
		"-flags", "low_delay",
		"-reorder_queue_size", "64",
		"-max_delay", strconv.FormatInt(rtpJitterDelay.Microseconds(), 10),
		"-f", "sdp",
		"-i", "pipe:0",
		"-an",
		"-framedrop",
		"-window_title", "MC-QUIC RTP/H.264",
	}
}

type rtpPacketInfo struct {
	PayloadType uint8
	Marker      bool
	Sequence    uint16
	Timestamp   uint32
	SSRC        uint32
	Payload     []byte
}

func parseRTPPacket(packet []byte, expectedPayloadType uint8) (rtpPacketInfo, error) {
	if len(packet) < 12 {
		return rtpPacketInfo{}, fmt.Errorf("RTP packet too short: %d bytes", len(packet))
	}
	if version := packet[0] >> 6; version != 2 {
		return rtpPacketInfo{}, fmt.Errorf("unexpected RTP version: %d", version)
	}

	payloadType := packet[1] & 0x7f
	if payloadType != expectedPayloadType {
		return rtpPacketInfo{}, fmt.Errorf(
			"unexpected RTP payload type: got %d, want %d",
			payloadType,
			expectedPayloadType,
		)
	}

	offset := 12 + 4*int(packet[0]&0xf)
	if len(packet) < offset {
		return rtpPacketInfo{}, errors.New("truncated RTP CSRC list")
	}
	if packet[0]&0x10 != 0 {
		if len(packet) < offset+4 {
			return rtpPacketInfo{}, errors.New("truncated RTP extension header")
		}
		extensionWords := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4 + 4*extensionWords
		if len(packet) < offset {
			return rtpPacketInfo{}, errors.New("truncated RTP extension data")
		}
	}

	end := len(packet)
	if packet[0]&0x20 != 0 {
		padding := int(packet[len(packet)-1])
		if padding == 0 || padding > end-offset {
			return rtpPacketInfo{}, errors.New("invalid RTP padding")
		}
		end -= padding
	}
	if end <= offset {
		return rtpPacketInfo{}, errors.New("RTP packet has no payload")
	}

	return rtpPacketInfo{
		PayloadType: payloadType,
		Marker:      packet[1]&0x80 != 0,
		Sequence:    binary.BigEndian.Uint16(packet[2:4]),
		Timestamp:   binary.BigEndian.Uint32(packet[4:8]),
		SSRC:        binary.BigEndian.Uint32(packet[8:12]),
		Payload:     packet[offset:end],
	}, nil
}

func h264NALTypes(payload []byte) ([]uint8, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty H.264 RTP payload")
	}
	nalType := payload[0] & 0x1f
	switch nalType {
	case 24: // STAP-A
		var types []uint8
		for offset := 1; offset < len(payload); {
			if len(payload)-offset < 2 {
				return nil, errors.New("truncated H.264 STAP-A length")
			}
			length := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 2
			if length == 0 || length > len(payload)-offset {
				return nil, errors.New("invalid H.264 STAP-A NAL length")
			}
			types = append(types, payload[offset]&0x1f)
			offset += length
		}
		return types, nil
	case 28: // FU-A
		if len(payload) < 2 {
			return nil, errors.New("truncated H.264 FU-A header")
		}
		return []uint8{payload[1] & 0x1f}, nil
	default:
		return []uint8{nalType}, nil
	}
}

func formatNALTypes(types []uint8) string {
	if len(types) == 0 {
		return "[]"
	}
	values := make([]string, 0, len(types))
	for _, typ := range types {
		values = append(values, strconv.Itoa(int(typ)))
	}
	return "[" + strings.Join(values, ",") + "]"
}
