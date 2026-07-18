# Experimental minimal multicast QUIC client

This fork contains a proof-of-concept client for the minimal multicast QUIC
profile. It is intentionally limited to one IPv4 or IPv6 multicast flow per client
connection, `TLS_AES_128_GCM_SHA256`, standard one- through four-byte truncated
QUIC packet numbers, Key Phase 0, and DATAGRAM payloads.

Enable it on a normal client connection:

```go
conn, err := quic.DialAddr(ctx, address, &tls.Config{
	NextProtos: []string{"mc-quic"},
}, &quic.Config{
	EnableMulticast: true,
	// Optional. If omitted, the client selects the interface from the route
	// to the source advertised by MC_FLOW.
	MulticastInterface: "en0",
})
```

`EnableMulticast` also enables RFC 9221 DATAGRAM support. Multicast DATAGRAM
payloads are delivered by the existing `Conn.ReceiveDatagram` method and are
not distinguished from unicast DATAGRAMs.

The client advertises transport parameter `0xff4d40`, accepts `MC_FLOW`
(`0xff4d43`) on the unicast connection, joins the announced `(S,G):port` for
SSM or `(*,G):port` for ASM, and uses an independent fixed-key receive and
packet-number context. Multicast packets never generate ACKs, refresh the
unicast idle timeout, or update unicast loss recovery, RTT, congestion, or path
state.

This client accepts every packet-number length encoded by a standard QUIC
short header (one through four bytes) and reconstructs the full value in the
flow's independent packet-number space. This intentionally relaxes the original
PoC interop profile's fixed four-byte restriction. The `First Packet Number`
field in `MC_FLOW` remains a QUIC variable-length integer; packet numbers in
short headers use QUIC's truncated packet-number encoding, not QUIC varints.

Accepted IPv4 groups are in `224.0.0.0/4`, excluding the reserved addresses
`224.0.0.0` and `232.0.0.0`. Groups in `232.0.0.0/8` use source-specific
multicast (SSM); every other accepted IPv4 group uses any-source multicast
(ASM). For local IPv4 ASM experiments, prefer an administratively scoped
`239/8` group and avoid the `224.0.0.0/24` control block.

For IPv6, a group with the SSM flag pattern and a zero prefix length uses SSM;
the canonical form is `ff3x:0000::/32`. Other supported IPv6 multicast groups
use ASM. This includes the server's RFC 3306-form lab group
`ff3e:30:3ffe:ffff:1::4`: its nonzero prefix-length field makes it ASM despite
the leading `ff3e`. Use an explicit interface for scoped IPv6 when route
selection would be ambiguous.

This is an extension of the original SSM-only PoC profile and does not change
the `MC_FLOW` encoding. For ASM, the advertised source address is used as the
default interface-route hint, but group membership and packet filtering accept
any usable source of the same IP family.
Only packets that authenticate with the flow secret are delivered, but
unauthenticated ASM traffic can still consume sustained receive and
cryptographic processing capacity; only queued memory is bounded.

ASM changes IP membership and source filtering only. A flow still needs one
coordinated packet-number allocator across all multicast senders. Independent
senders sharing a flow secret and packet-number space can reuse AEAD nonces and
are not supported by this PoC.

Run the example:

```sh
go run ./example/multicast-client -insecure -interface en0 server.example:4433
```

For an IPv6 unicast server address, include the port inside brackets and quote
the shell argument:

```sh
go run ./example/multicast-client -insecure -interface en0 \
  '[2001:67c:1232:6004:c78:6140:6e37:69ce]:4434'
```

By default it prints one hexadecimal DATAGRAM payload per line. Pass `-raw` to
write payload bytes directly.

This is a lab PoC. All receivers share one traffic secret and can therefore
forge packets accepted by other receivers. It is not suitable for production.
