package shadowstream

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/sing-shadowsocks2/cipher"
)

// udpPair returns a client packet conn writing to a raw UDP socket we read.
func udpPair(t *testing.T, method string) (*clientPacketConn, *net.UDPConn, *Method) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	raw, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	created, err := NewMethod(method, C.MethodOptions{Password: "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	m := created.(*Method)
	return m.DialPacketConn(raw).(*clientPacketConn), server, m
}

// Ordinary stream-SS UDP through the net.PacketConn API (the path the mihomo
// tunnel uses) must not panic and must produce exactly the standard wire:
// salt || E(addr || payload).
func TestStreamUDPWriteToMatchesStandardWire(t *testing.T) {
	for _, method := range []string{"aes-128-ctr", "aes-256-cfb", "chacha20-ietf", "rc4-md5"} {
		t.Run(method, func(t *testing.T) {
			conn, server, m := udpPair(t, method)
			payload := make([]byte, 333)
			_, _ = rand.Read(payload)
			dest := &net.UDPAddr{IP: net.IP{198, 51, 100, 7}, Port: 5353}
			n, err := conn.WriteTo(payload, dest)
			if err != nil || n != len(payload) {
				t.Fatalf("WriteTo n=%d err=%v", n, err)
			}
			_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
			wire := make([]byte, 65535)
			wn, _, err := server.ReadFromUDP(wire)
			if err != nil {
				t.Fatal(err)
			}
			wire = wire[:wn]
			want := m.saltLength + 1 + 4 + 2 + len(payload)
			if wn != want {
				t.Fatalf("wire length %d, want %d (payload duplicated or truncated)", wn, want)
			}
			stream, err := m.decryptConstructor(m.key, wire[:m.saltLength])
			if err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, wn-m.saltLength)
			stream.XORKeyStream(plain, wire[m.saltLength:])
			if plain[0] != 0x01 || !bytes.Equal(plain[1:5], dest.IP.To4()) || int(plain[5])<<8|int(plain[6]) != dest.Port {
				t.Fatalf("address header mismatch: % x", plain[:7])
			}
			if !bytes.Equal(plain[7:], payload) {
				t.Fatal("payload mismatch after decrypt")
			}
		})
	}
}

// A datagram shorter than the salt must be rejected, not sliced out of range.
func TestStreamUDPReadFromRejectsShortDatagram(t *testing.T) {
	conn, server, m := udpPair(t, "aes-128-ctr")
	if _, err := conn.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, client, err := server.ReadFromUDP(make([]byte, 2048))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.WriteToUDP(make([]byte, m.saltLength-1), client); err != nil {
		t.Fatal(err)
	}
	_ = conn.ExtendedConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("short datagram panicked: %v", r)
		}
	}()
	if _, _, err := conn.ReadFrom(make([]byte, 2048)); err == nil {
		t.Fatal("short datagram was accepted")
	}
}
