package shadowstream

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/sing-shadowsocks2/cipher"
	M "github.com/metacubex/sing/common/metadata"
)

type memoryConn struct {
	reader io.Reader
	writes bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error) {
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}
func (c *memoryConn) Write(p []byte) (int, error)    { return c.writes.Write(p) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (*memoryConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

func newBlackstoneMethod(t *testing.T) *Method {
	t.Helper()
	created, err := NewMethod("aes-128-ctr", C.MethodOptions{Password: "secret#BLACKSTONE"})
	if err != nil {
		t.Fatal(err)
	}
	return created.(*Method)
}

func TestBlackstoneFirstWriteHeader(t *testing.T) {
	method := newBlackstoneMethod(t)
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	oldReader := blackstoneRandReader
	blackstoneRandReader = bytes.NewReader(salt)
	t.Cleanup(func() { blackstoneRandReader = oldReader })

	underlying := &memoryConn{}
	destination := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 443)
	conn := method.DialEarlyConn(underlying, destination)
	payload := []byte("hello")
	n, err := conn.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(payload))
	}

	wire := underlying.writes.Bytes()
	if len(wire) <= 35 {
		t.Fatalf("wire length = %d; want header plus encrypted request", len(wire))
	}
	header := wire[:35]
	if header[0] != 0x01 || header[1] != 0x00 || header[18] != 0x10 {
		t.Fatalf("header markers = %x %x %x; want 01 00 10", header[0], header[1], header[18])
	}
	wantToken := md5.Sum([]byte("secret_onesocks"))
	if !bytes.Equal(header[2:18], wantToken[:]) {
		t.Fatalf("token = %x; want %x", header[2:18], wantToken)
	}
	if !bytes.Equal(header[19:35], salt) {
		t.Fatalf("IV = %x; want %x", header[19:35], salt)
	}
}

func blackstoneResponse(t *testing.T, method *Method, magic byte, pad, iv, plaintext []byte) []byte {
	t.Helper()
	stream, err := method.encryptConstructor(method.key, iv)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := append([]byte(nil), plaintext...)
	stream.XORKeyStream(ciphertext, ciphertext)
	wire := []byte{magic, byte(len(pad))}
	wire = append(wire, pad...)
	wire = append(wire, bytes.Repeat([]byte{0x5a}, 17)...)
	wire = append(wire, iv...)
	return append(wire, ciphertext...)
}

func TestBlackstoneReadResponseMagicAndIV(t *testing.T) {
	method := newBlackstoneMethod(t)
	iv := []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	plaintext := []byte("server payload")
	wire := blackstoneResponse(t, method, 0x01, []byte{0xaa, 0xbb, 0xcc}, iv, plaintext)
	underlying := &memoryConn{reader: bytes.NewReader(wire)}
	conn := method.DialEarlyConn(underlying, M.Socksaddr{})

	got := make([]byte, len(plaintext))
	n, err := io.ReadFull(conn, got)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(plaintext) || !bytes.Equal(got, plaintext) {
		t.Fatalf("Read = %q; want %q", got[:n], plaintext)
	}
}

func TestBlackstoneReadRejectsInvalidMagic(t *testing.T) {
	method := newBlackstoneMethod(t)
	iv := bytes.Repeat([]byte{0x11}, method.saltLength)
	wire := blackstoneResponse(t, method, 0x02, nil, iv, []byte("payload"))
	conn := method.DialEarlyConn(&memoryConn{reader: bytes.NewReader(wire)}, M.Socksaddr{})

	if _, err := conn.Read(make([]byte, 7)); err == nil {
		t.Fatal("Read succeeded with invalid BLACKSTONE magic")
	}
}

func TestBlackstoneReadRejectsTruncatedHeader(t *testing.T) {
	method := newBlackstoneMethod(t)
	iv := bytes.Repeat([]byte{0x22}, method.saltLength)
	full := blackstoneResponse(t, method, 0x01, []byte{1, 2}, iv, nil)
	cases := map[string][]byte{
		"magic":   full[:1],
		"padding": full[:3],
		"token":   full[:2+2+8],
		"IV":      full[:2+2+17+8],
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			conn := method.DialEarlyConn(&memoryConn{reader: bytes.NewReader(wire)}, M.Socksaddr{})
			_, err := conn.Read(make([]byte, 1))
			if err == nil || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("Read error = %v; want EOF or unexpected EOF", err)
			}
		})
	}
}
