package dialer

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type dummyPacketConn struct {
	readPayload []byte
	readAddr    net.Addr
	readErr     error
	writtenData []byte
	writtenAddr net.Addr
	closed      bool
}

func (d *dummyPacketConn) Read(b []byte) (n int, err error) {
	copy(b, d.readPayload)
	return len(d.readPayload), d.readErr
}

func (d *dummyPacketConn) Write(b []byte) (n int, err error) {
	d.writtenData = append([]byte(nil), b...)
	return len(b), nil
}

func (d *dummyPacketConn) Close() error {
	d.closed = true
	return nil
}

func (d *dummyPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (d *dummyPacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
}

func (d *dummyPacketConn) SetDeadline(t time.Time) error      { return nil }
func (d *dummyPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *dummyPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (d *dummyPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	copy(p, d.readPayload)
	return len(d.readPayload), d.readAddr, d.readErr
}

func (d *dummyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	d.writtenData = append([]byte(nil), p...)
	d.writtenAddr = addr
	return len(p), nil
}

func TestUDPConnImplementsPacketConn(t *testing.T) {
	dummy := &dummyPacketConn{
		readPayload: []byte("test-payload"),
		readAddr:    &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9999},
	}
	conn := &udpConn{
		Conn:       dummy,
		packetConn: dummy,
	}

	// Must satisfy net.PacketConn interface assertion without panic
	pc, ok := any(conn).(net.PacketConn)
	if !ok || pc == nil {
		t.Fatal("udpConn does not implement net.PacketConn")
	}

	buf := make([]byte, 64)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(dummy.readPayload) || !bytes.Equal(buf[:n], dummy.readPayload) {
		t.Fatalf("unexpected read data: %s", string(buf[:n]))
	}
	if addr.String() != dummy.readAddr.String() {
		t.Fatalf("unexpected addr: %v", addr)
	}

	destAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4500}
	sendPayload := []byte("ikev2-payload")
	n, err = pc.WriteTo(sendPayload, destAddr)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(sendPayload) || !bytes.Equal(dummy.writtenData, sendPayload) {
		t.Fatalf("unexpected written data: %s", string(dummy.writtenData))
	}
	if dummy.writtenAddr.String() != destAddr.String() {
		t.Fatalf("unexpected written addr: %v", dummy.writtenAddr)
	}
}
