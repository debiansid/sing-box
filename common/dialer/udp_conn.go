package dialer

import (
	"io"
	"net"
	"syscall"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	N "github.com/sagernet/sing/common/network"
)

type udpConn struct {
	net.Conn
	packetConn net.PacketConn
	rawConn    syscall.RawConn
}

func (c *udpConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n == 0 && err == nil {
		var isEOF bool
		c.rawConn.Control(func(fd uintptr) {
			isEOF = control.IsUDPEOF(fd)
		})
		if isEOF {
			err = io.EOF
		}
	}
	return
}

func (c *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.packetConn.ReadFrom(p)
	if n == 0 && err == nil {
		var isEOF bool
		c.rawConn.Control(func(fd uintptr) {
			isEOF = control.IsUDPEOF(fd)
		})
		if isEOF {
			err = io.EOF
		}
	}
	return
}

func (c *udpConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.packetConn.WriteTo(p, addr)
}

func (c *udpConn) SyscallConn() (syscall.RawConn, error) {
	return c.rawConn, nil
}

func (c *udpConn) Upstream() any {
	return c.Conn
}

func (c *udpConn) ReaderReplaceable() bool {
	return true
}

func (c *udpConn) WriterReplaceable() bool {
	return true
}

var (
	_ syscall.Conn         = (*udpConn)(nil)
	_ common.WithUpstream  = (*udpConn)(nil)
	_ N.ReaderWithUpstream = (*udpConn)(nil)
	_ N.WriterWithUpstream = (*udpConn)(nil)
	_ net.PacketConn       = (*udpConn)(nil)
)
