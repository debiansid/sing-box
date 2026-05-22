package snellprotocol

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	M "github.com/sagernet/sing/common/metadata"
)

type contextCheckingDialer struct {
	dialed bool
}

func (d *contextCheckingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.dialed = true
	return &writeOnlyConn{remoteAddr: destination.UDPAddr()}, nil
}

func (d *contextCheckingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, net.ErrClosed
}

type writeOnlyConn struct {
	remoteAddr net.Addr
}

func (c *writeOnlyConn) Read([]byte) (int, error) {
	return 0, net.ErrClosed
}

func (c *writeOnlyConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *writeOnlyConn) Close() error {
	return nil
}

func (c *writeOnlyConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *writeOnlyConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *writeOnlyConn) SetDeadline(time.Time) error {
	return nil
}

func (c *writeOnlyConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *writeOnlyConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestV5LazyPacketConnSurvivesCanceledDialContext(t *testing.T) {
	dialer := &contextCheckingDialer{}
	outbound := &Outbound{
		dialer:     dialer,
		serverAddr: M.ParseSocksaddr("127.0.0.1:12345"),
		psk:        []byte("password"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn := newV5LazyPacketConn(ctx, outbound, M.Socksaddr{}, M.ParseSocksaddr("example.com:443"), true)
	cancel()

	_, err := conn.WriteTo([]byte{0xc0, 0x00, 0x00, 0x00}, nil)
	require.NoError(t, err)
	require.True(t, dialer.dialed)
}
