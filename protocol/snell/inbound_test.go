package snell

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type captureQUICProxyConn struct {
	packet []byte
}

func (c *captureQUICProxyConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *captureQUICProxyConn) Write(payload []byte) (int, error) {
	c.packet = append([]byte(nil), payload...)
	return len(payload), nil
}
func (c *captureQUICProxyConn) Close() error                     { return nil }
func (c *captureQUICProxyConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *captureQUICProxyConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *captureQUICProxyConn) SetDeadline(time.Time) error      { return nil }
func (c *captureQUICProxyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureQUICProxyConn) SetWriteDeadline(time.Time) error { return nil }

func TestQUICProxyEmptyInitDoesNotCreateSession(t *testing.T) {
	psk := []byte("test-password")
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk})
	require.NoError(t, err)
	inbound := &Inbound{
		ctx:     context.Background(),
		logger:  log.NewNOPFactory().NewLogger("snell"),
		service: service,
	}
	inbound.udpNat = newQUICProxyNATService((*inboundUDPHandler)(inbound), inbound.preparePacketConnection, time.Minute)
	t.Cleanup(inbound.udpNat.Close)
	encoded := new(captureQUICProxyConn)
	_, err = snellprotocol.NewQUICProxyPacketConn(encoded, psk, nil, M.ParseSocksaddr("example.com:443"), nil)
	require.NoError(t, err)
	packet := buf.NewSize(len(encoded.packet))
	_, err = packet.Write(encoded.packet)
	require.NoError(t, err)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	(*inboundPacketHandler)(inbound).NewPacket(packet, source)
	require.Equal(t, 0, inbound.udpNat.Len())
}
