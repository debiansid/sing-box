package adapter

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
)

type ConnectionManager interface {
	Lifecycle
	Count() int
	CloseAll()
	CloseGeneration(generation uint64)
	CurrentGeneration() uint64
	SetGeneration(generation uint64)
	TrackConn(conn net.Conn) net.Conn
	TrackConnWithContext(ctx context.Context, conn net.Conn) net.Conn
	TrackPacketConn(conn net.PacketConn) net.PacketConn
	TrackPacketConnWithContext(ctx context.Context, conn net.PacketConn) net.PacketConn
	NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
	NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}
