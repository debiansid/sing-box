package route

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type connectionTestDialer struct {
	access       sync.Mutex
	destinations []M.Socksaddr
	conns        []net.Conn
}

type connectionTestCloser struct {
	net.Conn
	closeCount atomic.Int32
}

func (c *connectionTestCloser) Close() error {
	c.closeCount.Add(1)
	return c.Conn.Close()
}

type packetConnectionTestCloser struct {
	net.PacketConn
	closeCount atomic.Int32
}

func (c *packetConnectionTestCloser) Close() error {
	c.closeCount.Add(1)
	return nil
}

func (d *connectionTestDialer) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.destinations = append(d.destinations, destination)
	d.access.Unlock()
	return d.newConn(), nil
}

func (d *connectionTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unexpected ListenPacket")
}

func (d *connectionTestDialer) newConn() net.Conn {
	conn, peer := net.Pipe()
	d.access.Lock()
	d.conns = append(d.conns, conn, peer)
	d.access.Unlock()
	return conn
}

func (d *connectionTestDialer) closeAll() {
	d.access.Lock()
	defer d.access.Unlock()
	for _, conn := range d.conns {
		_ = conn.Close()
	}
}

func (d *connectionTestDialer) dialedDestinations() []M.Socksaddr {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]M.Socksaddr(nil), d.destinations...)
}

func TestConnectionManagerUsesResolvedTCPDestinationAddress(t *testing.T) {
	t.Parallel()

	ctx := newConnectionTestContext(t)
	testDialer := &connectionTestDialer{}
	defer testDialer.closeAll()
	clientConn, inboundConn := net.Pipe()
	defer clientConn.Close()
	defer inboundConn.Close()

	connectionManager := NewConnectionManager(log.NewNOPFactory().NewLogger("connection"))
	connectionManager.NewConnection(ctx, testDialer, inboundConn, adapter.InboundContext{
		Destination: M.ParseSocksaddrHostPort("example.com", 443),
		DestinationAddresses: []netip.Addr{
			netip.MustParseAddr("127.0.0.11"),
			netip.MustParseAddr("127.0.0.12"),
		},
	}, nil)

	require.Equal(t, []M.Socksaddr{M.ParseSocksaddrHostPort("127.0.0.11", 443)}, testDialer.dialedDestinations())
}

func TestConnectionManagerPreservesUnresolvedTCPDestinationDomain(t *testing.T) {
	t.Parallel()

	ctx := newConnectionTestContext(t)
	testDialer := &connectionTestDialer{}
	defer testDialer.closeAll()
	clientConn, inboundConn := net.Pipe()
	defer clientConn.Close()
	defer inboundConn.Close()

	connectionManager := NewConnectionManager(log.NewNOPFactory().NewLogger("connection"))
	connectionManager.NewConnection(ctx, testDialer, inboundConn, adapter.InboundContext{
		Destination: M.ParseSocksaddrHostPort("example.com", 443),
	}, nil)

	require.Equal(t, []M.Socksaddr{M.ParseSocksaddrHostPort("example.com", 443)}, testDialer.dialedDestinations())
}

func TestConnectionManagerSelectiveCloseByGeneration(t *testing.T) {
	t.Parallel()

	manager := NewConnectionManager(log.NewNOPFactory().NewLogger("connection"))
	ordinaryG1 := &connectionTestCloser{Conn: netConnPipe(t)}
	manager.TrackConn(ordinaryG1)
	manager.SetGeneration(2)
	ordinaryG2 := &connectionTestCloser{Conn: netConnPipe(t)}
	manager.TrackConn(ordinaryG2)
	vpnPayload := &connectionTestCloser{Conn: netConnPipe(t)}
	manager.TrackConnWithContext(adapter.ContextWithVPNPayload(context.Background()), vpnPayload)

	manager.CloseGeneration(1)
	require.Equal(t, int32(1), ordinaryG1.closeCount.Load())
	require.Equal(t, int32(0), ordinaryG2.closeCount.Load())
	require.Equal(t, int32(0), vpnPayload.closeCount.Load())
	require.Equal(t, 2, manager.Count())

	manager.CloseGeneration(1)
	require.Equal(t, int32(1), ordinaryG1.closeCount.Load())
	manager.CloseGeneration(2)
	require.Equal(t, int32(1), ordinaryG2.closeCount.Load())
	require.Equal(t, int32(0), vpnPayload.closeCount.Load())
	require.Equal(t, 1, manager.Count())

	manager.CloseAll()
	require.Equal(t, int32(1), vpnPayload.closeCount.Load())
	require.Equal(t, 0, manager.Count())
}

func TestConnectionManagerPacketProvenance(t *testing.T) {
	t.Parallel()

	manager := NewConnectionManager(log.NewNOPFactory().NewLogger("connection"))
	ordinary := &packetConnectionTestCloser{}
	manager.TrackPacketConn(ordinary)
	manager.SetGeneration(2)
	vpnPayload := &packetConnectionTestCloser{}
	manager.TrackPacketConnWithContext(adapter.ContextWithVPNPayload(context.Background()), vpnPayload)

	manager.CloseGeneration(1)
	require.Equal(t, int32(1), ordinary.closeCount.Load())
	require.Equal(t, int32(0), vpnPayload.closeCount.Load())
	manager.CloseAll()
	require.Equal(t, int32(1), vpnPayload.closeCount.Load())
}

func TestConnectionManagerSetGenerationRejectsUnboundGeneration(t *testing.T) {
	t.Parallel()

	manager := NewConnectionManager(log.NewNOPFactory().NewLogger("connection"))
	require.Equal(t, uint64(1), manager.CurrentGeneration())
	manager.SetGeneration(0)
	require.Equal(t, uint64(1), manager.CurrentGeneration())
	manager.SetGeneration(1)
	require.Equal(t, uint64(1), manager.CurrentGeneration())
	manager.SetGeneration(2)
	manager.SetGeneration(1)
	require.Equal(t, uint64(2), manager.CurrentGeneration())
}

func TestConnectionManagerAdvanceGenerationClosesPreviousOnly(t *testing.T) {
	t.Parallel()

	manager := NewConnectionManager(log.NewNOPFactory().NewLogger("connection"))
	ordinaryG1 := &connectionTestCloser{Conn: netConnPipe(t)}
	manager.TrackConn(ordinaryG1)
	vpnPayload := &connectionTestCloser{Conn: netConnPipe(t)}
	manager.TrackConnWithContext(adapter.ContextWithVPNPayload(context.Background()), vpnPayload)

	require.Equal(t, uint64(2), manager.AdvanceGeneration())
	require.Equal(t, int32(1), ordinaryG1.closeCount.Load())
	require.Equal(t, int32(0), vpnPayload.closeCount.Load())
	require.Equal(t, uint64(2), manager.CurrentGeneration())
	require.Equal(t, 1, manager.Count())

	ordinaryG2 := &connectionTestCloser{Conn: netConnPipe(t)}
	manager.TrackConn(ordinaryG2)
	manager.AdvanceGeneration()
	require.Equal(t, int32(1), ordinaryG2.closeCount.Load())
	require.Equal(t, int32(0), vpnPayload.closeCount.Load())
	manager.CloseAll()
	require.Equal(t, int32(1), vpnPayload.closeCount.Load())
}

func netConnPipe(t *testing.T) net.Conn {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	return conn
}

func newConnectionTestContext(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
