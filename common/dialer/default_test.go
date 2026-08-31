package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/database64128/tfo-go/v2"
	"github.com/stretchr/testify/require"
)

func newControlTestDialer(ordinaryCalls, payloadCalls *atomic.Int32) *DefaultDialer {
	ordinaryControl := func(string, string, syscall.RawConn) error {
		ordinaryCalls.Add(1)
		return nil
	}
	payloadControl := func(string, string, syscall.RawConn) error {
		payloadCalls.Add(1)
		return nil
	}
	return &DefaultDialer{
		dialer4:                tfo.Dialer{Dialer: net.Dialer{Control: ordinaryControl}, DisableTFO: true},
		dialer6:                tfo.Dialer{Dialer: net.Dialer{Control: ordinaryControl}, DisableTFO: true},
		udpDialer4:             net.Dialer{Control: ordinaryControl},
		udpDialer6:             net.Dialer{Control: ordinaryControl},
		udpListener:            net.ListenConfig{Control: ordinaryControl},
		dialerControl:          ordinaryControl,
		listenerControl:        ordinaryControl,
		payloadDialerControl:   payloadControl,
		payloadListenerControl: payloadControl,
		networkStrategy:        adapterNetworkStrategy(C.NetworkStrategyDefault),
	}
}

func adapterNetworkStrategy(strategy C.NetworkStrategy) *C.NetworkStrategy {
	return &strategy
}

func TestDefaultDialerVPNPayloadSocketControls(t *testing.T) {
	t.Parallel()
	var ordinaryCalls, payloadCalls atomic.Int32
	dialer := newControlTestDialer(&ordinaryCalls, &payloadCalls)
	ctx := adapter.ContextWithVPNPayload(context.Background())

	server, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	go func() {
		for range 2 {
			conn, acceptErr := server.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()
	address := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), uint16(server.Addr().(*net.TCPAddr).Port))
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, address)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	conn, err = dialer.DialParallelInterface(ctx, N.NetworkTCP, address, adapterNetworkStrategy(C.NetworkStrategyHybrid), nil, nil, 0)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	packetConn, err := dialer.ListenSerialInterfacePacket(ctx, M.Socksaddr{}, adapterNetworkStrategy(C.NetworkStrategyHybrid), nil, nil, 0)
	require.NoError(t, err)
	require.NoError(t, packetConn.Close())
	require.Zero(t, ordinaryCalls.Load())
	require.Equal(t, int32(3), payloadCalls.Load())
}

func TestDefaultDialerOrdinarySocketControlsUnchanged(t *testing.T) {
	t.Parallel()
	var ordinaryCalls, payloadCalls atomic.Int32
	dialer := newControlTestDialer(&ordinaryCalls, &payloadCalls)
	dialer.networkStrategy = nil

	server, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	go func() {
		conn, acceptErr := server.Accept()
		if acceptErr == nil {
			conn.Close()
		}
	}()
	address := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), uint16(server.Addr().(*net.TCPAddr).Port))
	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, address)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, int32(1), ordinaryCalls.Load())
	require.Zero(t, payloadCalls.Load())
}
