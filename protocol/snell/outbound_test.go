package snell

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/expiringmap"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestBuildSnellNetworks(t *testing.T) {
	for _, version := range []int{1, 2} {
		networks, err := buildSnellNetworks(version, "")
		require.NoError(t, err)
		require.Equal(t, []string{N.NetworkTCP}, networks)
		_, err = buildSnellNetworks(version, option.NetworkList(N.NetworkUDP))
		require.Error(t, err)
	}
	for version := 3; version <= 6; version++ {
		networks, err := buildSnellNetworks(version, "")
		require.NoError(t, err)
		require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, networks)
	}
	networks, err := buildSnellNetworks(5, option.NetworkList(N.NetworkUDP))
	require.NoError(t, err)
	require.Equal(t, []string{N.NetworkUDP}, networks)
}

func TestValidateSnellOutboundVersionOptions(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		err := validateSnellOutboundVersionOptions(version, true)
		require.EqualError(t, err, "snell: reuse requires version 4 or above")
	}
	for _, version := range []int{4, 5, 6} {
		require.NoError(t, validateSnellOutboundVersionOptions(version, true))
	}
	require.NoError(t, validateSnellOutboundVersionOptions(3, false))
}

func TestQUICDestCacheRetainsAllEntriesUntilExpiry(t *testing.T) {
	outbound := &Outbound{quicDestCache: expiringmap.New[quicDestCacheKey, uint64](20 * time.Millisecond)}
	t.Cleanup(outbound.quicDestCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:1000")
	const destinationCount = 2048
	for index := range destinationCount {
		outbound.markQUICDest(source, M.ParseSocksaddrHostPort("example.com", uint16(index+1)))
	}
	require.Equal(t, destinationCount, outbound.quicDestCache.Len())
	require.True(t, outbound.isRecentQUICDest(source, M.ParseSocksaddr("example.com:1")))
	require.True(t, outbound.isRecentQUICDest(source, M.ParseSocksaddr("example.com:2048")))
	require.Eventually(t, func() bool {
		return outbound.quicDestCache.Len() == 0
	}, time.Second, 10*time.Millisecond)
}

func TestQUICDestCacheLookupRefreshesTTL(t *testing.T) {
	outbound := &Outbound{quicDestCache: expiringmap.New[quicDestCacheKey, uint64](200 * time.Millisecond)}
	t.Cleanup(outbound.quicDestCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:1000")
	destination := M.ParseSocksaddr("example.com:443")
	outbound.markQUICDest(source, destination)
	time.Sleep(120 * time.Millisecond)
	require.True(t, outbound.isRecentQUICDest(source, destination))
	time.Sleep(120 * time.Millisecond)
	require.True(t, outbound.isRecentQUICDest(source, destination))
	require.Eventually(t, func() bool {
		return outbound.quicDestCache.Len() == 0
	}, time.Second, 10*time.Millisecond)
}

func TestQUICDestCacheCloseRefreshesAfterOriginalExpiry(t *testing.T) {
	outbound := &Outbound{quicDestCache: expiringmap.New[quicDestCacheKey, uint64](20 * time.Millisecond)}
	t.Cleanup(outbound.quicDestCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:1000")
	destination := M.ParseSocksaddr("example.com:443")
	token := outbound.markQUICDest(source, destination)
	require.Eventually(t, func() bool {
		return outbound.quicDestCache.Len() == 0
	}, time.Second, 10*time.Millisecond)
	packetConn := &v5LazyPacketConn{
		outbound:      outbound,
		source:        source,
		destination:   destination,
		quicDestToken: token,
	}
	packetConn.refreshQUICDestOnClose()
	require.True(t, outbound.isRecentQUICDest(source, destination))
}

func TestQUICDestCacheCloseKeepsNewerToken(t *testing.T) {
	outbound := &Outbound{quicDestCache: expiringmap.New[quicDestCacheKey, uint64](time.Second)}
	t.Cleanup(outbound.quicDestCache.Close)
	source := M.ParseSocksaddr("127.0.0.1:1000")
	destination := M.ParseSocksaddr("example.com:443")
	oldToken := outbound.markQUICDest(source, destination)
	newToken := outbound.markQUICDest(source, destination)
	outbound.refreshQUICDest(source, destination, oldToken)
	token, loaded := outbound.quicDestCache.Load(quicDestCacheKey{source: source, destination: destination})
	require.True(t, loaded)
	require.Equal(t, newToken, token)
}

func TestV5LazyPacketConnCloseUnblocksRead(t *testing.T) {
	packetConn := newV5LazyPacketConn(context.Background(), nil, M.Socksaddr{}, M.Socksaddr{}, false)
	readDone := make(chan error, 1)
	go func() {
		_, _, err := packetConn.ReadFrom(make([]byte, 1))
		readDone <- err
	}()
	require.NoError(t, packetConn.Close())
	select {
	case err := <-readDone:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("ReadFrom remained blocked after Close")
	}
	_, err := packetConn.WriteTo([]byte{1}, M.Socksaddr{})
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestV5LazyPacketConnReadDeadlineBeforeInit(t *testing.T) {
	packetConn := newV5LazyPacketConn(context.Background(), nil, M.Socksaddr{}, M.Socksaddr{}, false)
	t.Cleanup(func() { packetConn.Close() })
	require.NoError(t, packetConn.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	_, _, err := packetConn.ReadFrom(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestV5LazyPacketConnWriteDeadlineBeforeInit(t *testing.T) {
	packetConn := newV5LazyPacketConn(context.Background(), nil, M.Socksaddr{}, M.Socksaddr{}, false)
	t.Cleanup(func() { packetConn.Close() })
	require.NoError(t, packetConn.SetWriteDeadline(time.Now().Add(-time.Second)))
	_, err := packetConn.WriteTo([]byte{1}, M.Socksaddr{})
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestV5LazyPacketConnEmptyWriteDoesNotInitialize(t *testing.T) {
	for _, sniffQUIC := range []bool{false, true} {
		packetConn := newV5LazyPacketConn(context.Background(), nil, M.Socksaddr{}, M.Socksaddr{}, sniffQUIC)
		_, err := packetConn.WriteTo(nil, M.Socksaddr{})
		require.NoError(t, err)
		select {
		case <-packetConn.initDone:
			t.Fatal("empty write consumed lazy initialization")
		default:
		}
		require.NoError(t, packetConn.Close())
	}
}

type v5DeadlineTestDialer struct {
	conn net.Conn
}

func (d *v5DeadlineTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func (d *v5DeadlineTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unexpected ListenPacket")
}

type v5DeadlineTestClient struct {
	writeStarted chan struct{}
}

func (c *v5DeadlineTestClient) DialContext(context.Context, M.Socksaddr) (net.Conn, error) {
	panic("unexpected DialContext")
}

func (c *v5DeadlineTestClient) DialConn(net.Conn, M.Socksaddr) (net.Conn, error) {
	panic("unexpected DialConn")
}

func (c *v5DeadlineTestClient) DialEarlyConn(net.Conn, M.Socksaddr) net.Conn {
	panic("unexpected DialEarlyConn")
}

func (c *v5DeadlineTestClient) DialPacketConn(conn net.Conn) (N.NetPacketConn, error) {
	close(c.writeStarted)
	_, err := conn.Write([]byte{1})
	return nil, err
}

func (c *v5DeadlineTestClient) Close() error { return nil }

func TestV5LazyPacketConnWriteDeadlineDuringInit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { serverConn.Close() })
	client := &v5DeadlineTestClient{writeStarted: make(chan struct{})}
	outbound := &Outbound{
		tcpDialer: &v5DeadlineTestDialer{conn: clientConn},
		client:    client,
	}
	packetConn := newV5LazyPacketConn(context.Background(), outbound, M.Socksaddr{}, M.Socksaddr{}, false)
	t.Cleanup(func() { packetConn.Close() })
	writeDone := make(chan error, 1)
	go func() {
		_, err := packetConn.WriteTo([]byte{1}, M.Socksaddr{})
		writeDone <- err
	}()
	select {
	case <-client.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("Snell packet initialization did not start")
	}
	require.NoError(t, packetConn.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
	select {
	case err := <-writeDone:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("Snell packet initialization ignored the updated write deadline")
	}
}

func TestV5LazyPacketConnCloseDuringInit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { serverConn.Close() })
	client := &v5DeadlineTestClient{writeStarted: make(chan struct{})}
	outbound := &Outbound{
		tcpDialer: &v5DeadlineTestDialer{conn: clientConn},
		client:    client,
	}
	packetConn := newV5LazyPacketConn(context.Background(), outbound, M.Socksaddr{}, M.Socksaddr{}, false)
	writeDone := make(chan error, 1)
	go func() {
		_, err := packetConn.WriteTo([]byte{1}, M.Socksaddr{})
		writeDone <- err
	}()
	select {
	case <-client.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("Snell packet initialization did not start")
	}
	require.NoError(t, packetConn.Close())
	select {
	case err := <-writeDone:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt Snell packet initialization")
	}
}
