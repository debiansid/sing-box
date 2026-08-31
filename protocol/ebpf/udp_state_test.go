//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
)

func TestUDPDirectBinding(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	sourceMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	if _, accepted := table.setDirectBinding(client, destination, sourceMAC, 42, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("direct binding was rejected")
	}
	state, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	if _, loaded := state.redirectBinding(destination); !loaded {
		t.Fatal("direct binding was not installed")
	}
	if actual := state.sourceMACAddress(); !bytes.Equal(actual, sourceMAC) {
		t.Fatalf("unexpected source MAC: %s", actual)
	}
	if state.processSocketCookie() != 42 {
		t.Fatalf("unexpected process socket cookie: %d", state.processSocketCookie())
	}
	if state.tcPath() != commonEBPF.TCPathShared {
		t.Fatalf("unexpected TC path: %d", state.tcPath())
	}
	if state.tcAttachmentGeneration() != 7 {
		t.Fatalf("unexpected attachment generation: %d", state.tcAttachmentGeneration())
	}
	ctx := udpSessionContext(context.Background(), state, true)
	if !adapter.IsVPNPayloadContext(ctx) {
		t.Fatal("shared UDP session did not receive VPN payload intent")
	}
	if adapter.IsVPNPayloadContext(udpSessionContext(context.Background(), state, false)) {
		t.Fatal("disabled Android VPN capability produced UDP payload intent")
	}
	if _, accepted := table.setDirectBinding(client, netip.MustParseAddrPort("8.8.8.8:53"), sourceMAC, 42, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("later datagram with the same path was rejected")
	}
	if !adapter.IsVPNPayloadContext(ctx) || state.tcPath() != commonEBPF.TCPathShared {
		t.Fatal("later datagram lost UDP session ownership")
	}
}

func TestUDPDirectBindingRejectsConflictingPath(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	sharedDestination := netip.MustParseAddrPort("1.1.1.1:53")
	deliveryDestination := netip.MustParseAddrPort("8.8.8.8:53")
	if _, accepted := table.setDirectBinding(client, sharedDestination, nil, 42, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("shared binding was rejected")
	}
	if _, accepted := table.setDirectBinding(client, deliveryDestination, nil, 84, commonEBPF.TCPathDelivery, 8); accepted {
		t.Fatal("conflicting path silently replaced UDP session ownership")
	}
	state, _ := table.load(client)
	if state.tcPath() != commonEBPF.TCPathShared || state.processSocketCookie() != 42 {
		t.Fatal("conflicting path changed existing UDP session metadata")
	}
	if _, loaded := state.redirectBinding(deliveryDestination); loaded {
		t.Fatal("conflicting destination was added to the existing UDP session")
	}
}

func TestUDPDirectBindingRejectsConflictingAttachmentGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	firstDestination := netip.MustParseAddrPort("1.1.1.1:53")
	secondDestination := netip.MustParseAddrPort("8.8.8.8:53")
	if _, accepted := table.setDirectBinding(client, firstDestination, nil, 42, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("initial binding was rejected")
	}
	if _, accepted := table.setDirectBinding(client, secondDestination, nil, 84, commonEBPF.TCPathShared, 8); accepted {
		t.Fatal("conflicting attachment generation silently replaced UDP session provenance")
	}
	state, _ := table.load(client)
	if state.tcAttachmentGeneration() != 7 || state.processSocketCookie() != 42 {
		t.Fatal("conflicting attachment generation changed existing UDP session metadata")
	}
}

func TestUDPDirectBindingTracksLocalAttachmentGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	if _, accepted := table.setDirectBinding(
		client,
		netip.MustParseAddrPort("1.1.1.1:53"),
		nil,
		42,
		commonEBPF.TCPathDelivery,
		9,
	); !accepted {
		t.Fatal("local direct binding was rejected")
	}
	state, _ := table.load(client)
	if state.tcPath() != commonEBPF.TCPathDelivery || state.tcAttachmentGeneration() != 9 {
		t.Fatalf("unexpected local UDP provenance: path=%d generation=%d", state.tcPath(), state.tcAttachmentGeneration())
	}
}

func TestUDPReplySocketLifecycle(t *testing.T) {
	var pool udpReplySocketPool
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	created := 0
	create := func(netip.AddrPort) (*net.UDPConn, error) {
		created++
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	first, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || created != 1 {
		t.Fatalf("reply socket was not reused: first=%p second=%p created=%d", first, second, created)
	}
	if err = pool.close(); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.get(destination, create); err == nil {
		t.Fatal("closed inbound accepted a reply socket")
	}
	if _, err = first.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("UDP reply socket remained open after inbound closure")
	}
}

func TestUDPReplySocketPoolSharesAcrossClients(t *testing.T) {
	var pool udpReplySocketPool
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	created := 0
	create := func(netip.AddrPort) (*net.UDPConn, error) {
		created++
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	first, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || created != 1 {
		t.Fatalf("reply socket was not shared: first=%p second=%p created=%d", first, second, created)
	}
	_ = pool.close()
}

func TestUDPReplySocketPoolSurvivesSelectiveInvalidation(t *testing.T) {
	var pool udpReplySocketPool
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	created := 0
	create := func(netip.AddrPort) (*net.UDPConn, error) {
		created++
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	first, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	var table udpClientTable
	_, _, closer := startUDPTestSession(
		t,
		&table,
		netip.MustParseAddrPort("192.0.2.10:53000"),
		netip.MustParseAddrPort("198.51.100.1:53"),
		commonEBPF.TCPathShared,
		7,
	)
	if err = table.invalidateAttachmentGenerations(map[uint64]struct{}{7: {}}); err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || created != 1 {
		t.Fatalf("selective invalidation replaced the shared reply socket: first=%p second=%p created=%d", first, second, created)
	}
	if closer.closeCount.Load() != 1 {
		t.Fatalf("invalidated UDP session closer called %d times", closer.closeCount.Load())
	}
	_ = pool.close()
}

func TestUDPDirectReplyBindingChecksGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	base := netip.MustParseAddrPort("1.1.1.1:53")
	reply := netip.MustParseAddrPort("8.8.8.8:53")
	if _, accepted := table.setDirectBinding(client, base, nil, 0, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("direct binding was rejected")
	}
	state, _ := table.load(client)
	sessionID, loaded := table.beginSession(client, state)
	if !loaded {
		t.Fatal("UDP session was not started")
	}
	if !table.setDirectReplyBinding(client, state, sessionID, reply) {
		t.Fatal("reply binding was not installed")
	}
	if binding, loaded := state.redirectBinding(reply); !loaded || !binding.replyAlias {
		t.Fatalf("unexpected reply binding: %+v", binding)
	}
	table.delete(client, state)
	if table.setDirectReplyBinding(client, state, sessionID, netip.MustParseAddrPort("9.9.9.9:53")) {
		t.Fatal("closed session was resurrected")
	}
}

type udpSessionTestCloser struct {
	closeCount atomic.Int32
	onClose    func()
}

func startUDPTestSession(
	t *testing.T,
	table *udpClientTable,
	client netip.AddrPort,
	destination netip.AddrPort,
	path uint8,
	generation uint64,
) (*udpClientState, uint64, *udpSessionTestCloser) {
	t.Helper()
	state, accepted := table.setDirectBinding(client, destination, nil, 0, path, generation)
	if !accepted {
		t.Fatal("direct binding was rejected")
	}
	sessionID, started := table.beginSession(client, state)
	if !started {
		t.Fatal("UDP session was not started")
	}
	closer := &udpSessionTestCloser{onClose: func() {
		table.endSession(client, state, sessionID)
	}}
	if !table.attachSession(client, state, sessionID, closer) {
		t.Fatal("UDP session closer was not attached")
	}
	return state, sessionID, closer
}

func TestUDPSelectiveInvalidationClosesOnlyMatchingGeneration(t *testing.T) {
	var table udpClientTable
	localClient := netip.MustParseAddrPort("192.0.2.10:53000")
	sharedClient := netip.MustParseAddrPort("192.0.2.11:53001")
	_, _, localCloser := startUDPTestSession(
		t,
		&table,
		localClient,
		netip.MustParseAddrPort("198.51.100.1:443"),
		commonEBPF.TCPathDelivery,
		7,
	)
	sharedState, sharedSessionID, sharedCloser := startUDPTestSession(
		t,
		&table,
		sharedClient,
		netip.MustParseAddrPort("203.0.113.1:443"),
		commonEBPF.TCPathShared,
		8,
	)
	if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{7: {}}); err != nil {
		t.Fatal(err)
	}
	if _, loaded := table.load(localClient); loaded || localCloser.closeCount.Load() != 1 {
		t.Fatal("old local generation remained active")
	}
	if current, loaded := table.load(sharedClient); !loaded || current != sharedState ||
		!table.sessionActive(sharedClient, sharedState, sharedSessionID) || sharedCloser.closeCount.Load() != 0 {
		t.Fatal("unrelated shared generation was invalidated")
	}
	if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{7: {}}); err != nil {
		t.Fatal(err)
	}
	if localCloser.closeCount.Load() != 1 {
		t.Fatal("selective invalidation closed a session twice")
	}
	if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{8: {}}); err != nil {
		t.Fatal(err)
	}
	if _, loaded := table.load(sharedClient); loaded || sharedCloser.closeCount.Load() != 1 {
		t.Fatal("removed shared attachment generation remained active")
	}
}

func TestUDP500And4500FollowAttachmentGeneration(t *testing.T) {
	var table udpClientTable
	ikeClient := netip.MustParseAddrPort("192.0.2.10:53000")
	natTClient := netip.MustParseAddrPort("192.0.2.11:53001")
	_, _, ikeCloser := startUDPTestSession(
		t,
		&table,
		ikeClient,
		netip.MustParseAddrPort("198.51.100.1:500"),
		commonEBPF.TCPathDelivery,
		7,
	)
	_, _, natTCloser := startUDPTestSession(
		t,
		&table,
		natTClient,
		netip.MustParseAddrPort("198.51.100.1:4500"),
		commonEBPF.TCPathDelivery,
		8,
	)
	if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{9: {}}); err != nil {
		t.Fatal(err)
	}
	if ikeCloser.closeCount.Load() != 0 || natTCloser.closeCount.Load() != 0 {
		t.Fatal("unrelated attachment change closed IKE/IPsec UDP sessions")
	}
	if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{7: {}}); err != nil {
		t.Fatal(err)
	}
	if ikeCloser.closeCount.Load() != 1 || natTCloser.closeCount.Load() != 0 {
		t.Fatal("UDP port affected generation-based invalidation")
	}
	if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{8: {}}); err != nil {
		t.Fatal(err)
	}
	if natTCloser.closeCount.Load() != 1 {
		t.Fatal("owning attachment invalidation did not close UDP 4500")
	}
}

func TestUDPSelectiveInvalidationAllowsSafeReplacement(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	_, _, oldCloser := startUDPTestSession(t, &table, client, destination, commonEBPF.TCPathShared, 7)
	if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{7: {}}); err != nil {
		t.Fatal(err)
	}
	newState, accepted := table.setDirectBinding(client, destination, nil, 0, commonEBPF.TCPathShared, 8)
	if !accepted {
		t.Fatal("next packet did not create state for the replacement generation")
	}
	newSessionID, started := table.beginSession(client, newState)
	if !started {
		t.Fatal("replacement UDP session was not started")
	}
	if oldCloser.closeCount.Load() != 1 || !table.sessionActive(client, newState, newSessionID) {
		t.Fatal("old session teardown affected the replacement session")
	}
	table.endSession(client, newState, newSessionID)
}

func TestUDPSelectiveInvalidationRacesSessionReplacement(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	_, _, oldCloser := startUDPTestSession(t, &table, client, destination, commonEBPF.TCPathShared, 7)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	var newState *udpClientState
	var newSessionID uint64
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-start
		if err := table.invalidateAttachmentGenerations(map[uint64]struct{}{7: {}}); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		for attempt := 0; attempt < 10000; attempt++ {
			state, accepted := table.setDirectBinding(client, destination, nil, 0, commonEBPF.TCPathShared, 8)
			if !accepted {
				runtime.Gosched()
				continue
			}
			sessionID, started := table.beginSession(client, state)
			if started {
				newState = state
				newSessionID = sessionID
			}
			return
		}
		t.Error("replacement generation was not accepted after invalidation")
	}()
	close(start)
	waitGroup.Wait()
	if newState == nil || !table.sessionActive(client, newState, newSessionID) {
		t.Fatal("new generation session was lost during old-generation invalidation")
	}
	if oldCloser.closeCount.Load() != 1 {
		t.Fatalf("old generation closer called %d times", oldCloser.closeCount.Load())
	}
	table.endSession(client, newState, newSessionID)
}

func (c *udpSessionTestCloser) Close() error {
	c.closeCount.Add(1)
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func TestUDPSessionCloserLifecycle(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	if _, accepted := table.setDirectBinding(client, netip.MustParseAddrPort("1.1.1.1:53"), nil, 0, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("direct binding was rejected")
	}
	state, _ := table.load(client)
	sessionID, loaded := table.beginSession(client, state)
	if !loaded {
		t.Fatal("UDP session was not started")
	}
	closer := &udpSessionTestCloser{onClose: func() {
		table.endSession(client, state, sessionID)
	}}
	if !table.attachSession(client, state, sessionID, closer) {
		t.Fatal("UDP session closer was not attached")
	}
	if !table.sessionActive(client, state, sessionID) {
		t.Fatal("attached UDP session was not active")
	}
	if err := state.requestSessionClose(sessionID); err != nil {
		t.Fatal(err)
	}
	if table.sessionActive(client, state, sessionID) {
		t.Fatal("closing UDP session remained active")
	}
	if err := state.requestSessionClose(sessionID); err != nil {
		t.Fatal(err)
	}
	if closer.closeCount.Load() != 1 {
		t.Fatalf("UDP session closer called %d times", closer.closeCount.Load())
	}
	if _, loaded = table.load(client); loaded {
		t.Fatal("UDP session teardown did not remove client state")
	}
	if _, loaded = state.redirectBinding(netip.MustParseAddrPort("1.1.1.1:53")); loaded {
		t.Fatal("UDP session teardown did not clear bindings")
	}
}

func TestUDPSessionCloseBeforeCloserAttach(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	if _, accepted := table.setDirectBinding(client, netip.MustParseAddrPort("1.1.1.1:53"), nil, 0, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("direct binding was rejected")
	}
	state, _ := table.load(client)
	sessionID, _ := table.beginSession(client, state)
	if err := state.requestSessionClose(sessionID); err != nil {
		t.Fatal(err)
	}
	if table.attachSession(client, state, sessionID, new(udpSessionTestCloser)) {
		t.Fatal("closer attached after the session was marked closing")
	}
	table.endSession(client, state, sessionID)
}

func TestUDPSessionReplacementIsRaceSafe(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	if _, accepted := table.setDirectBinding(client, netip.MustParseAddrPort("1.1.1.1:53"), nil, 0, commonEBPF.TCPathShared, 7); !accepted {
		t.Fatal("direct binding was rejected")
	}
	state, _ := table.load(client)
	oldSessionID, _ := table.beginSession(client, state)
	newSessionID, _ := table.beginSession(client, state)
	closer := new(udpSessionTestCloser)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		table.endSession(client, state, oldSessionID)
	}()
	go func() {
		defer waitGroup.Done()
		if !table.attachSession(client, state, newSessionID, closer) {
			t.Error("replacement session closer was rejected")
		}
	}()
	waitGroup.Wait()
	if current, loaded := table.load(client); !loaded || current != state {
		t.Fatal("late old-session teardown deleted the replacement session")
	}
	table.endSession(client, state, newSessionID)
}

func TestUDPSessionRejectsReplacedProvenanceState(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	oldState, accepted := table.setDirectBinding(client, destination, nil, 0, commonEBPF.TCPathShared, 7)
	if !accepted {
		t.Fatal("initial direct binding was rejected")
	}
	table.delete(client, oldState)
	newState, accepted := table.setDirectBinding(client, destination, nil, 0, commonEBPF.TCPathShared, 8)
	if !accepted {
		t.Fatal("replacement direct binding was rejected")
	}
	if _, started := table.beginSession(client, oldState); started {
		t.Fatal("replaced provenance state started a new UDP session")
	}
	if _, started := table.beginSession(client, newState); !started {
		t.Fatal("current provenance state did not start a UDP session")
	}
}

type udpShutdownTestHandler struct {
	started chan struct{}
	closed  chan struct{}
}

func (h *udpShutdownTestHandler) NewPacketConnectionEx(
	_ context.Context,
	conn N.PacketConn,
	_ M.Socksaddr,
	_ M.Socksaddr,
	_ N.CloseHandlerFunc,
) {
	close(h.started)
	for {
		buffer := buf.New()
		_, err := conn.ReadPacket(buffer)
		buffer.Release()
		if err != nil {
			close(h.closed)
			return
		}
	}
}

type udpShutdownTestWriter struct{}

func (udpShutdownTestWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func TestUDPShutdownStillPurgesSessionsAndReplySockets(t *testing.T) {
	handler := &udpShutdownTestHandler{started: make(chan struct{}), closed: make(chan struct{})}
	service := udpnat.New(
		handler,
		func(M.Socksaddr, M.Socksaddr, any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.Background(), udpShutdownTestWriter{}, nil
		},
		time.Minute,
		false,
	)
	inbound := &Inbound{udpNat: service}
	replySource := netip.MustParseAddrPort("127.0.0.1:0")
	replySocket, err := inbound.udpReplySockets.get(replySource, func(netip.AddrPort) (*net.UDPConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	})
	if err != nil {
		t.Fatal(err)
	}
	service.NewPacket(
		[][]byte{{1}},
		M.SocksaddrFromNetIP(netip.MustParseAddrPort("192.0.2.10:53000")),
		M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.1:53")),
		nil,
	)
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("UDP NAT session did not start")
	}
	if err = inbound.closeResources(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not purge the UDP NAT session")
	}
	if _, err = inbound.udpReplySockets.get(replySource, func(netip.AddrPort) (*net.UDPConn, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("shutdown left the UDP reply socket pool usable")
	}
	if _, err = replySocket.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("shutdown left a UDP reply socket open")
	}
}
