//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestUDPDirectBinding(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	sourceMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	if !table.setDirectBinding(client, destination, sourceMAC, 42, commonEBPF.TCPathShared) {
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
	ctx := udpSessionContext(context.Background(), state, true)
	if !adapter.IsVPNPayloadContext(ctx) {
		t.Fatal("shared UDP session did not receive VPN payload intent")
	}
	if adapter.IsVPNPayloadContext(udpSessionContext(context.Background(), state, false)) {
		t.Fatal("disabled Android VPN capability produced UDP payload intent")
	}
	if !table.setDirectBinding(client, netip.MustParseAddrPort("8.8.8.8:53"), sourceMAC, 42, commonEBPF.TCPathShared) {
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
	if !table.setDirectBinding(client, sharedDestination, nil, 42, commonEBPF.TCPathShared) {
		t.Fatal("shared binding was rejected")
	}
	if table.setDirectBinding(client, deliveryDestination, nil, 84, commonEBPF.TCPathDelivery) {
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

func TestUDPReplySocketPoolResetsForNetworkChange(t *testing.T) {
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
	if err = pool.reset(); err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || created != 2 {
		t.Fatalf("network reset did not replace the reply socket: first=%p second=%p created=%d", first, second, created)
	}
	if _, err = first.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("reset reply socket remained open")
	}
	_ = pool.close()
}

func TestUDPDirectReplyBindingChecksGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	base := netip.MustParseAddrPort("1.1.1.1:53")
	reply := netip.MustParseAddrPort("8.8.8.8:53")
	if !table.setDirectBinding(client, base, nil, 0, commonEBPF.TCPathShared) {
		t.Fatal("direct binding was rejected")
	}
	state, _ := table.load(client)
	if !table.setDirectReplyBinding(client, state, reply) {
		t.Fatal("reply binding was not installed")
	}
	if binding, loaded := state.redirectBinding(reply); !loaded || !binding.replyAlias {
		t.Fatalf("unexpected reply binding: %+v", binding)
	}
	table.delete(client, state)
	if table.setDirectReplyBinding(client, state, netip.MustParseAddrPort("9.9.9.9:53")) {
		t.Fatal("closed session was resurrected")
	}
}
