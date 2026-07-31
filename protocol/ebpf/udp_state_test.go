//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"
	"testing"
)

func TestUDPClientTableBindings(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:1234")
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	redirectAddress := netip.MustParseAddr("127.128.0.1")

	table.setBinding(client, destination, redirectAddress, false, 10001)
	clientState, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	if actual, loaded := clientState.redirectAddress(destination); !loaded || actual != redirectAddress {
		t.Fatalf("unexpected redirect binding: %v, %v", actual, loaded)
	}
	clientState.setConnected(true)
	if !clientState.isConnected() {
		t.Fatal("connected UDP state was not retained")
	}
	if uid := clientState.sourceUID(); uid != 10001 {
		t.Fatalf("unexpected source UID: %d", uid)
	}
	table.setBinding(client, destination, redirectAddress, false, 10002)
	if uid := clientState.sourceUID(); uid != 10002 {
		t.Fatalf("source UID was not updated with the binding: %d", uid)
	}
}

func TestUDPClientTableDeleteChecksGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("[::1]:1234")
	oldState := table.loadOrCreate(client)
	table.delete(client, oldState)
	newState := table.loadOrCreate(client)
	table.delete(client, oldState)
	if actual, loaded := table.load(client); !loaded || actual != newState {
		t.Fatal("an old session removed the current UDP client state")
	}
}

func TestUDPClientTableConcurrentBindings(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:4321")
	redirectAddress := netip.MustParseAddr("127.128.0.2")
	const destinationCount = 64
	var waitGroup sync.WaitGroup
	for index := 0; index < destinationCount; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			destination := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 0, 0, byte(index + 1)}), 443)
			table.setBinding(client, destination, redirectAddress, false, 0)
		}(index)
	}
	waitGroup.Wait()
	clientState, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	clientState.access.RLock()
	bindingCount := len(clientState.bindings)
	clientState.access.RUnlock()
	if bindingCount != destinationCount {
		t.Fatalf("unexpected binding count: got %d, want %d", bindingCount, destinationCount)
	}
}

func TestUDPClientTableSharesUnconnectedRedirect(t *testing.T) {
	var table udpClientTable
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	redirectAddress := netip.MustParseAddr("127.128.0.3")
	client1 := netip.MustParseAddrPort("127.0.0.1:1001")
	client2 := netip.MustParseAddrPort("127.0.0.1:1002")

	table.setBinding(client1, destination, redirectAddress, false, 0)
	table.setBinding(client2, destination, redirectAddress, false, 0)
	if references := redirectReferenceCount(&table, redirectAddress); references != 2 {
		t.Fatalf("unexpected shared redirect references: %d", references)
	}
	state1, _ := table.load(client1)
	if released := table.delete(client1, state1); len(released) != 0 {
		t.Fatalf("redirect released while another client still referenced it: %v", released)
	}
	state2, _ := table.load(client2)
	released := table.delete(client2, state2)
	if len(released) != 1 || released[0] != redirectAddress {
		t.Fatalf("redirect was not released with the last client: %v", released)
	}
}

func TestUDPClientTableSeparatesSharedRedirectsByClient(t *testing.T) {
	var table udpClientTable
	destination := netip.MustParseAddrPort("1.1.1.1:443")
	redirectAddress := netip.MustParseAddr("127.128.0.3")
	client1 := netip.MustParseAddrPort("192.168.43.10:1001")
	client2 := netip.MustParseAddrPort("192.168.43.11:1001")

	table.setSharedBinding(client1, destination, redirectAddress, nil)
	table.setSharedBinding(client2, destination, redirectAddress, nil)
	state1, _ := table.load(client1)
	if released := table.deleteShared(client1, state1); len(released) != 1 {
		t.Fatalf("first client flow was not released independently: %v", released)
	}
	state2, _ := table.load(client2)
	if released := table.deleteShared(client2, state2); len(released) != 1 {
		t.Fatalf("second client flow was not released independently: %v", released)
	}
}

func TestUDPClientTableDoesNotReferenceConnectedRedirect(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:2001")
	destination := netip.MustParseAddrPort("8.8.8.8:53")
	redirectAddress := netip.MustParseAddr("127.128.0.4")

	table.setBinding(client, destination, redirectAddress, true, 0)
	if references := redirectReferenceCount(&table, redirectAddress); references != 0 {
		t.Fatalf("connected redirect entered userspace reference table: %d", references)
	}
	state, _ := table.load(client)
	if released := table.delete(client, state); len(released) != 0 {
		t.Fatalf("connected redirect was selected for userspace deletion: %v", released)
	}
}

func TestUDPClientTableReplacesRedirectReference(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:3001")
	destination := netip.MustParseAddrPort("9.9.9.9:53")
	oldRedirect := netip.MustParseAddr("127.128.0.5")
	newRedirect := netip.MustParseAddr("127.128.0.6")

	table.setBinding(client, destination, oldRedirect, false, 0)
	released := table.setBinding(client, destination, newRedirect, false, 0)
	if len(released) != 1 || released[0] != oldRedirect {
		t.Fatalf("old redirect was not released: %v", released)
	}
	if references := redirectReferenceCount(&table, oldRedirect); references != 0 {
		t.Fatalf("old redirect still has references: %d", references)
	}
	if references := redirectReferenceCount(&table, newRedirect); references != 1 {
		t.Fatalf("new redirect has unexpected references: %d", references)
	}
}

func TestUDPClientTableDuplicateBindingDoesNotRetainTwice(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("127.0.0.1:4001")
	destination := netip.MustParseAddrPort("1.0.0.1:53")
	redirectAddress := netip.MustParseAddr("127.128.0.7")

	table.setBinding(client, destination, redirectAddress, false, 0)
	table.setBinding(client, destination, redirectAddress, false, 0)
	if references := redirectReferenceCount(&table, redirectAddress); references != 1 {
		t.Fatalf("duplicate packet changed redirect references: %d", references)
	}
}

func TestUDPClientTableCachesOriginalByClientAndToken(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.168.43.10:4001")
	otherClient := netip.MustParseAddrPort("192.168.43.11:4001")
	destination := netip.MustParseAddrPort("1.0.0.1:53")
	redirectAddress := netip.MustParseAddr("127.128.0.7")

	if _, loaded := table.cachedOriginal(client, redirectAddress); loaded {
		t.Fatal("original destination was cached before binding")
	}
	table.setBinding(client, destination, redirectAddress, false, 10001)
	cached, loaded := table.cachedOriginal(client, redirectAddress)
	if !loaded || cached.original.Destination != destination || cached.original.UID != 10001 {
		t.Fatalf("unexpected cached original destination: %+v, %v", cached, loaded)
	}
	if _, loaded = table.cachedOriginal(otherClient, redirectAddress); loaded {
		t.Fatal("original destination cache leaked to another client")
	}
	state, _ := table.load(client)
	table.delete(client, state)
	if _, loaded = table.cachedOriginal(client, redirectAddress); loaded {
		t.Fatal("original destination cache survived session deletion")
	}
}

func TestUDPClientTableConcurrentReleaseSelectsRedirectOnce(t *testing.T) {
	var table udpClientTable
	destination := netip.MustParseAddrPort("8.8.4.4:53")
	redirectAddress := netip.MustParseAddr("127.128.0.8")
	const clientCount = 64
	clients := make([]netip.AddrPort, clientCount)
	states := make([]*udpClientState, clientCount)
	for index := range clients {
		clients[index] = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(5000+index),
		)
		table.setBinding(clients[index], destination, redirectAddress, false, 0)
		states[index], _ = table.load(clients[index])
	}

	releases := make(chan netip.Addr, clientCount)
	var waitGroup sync.WaitGroup
	for index := range clients {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			for _, released := range table.delete(clients[index], states[index]) {
				releases <- released
			}
		}(index)
	}
	waitGroup.Wait()
	close(releases)
	var releaseCount int
	for released := range releases {
		if released != redirectAddress {
			t.Fatalf("unexpected redirect released: %v", released)
		}
		releaseCount++
	}
	if releaseCount != 1 {
		t.Fatalf("redirect selected for deletion %d times", releaseCount)
	}
}

func redirectReferenceCount(table *udpClientTable, redirectAddress netip.Addr) uint32 {
	table.redirectAccess.Lock()
	defer table.redirectAccess.Unlock()
	return table.redirectReferences[udpRedirectReference{address: redirectAddress}]
}
