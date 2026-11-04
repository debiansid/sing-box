//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"golang.org/x/sys/unix"
)

func TestActiveSharedInterfaces(t *testing.T) {
	configured := []string{"wlan0", "rndis0"}
	if active := activeSharedInterfaces(configured, "wlan0", false); !slices.Equal(active, []string{"rndis0"}) {
		t.Fatalf("default upstream was not excluded: %v", active)
	}
	if active := activeSharedInterfaces(configured, "rmnet_data2", false); !slices.Equal(active, configured) {
		t.Fatalf("downstream interfaces changed unexpectedly: %v", active)
	}
	if active := activeSharedInterfaces(configured, "wlan0", true); !slices.Equal(active, configured) {
		t.Fatalf("enabled default interface was excluded: %v", active)
	}
	if active := activeSharedInterfaces(configured, "rmnet_data2", true); !slices.Equal(active, configured) {
		t.Fatalf("unconfigured cellular default interface changed shared interfaces: %v", active)
	}
	if !slices.Equal(configured, []string{"wlan0", "rndis0"}) {
		t.Fatalf("configured interfaces were modified: %v", configured)
	}
}

func TestTCInterfaceMonitorLifecycle(t *testing.T) {
	if runtime.GOOS == "android" {
		previousFinder := androidDefaultInterfaceFinder
		androidDefaultInterfaceFinder = func() string { return "" }
		t.Cleanup(func() {
			androidDefaultInterfaceFinder = previousFinder
		})
	}
	networkMonitor := &testNetworkUpdateMonitor{}
	defaultMonitor := &testDefaultInterfaceMonitor{current: &control.Interface{Name: "wlan0", Index: 8}}
	inbound := &Inbound{
		ctx: context.Background(),
		networkManager: &testInterfaceNetworkManager{
			networkMonitor: networkMonitor,
			defaultMonitor: defaultMonitor,
			finder:         control.NewDefaultInterfaceFinder(),
		},
	}
	if err := inbound.startTCInterfaceMonitor(); err != nil {
		t.Fatal(err)
	}
	if networkMonitor.callbackCount() != 1 || defaultMonitor.callbackCount() != 1 {
		t.Fatalf("unexpected callback counts after start: network=%d default=%d", networkMonitor.callbackCount(), defaultMonitor.callbackCount())
	}
	if current := inbound.monitoredDefaultInterfaceName(); current != "wlan0" {
		t.Fatalf("unexpected initial default interface: %q", current)
	}
	defaultMonitor.emit(nil)
	if current := inbound.monitoredDefaultInterfaceName(); current != "" {
		t.Fatalf("default interface was not cleared: %q", current)
	}
	defaultMonitor.emit(&control.Interface{Name: "rmnet_data1", Index: 19})
	defaultMonitor.emit(&control.Interface{Name: "rmnet_data2", Index: 21})
	if current := inbound.monitoredDefaultInterfaceName(); current != "rmnet_data2" {
		t.Fatalf("SIM interface switch was not recorded: %q", current)
	}
	if err := inbound.stopTCInterfaceMonitor(); err != nil {
		t.Fatal(err)
	}
	if networkMonitor.callbackCount() != 0 || defaultMonitor.callbackCount() != 0 {
		t.Fatalf("unexpected callback counts after stop: network=%d default=%d", networkMonitor.callbackCount(), defaultMonitor.callbackCount())
	}
}

func TestTCInterfaceNotificationsCoalesce(t *testing.T) {
	networkMonitor := &testNetworkUpdateMonitor{}
	updates := make(chan struct{}, 1)
	inbound := &Inbound{inboundWorkers: inboundWorkers{interfaceMonitor: tcInterfaceMonitor{network: networkMonitor, updates: updates}}}
	inbound.notifyTCInterfaceUpdate()
	inbound.notifyTCInterfaceUpdate()
	if len(updates) != 1 {
		t.Fatalf("unexpected pending update count: %d", len(updates))
	}
}

func TestNetworkStateResetUsesCoordinatedInterfaceUpdate(t *testing.T) {
	handler := &udpNATTestHandler{connections: make(chan udpNATTestConnection, 1)}
	service := newUDPNATService(
		handler,
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(func() { _ = service.Close() })

	defaultMonitor := &testDefaultInterfaceMonitor{current: &control.Interface{Name: "wlan0", Index: 8}}
	inbound := &Inbound{
		networkManager:   &testInterfaceNetworkManager{defaultMonitor: defaultMonitor},
		inboundResources: inboundResources{udpNat: service},
	}
	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("198.51.100.1:443")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalCgroup, SocketCookie: 1}
	service.NewPacket(key, [][]byte{[]byte("test")}, source, destination, nil)
	if count := service.cache.Len(); count != 1 {
		t.Fatalf("unexpected initial UDP session count: %d", count)
	}

	// Raw monitor observations may describe an intermediate handover state and
	// must only schedule topology reconciliation, not tear down live flows.
	inbound.defaultInterfaceUpdated(&control.Interface{Name: "rmnet_data0", Index: 19}, 0)
	if count := service.cache.Len(); count != 1 {
		t.Fatalf("raw interface update purged UDP sessions: %d", count)
	}

	defaultMonitor.current = &control.Interface{Name: "rmnet_data0", Index: 19}
	inbound.InterfaceUpdated(context.Background())
	if count := service.cache.Len(); count != 0 {
		t.Fatalf("coordinated interface update retained UDP sessions: %d", count)
	}
	if current := inbound.monitoredDefaultInterfaceName(); current != "rmnet_data0" {
		t.Fatalf("unexpected coordinated default interface: %q", current)
	}
}

func TestInterfaceDriftCheckOnlyTracksTCState(t *testing.T) {
	inbound := &Inbound{}
	if interval := inbound.interfaceDriftCheckInterval(); interval != 0 {
		t.Fatalf("pure cgroup drift interval = %s, want disabled", interval)
	}

	expectedInterval := tcDriftCheckInterval
	if runtime.GOOS == "android" {
		expectedInterval = androidTCDriftCheckInterval
	}

	inbound.setTCDataPlane(&retryTestTCRuntime{})
	if interval := inbound.interfaceDriftCheckInterval(); interval != expectedInterval {
		t.Fatalf("TC drift interval = %s, want %s", interval, expectedInterval)
	}
	inbound.takeTCDataPlane()

	inbound.setSharedRewrite(&sharedRewrite{})
	if interval := inbound.interfaceDriftCheckInterval(); interval != expectedInterval {
		t.Fatalf("shared rewrite drift interval = %s, want %s", interval, expectedInterval)
	}
	inbound.takeSharedRewrite()

	if interval := inbound.interfaceDriftCheckInterval(); interval != time.Duration(0) {
		t.Fatalf("cleared data-plane drift interval = %s, want disabled", interval)
	}
}

func TestIsCandidateDefaultRoute(t *testing.T) {
	if !isCandidateDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 1}) {
		t.Fatal("expected route with nil Dst to be candidate default route")
	}
	_, v4Default, _ := net.ParseCIDR("0.0.0.0/0")
	if !isCandidateDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 1, Dst: v4Default}) {
		t.Fatal("expected 0.0.0.0/0 to be candidate default route")
	}
	_, v6Default, _ := net.ParseCIDR("::/0")
	if !isCandidateDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 1, Dst: v6Default}) {
		t.Fatal("expected ::/0 to be candidate default route")
	}
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	if isCandidateDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 1, Dst: subnet}) {
		t.Fatal("expected subnet route to not be candidate default route")
	}
	if isCandidateDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 1, Table: unix.RT_TABLE_LOCAL}) {
		t.Fatal("expected local table route to not be candidate default route")
	}
	if isCandidateDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, LinkIndex: 0}) {
		t.Fatal("expected non-positive LinkIndex route to not be candidate default route")
	}
}

func TestAndroidDefaultInterfaceFallback(t *testing.T) {
	previousFinder := androidDefaultInterfaceFinder
	androidDefaultInterfaceFinder = func() string { return "wlan0" }
	t.Cleanup(func() {
		androidDefaultInterfaceFinder = previousFinder
	})

	inbound := &Inbound{
		networkManager: &testInterfaceNetworkManager{
			defaultMonitor: &testDefaultInterfaceMonitor{current: nil},
		},
	}
	name := inbound.currentDefaultInterfaceName()
	if runtime.GOOS == "android" {
		if name != "wlan0" {
			t.Fatalf("expected fallback to wlan0 on android, got %q", name)
		}
	} else {
		if name != "" {
			t.Fatalf("expected empty name on non-android, got %q", name)
		}
	}
}

func TestAndroidRuleTablesPreferDefaultNetwork(t *testing.T) {
	// netd order: explicit (13000), output iface (14000), implicit (16000) per
	// network, then the default network rule (22000, fwmark mask 0xffff).
	rules := []netlink.Rule{
		{Priority: 0, Table: unix.RT_TABLE_LOCAL},
		{Priority: 13000, Table: 1021, Mask: 0x1ffff},
		{Priority: 13000, Table: 1033, Mask: 0x1ffff},
		{Priority: 14000, Table: 1021},
		{Priority: 16000, Table: 1033, Mask: 0x1ffff},
		{Priority: 22000, Table: 1033, Mask: androidDefaultNetworkRuleMask},
		{Priority: 32000, Table: 0},
	}
	got := androidRuleTables(rules)
	want := []int{1033, 1021}
	if !slices.Equal(got, want) {
		t.Fatalf("default-network table not preferred: got %v want %v", got, want)
	}
	if got := androidRuleTables(rules[:5]); !slices.Equal(got, []int{1021, 1033}) {
		t.Fatalf("without a default-network rule, rule order must be kept: %v", got)
	}
}

func TestDefaultInterfaceCandidateSkipsShims(t *testing.T) {
	up := net.FlagUp
	for name, want := range map[string]bool{
		"wlan0":         true,
		"rmnet_data0":   true,
		"v4-wlan0":      false,
		"v4-rmnet_data": false,
		"tun0":          false,
		"ipsec0":        false,
	} {
		if got := isDefaultInterfaceCandidate(&netlink.LinkAttrs{Name: name, Flags: up}); got != want {
			t.Fatalf("%s: got %v want %v", name, got, want)
		}
	}
	if isDefaultInterfaceCandidate(&netlink.LinkAttrs{Name: "wlan0"}) {
		t.Fatal("down interface accepted")
	}
	if isDefaultInterfaceCandidate(&netlink.LinkAttrs{Name: "lo", Flags: up | net.FlagLoopback}) {
		t.Fatal("loopback accepted")
	}
}

type testInterfaceNetworkManager struct {
	adapter.NetworkManager
	networkMonitor tun.NetworkUpdateMonitor
	defaultMonitor tun.DefaultInterfaceMonitor
	finder         control.InterfaceFinder
}

func (m *testInterfaceNetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor {
	return m.networkMonitor
}

func (m *testInterfaceNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return m.defaultMonitor
}

func (m *testInterfaceNetworkManager) UpdateInterfaces() error { return nil }

func (m *testInterfaceNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return m.finder
}

type testNetworkUpdateMonitor struct {
	callbacks list.List[tun.NetworkUpdateCallback]
}

func (m *testNetworkUpdateMonitor) Start() error { return nil }

func (m *testNetworkUpdateMonitor) Close() error { return nil }

func (m *testNetworkUpdateMonitor) RegisterCallback(callback tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	return m.callbacks.PushBack(callback)
}

func (m *testNetworkUpdateMonitor) UnregisterCallback(element *list.Element[tun.NetworkUpdateCallback]) {
	m.callbacks.Remove(element)
}

func (m *testNetworkUpdateMonitor) callbackCount() int {
	return len(m.callbacks.Array())
}

type testDefaultInterfaceMonitor struct {
	current   *control.Interface
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
}

func (m *testDefaultInterfaceMonitor) Start() error { return nil }

func (m *testDefaultInterfaceMonitor) Close() error { return nil }

func (m *testDefaultInterfaceMonitor) DefaultInterface() *control.Interface { return m.current }

func (m *testDefaultInterfaceMonitor) OverrideAndroidVPN() bool { return false }

func (m *testDefaultInterfaceMonitor) AndroidVPNEnabled() bool { return false }

func (m *testDefaultInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return m.callbacks.PushBack(callback)
}

func (m *testDefaultInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.callbacks.Remove(element)
}

func (m *testDefaultInterfaceMonitor) RegisterMyInterface(string) {}

func (m *testDefaultInterfaceMonitor) MyInterfaces() []string { return nil }

func (m *testDefaultInterfaceMonitor) callbackCount() int {
	return len(m.callbacks.Array())
}

func (m *testDefaultInterfaceMonitor) emit(networkInterface *control.Interface) {
	m.current = networkInterface
	for _, callback := range m.callbacks.Array() {
		callback(networkInterface, 0)
	}
}
