//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

func TestReconcileVPNReady(t *testing.T) {
	for _, test := range []struct {
		name         string
		previous     bool
		active       int
		sampledReady bool
		want         bool
	}{
		{"baseline stays not ready", false, 1, false, false},
		{"traffic becomes ready", false, 1, true, true},
		{"ready persists without increase", true, 1, false, true},
		{"ready persists across counter reset", true, 2, false, true},
		{"zero active disconnects", true, 0, false, false},
		{"sampled ready wins", false, 1, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := reconcileVPNReady(test.previous, test.active, test.sampledReady); got != test.want {
				t.Fatalf("unexpected readiness: got %v, want %v", got, test.want)
			}
		})
	}
}

func TestVPNInterfacePatterns(t *testing.T) {
	for _, name := range []string{"tun0", "TUN-CF", "ipsec0", "IPSEC1"} {
		if !isVPNInterface(name) {
			t.Fatalf("expected VPN interface match: %s", name)
		}
	}
	for _, name := range []string{"wlan0", "rmnet_data0", "tap0"} {
		if isVPNInterface(name) {
			t.Fatalf("unexpected VPN interface match: %s", name)
		}
	}
}

func TestVPNPacketCountIncrease(t *testing.T) {
	baseline := interfacePacketCount{rx: 10, tx: 20}
	if packetCountIncreased(baseline, baseline) {
		t.Fatal("unchanged counters reported activity")
	}
	if packetCountIncreased(baseline, interfacePacketCount{rx: 1, tx: 2}) {
		t.Fatal("counter reset reported activity")
	}
	if !packetCountIncreased(baseline, interfacePacketCount{rx: 11, tx: 20}) ||
		!packetCountIncreased(baseline, interfacePacketCount{rx: 10, tx: 21}) {
		t.Fatal("RX/TX increase did not report activity")
	}
}

func TestVPNDefaultRoutePredicate(t *testing.T) {
	if !isVPNDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, Table: unix.RT_TABLE_MAIN}) {
		t.Fatal("nil-destination unicast default route was rejected")
	}
	_, defaultIPv4, _ := net.ParseCIDR("0.0.0.0/0")
	if !isVPNDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, Table: 100, Dst: defaultIPv4}) {
		t.Fatal("explicit IPv4 default route was rejected")
	}
	_, specificIPv4, _ := net.ParseCIDR("192.0.2.0/24")
	for _, route := range []netlink.Route{
		{Type: unix.RTN_UNICAST, Table: unix.RT_TABLE_LOCAL},
		{Type: unix.RTN_BLACKHOLE, Table: unix.RT_TABLE_MAIN},
		{Type: unix.RTN_UNICAST, Table: unix.RT_TABLE_MAIN, Dst: specificIPv4},
	} {
		if isVPNDefaultRoute(route) {
			t.Fatalf("non-qualifying route was accepted: %+v", route)
		}
	}
}
