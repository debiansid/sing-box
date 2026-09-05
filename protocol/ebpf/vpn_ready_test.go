//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"golang.org/x/sys/unix"
)

type testEndpointVPNReadyControl struct {
	updates []bool
	err     error
}

func (c *testEndpointVPNReadyControl) SetEndpointVPNReady(ready bool) error {
	c.updates = append(c.updates, ready)
	return c.err
}

func TestVPNReadinessTransitionOnlyControlUpdates(t *testing.T) {
	inbound := Inbound{
		logger:                  log.NewNOPFactory().Logger(),
		endpointConnectedBypass: option.EBPFEndpointConnectedBypassOptions{Enabled: true},
	}
	inbound.resetVPNReadinessState()
	control := &testEndpointVPNReadyControl{}
	baseline := vpnReadinessSample{activeInterfaces: []string{"tun0"}}
	inbound.transitionVPNReadinessWithControl(baseline, control)
	inbound.transitionVPNReadinessWithControl(baseline, control)
	if len(control.updates) != 0 {
		t.Fatalf("NOT READY samples updated control state: %v", control.updates)
	}
	ready := vpnReadinessSample{
		activeInterfaces: []string{"tun0"},
		readyInterface:   "tun0",
		readyReason:      endpointReadyReasonRXActivity,
		ready:            true,
	}
	inbound.transitionVPNReadinessWithControl(ready, control)
	inbound.transitionVPNReadinessWithControl(ready, control)
	if len(control.updates) != 1 || !control.updates[0] {
		t.Fatalf("READY transition did not produce exactly one control update: %v", control.updates)
	}
	disconnected := vpnReadinessSample{}
	inbound.transitionVPNReadinessWithControl(disconnected, control)
	inbound.transitionVPNReadinessWithControl(disconnected, control)
	if len(control.updates) != 2 || control.updates[1] {
		t.Fatalf("disconnect transition did not produce exactly one control update: %v", control.updates)
	}
}

func TestVPNReadinessControlFailureDoesNotCommit(t *testing.T) {
	inbound := Inbound{
		logger:                  log.NewNOPFactory().Logger(),
		endpointConnectedBypass: option.EBPFEndpointConnectedBypassOptions{Enabled: true},
	}
	inbound.resetVPNReadinessState()
	control := &testEndpointVPNReadyControl{err: errors.New("control update failed")}
	inbound.transitionVPNReadinessWithControl(vpnReadinessSample{
		activeInterfaces: []string{"ipsec0"},
		readyInterface:   "ipsec0",
		readyReason:      endpointReadyReasonIPsecDefaultRoute,
		ready:            true,
	}, control)
	if inbound.vpnReady.Load() {
		t.Fatal("failed control update advanced committed READY state")
	}
	if status := inbound.currentEndpointBypassStatus(); status.VPNReady {
		t.Fatalf("failed control update published READY status: %+v", status)
	}
	if len(control.updates) != 1 || !control.updates[0] {
		t.Fatalf("unexpected failed control updates: %v", control.updates)
	}
}

func TestEndpointBypassStatusSnapshot(t *testing.T) {
	inbound := Inbound{
		endpointConnectedBypass: option.EBPFEndpointConnectedBypassOptions{Enabled: true},
	}
	configured := endpointBypassStatus{Enabled: true}
	if got := inbound.currentEndpointBypassStatus(); got != configured {
		t.Fatalf("unexpected initial status: got %+v, want %+v", got, configured)
	}
	ready := endpointBypassStatus{
		Enabled:            true,
		VPNReady:           true,
		ActiveVPNInterface: "ipsec0",
		ReadyReason:        endpointReadyReasonIPsecDefaultRoute,
	}
	inbound.storeEndpointBypassStatus(ready)
	if got := inbound.currentEndpointBypassStatus(); got != ready {
		t.Fatalf("unexpected stored status: got %+v, want %+v", got, ready)
	}
	inbound.resetEndpointBypassStatus()
	if got := inbound.currentEndpointBypassStatus(); got != configured {
		t.Fatalf("unexpected reset status: got %+v, want %+v", got, configured)
	}
}

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
	if reason := packetCountReadyReason(baseline, interfacePacketCount{rx: 11, tx: 20}); reason != endpointReadyReasonRXActivity {
		t.Fatalf("unexpected RX readiness reason: %q", reason)
	}
	if reason := packetCountReadyReason(baseline, interfacePacketCount{rx: 10, tx: 21}); reason != endpointReadyReasonTXActivity {
		t.Fatalf("unexpected TX readiness reason: %q", reason)
	}
	if reason := packetCountReadyReason(baseline, baseline); reason != "" {
		t.Fatalf("unchanged counters returned readiness reason: %q", reason)
	}
}

func TestReconcileEndpointBypassStatus(t *testing.T) {
	readyStatus := endpointBypassStatus{
		Enabled:            true,
		VPNReady:           true,
		ActiveVPNInterface: "tun0",
		ReadyReason:        endpointReadyReasonRXActivity,
	}
	for _, test := range []struct {
		name             string
		previous         endpointBypassStatus
		enabled          bool
		activeInterfaces []string
		sampledInterface string
		sampledReason    string
		vpnReady         bool
		want             endpointBypassStatus
	}{
		{
			name:             "disabled",
			enabled:          false,
			activeInterfaces: []string{"tun0"},
			want:             endpointBypassStatus{},
		},
		{
			name:    "no active interface",
			enabled: true,
			want: endpointBypassStatus{
				Enabled:     true,
				ReadyReason: endpointReadyReasonNoActiveInterface,
			},
		},
		{
			name:             "baseline candidate",
			enabled:          true,
			activeInterfaces: []string{"tun0"},
			want: endpointBypassStatus{
				Enabled:            true,
				ActiveVPNInterface: "tun0",
			},
		},
		{
			name:             "RX establishes readiness",
			enabled:          true,
			activeInterfaces: []string{"tun0"},
			sampledInterface: "tun0",
			sampledReason:    endpointReadyReasonRXActivity,
			vpnReady:         true,
			want:             readyStatus,
		},
		{
			name:             "unchanged active interface retains reason",
			previous:         readyStatus,
			enabled:          true,
			activeInterfaces: []string{"tun0"},
			vpnReady:         true,
			want:             readyStatus,
		},
		{
			name:             "replacement candidate has no invented reason",
			previous:         readyStatus,
			enabled:          true,
			activeInterfaces: []string{"tun1"},
			vpnReady:         true,
			want: endpointBypassStatus{
				Enabled:            true,
				VPNReady:           true,
				ActiveVPNInterface: "tun1",
			},
		},
		{
			name:             "IPsec route establishes readiness",
			enabled:          true,
			activeInterfaces: []string{"ipsec0"},
			sampledInterface: "ipsec0",
			sampledReason:    endpointReadyReasonIPsecDefaultRoute,
			vpnReady:         true,
			want: endpointBypassStatus{
				Enabled:            true,
				VPNReady:           true,
				ActiveVPNInterface: "ipsec0",
				ReadyReason:        endpointReadyReasonIPsecDefaultRoute,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := reconcileEndpointBypassStatus(
				test.previous,
				test.enabled,
				test.activeInterfaces,
				test.sampledInterface,
				test.sampledReason,
				test.vpnReady,
			)
			if got != test.want {
				t.Fatalf("unexpected status: got %+v, want %+v", got, test.want)
			}
		})
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
