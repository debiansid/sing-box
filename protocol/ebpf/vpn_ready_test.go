//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"path/filepath"
	"slices"
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
	baseline := vpnReadinessSample{}
	inbound.transitionVPNReadinessWithControl(baseline, control)
	inbound.transitionVPNReadinessWithControl(baseline, control)
	if len(control.updates) != 0 {
		t.Fatalf("NOT READY samples updated control state: %v", control.updates)
	}
	ready := vpnReadinessSample{ready: true}
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
	inbound.transitionVPNReadinessWithControl(vpnReadinessSample{ready: true}, control)
	if inbound.vpnReady.Load() {
		t.Fatal("failed control update advanced committed READY state")
	}
	if len(control.updates) != 1 || !control.updates[0] {
		t.Fatalf("unexpected failed control updates: %v", control.updates)
	}
	control.err = nil
	inbound.transitionVPNReadinessWithControl(vpnReadinessSample{ready: true}, control)
	inbound.transitionVPNReadinessWithControl(vpnReadinessSample{ready: true}, control)
	if !inbound.vpnReady.Load() || !slices.Equal(control.updates, []bool{true, true}) {
		t.Fatalf("activation retry/duplicate handling failed: committed=%v writes=%v", inbound.vpnReady.Load(), control.updates)
	}
}

func TestVPNReadinessReset(t *testing.T) {
	inbound := Inbound{vpnInterfacePackets: map[vpnInterfaceIdentity]vpnInterfaceState{
		{name: "tun0", index: 10}: {packets: interfacePacketCount{rx: 1}, readyReason: endpointReadyReasonRXActivity},
	}}
	inbound.vpnReady.Store(true)
	inbound.resetVPNReadinessState()
	if inbound.vpnReady.Load() || inbound.vpnInterfacePackets != nil {
		t.Fatal("reset retained committed READY or per-interface state")
	}
}

func TestVPNInterfacePatterns(t *testing.T) {
	for _, name := range []string{"tun", "tun0", "TUN-CF", "TuN+", "ipsec", "ipsec0", "IPSEC1", "ipsec++", "IpSeC++"} {
		if !isVPNInterface(name) {
			t.Fatalf("expected VPN interface match: %s", name)
		}
	}
	for _, name := range []string{"", "wlan0", "rmnet_data0", "tap0", "xtun0", "xipsec0"} {
		if isVPNInterface(name) {
			t.Fatalf("unexpected VPN interface match: %s", name)
		}
	}
}

func TestVPNDiscoveryAddressQualification(t *testing.T) {
	for _, test := range []struct {
		address string
		active  bool
	}{
		{"", false}, {"0.0.0.0", false}, {"::", false},
		{"127.0.0.1", false}, {"::1", false},
		{"169.254.1.1", false}, {"fe80::1", false},
		{"224.0.0.1", false}, {"ff02::1", false}, {"255.255.255.255", false},
		{"10.0.0.1", true}, {"fd00::1", true}, {"2001:db8::1", true},
		{"::ffff:10.0.0.1", true}, {"::ffff:127.0.0.1", false},
	} {
		for _, fallback := range []bool{false, true} {
			ip := net.ParseIP(test.address)
			got := findActiveVPNInterfaces(nil, func() ([]netlink.Link, error) {
				if fallback {
					return nil, errors.New("use fallback")
				}
				return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tun0", Index: 10, Flags: net.FlagUp}}}, nil
			}, func(netlink.Link, int) ([]netlink.Addr, error) {
				return []netlink.Addr{{IPNet: &net.IPNet{IP: ip}}}, nil
			}, func() ([]net.Interface, error) {
				if !fallback {
					return nil, nil
				}
				return []net.Interface{{Name: "tun0", Index: 10, Flags: net.FlagUp}}, nil
			}, func(*net.Interface) ([]net.Addr, error) {
				return []net.Addr{&net.IPAddr{IP: ip}}, nil
			})
			if (len(got) != 0) != test.active {
				t.Fatalf("address=%q fallback=%v: got %v, want active=%v", test.address, fallback, got, test.active)
			}
		}
	}
}

func TestVPNPacketCounterReadValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		rx   string
		tx   string
	}{
		{"empty RX", "", "100"},
		{"invalid RX", "invalid", "100"},
		{"negative RX", "-1", "100"},
		{"overflow RX", "18446744073709551616", "100"},
		{"empty TX", "100", ""},
		{"invalid TX", "100", "invalid"},
		{"negative TX", "100", "-1"},
		{"overflow TX", "100", "18446744073709551616"},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := vpnInterfaceIdentity{name: "tun0", index: 10}
			states := make(map[vpnInterfaceIdentity]vpnInterfaceState)
			rxData, txData := test.rx, test.tx
			readCounts := func(name string) (uint64, uint64, error) {
				return readInterfacePacketCount(name, func(path string) ([]byte, error) {
					switch path {
					case filepath.Join("/sys/class/net", identity.name, "statistics", "rx_packets"):
						return []byte(rxData), nil
					case filepath.Join("/sys/class/net", identity.name, "statistics", "tx_packets"):
						return []byte(txData), nil
					default:
						t.Fatalf("unexpected counter path: %s", path)
						return nil, errors.New("unexpected counter path")
					}
				})
			}
			if _, _, err := readCounts(identity.name); err == nil {
				t.Fatal("malformed packet counter accepted as a successful read")
			}
			sample := func() vpnReadinessSample {
				return sampleVPNInterfaces([]vpnInterfaceIdentity{identity}, states, readCounts, func(int) bool { return false })
			}
			if got := sample(); got.ready || len(states) != 0 {
				t.Fatalf("malformed initial counters established readiness state: %+v, %v", got, states)
			}
			rxData, txData = " 100\n", "100\n"
			if got := sample(); got.ready || len(states) != 1 {
				t.Fatalf("first valid sample must establish baseline only: %+v, %v", got, states)
			}
			rxData, txData = test.rx, test.tx
			if got := sample(); got.ready || states[identity].packets != (interfacePacketCount{rx: 100, tx: 100}) {
				t.Fatalf("malformed sample changed the last successful baseline: %+v, %v", got, states)
			}
			rxData, txData = "100", "101"
			if got := sample(); !got.ready || states[identity].readyReason != endpointReadyReasonTXActivity {
				t.Fatalf("valid growth did not establish readiness: %+v", got)
			}
		})
	}
}

type testVPNReadinessSampler struct {
	states     map[vpnInterfaceIdentity]vpnInterfaceState
	packets    map[string]interfacePacketCount
	routes     map[int]bool
	reads      map[string]int
	routeReads map[int]int
	packetErr  error
}

func newTestVPNReadinessSampler() *testVPNReadinessSampler {
	return &testVPNReadinessSampler{
		states:     make(map[vpnInterfaceIdentity]vpnInterfaceState),
		packets:    make(map[string]interfacePacketCount),
		routes:     make(map[int]bool),
		reads:      make(map[string]int),
		routeReads: make(map[int]int),
	}
}

func (s *testVPNReadinessSampler) sample(interfaces ...vpnInterfaceIdentity) vpnReadinessSample {
	return sampleVPNInterfaces(interfaces, s.states, func(name string) (uint64, uint64, error) {
		s.reads[name]++
		packets := s.packets[name]
		return packets.rx, packets.tx, s.packetErr
	}, func(index int) bool {
		s.routeReads[index]++
		return s.routes[index]
	})
}

func TestVPNTUNLocalReadiness(t *testing.T) {
	identity := vpnInterfaceIdentity{name: "tun0", index: 10}
	for _, reason := range []string{endpointReadyReasonRXActivity, endpointReadyReasonTXActivity} {
		t.Run(reason, func(t *testing.T) {
			s := newTestVPNReadinessSampler()
			s.packets[identity.name] = interfacePacketCount{rx: 100, tx: 100}
			s.packetErr = errors.New("counter read failed")
			if got := s.sample(identity); got.ready || len(s.states) != 0 {
				t.Fatalf("failed initial read established state: %+v, %v", got, s.states)
			}
			s.packetErr = nil
			if got := s.sample(identity); got.ready || len(s.states) != 1 {
				t.Fatalf("first successful read must establish baseline only: %+v", got)
			}
			counts := s.packets[identity.name]
			if reason == endpointReadyReasonRXActivity {
				counts.rx++
			} else {
				counts.tx++
			}
			s.packets[identity.name] = counts
			for _, phase := range []string{"growth", "silence", "regression", "read failure"} {
				if phase == "regression" {
					s.packets[identity.name] = interfacePacketCount{rx: 1, tx: 1}
				}
				if phase == "read failure" {
					s.packetErr = errors.New("counter read failed")
				}
				got := s.sample(identity)
				if !got.ready || s.states[identity].readyReason != reason {
					t.Fatalf("%s: unexpected local latch: %+v", phase, got)
				}
			}
		})
	}
}

func TestVPNTUNReadinessIdentityChurn(t *testing.T) {
	old := vpnInterfaceIdentity{name: "tun0", index: 10}
	for _, test := range []struct {
		name        string
		replacement vpnInterfaceIdentity
		disappear   bool
	}{
		{"same name different index", vpnInterfaceIdentity{name: "tun0", index: 11}, false},
		{"same index different name", vpnInterfaceIdentity{name: "tun1", index: 10}, false},
		{"disappear and reappear", old, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newTestVPNReadinessSampler()
			s.sample(old)
			s.packets[old.name] = interfacePacketCount{rx: 1}
			if !s.sample(old).ready {
				t.Fatal("old interface did not become ready")
			}
			if test.disappear {
				if got := s.sample(); got.ready || len(s.states) != 0 {
					t.Fatalf("disappearance retained state: %+v, %v", got, s.states)
				}
			}
			s.packets[test.replacement.name] = interfacePacketCount{rx: 100}
			if got := s.sample(test.replacement); got.ready || s.states[test.replacement].readyReason != "" || len(s.states) != 1 {
				t.Fatalf("replacement inherited readiness: %+v, %v", got, s.states)
			}
			s.packets[test.replacement.name] = interfacePacketCount{rx: 101}
			if !s.sample(test.replacement).ready {
				t.Fatal("replacement failed to establish independent readiness")
			}
		})
	}
}

func TestVPNReadyTUNDisappearsWithUnreadyCandidate(t *testing.T) {
	s := newTestVPNReadinessSampler()
	ready := vpnInterfaceIdentity{name: "tun0", index: 10}
	unready := vpnInterfaceIdentity{name: "tun1", index: 11}
	s.sample(ready, unready)
	s.packets[ready.name] = interfacePacketCount{rx: 1}
	if !s.sample(ready, unready).ready {
		t.Fatal("traffic did not establish readiness")
	}
	if got := s.sample(unready); got.ready || s.states[unready].readyReason != "" {
		t.Fatalf("unready survivor inherited global readiness: %+v", got)
	}
}

func TestVPNIPsecRouteReadiness(t *testing.T) {
	s := newTestVPNReadinessSampler()
	ipsec := vpnInterfaceIdentity{name: "ipsec++", index: 10}
	for _, ready := range []bool{true, false, true} {
		s.routes[ipsec.index] = ready
		got := s.sample(ipsec)
		if got.ready != ready || len(s.states) != 0 || len(s.reads) != 0 {
			t.Fatalf("IPsec must reflect current route without activity state: %+v", got)
		}
	}
}

func TestVPNAllCandidatesSampledAndSourceSwitch(t *testing.T) {
	s := newTestVPNReadinessSampler()
	interfaces := []vpnInterfaceIdentity{
		{name: "tun5", index: 5}, {name: "ipsec0", index: 10},
		{name: "tun6", index: 11}, {name: "ipsec1", index: 12},
	}
	s.routes[10], s.routes[12] = true, true
	inbound := Inbound{logger: log.NewNOPFactory().Logger(), endpointConnectedBypass: option.EBPFEndpointConnectedBypassOptions{Enabled: true}}
	inbound.resetVPNReadinessState()
	control := &testEndpointVPNReadyControl{}
	for cycle := 1; cycle <= 3; cycle++ {
		if cycle == 2 {
			s.packets["tun5"] = interfacePacketCount{tx: 1}
			s.packets["tun6"] = interfacePacketCount{rx: 1}
		}
		if cycle == 3 {
			s.routes[10], s.routes[12] = false, false
		}
		sampleOrder := slices.Clone(interfaces)
		if cycle == 2 {
			slices.Reverse(sampleOrder)
		}
		got := s.sample(sampleOrder...)
		if !got.ready {
			t.Fatalf("cycle %d: lost readiness during source switch", cycle)
		}
		inbound.transitionVPNReadinessWithControl(got, control)
		if !inbound.vpnReady.Load() {
			t.Fatalf("cycle %d: READY was not committed", cycle)
		}
		for _, name := range []string{"tun5", "tun6"} {
			if s.reads[name] != cycle {
				t.Fatalf("%s starved: %v", name, s.reads)
			}
		}
		for _, index := range []int{10, 12} {
			if s.routeReads[index] != cycle {
				t.Fatalf("IPsec %d starved: %v", index, s.routeReads)
			}
		}
	}
	if !slices.Equal(control.updates, []bool{true}) {
		t.Fatalf("source switch rewrote TC control: %v", control.updates)
	}
	if s.states[interfaces[2]].readyReason != endpointReadyReasonRXActivity {
		t.Fatal("later TUN did not latch independently")
	}
}

func TestVPNReadinessRevocationFailureRetries(t *testing.T) {
	s := newTestVPNReadinessSampler()
	ipsec := vpnInterfaceIdentity{name: "ipsec++", index: 10}
	tun := vpnInterfaceIdentity{name: "tun0", index: 11}
	inbound := Inbound{logger: log.NewNOPFactory().Logger(), endpointConnectedBypass: option.EBPFEndpointConnectedBypassOptions{Enabled: true}}
	inbound.resetVPNReadinessState()
	control := &testEndpointVPNReadyControl{}
	s.routes[10] = true
	inbound.transitionVPNReadinessWithControl(s.sample(ipsec, tun), control)
	if !inbound.vpnReady.Load() {
		t.Fatal("initial READY was not committed")
	}
	s.routes[10] = false
	control.err = errors.New("control write failed")
	sample := s.sample(ipsec, tun)
	if sample.ready {
		t.Fatal("route withdrawal retained desired READY")
	}
	inbound.transitionVPNReadinessWithControl(sample, control)
	if !inbound.vpnReady.Load() {
		t.Fatal("failed revocation changed committed READY")
	}
	control.err = nil
	// The old source disappears before retry; a fresh sample must clear it.
	inbound.transitionVPNReadinessWithControl(s.sample(tun), control)
	if inbound.vpnReady.Load() {
		t.Fatal("successful retry retained committed READY")
	}
	inbound.transitionVPNReadinessWithControl(s.sample(tun), control)
	if !slices.Equal(control.updates, []bool{true, false, false}) {
		t.Fatalf("unexpected retry/duplicate writes: %v", control.updates)
	}
}

func TestVPNDiscoverySelfExclusion(t *testing.T) {
	for _, path := range []string{"netlink", "fallback", "both", "fallback failure"} {
		t.Run(path, func(t *testing.T) {
			self := vpnInterfaceIdentity{name: "tun0", index: 10}
			external := vpnInterfaceIdentity{name: "tun1", index: 11}
			address := &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}
			discover := func(excluded []string) []vpnInterfaceIdentity {
				return findActiveVPNInterfaces(excluded, func() ([]netlink.Link, error) {
					if path == "fallback" {
						return nil, errors.New("netlink unavailable")
					}
					return []netlink.Link{
						&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: external.name, Index: external.index, Flags: net.FlagUp}},
						&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: self.name, Index: self.index, Flags: net.FlagUp}},
					}, nil
				}, func(link netlink.Link, family int) ([]netlink.Addr, error) {
					if slices.Contains(excluded, link.Attrs().Name) {
						t.Fatal("queried excluded netlink interface")
					}
					return []netlink.Addr{{IPNet: address}}, nil
				}, func() ([]net.Interface, error) {
					if path == "netlink" {
						return nil, nil
					}
					if path == "fallback failure" {
						return nil, errors.New("fallback unavailable")
					}
					return []net.Interface{
						{Name: external.name, Index: external.index, Flags: net.FlagUp},
						{Name: self.name, Index: self.index, Flags: net.FlagUp},
					}, nil
				}, func(networkInterface *net.Interface) ([]net.Addr, error) {
					if slices.Contains(excluded, networkInterface.Name) {
						t.Fatal("queried excluded fallback interface")
					}
					return []net.Addr{address}, nil
				})
			}
			s := newTestVPNReadinessSampler()
			if got := discover(nil); len(got) != 2 || !slices.Contains(got, self) || !slices.Contains(got, external) {
				t.Fatalf("discovery membership/deduplication: %v", got)
			}
			s.sample(discover(nil)...)
			s.packets[self.name] = interfacePacketCount{rx: 1}
			if !s.sample(discover(nil)...).ready {
				t.Fatal("pre-registration TUN did not become ready")
			}
			monitor := &testDefaultInterfaceMonitor{}
			monitor.RegisterMyInterface(self.name)
			eligible := discover(slices.Clone(monitor.MyInterfaces()))
			if !slices.Equal(eligible, []vpnInterfaceIdentity{external}) {
				t.Fatalf("self interface eligible: %v", eligible)
			}
			if got := s.sample(eligible...); got.ready || len(s.states) != 1 {
				t.Fatalf("ownership retained latch: %+v, %v", got, s.states)
			}
			if _, exists := s.states[self]; exists {
				t.Fatal("self baseline retained")
			}
			for cycle := 0; cycle < 2; cycle++ {
				s.packets[self.name] = interfacePacketCount{rx: uint64(100 + cycle)}
				if got := s.sample(discover(monitor.MyInterfaces())...); got.ready {
					t.Fatalf("self traffic established READY: %+v", got)
				}
			}
		})
	}
}

func TestVPNInterfaceBaselineIdentity(t *testing.T) {
	oldInterface := vpnInterfaceIdentity{name: "tun0", index: 10}
	newInterface := vpnInterfaceIdentity{name: "tun0", index: 11}
	baseline := map[vpnInterfaceIdentity]vpnInterfaceState{
		oldInterface: {packets: interfacePacketCount{rx: 100, tx: 200}, readyReason: endpointReadyReasonRXActivity},
	}
	retainActiveVPNPacketBaselines(baseline, []vpnInterfaceIdentity{newInterface})
	if _, loaded := baseline[oldInterface]; loaded {
		t.Fatal("same-name replacement retained the old interface baseline")
	}
	if _, loaded := baseline[newInterface]; loaded {
		t.Fatal("replacement interface inherited a baseline before its first sample")
	}
}

func TestVPNPacketCountIncrease(t *testing.T) {
	baseline := interfacePacketCount{rx: 10, tx: 20}
	if packetCountReadyReason(baseline, interfacePacketCount{rx: 1, tx: 2}) != "" {
		t.Fatal("counter reset reported activity")
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

func TestVPNDefaultRoutePredicate(t *testing.T) {
	if !isVPNDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, Table: unix.RT_TABLE_MAIN}) {
		t.Fatal("nil-destination unicast default route was rejected")
	}
	_, defaultIPv4, _ := net.ParseCIDR("0.0.0.0/0")
	if !isVPNDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, Table: 100, Dst: defaultIPv4}) {
		t.Fatal("explicit IPv4 default route was rejected")
	}
	_, defaultIPv6, _ := net.ParseCIDR("::/0")
	if !isVPNDefaultRoute(netlink.Route{Type: unix.RTN_UNICAST, Table: 100, Dst: defaultIPv6}) {
		t.Fatal("explicit IPv6 default route was rejected")
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
