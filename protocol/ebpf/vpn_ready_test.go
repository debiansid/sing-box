//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type readyControl struct {
	calls int
	err   error
}

func (c *readyControl) SetEndpointVPNReady(bool) error { c.calls++; return c.err }

func TestVPNReadyCommit(t *testing.T) {
	i := &Inbound{}
	c := &readyControl{err: errors.New("map write")}
	if i.commitVPNReady(true, c) == nil || i.vpnReady.Load() {
		t.Fatal("failed update committed")
	}
	c.err = nil
	if err := i.commitVPNReady(true, c); err != nil {
		t.Fatal(err)
	}
	if err := i.commitVPNReady(true, c); err != nil || c.calls != 2 {
		t.Fatal("duplicate control update")
	}
	if err := i.commitVPNReady(false, c); err != nil || i.vpnReady.Load() {
		t.Fatal("disconnect failed")
	}
}

func TestVPNReadySamples(t *testing.T) {
	states := make(map[vpnInterfaceIdentity]vpnInterfaceState)
	id := vpnInterfaceIdentity{"tun0", 10}
	rx, tx := uint64(100), uint64(100)
	var readErr error
	packets := func(string) (uint64, uint64, error) { return rx, tx, readErr }
	route := false
	var pending bool
	sample := func(ids ...vpnInterfaceIdentity) bool {
		var ready bool
		ready, pending = sampleVPNInterfaces(ids, states, packets, func(int) bool { return route })
		return ready
	}
	if sample(id) || sample(id) {
		t.Fatal("baseline or idle TUN became ready")
	}
	if !pending {
		t.Fatal("an unready TUN did not request counter polling")
	}
	tx++
	if !sample(id) {
		t.Fatal("TUN TX did not establish readiness")
	}
	if pending {
		t.Fatal("a ready TUN kept counter polling active")
	}
	readErr = errors.New("temporary counter read failure")
	if !sample(id) {
		t.Fatal("active TUN lost latched readiness")
	}
	id.index++
	if sample(id) {
		t.Fatal("recreated TUN inherited readiness")
	}
	readErr = nil
	if sample(id) {
		t.Fatal("first successful sample was not baseline")
	}
	rx++
	if !sample(id) {
		t.Fatal("TUN RX did not establish readiness")
	}
	if sample() || len(states) != 0 {
		t.Fatal("disconnect retained state")
	}
	if pending {
		t.Fatal("no candidate kept counter polling active")
	}
	ipsec := vpnInterfaceIdentity{"ipsec0", 20}
	if sample(ipsec) {
		t.Fatal("IPsec without route ready")
	}
	if pending {
		t.Fatal("IPsec readiness polled counters instead of waiting for route events")
	}
	route = true
	if !sample(ipsec) {
		t.Fatal("IPsec default route not ready")
	}
	route = false
	if sample(ipsec) {
		t.Fatal("IPsec route loss retained readiness")
	}
}

func TestVPNDiscovery(t *testing.T) {
	for _, address := range []string{"10.0.0.1", "fd00::1", "127.0.0.1", "fe80::1"} {
		for _, fallback := range []bool{false, true} {
			for _, excluded := range [][]string{nil, {"tun0"}} {
				ip := net.ParseIP(address)
				got := findActiveVPNInterfaces(excluded, nil,
					func() ([]netlink.Link, error) {
						if fallback {
							return nil, errors.New("netlink unavailable")
						}
						return []netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tun0", Index: 1, Flags: net.FlagUp}}}, nil
					}, func(netlink.Link, int) ([]netlink.Addr, error) {
						return []netlink.Addr{{IPNet: &net.IPNet{IP: ip}}}, nil
					},
					func() ([]net.Interface, error) {
						return []net.Interface{{Name: "tun0", Index: 1, Flags: net.FlagUp}}, nil
					},
					func(*net.Interface) ([]net.Addr, error) { return []net.Addr{&net.IPAddr{IP: ip}}, nil })
				want := 0
				if ip.IsGlobalUnicast() && len(excluded) == 0 {
					want = 1
				}
				if len(got) != want {
					t.Fatalf("address=%s fallback=%v excluded=%v: %v", address, fallback, excluded, got)
				}
			}
		}
	}
	for _, name := range []string{"tun0", "TUN-CF", "ipsec0", "IPSEC1"} {
		if !isVPNInterface(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"wlan0", "tap0", "xtun0"} {
		if isVPNInterface(name) {
			t.Fatal(name)
		}
	}
}

func TestVPNDefaultRoute(t *testing.T) {
	for _, tc := range []struct {
		route netlink.Route
		want  bool
	}{
		{netlink.Route{Table: 100, Type: unix.RTN_UNICAST}, true},
		{netlink.Route{Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_UNICAST}, false},
		{netlink.Route{Table: 100, Type: unix.RTN_BLACKHOLE}, false},
		{netlink.Route{Table: 100, Type: unix.RTN_UNICAST, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}, true},
		{netlink.Route{Table: 100, Type: unix.RTN_UNICAST, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(24, 32)}}, false},
	} {
		if isVPNDefaultRoute(tc.route) != tc.want {
			t.Fatal(tc)
		}
	}
}

func TestVPNInterfaceAddressFilter(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16"), netip.MustParsePrefix("fd00:8::/64")}
	for _, testCase := range []struct {
		address string
		allowed []netip.Prefix
		want    bool
	}{
		{"10.8.1.2", nil, true},
		{"fe80::1", nil, false},
		{"10.8.1.2", allowed, true},
		{"::ffff:10.8.1.2", allowed, true},
		{"fd00:8::2", allowed, true},
		{"10.9.0.1", allowed, false},
		{"2001:db8::1", allowed, false},
	} {
		if got := vpnAddressEligible(net.ParseIP(testCase.address), testCase.allowed); got != testCase.want {
			t.Fatalf("address=%s allowed=%v: got %v", testCase.address, testCase.allowed, got)
		}
	}
	links := func() ([]netlink.Link, error) {
		return []netlink.Link{
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tun0", Index: 1, Flags: net.FlagUp}},
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ipsec3", Index: 2, Flags: net.FlagUp}},
		}, nil
	}
	addresses := func(link netlink.Link, _ int) ([]netlink.Addr, error) {
		address := "10.8.0.2"
		if link.Attrs().Name == "ipsec3" {
			// e.g. a Wi-Fi calling tunnel, unrelated to the configured VPN
			address = "2001:db8::5"
		}
		return []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP(address)}}}, nil
	}
	noInterfaces := func() ([]net.Interface, error) { return nil, errors.New("unavailable") }
	got := findActiveVPNInterfaces(nil, allowed, links, addresses, noInterfaces, nil)
	if len(got) != 1 || got[0].name != "tun0" {
		t.Fatalf("filtered candidates: %v", got)
	}
	if got = findActiveVPNInterfaces(nil, nil, links, addresses, noInterfaces, nil); len(got) != 2 {
		t.Fatalf("unfiltered candidates: %v", got)
	}
}

func TestVPNPollDoesNotReconcile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	samples := 0
	runTCInterfaceUpdateLoopWithVPN(ctx, nil, 0, nil, func(context.Context) tcUpdateOutcome {
		t.Fatal("VPN poll rebuilt network state")
		return tcUpdateOutcome{}
	}, nil, time.Millisecond, func() bool {
		samples++
		if samples == 2 {
			cancel()
		}
		return true
	})
	if samples != 2 {
		t.Fatal(samples)
	}
}

func TestVPNPollStopsWithoutPendingCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan struct{}, 1)
	samples := make(chan int, 8)
	count := 0
	go runTCInterfaceUpdateLoopWithVPN(ctx, updates, 0, nil, func(context.Context) tcUpdateOutcome {
		return tcUpdateOutcome{}
	}, nil, time.Millisecond, func() bool {
		count++
		samples <- count
		return false
	})
	if <-samples != 1 {
		t.Fatal("initial readiness sample missing")
	}
	select {
	case sample := <-samples:
		t.Fatalf("idle readiness was polled: sample %d", sample)
	case <-time.After(50 * time.Millisecond):
	}
	updates <- struct{}{}
	select {
	case sample := <-samples:
		if sample != 2 {
			t.Fatal(sample)
		}
	case <-time.After(time.Second):
		t.Fatal("network event did not resample readiness")
	}
}

func TestVPNMonitorCloseJoinsBeforeLifecycleLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	i := &Inbound{interfaceMonitor: tcInterfaceMonitor{
		network: &testNetworkUpdateMonitor{}, cancel: cancel, done: done,
	}}
	i.udpNat = newUDPNATService(i, nil, time.Minute)
	go func() {
		<-ctx.Done()
		i.lifecycleAccess.Lock()
		i.lifecycleAccess.Unlock()
		close(done)
	}()
	closed := make(chan error, 1)
	go func() { closed <- i.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited for worker while holding lifecycle lock")
	}
	if i.vpnReady.Load() || i.vpnInterfacePackets != nil {
		t.Fatal("Close retained readiness")
	}
}
