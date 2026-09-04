//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestTCProgramRunIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run unified TC eBPF programs in the kernel")
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:           true,
		SharedDNSMode:       DNSModeRespectPolicy,
		SharedBypassPrivate: true,
		FakeIPIPv4:          netip.MustParsePrefix("198.18.0.0/15"),
		IncludeSourceMAC:    []MACAddress{{0x02, 0, 0, 0, 0, 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65531,
		EnableShared: true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]

	selected := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), 53000, 443,
	)
	action, _ := runTCProgram(t, sharedIngress, selected)
	if action != testTCActShot {
		t.Fatalf("selected flow did not reach socket assignment: action=%d", action)
	}

	unselectedMAC := append([]byte(nil), selected...)
	unselectedMAC[11] = 2
	action, _ = runTCProgram(t, sharedIngress, unselectedMAC)
	if action != testTCActUnspec {
		t.Fatalf("unselected source MAC was intercepted: action=%d", action)
	}

	private := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.168.1.1"), 53001, 443,
	)
	action, _ = runTCProgram(t, sharedIngress, private)
	if action != testTCActUnspec {
		t.Fatalf("private destination was intercepted: action=%d", action)
	}

	fakeIP := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.1.1"), 53002, 443,
	)
	fakeIP[11] = 2
	action, _ = runTCProgram(t, sharedIngress, fakeIP)
	if action != testTCActShot {
		t.Fatalf("FakeIP did not override source and private bypass: action=%d", action)
	}

	bypassPolicy, err := CompileBypassCIDRPolicy([]netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = backend.UpdateCompiledBypassCIDR(bypassPolicy); err != nil {
		t.Fatal(err)
	}
	bypassedHTTPS := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("1.1.1.1"), 53003, 443,
	)
	action, _ = runTCProgram(t, sharedIngress, bypassedHTTPS)
	if action != testTCActUnspec {
		t.Fatalf("destination bypass policy did not bypass HTTPS: action=%d", action)
	}
	respectedDNS := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("1.1.1.1"), 53004, 53,
	)
	action, _ = runTCProgram(t, sharedIngress, respectedDNS)
	if action != testTCActShot {
		t.Fatalf("respect_policy DNS did not override destination bypass: action=%d", action)
	}

}

func TestTCEndpointTriStateIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC endpoint tri-state policy")
	endpoint := netip.MustParsePrefix("203.0.113.0/24")
	endpointIPv6 := netip.MustParsePrefix("2001:db8:1::/48")
	fakeIP := netip.MustParsePrefix("198.18.0.0/15")
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:       true,
		EnableUDP:       true,
		EndpointEnabled: true,
		EndpointCIDR:    []netip.Prefix{endpoint, endpointIPv6, fakeIP},
		EndpointPort:    []PortRange{{Start: 4500, End: 4500}},
		LocalBypassPort: []PortRange{{Start: 4500, End: 4500}},
		FakeIPIPv4:      fakeIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort:      65531,
		EnableLocal:       true,
		EnableShared:      true,
		EnableIPv4:        true,
		EnableLocalIPv6:   true,
		EnableTCP:         true,
		EnableUDP:         true,
		DeliveryInterface: 1,
		Policy:            policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	localEgress := backend.runtime.programs[tcProgramLocalEgressEthernet]
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]
	matching := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), 53000, 4500,
	)
	action, _ := runTCProgram(t, localEgress, matching)
	if action != testTCActRedirect {
		t.Fatalf("NOT READY endpoint did not force interception over local bypass port: action=%d", action)
	}
	matchingUDP := testIPv4UDPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), 53001, 4500,
	)
	action, _ = runTCProgram(t, localEgress, matchingUDP)
	if action != testTCActRedirect {
		t.Fatalf("NOT READY UDP endpoint did not force interception: action=%d", action)
	}
	matchingIPv6 := testIPv6TCPPacket(
		netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8:1::10"), 53002, 4500, nil,
	)
	action, _ = runTCProgram(t, localEgress, matchingIPv6)
	if action != testTCActRedirect {
		t.Fatalf("NOT READY IPv6 endpoint did not force interception: action=%d", action)
	}
	wrongPort := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), 53003, 443,
	)
	bypassPolicy, err := CompileBypassCIDRPolicy([]netip.Prefix{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = backend.UpdateCompiledBypassCIDR(bypassPolicy); err != nil {
		t.Fatal(err)
	}
	action, _ = runTCProgram(t, localEgress, wrongPort)
	if action != testTCActUnspec {
		t.Fatalf("wrong endpoint port did not continue original CIDR policy: action=%d", action)
	}
	wrongIP := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.10"), 53004, 4500,
	)
	action, _ = runTCProgram(t, localEgress, wrongIP)
	if action != testTCActUnspec {
		t.Fatalf("wrong endpoint IP did not continue original port policy: action=%d", action)
	}
	if err = backend.SetEndpointVPNReady(true); err != nil {
		t.Fatal(err)
	}
	action, _ = runTCProgram(t, localEgress, matching)
	if action != testTCActUnspec {
		t.Fatalf("READY endpoint did not native-bypass: action=%d", action)
	}
	for name, packet := range map[string][]byte{"UDP": matchingUDP, "IPv6": matchingIPv6} {
		action, _ = runTCProgram(t, localEgress, packet)
		if action != testTCActUnspec {
			t.Fatalf("READY %s endpoint did not native-bypass: action=%d", name, action)
		}
	}
	fakeEndpoint := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.18.1.1"), 53005, 4500,
	)
	action, _ = runTCProgram(t, localEgress, fakeEndpoint)
	if action != testTCActRedirect {
		t.Fatalf("FakeIP did not override READY endpoint bypass: action=%d", action)
	}
	action, _ = runTCProgram(t, sharedIngress, matching)
	if action != testTCActShot {
		t.Fatalf("endpoint policy changed shared selection: action=%d", action)
	}
}

func TestTCIPv6PathIsolationIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC eBPF IPv6 path isolation")
	packet := testIPv6TCPPacket(
		netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:4860:4860::8888"), 53000, 443, nil,
	)
	for _, testCase := range []struct {
		name       string
		config     TCConfig
		program    int
		wantAction uint32
	}{
		{
			"shared IPv6 disabled on shared program",
			TCConfig{EnableLocal: true, EnableIPv4: true, EnableLocalIPv6: true, EnableTCP: true},
			tcProgramSharedIngressEthernet,
			testTCActUnspec,
		},
		{
			"shared enabled on shared program",
			TCConfig{EnableShared: true, EnableIPv4: true, EnableSharedIPv6: true, EnableTCP: true},
			tcProgramSharedIngressEthernet,
			testTCActShot,
		},
		{
			"local enabled on delivery program",
			TCConfig{EnableLocal: true, EnableIPv4: true, EnableLocalIPv6: true, EnableTCP: true},
			tcProgramDeliveryIngress,
			testTCActShot,
		},
		{
			"local IPv6 disabled on delivery program",
			TCConfig{EnableShared: true, EnableIPv4: true, EnableSharedIPv6: true, EnableTCP: true},
			tcProgramDeliveryIngress,
			testTCActUnspec,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.config.ListenerPort = 65531
			backend, err := PrepareTC(testCase.config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			if err = backend.Enable(); err != nil {
				t.Fatal(err)
			}
			action, _ := runTCProgram(t, backend.runtime.programs[testCase.program], packet)
			if action != testCase.wantAction {
				t.Fatalf("unexpected action: %d != %d", action, testCase.wantAction)
			}
		})
	}
}

func TestTCFragmentPolicyIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify TC eBPF fragment policy")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:     65531,
		EnableShared:     true,
		EnableIPv4:       true,
		EnableSharedIPv6: true,
		EnableTCP:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]

	ipv4First := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.10"), 53000, 443,
	)
	binary.BigEndian.PutUint16(ipv4First[20:22], 0x2000)
	ipv4Later := append([]byte(nil), ipv4First...)
	binary.BigEndian.PutUint16(ipv4Later[20:22], 1)
	for name, packet := range map[string][]byte{
		"IPv4 first fragment": ipv4First,
		"IPv4 later fragment": ipv4Later,
	} {
		t.Run(name, func(t *testing.T) {
			action, _ := runTCProgram(t, sharedIngress, packet)
			if action != testTCActUnspec {
				t.Fatalf("fragment was intercepted: action=%d", action)
			}
		})
	}

	moreFragments := uint16(1)
	laterFragment := uint16(8)
	atomicFragment := uint16(0)
	for _, testCase := range []struct {
		name       string
		fragment   *uint16
		wantAction uint32
	}{
		{"IPv6 first fragment", &moreFragments, testTCActUnspec},
		{"IPv6 later fragment", &laterFragment, testTCActUnspec},
		{"IPv6 atomic fragment", &atomicFragment, testTCActShot},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			packet := testIPv6TCPPacket(
				netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:4860:4860::8888"),
				53000, 443, testCase.fragment,
			)
			action, _ := runTCProgram(t, sharedIngress, packet)
			if action != testCase.wantAction {
				t.Fatalf("unexpected action: %d != %d", action, testCase.wantAction)
			}
		})
	}
}
