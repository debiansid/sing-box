//go:build with_ebpf && (linux || android)

package ebpf

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
)

func TestAndroidEgressGuardRulesPerUserAndSelf(t *testing.T) {
	appUIDs := []uidRange{{Start: 10000, End: 99999}, {Start: 1010000, End: 1099999}}
	excludeMode := &Inbound{localPolicy: localUIDPolicy{ExcludeUID: []uidRange{{Start: 10123, End: 10123}}}}
	rules := excludeMode.androidEgressGuardRules("guard", "wlan0", nil, appUIDs)
	self := strconv.Itoa(os.Getuid())
	for _, want := range []string{
		"-A guard -m owner --uid-owner " + self + "-" + self + " -j RETURN",
		"-A guard -m owner --uid-owner 10123-10123 -j RETURN",
		"-A guard -m owner --uid-owner 10000-99999 -j REJECT",
		"-A guard -m owner --uid-owner 1010000-1099999 -j REJECT",
	} {
		if !strings.Contains(rules, want+"\n") {
			t.Fatalf("missing %q in:\n%s", want, rules)
		}
	}
	// System app IDs of a secondary user must stay unguarded.
	if strings.Contains(rules, "2147483647") || strings.Contains(rules, "1001000") {
		t.Fatalf("guard covers non-application UIDs:\n%s", rules)
	}

	includeMode := &Inbound{localPolicy: localUIDPolicy{
		IncludeUIDConfigured: true,
		IncludeUID:           []uidRange{{Start: 0, End: 1050000}},
	}}
	rules = includeMode.androidEgressGuardRules("guard", "wlan0", nil, appUIDs)
	for _, want := range []string{"10000-99999 -j REJECT", "1010000-1050000 -j REJECT"} {
		if !strings.Contains(rules, want+"\n") {
			t.Fatalf("missing %q in:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "0-9999 -j REJECT") {
		t.Fatalf("include mode rejects system UIDs:\n%s", rules)
	}
}

func TestAndroidEgressGuardChainPerInbound(t *testing.T) {
	first := &Inbound{Adapter: inbound.NewAdapter(C.TypeEBPF, "ebpf-a")}
	second := &Inbound{Adapter: inbound.NewAdapter(C.TypeEBPF, "ebpf-b")}
	if first.androidEgressGuardChain() == second.androidEgressGuardChain() {
		t.Fatal("inbounds share an egress guard chain")
	}
	if first.androidEgressGuardChain() != (&Inbound{Adapter: inbound.NewAdapter(C.TypeEBPF, "ebpf-a")}).androidEgressGuardChain() {
		t.Fatal("chain name is not stable across restarts")
	}
	// iptables chain names are limited to 28 characters.
	if name := first.androidEgressGuardChain(); len(name) > 28 {
		t.Fatalf("chain name %q too long", name)
	}
}
