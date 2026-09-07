//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestBypassRuleSetPolicyRetryLatestWins(t *testing.T) {
	policyA := testBypassPolicy(t, "192.0.2.0/24")
	policyB := testBypassPolicy(t, "198.51.100.0/24")
	applyErr := errors.New("transient apply failure")
	var state bypassRuleSetPolicyState
	state.replace(policyA)
	if err := state.apply(func(commonEBPF.BypassCIDRPolicy) error { return applyErr }); !errors.Is(err, applyErr) {
		t.Fatalf("unexpected first apply error: %v", err)
	}
	state.replace(policyB)
	var applied []commonEBPF.BypassCIDRPolicy
	if err := state.apply(func(policy commonEBPF.BypassCIDRPolicy) error {
		applied = append(applied, policy)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || !reflect.DeepEqual(applied[0], policyB) {
		t.Fatalf("retry did not apply only the latest desired policy: %+v", applied)
	}
}

func TestBypassRuleSetPolicyTransientFailureRetry(t *testing.T) {
	policy := testBypassPolicy(t, "192.0.2.0/24")
	applyErr := errors.New("transient apply failure")
	var state bypassRuleSetPolicyState
	state.replace(policy)
	if err := state.apply(func(commonEBPF.BypassCIDRPolicy) error { return applyErr }); !errors.Is(err, applyErr) {
		t.Fatalf("unexpected first apply error: %v", err)
	}
	if !state.dirty {
		t.Fatal("failed desired policy was not retained for a network retry opportunity")
	}
	if err := state.apply(func(applied commonEBPF.BypassCIDRPolicy) error {
		if !reflect.DeepEqual(applied, policy) {
			t.Fatalf("retry changed the desired policy: %+v", applied)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if state.dirty {
		t.Fatal("successful retry did not clear dirty state")
	}
}

func TestBypassRuleSetPolicyRetryNoopWhenClean(t *testing.T) {
	var state bypassRuleSetPolicyState
	state.replace(testBypassPolicy(t, "192.0.2.0/24"))
	applyCount := 0
	apply := func(commonEBPF.BypassCIDRPolicy) error {
		applyCount++
		return nil
	}
	if err := state.apply(apply); err != nil {
		t.Fatal(err)
	}
	if err := state.apply(apply); err != nil {
		t.Fatal(err)
	}
	if applyCount != 1 {
		t.Fatalf("clean policy was mutated by duplicate network retry opportunities: %d applies", applyCount)
	}
}

func TestBypassRuleSetPolicyLifecycleReset(t *testing.T) {
	oldPolicy := testBypassPolicy(t, "192.0.2.0/24")
	currentPolicy := testBypassPolicy(t, "203.0.113.0/24")
	var state bypassRuleSetPolicyState
	state.replace(oldPolicy)
	_ = state.apply(func(commonEBPF.BypassCIDRPolicy) error { return errors.New("pending") })
	inbound := &Inbound{bypassRuleSetPolicy: state}
	inbound.stopBypassRuleSetsLocked()
	state = inbound.bypassRuleSetPolicy
	applyCount := 0
	if err := state.apply(func(commonEBPF.BypassCIDRPolicy) error {
		applyCount++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	state.replace(currentPolicy)
	if err := state.apply(func(policy commonEBPF.BypassCIDRPolicy) error {
		applyCount++
		if !reflect.DeepEqual(policy, currentPolicy) {
			t.Fatalf("restart did not derive current rule-set policy: %+v", policy)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if applyCount != 1 {
		t.Fatalf("old pending state survived lifecycle reset: %d applies", applyCount)
	}
}

func testBypassPolicy(t *testing.T, prefix string) commonEBPF.BypassCIDRPolicy {
	t.Helper()
	policy, err := commonEBPF.CompileBypassCIDRPolicy([]netip.Prefix{netip.MustParsePrefix(prefix)})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
