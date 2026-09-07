//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

type bypassRuleSetPolicyState struct {
	desired commonEBPF.BypassCIDRPolicy
	dirty   bool
}

func (s *bypassRuleSetPolicyState) replace(policy commonEBPF.BypassCIDRPolicy) {
	s.desired = policy
	s.dirty = true
}

func (s *bypassRuleSetPolicyState) apply(update func(commonEBPF.BypassCIDRPolicy) error) error {
	if !s.dirty {
		return nil
	}
	if err := update(s.desired); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

func (s *bypassRuleSetPolicyState) reset() {
	s.desired = commonEBPF.BypassCIDRPolicy{}
	s.dirty = false
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	i.bypassRuleSetPolicy.reset()
	i.bypassRuleSetCallbacks = make([]*list.Element[adapter.RuleSetUpdateCallback], 0, len(i.bypassRuleSet))
	for _, ruleSet := range i.bypassRuleSet {
		ruleSet.IncRef()
		i.bypassRuleSetCallbacks = append(i.bypassRuleSetCallbacks, ruleSet.RegisterCallback(i.updateBypassRuleSet))
	}
	i.bypassRuleSetStarted = true
	err := i.refreshBypassRuleSetsLocked(true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	i.bypassRuleSetPolicy.reset()
	if !i.bypassRuleSetStarted {
		return
	}
	for ruleSetIndex, ruleSet := range i.bypassRuleSet {
		if ruleSetIndex < len(i.bypassRuleSetCallbacks) {
			ruleSet.UnregisterCallback(i.bypassRuleSetCallbacks[ruleSetIndex])
		}
		ruleSet.DecRef()
	}
	i.bypassRuleSetCallbacks = nil
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	err := i.refreshBypassRuleSetsLocked(false)
	if err != nil {
		i.policyWarnings.warn(i.logger, "refresh TC eBPF bypass_rule_set: ", err)
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(startup bool) error {
	var prefixes []netip.Prefix
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if startup && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		for _, ipSet := range ipSets {
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	if conflicts := i.fakeIPBypassConflictCount(prefixes); conflicts > 0 {
		if startup {
			i.logger.Warn("eBPF FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=", conflicts)
		} else {
			i.policyWarnings.warn(i.logger, "eBPF FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=", conflicts)
		}
	}
	policy, err := i.compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return err
	}
	i.bypassRuleSetPolicy.replace(policy)
	return i.applyBypassRuleSetPolicyLocked()
}

func (i *Inbound) retryBypassRuleSetPolicy() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return nil
	}
	return i.applyBypassRuleSetPolicyLocked()
}

func (i *Inbound) applyBypassRuleSetPolicyLocked() error {
	backend := i.tcBackend()
	if backend == nil {
		return nil
	}
	return i.bypassRuleSetPolicy.apply(func(policy commonEBPF.BypassCIDRPolicy) error {
		_, err := backend.UpdateCompiledBypassCIDR(policy)
		return err
	})
}

func (i *Inbound) compileBypassCIDRPolicy(prefixes []netip.Prefix) (commonEBPF.BypassCIDRPolicy, error) {
	policy, err := commonEBPF.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return policy, E.Cause(err, "compile TC eBPF bypass CIDR policy")
	}
	return policy, nil
}
