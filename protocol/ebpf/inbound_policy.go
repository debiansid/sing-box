//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	i.bypassRuleSetCallbacks = make([]*list.Element[adapter.RuleSetUpdateCallback], 0, len(i.bypassRuleSet))
	for _, ruleSet := range i.bypassRuleSet {
		ruleSet.IncRef()
		i.bypassRuleSetCallbacks = append(
			i.bypassRuleSetCallbacks,
			ruleSet.RegisterCallback(i.updateBypassRuleSet),
		)
	}
	i.bypassRuleSetStarted = true
	updated, err := i.refreshBypassRuleSetsLocked(true, true, true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
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
	i.bypassRuleSetCIDR = nil
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(true, false, true)
	if err != nil {
		i.logger.Error("refresh eBPF bypass_rule_set: ", err)
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(
	extractRuleSets bool,
	warnEmpty bool,
	logRuleSetCount bool,
) (bool, error) {
	if extractRuleSets {
		var ruleSetPrefixes []netip.Prefix
		for _, ruleSet := range i.bypassRuleSet {
			ipSets := ruleSet.ExtractIPSet()
			if warnEmpty && len(ipSets) == 0 {
				i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
			}
			var cidrCount int
			for _, ipSet := range ipSets {
				prefixes := ipSet.Prefixes()
				ruleSetPrefixes = append(ruleSetPrefixes, prefixes...)
				cidrCount += len(prefixes)
			}
			if logRuleSetCount {
				i.logger.Debug(
					"extracted eBPF bypass CIDRs from rule-set: tag=", ruleSet.Name(),
					", count=", cidrCount,
				)
			}
		}
		i.bypassRuleSetCIDR = ruleSetPrefixes
		if conflicts := i.fakeIPBypassConflictCount(ruleSetPrefixes); conflicts > 0 && logRuleSetCount {
			i.logger.Warn(
				"eBPF FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=",
				conflicts,
			)
		}
	}
	prefixes := slices.Clone(i.bypassRuleSetCIDR)
	backend := i.cgroupBackendInstance()
	if backend != nil {
		hostAddresses, hostBypassPrefixes := i.partitionLocalHostPrefixes(i.localInterfacePrefixes())
		prefixes = append(prefixes, hostBypassPrefixes...)
		if err := backend.UpdateHostAddresses(hostAddresses); err != nil {
			return false, err
		}
		policy, err := i.compileBypassCIDRPolicy(prefixes)
		if err != nil {
			return false, err
		}
		updateStarted := i.debug.bypassPolicyOperationStarted()
		updated, err := backend.UpdateCompiledBypassCIDR(policy)
		i.debug.observeBypassPolicyUpdate(updateStarted, err)
		if err != nil {
			return false, err
		}
		if i.sharedNetwork != nil {
			if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
				ipv4Count, ipv6Count := backend.BypassCIDRCount()
				if err = sharedBackend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
					return false, err
				}
			}
		}
		i.bypassCIDR = slices.Clone(prefixes)
		return updated, nil
	}
	if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
			policy, err := i.compileBypassCIDRPolicy(prefixes)
			if err != nil {
				return false, err
			}
			updateStarted := i.debug.bypassPolicyOperationStarted()
			updated, err := sharedBackend.UpdateCompiledBypassCIDR(policy)
			i.debug.observeBypassPolicyUpdate(updateStarted, err)
			if err != nil {
				return false, err
			}
			i.bypassCIDR = slices.Clone(prefixes)
			return updated, nil
		}
	}
	updated := !slices.Equal(i.bypassCIDR, prefixes)
	i.bypassCIDR = slices.Clone(prefixes)
	return updated, nil
}

func (i *Inbound) compileBypassCIDRPolicy(prefixes []netip.Prefix) (ECommon.BypassCIDRPolicy, error) {
	started := i.debug.bypassPolicyOperationStarted()
	policy, err := ECommon.CompileBypassCIDRPolicy(prefixes)
	i.debug.observeBypassPolicyCompile(started, len(prefixes), policy, err)
	if err != nil {
		return policy, E.Cause(err, "compile eBPF bypass CIDR policy")
	}
	return policy, nil
}

func (i *Inbound) partitionLocalHostPrefixes(prefixes []netip.Prefix) ([]netip.Addr, []netip.Prefix) {
	exactAddresses := make([]netip.Addr, 0, len(prefixes))
	bypassPrefixes := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if (prefix.Addr().Is4() && i.fakeIPIPv4Prefix.IsValid()) ||
			(prefix.Addr().Is6() && i.fakeIPIPv6Prefix.IsValid()) {
			exactAddresses = append(exactAddresses, prefix.Addr())
		} else {
			bypassPrefixes = append(bypassPrefixes, prefix)
		}
	}
	return exactAddresses, bypassPrefixes
}

func (i *Inbound) currentBypassCIDR() []netip.Prefix {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	return slices.Clone(i.bypassCIDR)
}

func (i *Inbound) localInterfacePrefixes() []netip.Prefix {
	return localInterfacePrefixes(i.networkManager.InterfaceFinder().Interfaces())
}

func localInterfacePrefixes(interfaces []control.Interface) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return prefixes
}

func (i *Inbound) logBypassCIDRUpdate() {
	var ipv4Count, ipv6Count int
	var countLoaded bool
	backend := i.cgroupBackendInstance()
	if backend != nil {
		ipv4Count, ipv6Count = backend.BypassCIDRCount()
		countLoaded = true
	} else if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
			ipv4Count, ipv6Count = sharedBackend.BypassCIDRCount()
			countLoaded = true
		}
	}
	if !countLoaded {
		for _, prefix := range i.bypassCIDR {
			if prefix.Addr().Is4() || prefix.Addr().Is4In6() {
				ipv4Count++
			} else {
				ipv6Count++
			}
		}
	}
	i.logger.Debug("refreshed eBPF bypass CIDR policy: ipv4=", ipv4Count, ", ipv6=", ipv6Count)
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
	i.bypassRuleSetAccess.Lock()
	if i.bypassRuleSetStarted {
		updated, err := i.refreshBypassRuleSetsLocked(false, false, false)
		if err != nil {
			i.logger.Error("refresh eBPF local interface bypass: ", err)
		} else if updated {
			i.logBypassCIDRUpdate()
		}
	}
	i.bypassRuleSetAccess.Unlock()
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if err := i.refreshCgroupIPv6Availability(false); err != nil {
		i.logger.Warn("refresh eBPF local cgroup IPv6 availability: ", err)
	}
	if i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}
