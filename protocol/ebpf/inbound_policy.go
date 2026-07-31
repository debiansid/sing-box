//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
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
	updated, err := i.refreshBypassRuleSetsLocked(true)
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
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(false)
	if err != nil {
		backend := i.cgroupBackendInstance()
		if backend != nil && !backend.IsClosed() {
			i.logger.Error("refresh eBPF bypass_rule_set: ", err)
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(warnEmpty bool) (bool, error) {
	prefixes := i.localInterfacePrefixes()
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if warnEmpty && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		for _, ipSet := range ipSets {
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return false, E.New("eBPF backend is not initialized")
	}
	return backend.UpdateBypassCIDR(prefixes)
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
			prefix = prefix.Masked()
			address := prefix.Addr().Unmap()
			prefixBits := prefix.Bits()
			if prefix.Addr().Is4In6() {
				if prefixBits < 96 {
					continue
				}
				prefixBits -= 96
			}
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, prefixBits).Masked())
		}
	}
	return prefixes
}

func (i *Inbound) logBypassCIDRUpdate() {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	ipv4Count, ipv6Count := backend.BypassCIDRCount()
	i.logger.Debug("refreshed eBPF bypass CIDR policy: ipv4=", ipv4Count, ", ipv6=", ipv6Count)
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
	i.bypassRuleSetAccess.Lock()
	if i.bypassRuleSetStarted {
		updated, err := i.refreshBypassRuleSetsLocked(false)
		if err != nil {
			i.logger.Error("refresh eBPF local interface bypass: ", err)
		} else if updated {
			i.logBypassCIDRUpdate()
		}
	}
	i.bypassRuleSetAccess.Unlock()
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}
