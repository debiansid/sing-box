//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"golang.org/x/sys/unix"
)

func isGlobalUnicastIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	return ip.IsGlobalUnicast()
}

func findActiveExcludedInterfaceNames(excludeInterfaces []string) []string {
	if len(excludeInterfaces) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var activeInterfaces []string
	links, err := netlink.LinkList()
	if err == nil && len(links) > 0 {
		for _, link := range links {
			attrs := link.Attrs()
			if attrs == nil || attrs.Flags&net.FlagUp == 0 || !isInterfaceExcluded(attrs.Name, excludeInterfaces) {
				continue
			}
			addrs, addrErr := netlink.AddrList(link, netlink.FAMILY_ALL)
			if addrErr != nil {
				continue
			}
			for _, addr := range addrs {
				if addr.IP != nil && isGlobalUnicastIP(addr.IP) {
					if _, loaded := seen[attrs.Name]; !loaded {
						seen[attrs.Name] = struct{}{}
						activeInterfaces = append(activeInterfaces, attrs.Name)
					}
					break
				}
			}
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return activeInterfaces
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || !isInterfaceExcluded(iface.Name, excludeInterfaces) {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && isGlobalUnicastIP(ip) {
				if _, loaded := seen[iface.Name]; !loaded {
					seen[iface.Name] = struct{}{}
					activeInterfaces = append(activeInterfaces, iface.Name)
				}
				break
			}
		}
	}
	return activeInterfaces
}

func isDefaultRoute(route netlink.Route) bool {
	if route.Table == unix.RT_TABLE_LOCAL || route.Type != unix.RTN_UNICAST {
		return false
	}
	if route.Dst == nil {
		return true
	}
	ones, bits := route.Dst.Mask.Size()
	return ones == 0 && (bits == net.IPv4len*8 || bits == net.IPv6len*8)
}

func interfaceHasDefaultRoute(interfaceName string) bool {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil || link.Attrs() == nil {
		return false
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, routeErr := netlink.RouteListFiltered(
			family,
			&netlink.Route{LinkIndex: link.Attrs().Index, Table: unix.RT_TABLE_UNSPEC},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE,
		)
		if routeErr != nil {
			continue
		}
		for _, route := range routes {
			if isDefaultRoute(route) {
				return true
			}
		}
	}
	return false
}

func excludedInterfaceWithDefaultRoute(interfaceNames []string) (string, bool) {
	for _, interfaceName := range interfaceNames {
		if interfaceHasDefaultRoute(interfaceName) {
			return interfaceName, true
		}
	}
	return "", false
}

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
	updated, err := i.refreshBypassRuleSetsLocked(true, true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
	i.startVPNWatchLocked()
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	done := i.stopBypassRuleSetsLocked()
	i.bypassRuleSetAccess.Unlock()
	if done != nil {
		<-done
	}
}

func (i *Inbound) stopBypassRuleSetsLocked() <-chan struct{} {
	done := i.cancelVPNWatchLocked()
	i.vpnBypassActive = false
	if !i.bypassRuleSetStarted {
		return done
	}
	for ruleSetIndex, ruleSet := range i.bypassRuleSet {
		if ruleSetIndex < len(i.bypassRuleSetCallbacks) {
			ruleSet.UnregisterCallback(i.bypassRuleSetCallbacks[ruleSetIndex])
		}
		ruleSet.DecRef()
	}
	i.bypassRuleSetCallbacks = nil
	i.bypassRuleSetStarted = false
	return done
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(false, true)
	if err != nil {
		i.logger.Error("refresh eBPF bypass_rule_set: ", err)
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) refreshBypassRuleSetsLocked(warnEmpty bool, logRuleSetCount bool) (bool, error) {
	var prefixes []netip.Prefix
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if warnEmpty && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		var cidrCount int
		for _, ipSet := range ipSets {
			ruleSetPrefixes := ipSet.Prefixes()
			prefixes = append(prefixes, ruleSetPrefixes...)
			cidrCount += len(ruleSetPrefixes)
		}
		if logRuleSetCount {
			i.logger.Debug(
				"extracted eBPF bypass CIDRs from rule-set: tag=", ruleSet.Name(),
				", count=", cidrCount,
			)
		}
	}
	if conflicts := i.fakeIPBypassConflictCount(prefixes); conflicts > 0 && logRuleSetCount {
		i.logger.Warn(
			"eBPF FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=",
			conflicts,
		)
	}
	if i.vpnBypassActive {
		prefixes = slices.Clone(fullBypassPrefixes)
	}
	backend := i.cgroupBackendInstance()
	if backend != nil {
		hostAddresses, hostBypassPrefixes := i.partitionLocalHostPrefixes(i.localInterfacePrefixes())
		prefixes = append(prefixes, hostBypassPrefixes...)
		if err := backend.UpdateHostAddresses(hostAddresses); err != nil {
			return false, err
		}
		updated, err := backend.UpdateBypassCIDR(prefixes)
		if err != nil {
			return false, err
		}
		if i.sharedNetwork != nil {
			if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
				if err = sharedBackend.SetBypassCIDRState(prefixes); err != nil {
					return false, err
				}
			}
		}
		i.bypassCIDR = slices.Clone(prefixes)
		return updated, nil
	}
	if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
			updated, err := sharedBackend.UpdateBypassCIDR(prefixes)
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

var fullBypassPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

const vpnInterfaceWatchInterval = time.Second

func (i *Inbound) startVPNWatchLocked() {
	if len(i.excludeInterface) == 0 || i.vpnWatchCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	i.vpnWatchCancel = cancel
	i.vpnWatchDone = done
	go i.watchExcludedInterfaces(ctx, slices.Clone(i.excludeInterface), done)
}

func (i *Inbound) cancelVPNWatchLocked() <-chan struct{} {
	if i.vpnWatchCancel != nil {
		i.vpnWatchCancel()
	}
	done := i.vpnWatchDone
	i.vpnWatchCancel = nil
	i.vpnWatchDone = nil
	return done
}

func (i *Inbound) enableVPNBypassLocked(interfaceName string) error {
	if i.vpnBypassActive {
		return nil
	}
	i.vpnBypassActive = true
	if _, err := i.refreshBypassRuleSetsLocked(false, false); err != nil {
		i.vpnBypassActive = false
		return err
	}
	i.logger.Info("eBPF cgroup socket redirection bypassed: excluded interface has a default route: ", interfaceName)
	return nil
}

func (i *Inbound) disableVPNBypassLocked() error {
	if !i.vpnBypassActive {
		return nil
	}
	i.vpnBypassActive = false
	updated, err := i.refreshBypassRuleSetsLocked(false, false)
	if err != nil {
		i.vpnBypassActive = true
		return err
	}
	i.logger.Info("eBPF cgroup socket redirection resumed: excluded VPN interface disconnected")
	if updated {
		i.logBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) syncVPNBypassState(excludeInterfaces []string) {
	interfaceNames := findActiveExcludedInterfaceNames(excludeInterfaces)
	interfaceName, active := excludedInterfaceWithDefaultRoute(interfaceNames)

	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	var err error
	if active {
		err = i.enableVPNBypassLocked(interfaceName)
	} else {
		err = i.disableVPNBypassLocked()
	}
	if err != nil {
		i.logger.Error("synchronize eBPF VPN bypass state: ", err)
	}
}

func (i *Inbound) refreshBypassPolicy() {
	i.bypassRuleSetAccess.Lock()
	updated, err := i.refreshBypassRuleSetsLocked(false, false)
	i.bypassRuleSetAccess.Unlock()
	if err != nil {
		i.logger.Error("refresh eBPF local interface bypass: ", err)
	} else if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) watchExcludedInterfaces(ctx context.Context, excludeInterfaces []string, done chan<- struct{}) {
	defer close(done)
	i.syncVPNBypassState(excludeInterfaces)
	ticker := time.NewTicker(vpnInterfaceWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i.syncVPNBypassState(excludeInterfaces)
		}
	}
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
	if len(i.excludeInterface) > 0 {
		i.syncVPNBypassState(i.excludeInterface)
	}
	i.refreshBypassPolicy()
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if err := i.refreshCgroupIPv6Availability(false); err != nil {
		i.logger.Warn("refresh eBPF local cgroup IPv6 availability: ", err)
	}
	if i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}
