//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
)

func isGlobalUnicastIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	return ip.IsGlobalUnicast()
}

func getInterfacePacketCount(interfaceName string) (rx uint64, tx uint64, err error) {
	rxData, err := os.ReadFile(filepath.Join("/sys/class/net", interfaceName, "statistics", "rx_packets"))
	if err != nil {
		return 0, 0, err
	}
	txData, err := os.ReadFile(filepath.Join("/sys/class/net", interfaceName, "statistics", "tx_packets"))
	if err != nil {
		return 0, 0, err
	}
	rx, _ = strconv.ParseUint(strings.TrimSpace(string(rxData)), 10, 64)
	tx, _ = strconv.ParseUint(strings.TrimSpace(string(txData)), 10, 64)
	return rx, tx, nil
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
			if attrs == nil || attrs.Flags&net.FlagUp == 0 {
				continue
			}
			if !isInterfaceExcluded(attrs.Name, excludeInterfaces) {
				continue
			}
			addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
			if err == nil {
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
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return activeInterfaces
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if !isInterfaceExcluded(iface.Name, excludeInterfaces) {
			continue
		}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
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
	}
	return activeInterfaces
}

func excludedInterfaceWithTraffic(interfaceNames []string) (string, bool) {
	for _, interfaceName := range interfaceNames {
		rx, tx, err := getInterfacePacketCount(interfaceName)
		if err == nil && (rx > 0 || tx > 1) {
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
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	i.cancelVPNWatchLocked()
	i.vpnBypassActive = false
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

func (i *Inbound) cancelVPNWatchLocked() {
	i.vpnWatchGeneration++
	if i.vpnWatchCancel != nil {
		i.vpnWatchCancel()
		i.vpnWatchCancel = nil
	}
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
	i.logger.Info("eBPF cgroup socket redirection bypassed: active VPN traffic confirmed on ", interfaceName)
	return nil
}

func (i *Inbound) watchExcludedInterfaces(ctx context.Context, generation uint64, interfaceNames []string) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			i.bypassRuleSetAccess.Lock()
			if i.vpnWatchGeneration == generation && i.vpnWatchCancel != nil {
				i.vpnWatchCancel = nil
				i.vpnWatchGeneration++
			}
			i.bypassRuleSetAccess.Unlock()
			return
		case <-ticker.C:
			interfaceName, active := excludedInterfaceWithTraffic(interfaceNames)
			if !active {
				continue
			}
			i.bypassRuleSetAccess.Lock()
			if i.vpnWatchGeneration != generation || i.vpnWatchCancel == nil {
				i.bypassRuleSetAccess.Unlock()
				return
			}
			err := i.enableVPNBypassLocked(interfaceName)
			i.bypassRuleSetAccess.Unlock()
			if err != nil {
				i.logger.Error("enable eBPF VPN bypass on ", interfaceName, ": ", err)
				continue
			}
			i.bypassRuleSetAccess.Lock()
			if i.vpnWatchGeneration == generation {
				i.vpnWatchCancel = nil
				i.vpnWatchGeneration++
			}
			i.bypassRuleSetAccess.Unlock()
			return
		}
	}
}

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
	i.bypassRuleSetAccess.Lock()

	var activeInterfaces []string
	if len(i.sharedNetworkOptions.ExcludeInterface) > 0 {
		activeInterfaces = findActiveExcludedInterfaceNames(i.sharedNetworkOptions.ExcludeInterface)
	}

	if len(activeInterfaces) > 0 {
		activeIface, trafficActive := excludedInterfaceWithTraffic(activeInterfaces)
		// If the interface is already receiving/sending packets (VPN tunnel established):
		if trafficActive {
			i.cancelVPNWatchLocked()
			if !i.vpnBypassActive {
				if err := i.enableVPNBypassLocked(activeIface); err != nil {
					i.logger.Error("enable eBPF VPN bypass on ", activeIface, ": ", err)
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
			return
		}

		// Fresh interface with rx_packets == 0 (Handshake in progress):
		// Keep proxying the handshake and poll rx_packets every 200ms until the first packet arrives.
		if !i.vpnBypassActive && i.vpnWatchCancel == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			i.vpnWatchGeneration++
			generation := i.vpnWatchGeneration
			i.vpnWatchCancel = cancel
			go i.watchExcludedInterfaces(ctx, generation, activeInterfaces)
		}
	} else {
		// VPN interface disconnected:
		i.cancelVPNWatchLocked()
		if i.vpnBypassActive {
			i.vpnBypassActive = false
			i.logger.Info("eBPF cgroup socket redirection resumed: VPN interface disconnected")
		}
		if i.bypassRuleSetStarted {
			updated, err := i.refreshBypassRuleSetsLocked(false, false)
			if err != nil {
				i.logger.Error("refresh eBPF local interface bypass: ", err)
			} else if updated {
				i.logBypassCIDRUpdate()
			}
		} else {
			if _, err := i.refreshBypassRuleSetsLocked(false, false); err != nil {
				i.logger.Error("restore eBPF bypass policy after VPN disconnect: ", err)
			}
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
