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
	if ip4 := ip.To4(); ip4 != nil {
		return true
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

func findActiveExcludedInterfaceName(excludeInterfaces []string) (string, bool) {
	if len(excludeInterfaces) == 0 {
		return "", false
	}
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
						return attrs.Name, true
					}
				}
			}
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", false
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
					return iface.Name, true
				}
			}
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
	if i.vpnWatchCancel != nil {
		i.vpnWatchCancel()
		i.vpnWatchCancel = nil
	}
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

func (i *Inbound) InterfaceUpdated() {
	i.udpNat.Purge()
	i.bypassRuleSetAccess.Lock()

	var activeIface string
	var excludedActive bool
	if len(i.sharedNetworkOptions.ExcludeInterface) > 0 {
		activeIface, excludedActive = findActiveExcludedInterfaceName(i.sharedNetworkOptions.ExcludeInterface)
	}

	if excludedActive {
		rx, tx, _ := getInterfacePacketCount(activeIface)
		// If the interface already received packets from remote VPN server:
		if rx > 0 || tx > 1 {
			if i.vpnWatchCancel != nil {
				i.vpnWatchCancel()
				i.vpnWatchCancel = nil
			}
			if !i.vpnBypassActive {
				if backend := i.cgroupBackendInstance(); backend != nil {
					_, _ = backend.UpdateBypassCIDR(fullBypassPrefixes)
					i.logger.Info("eBPF cgroup socket redirection bypassed: active VPN traffic confirmed on ", activeIface)
				}
				if i.sharedNetwork != nil {
					if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
						_ = sharedBackend.SetBypassCIDRState(fullBypassPrefixes)
					}
				}
				i.vpnBypassActive = true
			}
		} else {
			// Fresh interface with rx == 0 (Handshake in progress):
			// Keep eBPF proxying the handshake and poll rx_packets every 200ms.
			if !i.vpnBypassActive && i.vpnWatchCancel == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				i.vpnWatchCancel = cancel
				go func(iface string) {
					ticker := time.NewTicker(200 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							r, t, err := getInterfacePacketCount(iface)
							if err == nil && (r > 0 || t > 1) {
								i.bypassRuleSetAccess.Lock()
								if i.vpnWatchCancel != nil {
									i.vpnWatchCancel = nil
									if backend := i.cgroupBackendInstance(); backend != nil {
										_, _ = backend.UpdateBypassCIDR(fullBypassPrefixes)
										i.logger.Info("eBPF cgroup socket redirection bypassed: VPN tunnel established on ", iface)
									}
									if i.sharedNetwork != nil {
										if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
											_ = sharedBackend.SetBypassCIDRState(fullBypassPrefixes)
										}
									}
									i.vpnBypassActive = true
								}
								i.bypassRuleSetAccess.Unlock()
								return
							}
						}
					}
				}(activeIface)
			}
		}
	} else {
		// VPN interface disconnected:
		if i.vpnWatchCancel != nil {
			i.vpnWatchCancel()
			i.vpnWatchCancel = nil
		}
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
			_, _ = i.refreshBypassRuleSetsLocked(false, false)
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
