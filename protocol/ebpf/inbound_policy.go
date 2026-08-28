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
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

type interfacePacketCount struct {
	rx uint64
	tx uint64
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

func packetCountIncreased(previous, current interfacePacketCount) bool {
	return current.rx > previous.rx || current.tx > previous.tx
}

func isGlobalUnicastIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && ip.IsGlobalUnicast()
}

func findActiveExcludedInterfaceNames(excludeInterfaces []string) []string {
	if len(excludeInterfaces) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var activeInterfaces []string
	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			attributes := link.Attrs()
			if attributes == nil || attributes.Flags&net.FlagUp == 0 ||
				!isInterfaceExcluded(attributes.Name, excludeInterfaces) {
				continue
			}
			addresses, addressErr := netlink.AddrList(link, netlink.FAMILY_ALL)
			if addressErr != nil {
				continue
			}
			for _, address := range addresses {
				if isGlobalUnicastIP(address.IP) {
					seen[attributes.Name] = struct{}{}
					activeInterfaces = append(activeInterfaces, attributes.Name)
					break
				}
			}
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return activeInterfaces
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 ||
			!isInterfaceExcluded(networkInterface.Name, excludeInterfaces) {
			continue
		}
		if _, loaded := seen[networkInterface.Name]; loaded {
			continue
		}
		addresses, addressErr := networkInterface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if isGlobalUnicastIP(ip) {
				activeInterfaces = append(activeInterfaces, networkInterface.Name)
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
		if routeErr == nil && slices.ContainsFunc(routes, isDefaultRoute) {
			return true
		}
	}
	return false
}

func excludedInterfaceWithTraffic(interfaceNames []string, baseline map[string]interfacePacketCount) (string, bool) {
	for _, interfaceName := range interfaceNames {
		rx, tx, err := getInterfacePacketCount(interfaceName)
		if err != nil {
			continue
		}
		current := interfacePacketCount{rx: rx, tx: tx}
		previous, loaded := baseline[interfaceName]
		baseline[interfaceName] = current
		if loaded && packetCountIncreased(previous, current) {
			return interfaceName, true
		}
	}
	return "", false
}

func excludedInterfaceReady(interfaceNames []string, baseline map[string]interfacePacketCount) (string, bool) {
	var trafficInterfaces []string
	for _, interfaceName := range interfaceNames {
		if strings.HasPrefix(interfaceName, "ipsec") {
			if interfaceHasDefaultRoute(interfaceName) {
				return interfaceName, true
			}
		} else {
			trafficInterfaces = append(trafficInterfaces, interfaceName)
		}
	}
	return excludedInterfaceWithTraffic(trafficInterfaces, baseline)
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
	updated, err := i.refreshBypassRuleSetsLocked(true, true, true)
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
	i.vpnInterfacePackets = nil
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
	i.bypassRuleSetPolicy = ECommon.BypassCIDRPolicy{}
	i.bypassRuleSetDirty = false
	i.bypassRuleSetStarted = false
	return done
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassRuleSetsLocked(true, false, true)
	if err != nil {
		i.policyWarnings.warn(i.logger, "refresh eBPF bypass_rule_set; keeping previous policy: ", err)
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
	basePolicy := i.bypassRuleSetPolicy
	if extractRuleSets {
		var ruleSetPrefixes []netip.Prefix
		for _, ruleSet := range i.bypassRuleSet {
			ipSets := ruleSet.ExtractIPSet()
			if warnEmpty && len(ipSets) == 0 {
				i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
			}
			for _, ipSet := range ipSets {
				prefixes := ipSet.Prefixes()
				ruleSetPrefixes = append(ruleSetPrefixes, prefixes...)
			}
		}
		if logRuleSetCount {
			i.logger.Debug(
				"extracted eBPF bypass CIDRs: rule_sets=", len(i.bypassRuleSet),
				", raw_prefixes=", len(ruleSetPrefixes),
			)
		}
		if conflicts := i.fakeIPBypassConflictCount(ruleSetPrefixes); conflicts > 0 && logRuleSetCount {
			i.logger.Warn(
				"eBPF FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=",
				conflicts,
			)
		}
		var err error
		policy, err := i.compileBypassCIDRPolicy(ruleSetPrefixes)
		if err != nil {
			return false, err
		}
		i.bypassRuleSetPolicy = policy
		basePolicy = policy
		i.bypassRuleSetDirty = true
	}
	updatePolicy := i.bypassRuleSetDirty
	cgroupPolicy, sharedPolicy := effectiveBypassPolicies(
		basePolicy,
		i.vpnBypassPolicy,
		i.vpnBypassActive,
	)
	backend := i.cgroupBackendInstance()
	if backend != nil {
		if err := backend.UpdateHostAddresses(i.localInterfaceAddresses()); err != nil {
			return false, err
		}
		if !updatePolicy {
			return false, nil
		}
		updated, err := backend.UpdateCompiledBypassCIDR(cgroupPolicy)
		if err != nil {
			return false, err
		}
		i.bypassRuleSetDirty = false
		if i.sharedNetwork != nil {
			if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
				var sharedUpdated bool
				if sharedBackend.IndependentBypassCIDR() {
					sharedUpdated, err = sharedBackend.UpdateCompiledBypassCIDR(sharedPolicy)
				} else {
					ipv4Count, ipv6Count := backend.BypassCIDRCount()
					err = sharedBackend.SetBypassCIDRState(ipv4Count, ipv6Count)
				}
				if err != nil {
					return false, err
				}
				updated = updated || sharedUpdated
			}
		}
		return updated, nil
	}
	if i.sharedNetwork != nil {
		if sharedBackend := i.sharedNetwork.sharedBackendInstance(); sharedBackend != nil {
			if !updatePolicy {
				return false, nil
			}
			updated, err := sharedBackend.UpdateCompiledBypassCIDR(sharedPolicy)
			if err != nil {
				return false, err
			}
			i.bypassRuleSetDirty = false
			return updated, nil
		}
	}
	return updatePolicy, nil
}

func effectiveBypassPolicies(
	basePolicy ECommon.BypassCIDRPolicy,
	vpnPolicy ECommon.BypassCIDRPolicy,
	vpnActive bool,
) (cgroupPolicy ECommon.BypassCIDRPolicy, sharedPolicy ECommon.BypassCIDRPolicy) {
	cgroupPolicy = basePolicy
	if vpnActive {
		cgroupPolicy = vpnPolicy
	}
	return cgroupPolicy, basePolicy
}

func (i *Inbound) compileBypassCIDRPolicy(prefixes []netip.Prefix) (ECommon.BypassCIDRPolicy, error) {
	policy, err := ECommon.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return policy, E.Cause(err, "compile eBPF bypass CIDR policy")
	}
	return policy, nil
}

func (i *Inbound) localInterfaceAddresses() []netip.Addr {
	prefixes := localInterfacePrefixes(i.networkManager.InterfaceFinder().Interfaces())
	addresses := make([]netip.Addr, len(prefixes))
	for index, prefix := range prefixes {
		addresses[index] = prefix.Addr()
	}
	return addresses
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
		ipv4Count, ipv6Count = i.bypassRuleSetPolicy.Count()
	}
	i.logger.Debug("refreshed eBPF bypass CIDR policy: ipv4=", ipv4Count, ", ipv6=", ipv6Count)
}

var fullVPNBypassPrefixes = []netip.Prefix{
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
	backend := i.cgroupBackendInstance()
	if backend != nil {
		if err := backend.SetPreserveUIDActive(true); err != nil {
			i.vpnBypassActive = false
			return err
		}
	}
	i.bypassRuleSetDirty = true
	if _, err := i.refreshBypassRuleSetsLocked(false, false, false); err != nil {
		return i.rollbackVPNBypassLocked(false, backend, err)
	}
	i.logger.Info("eBPF cgroup socket redirection bypassed: excluded VPN interface active: ", interfaceName)
	return nil
}

func (i *Inbound) disableVPNBypassLocked() error {
	if !i.vpnBypassActive {
		return nil
	}
	i.vpnBypassActive = false
	backend := i.cgroupBackendInstance()
	if backend != nil {
		if err := backend.SetPreserveUIDActive(false); err != nil {
			i.vpnBypassActive = true
			return err
		}
	}
	i.bypassRuleSetDirty = true
	updated, err := i.refreshBypassRuleSetsLocked(false, false, false)
	if err != nil {
		return i.rollbackVPNBypassLocked(true, backend, err)
	}
	i.logger.Info("eBPF cgroup socket redirection resumed: excluded VPN interface disconnected")
	if updated {
		i.logBypassCIDRUpdate()
	}
	return nil
}

func (i *Inbound) rollbackVPNBypassLocked(active bool, backend *ECommon.CgroupBackend, originalErr error) error {
	i.vpnBypassActive = active
	var preserveErr error
	if backend != nil {
		preserveErr = backend.SetPreserveUIDActive(active)
	}
	i.bypassRuleSetDirty = true
	_, policyErr := i.refreshBypassRuleSetsLocked(false, false, false)
	return E.Errors(
		originalErr,
		E.Cause(preserveErr, "rollback VPN endpoint UID policy"),
		E.Cause(policyErr, "rollback VPN bypass CIDR policy"),
	)
}

func (i *Inbound) syncVPNBypassState(excludeInterfaces []string) {
	interfaceNames := findActiveExcludedInterfaceNames(excludeInterfaces)
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	if i.vpnInterfacePackets == nil {
		i.vpnInterfacePackets = make(map[string]interfacePacketCount, len(interfaceNames))
	}
	activeInterfaces := make(map[string]struct{}, len(interfaceNames))
	for _, interfaceName := range interfaceNames {
		activeInterfaces[interfaceName] = struct{}{}
	}
	for interfaceName := range i.vpnInterfacePackets {
		if _, loaded := activeInterfaces[interfaceName]; !loaded {
			delete(i.vpnInterfacePackets, interfaceName)
		}
	}
	interfaceName, active := excludedInterfaceReady(interfaceNames, i.vpnInterfacePackets)
	var err error
	if active {
		err = i.enableVPNBypassLocked(interfaceName)
	} else if len(interfaceNames) == 0 {
		err = i.disableVPNBypassLocked()
	}
	if err != nil {
		i.policyWarnings.warn(i.logger, "synchronize eBPF VPN bypass state: ", err)
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

func (i *Inbound) InterfaceUpdated(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	i.udpNat.Purge()
	if len(i.excludeInterface) > 0 {
		i.syncVPNBypassState(i.excludeInterface)
	}
	i.bypassRuleSetAccess.Lock()
	if ctx.Err() != nil {
		i.bypassRuleSetAccess.Unlock()
		return
	}
	if i.bypassRuleSetStarted {
		updated, err := i.refreshBypassRuleSetsLocked(false, false, false)
		if err != nil {
			i.policyWarnings.warn(i.logger, "refresh eBPF local interface bypass; keeping previous policy: ", err)
		} else if updated {
			i.logBypassCIDRUpdate()
		}
	}
	i.bypassRuleSetAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	if err := i.refreshCgroupIPv6Availability(false); err != nil {
		i.ipv6Warnings.warn(i.logger, "refresh eBPF local cgroup IPv6 availability: ", err)
	}
	if ctx.Err() == nil && i.sharedNetwork != nil {
		i.sharedNetwork.InterfaceUpdated()
	}
}
