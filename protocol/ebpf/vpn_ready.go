//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

var vpnInterfacePatterns = [...]string{"tun+", "ipsec+"}

type interfacePacketCount struct {
	rx uint64
	tx uint64
}

type vpnInterfaceIdentity struct {
	name  string
	index int
}

const (
	endpointReadyReasonIPsecDefaultRoute = "ipsec_default_route"
	endpointReadyReasonRXActivity        = "rx_activity"
	endpointReadyReasonTXActivity        = "tx_activity"
	endpointReadyReasonNoActiveInterface = "no_active_interface"
)

type endpointBypassStatus struct {
	Enabled            bool
	VPNReady           bool
	ActiveVPNInterface string
	ReadyReason        string
}

type vpnReadinessSample struct {
	activeInterfaces []string
	readyInterface   string
	readyReason      string
	ready            bool
}

type endpointVPNReadyControl interface {
	SetEndpointVPNReady(ready bool) error
}

// currentEndpointBypassStatus returns the last readiness state committed to the
// TC backend. Sampling or control-map failures do not publish an uncommitted
// transition.
func (i *Inbound) currentEndpointBypassStatus() endpointBypassStatus {
	status := i.endpointStatus.Load()
	if status == nil {
		return endpointBypassStatus{Enabled: i.endpointConnectedBypass.Enabled}
	}
	return *status
}

func (i *Inbound) storeEndpointBypassStatus(status endpointBypassStatus) {
	i.endpointStatus.Store(&status)
}

func (i *Inbound) resetEndpointBypassStatus() {
	i.storeEndpointBypassStatus(endpointBypassStatus{Enabled: i.endpointConnectedBypass.Enabled})
}

func (i *Inbound) resetVPNReadinessState() {
	i.vpnReady.Store(false)
	i.vpnInterfacePackets = nil
	i.resetEndpointBypassStatus()
}

func (i *Inbound) sampleVPNReadiness() vpnReadinessSample {
	interfaces := findActiveVPNInterfaces()
	if i.vpnInterfacePackets == nil {
		i.vpnInterfacePackets = make(map[vpnInterfaceIdentity]interfacePacketCount, len(interfaces))
	}
	retainActiveVPNPacketBaselines(i.vpnInterfacePackets, interfaces)
	readyInterface, readyReason, ready := vpnInterfaceReady(interfaces, i.vpnInterfacePackets)
	return vpnReadinessSample{
		activeInterfaces: vpnInterfaceNames(interfaces),
		readyInterface:   readyInterface,
		readyReason:      readyReason,
		ready:            ready,
	}
}

func (i *Inbound) syncVPNReadiness() {
	i.transitionVPNReadiness(i.sampleVPNReadiness())
}

// transitionVPNReadiness is the sole owner of runtime READY transitions. Both
// periodic samples and interface events reach this function through the same
// interface worker before dynamic TC control state is committed.
func (i *Inbound) transitionVPNReadiness(sample vpnReadinessSample) {
	i.transitionVPNReadinessWithControl(sample, nil)
}

func (i *Inbound) transitionVPNReadinessWithControl(sample vpnReadinessSample, control endpointVPNReadyControl) {
	previous := i.vpnReady.Load()
	next := reconcileVPNReady(previous, len(sample.activeInterfaces), sample.ready)
	status := reconcileEndpointBypassStatus(
		i.currentEndpointBypassStatus(),
		i.endpointConnectedBypass.Enabled,
		sample.activeInterfaces,
		sample.readyInterface,
		sample.readyReason,
		next,
	)
	if previous == next {
		i.storeEndpointBypassStatus(status)
		return
	}
	if control == nil {
		control = i.tcBackend()
	}
	if control == nil {
		return
	}
	if err := control.SetEndpointVPNReady(next); err != nil {
		i.logger.Error("update eBPF endpoint VPN readiness: ", err)
		return
	}
	i.vpnReady.Store(next)
	i.storeEndpointBypassStatus(status)
	if next {
		i.logger.Info("eBPF endpoint-connected bypass ready: VPN interface has traffic or an IPsec default route")
	} else {
		i.logger.Info("eBPF endpoint-connected bypass disconnected: no active VPN interface")
	}
}

func reconcileEndpointBypassStatus(
	previous endpointBypassStatus,
	enabled bool,
	activeInterfaces []string,
	sampledInterface string,
	sampledReason string,
	vpnReady bool,
) endpointBypassStatus {
	status := endpointBypassStatus{
		Enabled:  enabled,
		VPNReady: vpnReady,
	}
	if !enabled {
		return status
	}
	if len(activeInterfaces) == 0 {
		status.ReadyReason = endpointReadyReasonNoActiveInterface
		return status
	}
	if sampledInterface != "" {
		status.ActiveVPNInterface = sampledInterface
		if vpnReady {
			status.ReadyReason = sampledReason
		}
		return status
	}
	if slices.Contains(activeInterfaces, previous.ActiveVPNInterface) {
		status.ActiveVPNInterface = previous.ActiveVPNInterface
		if vpnReady && previous.VPNReady {
			status.ReadyReason = previous.ReadyReason
		}
		return status
	}
	status.ActiveVPNInterface = activeInterfaces[0]
	return status
}

func reconcileVPNReady(previous bool, activeInterfaceCount int, sampledReady bool) bool {
	if sampledReady {
		return true
	}
	if activeInterfaceCount == 0 {
		return false
	}
	return previous
}

func findActiveVPNInterfaces() []vpnInterfaceIdentity {
	seen := make(map[int]struct{})
	var activeInterfaces []vpnInterfaceIdentity
	links, err := netlink.LinkList()
	if err == nil && len(links) > 0 {
		for _, link := range links {
			attrs := link.Attrs()
			if attrs == nil || attrs.Flags&net.FlagUp == 0 || !isVPNInterface(attrs.Name) {
				continue
			}
			addrs, addrErr := netlink.AddrList(link, netlink.FAMILY_ALL)
			if addrErr != nil {
				continue
			}
			for _, addr := range addrs {
				if addr.IP != nil && isGlobalUnicastIP(addr.IP) {
					seen[attrs.Index] = struct{}{}
					activeInterfaces = append(activeInterfaces, vpnInterfaceIdentity{name: attrs.Name, index: attrs.Index})
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
		if networkInterface.Flags&net.FlagUp == 0 || !isVPNInterface(networkInterface.Name) {
			continue
		}
		if _, loaded := seen[networkInterface.Index]; loaded {
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
			if ip != nil && isGlobalUnicastIP(ip) {
				activeInterfaces = append(activeInterfaces, vpnInterfaceIdentity{
					name:  networkInterface.Name,
					index: networkInterface.Index,
				})
				break
			}
		}
	}
	slices.SortFunc(activeInterfaces, func(left, right vpnInterfaceIdentity) int {
		if left.index < right.index {
			return -1
		}
		if left.index > right.index {
			return 1
		}
		return strings.Compare(left.name, right.name)
	})
	return activeInterfaces
}

func vpnInterfaceNames(interfaces []vpnInterfaceIdentity) []string {
	names := make([]string, 0, len(interfaces))
	for _, vpnInterface := range interfaces {
		names = append(names, vpnInterface.name)
	}
	return names
}

func retainActiveVPNPacketBaselines(
	baseline map[vpnInterfaceIdentity]interfacePacketCount,
	interfaces []vpnInterfaceIdentity,
) {
	activeInterfaces := make(map[vpnInterfaceIdentity]struct{}, len(interfaces))
	for _, vpnInterface := range interfaces {
		activeInterfaces[vpnInterface] = struct{}{}
	}
	for vpnInterface := range baseline {
		if _, loaded := activeInterfaces[vpnInterface]; !loaded {
			delete(baseline, vpnInterface)
		}
	}
}

func isVPNInterface(interfaceName string) bool {
	lowerName := strings.ToLower(interfaceName)
	for _, pattern := range vpnInterfacePatterns {
		if strings.HasPrefix(lowerName, strings.TrimSuffix(pattern, "+")) {
			return true
		}
	}
	return false
}

func isGlobalUnicastIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() && ip.IsGlobalUnicast()
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

func packetCountIncreased(previous interfacePacketCount, current interfacePacketCount) bool {
	return packetCountReadyReason(previous, current) != ""
}

func packetCountReadyReason(previous interfacePacketCount, current interfacePacketCount) string {
	if current.rx > previous.rx {
		return endpointReadyReasonRXActivity
	}
	if current.tx > previous.tx {
		return endpointReadyReasonTXActivity
	}
	return ""
}

func vpnInterfaceReady(
	interfaces []vpnInterfaceIdentity,
	baseline map[vpnInterfaceIdentity]interfacePacketCount,
) (string, string, bool) {
	var tunInterfaces []vpnInterfaceIdentity
	for _, vpnInterface := range interfaces {
		if strings.HasPrefix(strings.ToLower(vpnInterface.name), "ipsec") {
			if interfaceHasDefaultRoute(vpnInterface.index) {
				return vpnInterface.name, endpointReadyReasonIPsecDefaultRoute, true
			}
		} else {
			tunInterfaces = append(tunInterfaces, vpnInterface)
		}
	}
	for _, vpnInterface := range tunInterfaces {
		rx, tx, err := getInterfacePacketCount(vpnInterface.name)
		if err != nil {
			continue
		}
		current := interfacePacketCount{rx: rx, tx: tx}
		previous, loaded := baseline[vpnInterface]
		baseline[vpnInterface] = current
		if reason := packetCountReadyReason(previous, current); loaded && reason != "" {
			return vpnInterface.name, reason, true
		}
	}
	return "", "", false
}

func interfaceHasDefaultRoute(interfaceIndex int) bool {
	if interfaceIndex <= 0 {
		return false
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, routeErr := netlink.RouteListFiltered(
			family,
			&netlink.Route{LinkIndex: interfaceIndex, Table: unix.RT_TABLE_UNSPEC},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE,
		)
		if routeErr == nil && slices.ContainsFunc(routes, isVPNDefaultRoute) {
			return true
		}
	}
	return false
}

func isVPNDefaultRoute(route netlink.Route) bool {
	if route.Table == unix.RT_TABLE_LOCAL || route.Type != unix.RTN_UNICAST {
		return false
	}
	if route.Dst == nil {
		return true
	}
	ones, bits := route.Dst.Mask.Size()
	return ones == 0 && (bits == net.IPv4len*8 || bits == net.IPv6len*8)
}
