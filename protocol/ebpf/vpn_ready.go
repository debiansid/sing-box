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

type interfacePacketCount struct {
	rx uint64
	tx uint64
}

// An entry exists only after a successful packet-counter read. The activity
// reason latches readiness only while this TUN identity remains eligible.
type vpnInterfaceState struct {
	packets     interfacePacketCount
	readyReason string
}

type vpnInterfaceIdentity struct {
	name  string
	index int
}

const (
	endpointReadyReasonRXActivity = "rx_activity"
	endpointReadyReasonTXActivity = "tx_activity"
)

type vpnReadinessSample struct {
	ready bool
}

type endpointVPNReadyControl interface {
	SetEndpointVPNReady(ready bool) error
}

func (i *Inbound) resetVPNReadinessState() {
	i.vpnReady.Store(false)
	i.vpnInterfacePackets = nil
}

func (i *Inbound) sampleVPNReadiness() vpnReadinessSample {
	var excludedInterfaces []string
	if monitor := i.networkManager.InterfaceMonitor(); monitor != nil {
		excludedInterfaces = slices.Clone(monitor.MyInterfaces())
	}
	interfaces := findActiveVPNInterfaces(excludedInterfaces, netlink.LinkList, netlink.AddrList, net.Interfaces, (*net.Interface).Addrs)
	if i.vpnInterfacePackets == nil {
		i.vpnInterfacePackets = make(map[vpnInterfaceIdentity]vpnInterfaceState, len(interfaces))
	}
	return sampleVPNInterfaces(interfaces, i.vpnInterfacePackets, getInterfacePacketCount, interfaceHasDefaultRoute)
}

func sampleVPNInterfaces(
	interfaces []vpnInterfaceIdentity,
	states map[vpnInterfaceIdentity]vpnInterfaceState,
	packetCount func(string) (uint64, uint64, error),
	hasDefaultRoute func(int) bool,
) vpnReadinessSample {
	retainActiveVPNPacketBaselines(states, interfaces)
	return vpnReadinessSample{
		ready: vpnInterfaceReady(interfaces, states, packetCount, hasDefaultRoute),
	}
}

func (i *Inbound) syncVPNReadiness() {
	i.transitionVPNReadinessWithControl(i.sampleVPNReadiness(), nil)
}

// transitionVPNReadinessWithControl is the sole owner of runtime READY transitions. Both
// periodic samples and interface events reach this function through the same
// interface worker before dynamic TC control state is committed.
func (i *Inbound) transitionVPNReadinessWithControl(sample vpnReadinessSample, control endpointVPNReadyControl) {
	previous := i.vpnReady.Load()
	next := sample.ready
	if previous == next {
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
	if next {
		i.logger.Info("eBPF endpoint-connected bypass ready: VPN interface has traffic or an IPsec default route")
	} else {
		i.logger.Info("eBPF endpoint-connected bypass not ready: no eligible VPN interface is ready")
	}
}

// Dependencies are passed explicitly so both discovery paths can be tested
// without changing host interfaces or package-global sampling functions.
func findActiveVPNInterfaces(
	excludedInterfaces []string,
	listLinks func() ([]netlink.Link, error),
	linkAddresses func(netlink.Link, int) ([]netlink.Addr, error),
	listInterfaces func() ([]net.Interface, error),
	interfaceAddresses func(*net.Interface) ([]net.Addr, error),
) []vpnInterfaceIdentity {
	seen := make(map[int]struct{})
	var activeInterfaces []vpnInterfaceIdentity
	links, err := listLinks()
	if err == nil && len(links) > 0 {
		for _, link := range links {
			attrs := link.Attrs()
			if attrs == nil || attrs.Flags&net.FlagUp == 0 || !isVPNInterface(attrs.Name) || slices.Contains(excludedInterfaces, attrs.Name) {
				continue
			}
			addrs, addrErr := linkAddresses(link, netlink.FAMILY_ALL)
			if addrErr != nil {
				continue
			}
			for _, addr := range addrs {
				if addr.IP.IsGlobalUnicast() {
					seen[attrs.Index] = struct{}{}
					activeInterfaces = append(activeInterfaces, vpnInterfaceIdentity{name: attrs.Name, index: attrs.Index})
					break
				}
			}
		}
	}
	interfaces, err := listInterfaces()
	if err != nil {
		interfaces = nil
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || !isVPNInterface(networkInterface.Name) || slices.Contains(excludedInterfaces, networkInterface.Name) {
			continue
		}
		if _, loaded := seen[networkInterface.Index]; loaded {
			continue
		}
		addresses, addressErr := interfaceAddresses(&networkInterface)
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
			if ip.IsGlobalUnicast() {
				activeInterfaces = append(activeInterfaces, vpnInterfaceIdentity{
					name:  networkInterface.Name,
					index: networkInterface.Index,
				})
				break
			}
		}
	}
	return activeInterfaces
}

func retainActiveVPNPacketBaselines(
	baseline map[vpnInterfaceIdentity]vpnInterfaceState,
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
	return strings.HasPrefix(lowerName, "tun") || strings.HasPrefix(lowerName, "ipsec")
}

func getInterfacePacketCount(interfaceName string) (rx uint64, tx uint64, err error) {
	return readInterfacePacketCount(interfaceName, os.ReadFile)
}

func readInterfacePacketCount(interfaceName string, readFile func(string) ([]byte, error)) (rx uint64, tx uint64, err error) {
	rxData, err := readFile(filepath.Join("/sys/class/net", interfaceName, "statistics", "rx_packets"))
	if err != nil {
		return 0, 0, err
	}
	txData, err := readFile(filepath.Join("/sys/class/net", interfaceName, "statistics", "tx_packets"))
	if err != nil {
		return 0, 0, err
	}
	rx, err = strconv.ParseUint(strings.TrimSpace(string(rxData)), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	tx, err = strconv.ParseUint(strings.TrimSpace(string(txData)), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return rx, tx, nil
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
	states map[vpnInterfaceIdentity]vpnInterfaceState,
	packetCount func(string) (uint64, uint64, error),
	hasDefaultRoute func(int) bool,
) bool {
	var ready bool
	// Always sample every candidate, even after one establishes readiness.
	for _, vpnInterface := range interfaces {
		if strings.HasPrefix(strings.ToLower(vpnInterface.name), "ipsec") {
			if hasDefaultRoute(vpnInterface.index) {
				ready = true
			}
			continue
		}
		state, loaded := states[vpnInterface]
		rx, tx, err := packetCount(vpnInterface.name)
		if err == nil {
			current := interfacePacketCount{rx: rx, tx: tx}
			if loaded && state.readyReason == "" {
				state.readyReason = packetCountReadyReason(state.packets, current)
			}
			state.packets = current
			states[vpnInterface] = state
		}
		if state.readyReason != "" {
			ready = true
		}
	}
	return ready
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
