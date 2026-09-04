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

func (i *Inbound) syncVPNReadiness() {
	interfaceNames := findActiveVPNInterfaceNames()
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
	_, ready := vpnInterfaceReady(interfaceNames, i.vpnInterfacePackets)
	previous := i.vpnReady.Load()
	next := reconcileVPNReady(previous, len(interfaceNames), ready)
	if previous == next {
		return
	}
	backend := i.tcBackend()
	if backend == nil {
		return
	}
	if next {
		if err := backend.SetEndpointVPNReady(true); err != nil {
			i.logger.Error("update eBPF endpoint VPN readiness: ", err)
			return
		}
		i.vpnReady.Store(true)
	} else {
		i.vpnReady.Store(false)
		if err := backend.SetEndpointVPNReady(false); err != nil {
			i.vpnReady.Store(true)
			i.logger.Error("update eBPF endpoint VPN readiness: ", err)
			return
		}
	}
	if next {
		i.logger.Info("eBPF endpoint-connected bypass ready: VPN interface has traffic or an IPsec default route")
	} else {
		i.logger.Info("eBPF endpoint-connected bypass disconnected: no active VPN interface")
	}
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

func findActiveVPNInterfaceNames() []string {
	seen := make(map[string]struct{})
	var activeInterfaces []string
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
					seen[attrs.Name] = struct{}{}
					activeInterfaces = append(activeInterfaces, attrs.Name)
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
			if ip != nil && isGlobalUnicastIP(ip) {
				activeInterfaces = append(activeInterfaces, networkInterface.Name)
				break
			}
		}
	}
	return activeInterfaces
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
	return current.rx > previous.rx || current.tx > previous.tx
}

func vpnInterfaceReady(interfaceNames []string, baseline map[string]interfacePacketCount) (string, bool) {
	var tunInterfaces []string
	for _, interfaceName := range interfaceNames {
		if strings.HasPrefix(strings.ToLower(interfaceName), "ipsec") {
			if interfaceHasDefaultRoute(interfaceName) {
				return interfaceName, true
			}
		} else {
			tunInterfaces = append(tunInterfaces, interfaceName)
		}
	}
	for _, interfaceName := range tunInterfaces {
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
