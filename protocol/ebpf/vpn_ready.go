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

type vpnInterfaceIdentity struct {
	name  string
	index int
}

type vpnInterfaceState struct {
	rx, tx uint64
	ready  bool
}

type endpointVPNReadyControl interface {
	SetEndpointVPNReady(bool) error
}

func (i *Inbound) resetVPNReadinessState() {
	i.vpnReady.Store(false)
	i.vpnInterfacePackets = nil
}

// Only the interface worker samples and commits readiness. The library owns
// the control map; readiness must not reconcile resources or change routing.
func (i *Inbound) syncVPNReadiness() {
	if i.vpnInterfacePackets == nil {
		i.vpnInterfacePackets = make(map[vpnInterfaceIdentity]vpnInterfaceState)
	}
	var excluded []string
	if monitor := i.networkManager.InterfaceMonitor(); monitor != nil {
		excluded = monitor.MyInterfaces()
	}
	candidates := findActiveVPNInterfaces(excluded, netlink.LinkList, netlink.AddrList, net.Interfaces, (*net.Interface).Addrs)
	next := sampleVPNInterfaces(candidates, i.vpnInterfacePackets, readVPNPackets, interfaceHasDefaultRoute)
	if backend := i.tcBackend(); backend != nil {
		if err := i.commitVPNReady(next, backend); err != nil {
			i.logger.Error("update eBPF endpoint VPN readiness: ", err)
		}
	}
}

func (i *Inbound) commitVPNReady(next bool, backend endpointVPNReadyControl) error {
	if i.vpnReady.Load() == next {
		return nil
	}
	if err := backend.SetEndpointVPNReady(next); err != nil {
		return err
	}
	i.vpnReady.Store(next)
	return nil
}

func isVPNInterface(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "ipsec")
}

// Keep the net.Interface fallback: Android may expose an eligible VPN through
// that inventory even when the netlink inventory is incomplete.
func findActiveVPNInterfaces(excluded []string,
	links func() ([]netlink.Link, error), addresses func(netlink.Link, int) ([]netlink.Addr, error),
	interfaces func() ([]net.Interface, error), interfaceAddresses func(*net.Interface) ([]net.Addr, error),
) []vpnInterfaceIdentity {
	var result []vpnInterfaceIdentity
	eligible := func(name string, flags net.Flags) bool {
		return flags&net.FlagUp != 0 && isVPNInterface(name) && !slices.Contains(excluded, name)
	}
	if inventory, err := links(); err == nil {
		for _, link := range inventory {
			a := link.Attrs()
			if a == nil || !eligible(a.Name, a.Flags) {
				continue
			}
			addrs, err := addresses(link, netlink.FAMILY_ALL)
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if addr.IPNet != nil && addr.IP.IsGlobalUnicast() {
					result = append(result, vpnInterfaceIdentity{a.Name, a.Index})
					break
				}
			}
		}
	}
	if inventory, err := interfaces(); err == nil {
		for _, intf := range inventory {
			id := vpnInterfaceIdentity{intf.Name, intf.Index}
			if !eligible(intf.Name, intf.Flags) || slices.Contains(result, id) {
				continue
			}
			addrs, err := interfaceAddresses(&intf)
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch addr := addr.(type) {
				case *net.IPNet:
					ip = addr.IP
				case *net.IPAddr:
					ip = addr.IP
				}
				if ip.IsGlobalUnicast() {
					result = append(result, id)
					break
				}
			}
		}
	}
	return result
}

func sampleVPNInterfaces(candidates []vpnInterfaceIdentity, states map[vpnInterfaceIdentity]vpnInterfaceState,
	packets func(string) (uint64, uint64, error), defaultRoute func(int) bool,
) bool {
	for id := range states {
		if !slices.Contains(candidates, id) {
			delete(states, id)
		}
	}
	ready := false
	for _, id := range candidates {
		if strings.HasPrefix(strings.ToLower(id.name), "ipsec") {
			ready = defaultRoute(id.index) || ready
			continue
		}
		previous, sampled := states[id]
		rx, tx, err := packets(id.name)
		if err == nil {
			previous = vpnInterfaceState{rx, tx, previous.ready || sampled && (rx > previous.rx || tx > previous.tx)}
			states[id] = previous
		}
		ready = previous.ready || ready
	}
	return ready
}

func readVPNPackets(name string) (uint64, uint64, error) {
	read := func(counter string) (uint64, error) {
		data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "statistics", counter))
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	rx, err := read("rx_packets")
	if err != nil {
		return 0, 0, err
	}
	tx, err := read("tx_packets")
	return rx, tx, err
}

func interfaceHasDefaultRoute(index int) bool {
	if index <= 0 {
		return false
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{LinkIndex: index, Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
		if err == nil && slices.ContainsFunc(routes, isVPNDefaultRoute) {
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
	return ones == 0 && (bits == 32 || bits == 128)
}
