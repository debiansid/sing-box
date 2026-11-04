//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
	"golang.org/x/sys/unix"
)

type tcInterfaceMonitor struct {
	access                   sync.Mutex
	network                  tun.NetworkUpdateMonitor
	networkOwned             bool
	networkCallback          *list.Element[tun.NetworkUpdateCallback]
	defaultInterface         tun.DefaultInterfaceMonitor
	defaultInterfaceOwned    bool
	defaultInterfaceCallback *list.Element[tun.DefaultInterfaceUpdateCallback]
	defaultInterfaceName     string
	cancel                   context.CancelFunc
	done                     chan struct{}
	updates                  chan struct{}
}

func (i *Inbound) InterfaceUpdated(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	i.diagnostics.access.Lock()
	i.networkGeneration++
	i.diagnostics.access.Unlock()
	// The raw netlink/default-interface monitors below are intentionally only
	// responsible for keeping kernel attachments and host policy current. A
	// network handover emits several transient topology states on Android (often
	// old interface -> no default -> new interface); tearing down userspace and
	// cgroup flow state for every one of those observations repeatedly disrupts
	// otherwise valid proxied connections.
	//
	// NetworkManager calls InterfaceUpdated only after it has selected the new
	// default network and closed the old generation's tracked connections. This
	// is therefore the same coordinated reset boundary used by TUN and TProxy,
	// and the only place where eBPF network-bound flow state is purged.
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	i.setDefaultInterfaceName(i.currentDefaultInterfaceName())
	i.udpNat.Purge()
	if err := i.udpReplySockets.reset(); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "reset TC eBPF UDP reply sockets after network change: ", err)
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		if err := backend.ResetNetworkState(); err != nil {
			i.interfaceWarnings.reconcile.warn(i.logger, "reset cgroup eBPF network state after network change: ", err)
		}
	}
	if backend := i.tcBackend(); backend != nil {
		generation := uint32(i.networkGeneration)
		if generation == 0 {
			generation = 1
		}
		if err := backend.SetNetworkGeneration(generation); err != nil {
			i.interfaceWarnings.reconcile.warn(i.logger, "advance TC eBPF network generation after network change: ", err)
		}
	}
}

func (i *Inbound) currentNetworkGeneration() uint64 {
	i.diagnostics.access.Lock()
	generation := i.networkGeneration
	i.diagnostics.access.Unlock()
	return generation
}

func (i *Inbound) startTCInterfaceMonitor() error {
	networkMonitor := i.networkManager.NetworkMonitor()
	networkOwned := false
	if networkMonitor == nil {
		var err error
		networkMonitor, err = tun.NewNetworkUpdateMonitor(i.logger)
		if err != nil {
			return E.Cause(err, "create TC eBPF network monitor")
		}
		networkOwned = true
	}
	defaultInterfaceMonitor := i.networkManager.InterfaceMonitor()
	defaultInterfaceOwned := false
	if defaultInterfaceMonitor == nil {
		var err error
		defaultInterfaceMonitor, err = tun.NewDefaultInterfaceMonitor(networkMonitor, i.logger, tun.DefaultInterfaceMonitorOptions{
			InterfaceFinder: i.networkManager.InterfaceFinder(),
		})
		if err != nil {
			if networkOwned {
				_ = networkMonitor.Close()
			}
			return E.Cause(err, "create TC eBPF default interface monitor")
		}
		defaultInterfaceOwned = true
	}
	monitorContext, cancel := context.WithCancel(i.ctx)
	done := make(chan struct{})
	updates := make(chan struct{}, 1)
	initialDefaultInterface := i.currentDefaultInterfaceName()
	state := &i.interfaceMonitor
	state.access.Lock()
	if state.network != nil {
		state.access.Unlock()
		cancel()
		if defaultInterfaceOwned {
			_ = defaultInterfaceMonitor.Close()
		}
		if networkOwned {
			_ = networkMonitor.Close()
		}
		return nil
	}
	state.network = networkMonitor
	state.networkOwned = networkOwned
	state.defaultInterface = defaultInterfaceMonitor
	state.defaultInterfaceOwned = defaultInterfaceOwned
	state.cancel = cancel
	state.done = done
	state.updates = updates
	state.networkCallback = networkMonitor.RegisterCallback(i.notifyTCInterfaceUpdate)
	state.defaultInterfaceCallback = defaultInterfaceMonitor.RegisterCallback(i.defaultInterfaceUpdated)
	state.defaultInterfaceName = initialDefaultInterface
	state.access.Unlock()
	i.resetVPNReadinessState()
	go i.runTCInterfaceUpdates(monitorContext, updates, done)
	if networkOwned {
		if err := networkMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF network monitor"), i.stopTCInterfaceMonitor())
		}
	}
	if defaultInterfaceOwned {
		if err := defaultInterfaceMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF default interface monitor"), i.stopTCInterfaceMonitor())
		}
	}
	i.notifyTCInterfaceUpdate()
	return nil
}

func (i *Inbound) stopTCInterfaceMonitor() error {
	state := &i.interfaceMonitor
	state.access.Lock()
	networkMonitor := state.network
	networkOwned := state.networkOwned
	networkCallback := state.networkCallback
	defaultInterfaceMonitor := state.defaultInterface
	defaultInterfaceOwned := state.defaultInterfaceOwned
	defaultInterfaceCallback := state.defaultInterfaceCallback
	cancel := state.cancel
	done := state.done
	state.network = nil
	state.networkOwned = false
	state.networkCallback = nil
	state.defaultInterface = nil
	state.defaultInterfaceOwned = false
	state.defaultInterfaceCallback = nil
	state.defaultInterfaceName = ""
	state.cancel = nil
	state.done = nil
	state.updates = nil
	state.access.Unlock()
	if networkMonitor == nil {
		return nil
	}
	if networkCallback != nil {
		networkMonitor.UnregisterCallback(networkCallback)
	}
	if defaultInterfaceMonitor != nil && defaultInterfaceCallback != nil {
		defaultInterfaceMonitor.UnregisterCallback(defaultInterfaceCallback)
	}
	if cancel != nil {
		cancel()
	}
	var closeErr error
	if defaultInterfaceOwned {
		closeErr = defaultInterfaceMonitor.Close()
	}
	if networkOwned {
		closeErr = E.Errors(closeErr, networkMonitor.Close())
	}
	if done != nil {
		<-done
	}
	i.resetVPNReadinessState()
	return closeErr
}

func (i *Inbound) defaultInterfaceUpdated(defaultInterface *control.Interface, _ int) {
	name := interfaceName(defaultInterface)
	if name == "" && runtime.GOOS == "android" {
		name = androidDefaultInterfaceFinder()
	}
	i.setDefaultInterfaceName(name)
}

func interfaceName(networkInterface *control.Interface) string {
	if networkInterface == nil {
		return ""
	}
	return networkInterface.Name
}

var androidDefaultInterfaceFinder = findAndroidDefaultInterfaceName

func (i *Inbound) currentDefaultInterfaceName() string {
	var name string
	if defaultInterfaceMonitor := i.networkManager.InterfaceMonitor(); defaultInterfaceMonitor != nil {
		name = interfaceName(defaultInterfaceMonitor.DefaultInterface())
	}
	if name == "" && runtime.GOOS == "android" {
		name = androidDefaultInterfaceFinder()
	}
	return name
}

type routeLinkResolver struct {
	names map[int]string
}

func newRouteLinkResolver() *routeLinkResolver {
	return &routeLinkResolver{names: make(map[int]string)}
}

func (r *routeLinkResolver) resolve(index int) string {
	if index <= 0 {
		return ""
	}
	if name, ok := r.names[index]; ok {
		return name
	}
	link, err := netlink.LinkByIndex(index)
	if err != nil || link == nil || link.Attrs() == nil {
		r.names[index] = ""
		return ""
	}
	attrs := link.Attrs()
	if !isDefaultInterfaceCandidate(attrs) {
		r.names[index] = ""
		return ""
	}
	r.names[index] = attrs.Name
	return attrs.Name
}

// clatd's raw-IP v4-* interface carries an IPv4 default route on IPv6-only
// networks, but it is a translation shim, not the network to attach TC to.
func isDefaultInterfaceCandidate(attrs *netlink.LinkAttrs) bool {
	if attrs.Flags&net.FlagUp == 0 || attrs.Flags&net.FlagLoopback != 0 {
		return false
	}
	return !isVPNInterface(attrs.Name) && !strings.HasPrefix(attrs.Name, "v4-")
}

func isCandidateDefaultRoute(route netlink.Route) bool {
	if route.Table == unix.RT_TABLE_LOCAL || (route.Type != unix.RTN_UNICAST && route.Type != 0) {
		return false
	}
	if route.LinkIndex <= 0 {
		return false
	}
	if route.Dst == nil {
		return true
	}
	ones, bits := route.Dst.Mask.Size()
	return ones == 0 && (bits == net.IPv4len*8 || bits == net.IPv6len*8)
}

// androidRuleTables orders candidate routing tables for the default-interface
// fallback. netd installs per-network explicit/output-interface/implicit rules
// for every connected network ahead of the default-network rule, so taking the
// first table with a default route can pick a secondary network (e.g. mobile
// data while Wi-Fi is the default). The default-network rule is the one with
// fwmark mask 0xffff -- the same rule sing-tun's Android monitor follows -- so
// its table is tried first; the remaining tables keep rule-priority order.
func androidRuleTables(rules []netlink.Rule) []int {
	var tables []int
	seen := make(map[int]bool)
	add := func(table int) {
		if table <= 0 || table == unix.RT_TABLE_LOCAL || seen[table] {
			return
		}
		seen[table] = true
		tables = append(tables, table)
	}
	// The default network's table also appears in earlier per-network rules,
	// so pick default-network tables in a separate first pass.
	for _, rule := range rules {
		if rule.Mask == androidDefaultNetworkRuleMask {
			add(rule.Table)
		}
	}
	for _, rule := range rules {
		add(rule.Table)
	}
	return tables
}

const androidDefaultNetworkRuleMask = 0xFFFF

func findAndroidDefaultInterfaceByRules(family int, resolver *routeLinkResolver) string {
	rules, err := netlink.RuleList(family)
	if err != nil {
		return ""
	}
	for _, table := range androidRuleTables(rules) {
		routes, err := netlink.RouteListFiltered(
			family,
			&netlink.Route{Table: table},
			netlink.RT_FILTER_TABLE,
		)
		if err != nil {
			continue
		}
		for _, route := range routes {
			if !isCandidateDefaultRoute(route) {
				continue
			}
			if iface := resolver.resolve(route.LinkIndex); iface != "" {
				return iface
			}
		}
	}
	return ""
}

func findAndroidDefaultInterfaceByRoutes(family int, resolver *routeLinkResolver) string {
	routes, err := netlink.RouteListFiltered(
		family,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return ""
	}
	for _, route := range routes {
		if !isCandidateDefaultRoute(route) {
			continue
		}
		if iface := resolver.resolve(route.LinkIndex); iface != "" {
			return iface
		}
	}
	return ""
}

func findAndroidDefaultInterfaceName() string {
	resolver := newRouteLinkResolver()
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if name := findAndroidDefaultInterfaceByRules(family, resolver); name != "" {
			return name
		}
		if name := findAndroidDefaultInterfaceByRoutes(family, resolver); name != "" {
			return name
		}
	}
	return ""
}

func (i *Inbound) setDefaultInterfaceName(interfaceName string) {
	state := &i.interfaceMonitor
	state.access.Lock()
	state.defaultInterfaceName = interfaceName
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if active {
		notifyTCInterfaceUpdate(updates)
	}
}

func (i *Inbound) notifyTCInterfaceUpdate() {
	state := &i.interfaceMonitor
	state.access.Lock()
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if !active {
		return
	}
	notifyTCInterfaceUpdate(updates)
}

func notifyTCInterfaceUpdate(updates chan<- struct{}) {
	select {
	case updates <- struct{}{}:
	default:
	}
}
