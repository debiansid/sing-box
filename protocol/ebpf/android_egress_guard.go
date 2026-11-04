//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"hash/fnv"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	androidEgressGuardTimeout  = 5 * time.Second
	androidFirstApplicationUID = 10000
	androidExplicitNetworkMark = "0x10000/0x10000"
	maxInterfaceNameLength     = 15
)

var (
	androidEgressGuardIPv4Unrouted = []string{
		"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
	}
	androidEgressGuardIPv6Unrouted = []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
)

type androidEgressGuard struct {
	access    sync.Mutex
	applied   string
	installed bool // an apply was attempted this run, so a chain may exist
}

// The local socket-assignment path only captures packets leaving the interface its TC programs
// are attached to. Until they follow a new default network, and on any other network an app is
// implicitly routed to, proxied apps would leave unproxied, so their packets are refused on every
// interface but the attached one. Sockets explicitly bound to a network, VPN interfaces, private
// destinations, system app IDs and the core's own UID are left alone.
func (i *Inbound) syncAndroidEgressGuard(localInterface string) error {
	if runtime.GOOS != "android" || !i.localSocketAssignEnabled() {
		return nil
	}
	chain := i.androidEgressGuardChain()
	appUIDs := androidApplicationUIDRanges()
	ipv4Rules := i.androidEgressGuardRules(chain, localInterface, androidEgressGuardIPv4Unrouted, appUIDs)
	ipv6Rules := ""
	if i.localIPv6 {
		ipv6Rules = i.androidEgressGuardRules(chain, localInterface, androidEgressGuardIPv6Unrouted, appUIDs)
	}
	applied := ipv4Rules + "\n" + ipv6Rules
	state := &i.egressGuard
	state.access.Lock()
	defer state.access.Unlock()
	if applied == state.applied {
		return nil
	}
	state.installed = true
	err := applyAndroidEgressGuard("iptables", chain, ipv4Rules)
	if err == nil {
		if ipv6Rules != "" {
			err = applyAndroidEgressGuard("ip6tables", chain, ipv6Rules)
		} else {
			removeAndroidEgressGuardFamily("ip6tables", chain)
		}
	}
	if err != nil {
		state.applied = ""
		i.logger.Warn("eBPF local egress guard: ", err)
		return err
	}
	state.applied = applied
	i.logger.Debug("eBPF local egress guard allows interface: ", localInterface)
	return nil
}

// androidEgressGuardHealthy reports whether the guard this inbound needs is still installed;
// netd or a firewall app may flush OUTPUT, and a failed apply leaves nothing installed. Either
// clears the cached rules so the next reconcile re-applies them.
func (i *Inbound) androidEgressGuardHealthy() bool {
	if runtime.GOOS != "android" || !i.localSocketAssignEnabled() {
		return true
	}
	chain := i.androidEgressGuardChain()
	state := &i.egressGuard
	state.access.Lock()
	defer state.access.Unlock()
	if state.applied == "" {
		return false
	}
	families := []string{"iptables"}
	if i.localIPv6 {
		families = append(families, "ip6tables")
	}
	for _, command := range families {
		if runAndroidXtables(command, "", "-w", "-C", "OUTPUT", "-j", chain) != nil {
			state.applied = ""
			return false
		}
	}
	return true
}

// removeAndroidEgressGuard skips the xtables calls when this run never applied a guard, unless
// stale is set: at start, a chain left by a crashed run would keep rejecting apps.
func (i *Inbound) removeAndroidEgressGuard(stale bool) {
	if runtime.GOOS != "android" {
		return
	}
	chain := i.androidEgressGuardChain()
	state := &i.egressGuard
	state.access.Lock()
	defer state.access.Unlock()
	if !stale && !state.installed {
		return
	}
	removeAndroidEgressGuardFamily("iptables", chain)
	removeAndroidEgressGuardFamily("ip6tables", chain)
	state.applied = ""
	state.installed = false
}

// Each inbound owns its chain, so one inbound's cleanup never removes another's guard. The
// name is derived from the tag so a restart after a crash finds and replaces its stale chain.
func (i *Inbound) androidEgressGuardChain() string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(i.Tag()))
	return "sb_ebpf_guard_" + strconv.FormatUint(uint64(hash.Sum32()), 16)
}

// androidApplicationUIDRanges returns the application UID range of every Android user. App IDs
// below 10000 are system services in every user, not only user 0.
// shortcut: users are read when the guard is rebuilt, so a user created later is guarded from the
// next network change on.
func androidApplicationUIDRanges() []uidRange {
	users := []uint32{0}
	if entries, err := os.ReadDir("/data/user"); err == nil {
		users = users[:0]
		for _, entry := range entries {
			if user, err := strconv.ParseUint(entry.Name(), 10, 32); err == nil && user < 21474 {
				users = append(users, uint32(user))
			}
		}
		if len(users) == 0 {
			users = append(users, 0)
		}
	}
	slices.Sort(users)
	appUIDs := make([]uidRange, 0, len(users))
	for _, user := range users {
		base := user * androidUserRange
		appUIDs = append(appUIDs, uidRange{Start: base + androidFirstApplicationUID, End: base + androidUserRange - 1})
	}
	return appUIDs
}

func (i *Inbound) androidEgressGuardRules(chain string, localInterface string, unrouted []string, appUIDs []uidRange) string {
	var builder strings.Builder
	builder.WriteString("*filter\n:" + chain + " - [0:0]\n-F " + chain + "\n")
	add := func(rule string) {
		builder.WriteString("-A " + chain + " " + rule + "\n")
	}
	add("-o lo -j RETURN")
	if localInterface != "" {
		add("-o " + localInterface + " -j RETURN")
		if clatInterface := "v4-" + localInterface; len(clatInterface) <= maxInterfaceNameLength {
			add("-o " + clatInterface + " -j RETURN")
		}
	}
	add("-o tun+ -j RETURN")
	add("-o ipsec+ -j RETURN")
	add("-m mark --mark " + androidExplicitNetworkMark + " -j RETURN")
	for _, prefix := range unrouted {
		add("-d " + prefix + " -j RETURN")
	}
	// The core may run inside an app process; its own sockets bound with SO_BINDTODEVICE carry
	// no explicit-network mark.
	selfUID := uint32(os.Getuid())
	add(androidUIDOwner(selfUID, selfUID) + " -j RETURN")
	decisions, defaultDecision := i.compileProcessUIDPolicy()
	if defaultDecision == commonEBPF.DecisionIntercept {
		for _, decision := range decisions {
			if decision.Action == commonEBPF.DecisionPass {
				add(androidUIDOwner(decision.Start, decision.End) + " -j RETURN")
			}
		}
		for _, appUID := range appUIDs {
			add(androidUIDOwner(appUID.Start, appUID.End) + " -j REJECT")
		}
	} else {
		for _, decision := range decisions {
			if decision.Action != commonEBPF.DecisionIntercept {
				continue
			}
			for _, appUID := range appUIDs {
				start := max(decision.Start, appUID.Start)
				end := min(decision.End, appUID.End)
				if start <= end {
					add(androidUIDOwner(start, end) + " -j REJECT")
				}
			}
		}
	}
	builder.WriteString("COMMIT\n")
	return builder.String()
}

func androidUIDOwner(start uint32, end uint32) string {
	return "-m owner --uid-owner " + strconv.FormatUint(uint64(start), 10) + "-" + strconv.FormatUint(uint64(end), 10)
}

// iptables-restore replaces the chain in one commit, so switching interfaces never opens a gap.
func applyAndroidEgressGuard(command string, chain string, rules string) error {
	if err := runAndroidXtables(command+"-restore", rules, "-w", "--noflush"); err != nil {
		return E.Cause(err, command, "-restore")
	}
	if runAndroidXtables(command, "", "-w", "-C", "OUTPUT", "-j", chain) == nil {
		return nil
	}
	if err := runAndroidXtables(command, "", "-w", "-I", "OUTPUT", "1", "-j", chain); err != nil {
		return E.Cause(err, command, " OUTPUT jump")
	}
	return nil
}

func removeAndroidEgressGuardFamily(command string, chain string) {
	for attempt := 0; attempt < 8; attempt++ {
		if runAndroidXtables(command, "", "-w", "-D", "OUTPUT", "-j", chain) != nil {
			break
		}
	}
	_ = runAndroidXtables(command, "", "-w", "-F", chain)
	_ = runAndroidXtables(command, "", "-w", "-X", chain)
}

func runAndroidXtables(name string, stdin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), androidEgressGuardTimeout)
	defer cancel()
	path := name
	if _, err := os.Stat("/system/bin/" + name); err == nil {
		path = "/system/bin/" + name
	}
	command := exec.CommandContext(ctx, path, args...)
	if stdin != "" {
		command.Stdin = strings.NewReader(stdin)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		if message := strings.TrimSpace(string(output)); message != "" {
			return E.Cause(err, message)
		}
		return err
	}
	return nil
}
