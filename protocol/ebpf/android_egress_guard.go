//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	androidEgressGuardChain    = "sb_ebpf_local_guard"
	androidEgressGuardTimeout  = 5 * time.Second
	androidFirstApplicationUID = 10000
	androidLastUID             = 2147483647
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
	access  sync.Mutex
	applied string
}

// The local socket-assignment path only captures packets leaving the interface its TC programs
// are attached to. Until they follow a new default network, and on any other network an app is
// implicitly routed to, proxied apps would leave unproxied, so their packets are refused on every
// interface but the attached one. Sockets explicitly bound to a network, VPN interfaces, private
// destinations and system UIDs, which include the core, are left alone.
func (i *Inbound) syncAndroidEgressGuard(localInterface string) {
	if runtime.GOOS != "android" || !i.localSocketAssignEnabled() {
		return
	}
	ipv4Rules := i.androidEgressGuardRules(localInterface, androidEgressGuardIPv4Unrouted)
	ipv6Rules := ""
	if i.localIPv6 {
		ipv6Rules = i.androidEgressGuardRules(localInterface, androidEgressGuardIPv6Unrouted)
	}
	applied := ipv4Rules + "\n" + ipv6Rules
	state := &i.egressGuard
	state.access.Lock()
	defer state.access.Unlock()
	if applied == state.applied {
		return
	}
	err := applyAndroidEgressGuard("iptables", ipv4Rules)
	if err == nil {
		if ipv6Rules != "" {
			err = applyAndroidEgressGuard("ip6tables", ipv6Rules)
		} else {
			removeAndroidEgressGuardFamily("ip6tables")
		}
	}
	if err != nil {
		state.applied = ""
		i.logger.Warn("eBPF local egress guard: ", err)
		return
	}
	state.applied = applied
	i.logger.Debug("eBPF local egress guard allows interface: ", localInterface)
}

func (i *Inbound) removeAndroidEgressGuard() {
	if runtime.GOOS != "android" {
		return
	}
	state := &i.egressGuard
	state.access.Lock()
	defer state.access.Unlock()
	removeAndroidEgressGuardFamily("iptables")
	removeAndroidEgressGuardFamily("ip6tables")
	state.applied = ""
}

func (i *Inbound) androidEgressGuardRules(localInterface string, unrouted []string) string {
	var builder strings.Builder
	builder.WriteString("*filter\n:" + androidEgressGuardChain + " - [0:0]\n-F " + androidEgressGuardChain + "\n")
	add := func(rule string) {
		builder.WriteString("-A " + androidEgressGuardChain + " " + rule + "\n")
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
	decisions, defaultDecision := i.compileProcessUIDPolicy()
	if defaultDecision == commonEBPF.DecisionIntercept {
		for _, decision := range decisions {
			if decision.Action == commonEBPF.DecisionPass {
				add(androidUIDOwner(decision.Start, decision.End) + " -j RETURN")
			}
		}
		add(androidUIDOwner(androidFirstApplicationUID, androidLastUID) + " -j REJECT")
	} else {
		for _, decision := range decisions {
			if decision.Action != commonEBPF.DecisionIntercept {
				continue
			}
			start := max(decision.Start, androidFirstApplicationUID)
			end := min(decision.End, androidLastUID)
			if start <= end {
				add(androidUIDOwner(start, end) + " -j REJECT")
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
func applyAndroidEgressGuard(command string, rules string) error {
	if err := runAndroidXtables(command+"-restore", rules, "-w", "--noflush"); err != nil {
		return E.Cause(err, command, "-restore")
	}
	if runAndroidXtables(command, "", "-w", "-C", "OUTPUT", "-j", androidEgressGuardChain) == nil {
		return nil
	}
	if err := runAndroidXtables(command, "", "-w", "-I", "OUTPUT", "1", "-j", androidEgressGuardChain); err != nil {
		return E.Cause(err, command, " OUTPUT jump")
	}
	return nil
}

func removeAndroidEgressGuardFamily(command string) {
	for attempt := 0; attempt < 8; attempt++ {
		if runAndroidXtables(command, "", "-w", "-D", "OUTPUT", "-j", androidEgressGuardChain) != nil {
			break
		}
	}
	_ = runAndroidXtables(command, "", "-w", "-F", androidEgressGuardChain)
	_ = runAndroidXtables(command, "", "-w", "-X", androidEgressGuardChain)
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
