//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"slices"

	E "github.com/sagernet/sing/common/exceptions"
)

func (b *SharedNetworkBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileSharedHostPrefixes(addresses)
	if len(ipv4) > 256 || len(ipv6) > 256 {
		return E.New("shared-network host address policy exceeds eBPF map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	if !slices.Equal(b.hostIPv6, ipv6) {
		if err := replaceBypassCIDRPolicyMap(
			int(b.runtime.host_ipv6_map_fd),
			b.hostIPv6,
			ipv6,
		); err != nil {
			return E.Cause(err, "update shared-network IPv6 host map")
		}
	}
	if !slices.Equal(b.hostIPv4, ipv4) {
		if err := replaceBypassCIDRPolicyMap(
			int(b.runtime.host_ipv4_map_fd),
			b.hostIPv4,
			ipv4,
		); err != nil {
			if !slices.Equal(b.hostIPv6, ipv6) {
				_ = replaceBypassCIDRPolicyMap(
					int(b.runtime.host_ipv6_map_fd),
					ipv6,
					b.hostIPv6,
				)
			}
			return E.Cause(err, "update shared-network IPv4 host map")
		}
	}
	b.hostIPv4 = ipv4
	b.hostIPv6 = ipv6
	return nil
}
