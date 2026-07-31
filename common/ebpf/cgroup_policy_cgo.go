//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"errors"
	"net/netip"
	"slices"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func validateMapCapacity(capacity CgroupMapCapacity) error {
	for _, entry := range []struct {
		name  string
		value uint32
	}{
		{"tcp_redirect", capacity.TCPRedirect},
		{"udp_redirect", capacity.UDPRedirect},
		{"socket_bypass", capacity.SocketBypass},
	} {
		if entry.value == 0 || entry.value > MaxConfigurableMapCapacity {
			return E.New("invalid eBPF ", entry.name, " map capacity: ", entry.value)
		}
	}
	return nil
}

func compileUIDPolicy(name string, uidRanges []UIDRange) ([]uidLPMKey, error) {
	for _, uidRange := range uidRanges {
		if uidRange.Start > uidRange.End {
			return nil, E.New("invalid ", name, " range: ", uidRange.Start, ":", uidRange.End)
		}
	}
	entries := compileUIDRanges(uidRanges)
	if len(entries) > maxUIDPolicyEntries {
		return nil, E.New(name, " compiles to too many eBPF map entries: ", len(entries), " > ", maxUIDPolicyEntries)
	}
	return entries, nil
}

func populateUIDPolicyMap(mapFD int, entries []uidLPMKey) error {
	if len(entries) == 0 {
		return nil
	}
	value := uint8(1)
	for entryIndex := range entries {
		if err := updateMap(mapFD, unsafe.Pointer(&entries[entryIndex]), unsafe.Pointer(&value)); err != nil {
			return err
		}
	}
	return nil
}

func (b *CgroupBackend) UpdateBypassCIDR(prefixes []netip.Prefix) (bool, error) {
	ipv4Prefixes, ipv6Prefixes, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return false, E.Cause(err, "compile bypass CIDR policy")
	}
	if len(ipv4Prefixes) > maxBypassCIDRPolicyEntries {
		return false, E.New("IPv4 bypass CIDR policy has too many eBPF map entries: ",
			len(ipv4Prefixes), " > ", maxBypassCIDRPolicyEntries)
	}
	if len(ipv6Prefixes) > maxBypassCIDRPolicyEntries {
		return false, E.New("IPv6 bypass CIDR policy has too many eBPF map entries: ",
			len(ipv6Prefixes), " > ", maxBypassCIDRPolicyEntries)
	}
	if b == nil {
		return false, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return false, errBackendClosed
	}
	ipv4Changed := !slices.Equal(b.bypassIPv4CIDR, ipv4Prefixes)
	ipv6Changed := !slices.Equal(b.bypassIPv6CIDR, ipv6Prefixes)
	if !ipv4Changed && !ipv6Changed {
		return false, nil
	}
	if ipv6Changed {
		if err = replaceBypassCIDRPolicyMap(
			b.bypassIPv6CIDRMapFD,
			b.bypassIPv6CIDR,
			ipv6Prefixes,
		); err != nil {
			return false, E.Cause(err, "update IPv6 bypass CIDR eBPF map")
		}
	}
	if ipv4Changed {
		if err = replaceBypassCIDRPolicyMap(
			b.bypassIPv4CIDRMapFD,
			b.bypassIPv4CIDR,
			ipv4Prefixes,
		); err != nil {
			var rollbackErr error
			if ipv6Changed {
				rollbackErr = replaceBypassCIDRPolicyMap(
					b.bypassIPv6CIDRMapFD,
					ipv6Prefixes,
					b.bypassIPv6CIDR,
				)
			}
			updateErr := E.Cause(err, "update IPv4 bypass CIDR eBPF map")
			if rollbackErr != nil {
				updateErr = E.Errors(
					updateErr,
					E.Cause(rollbackErr, "rollback IPv6 bypass CIDR eBPF map"),
				)
			}
			return false, updateErr
		}
	}
	b.bypassIPv4CIDR = slices.Clone(ipv4Prefixes)
	b.bypassIPv6CIDR = slices.Clone(ipv6Prefixes)
	return true, nil
}

func (b *CgroupBackend) BypassCIDRCount() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.bypassIPv4CIDR), len(b.bypassIPv6CIDR)
}

func replaceBypassCIDRPolicyMap(
	mapFD int,
	currentPrefixes []netip.Prefix,
	nextPrefixes []netip.Prefix,
) error {
	additions, removals := bypassCIDRPolicyDelta(currentPrefixes, nextPrefixes)
	if len(additions) == 0 && len(removals) == 0 {
		return nil
	}
	if mapFD < 0 {
		return errBackendClosed
	}
	value := uint8(1)
	added := make([]netip.Prefix, 0, len(additions))
	for _, prefix := range additions {
		err := updateBypassCIDRMapEntry(mapFD, prefix, &value, bpfNoExist)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return E.Errors(err, rollbackBypassCIDRPolicyMap(mapFD, added, nil))
		}
		added = append(added, prefix)
	}
	removed := make([]netip.Prefix, 0, len(removals))
	for _, prefix := range removals {
		err := deleteBypassCIDRMapEntry(mapFD, prefix)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return E.Errors(err, rollbackBypassCIDRPolicyMap(mapFD, added, removed))
		}
		removed = append(removed, prefix)
	}
	return nil
}

func rollbackBypassCIDRPolicyMap(mapFD int, added []netip.Prefix, removed []netip.Prefix) error {
	var rollbackErr error
	value := uint8(1)
	for _, prefix := range removed {
		if err := updateBypassCIDRMapEntry(mapFD, prefix, &value, 0); err != nil {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	for _, prefix := range added {
		if err := deleteBypassCIDRMapEntry(mapFD, prefix); err != nil && !errors.Is(err, unix.ENOENT) {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	return rollbackErr
}

func updateBypassCIDRMapEntry(mapFD int, prefix netip.Prefix, value *uint8, flags uint64) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
}

func deleteBypassCIDRMapEntry(mapFD int, prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return deleteMap(mapFD, unsafe.Pointer(&key))
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return deleteMap(mapFD, unsafe.Pointer(&key))
}
