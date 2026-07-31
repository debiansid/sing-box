package ebpf

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

type SharedNetworkConfig struct {
	ListenerPort uint16
	EnableTCP    bool
	EnableUDP    bool
	RedirectIPv4 netip.Prefix
	RedirectIPv6 netip.Prefix
	MapCapacity  uint32
}

type sharedNetworkControl struct {
	Enabled             uint32
	Flags               uint32
	ListenerPort        uint16
	Reserved            uint16
	TokenIPv4Prefix     [4]byte
	TokenIPv4PrefixBits uint8
	TokenIPv6PrefixBits uint8
	Reserved2           [2]byte
	TokenIPv6Prefix     [16]byte
}

type sharedNetworkListenerKey struct {
	Family       uint8
	Protocol     uint8
	ListenerPort uint16
	TokenAddr    [16]byte
	ClientPort   uint16
	Reserved     uint16
	ClientAddr   [16]byte
}

type sharedNetworkOriginalKey struct {
	InterfaceIndex uint32
	Family         uint8
	Protocol       uint8
	ClientPort     uint16
	OriginalPort   uint16
	Reserved       uint16
	ClientAddr     [16]byte
	OriginalAddr   [16]byte
}

type sharedNetworkReplyKey struct {
	InterfaceIndex uint32
	Family         uint8
	Protocol       uint8
	ClientPort     uint16
	ListenerPort   uint16
	Reserved       uint16
	ClientAddr     [16]byte
	TokenAddr      [16]byte
}

type sharedNetworkOriginalValue struct {
	Family         uint8
	Protocol       uint8
	Port           uint16
	Addr           [16]byte
	InterfaceIndex uint32
	Reserved       uint32
}

type SharedNetworkFlowHandle struct {
	originalKey sharedNetworkOriginalKey
	replyKey    sharedNetworkReplyKey
	listenerKey sharedNetworkListenerKey
}

const (
	sharedNetworkFlagIPv4 = 1 << iota
	sharedNetworkFlagIPv6
	sharedNetworkFlagTCP
	sharedNetworkFlagUDP
	sharedNetworkFlagDNSHijack
)

func makeSharedNetworkListenerKey(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (sharedNetworkListenerKey, error) {
	var key sharedNetworkListenerKey
	key.Protocol = protocol
	key.ListenerPort = tokenDestination.Port()
	key.ClientPort = client.Port()
	if err := encodeAddress(&key.Family, &key.TokenAddr, tokenDestination.Addr()); err != nil {
		return sharedNetworkListenerKey{}, E.Cause(err, "invalid shared-network redirect address")
	}
	var clientFamily uint8
	if err := encodeAddress(&clientFamily, &key.ClientAddr, client.Addr()); err != nil {
		return sharedNetworkListenerKey{}, E.Cause(err, "invalid shared-network client address")
	}
	if clientFamily != key.Family {
		return sharedNetworkListenerKey{}, E.New("shared-network client and redirect address families do not match")
	}
	return key, nil
}

func sharedNetworkOriginalAddress(value sharedNetworkOriginalValue) (netip.Addr, error) {
	switch value.Family {
	case addressFamilyIPv4:
		return netip.AddrFrom4([4]byte(value.Addr[:4])), nil
	case addressFamilyIPv6:
		return netip.AddrFrom16(value.Addr), nil
	default:
		return netip.Addr{}, E.New("invalid original destination family: ", value.Family)
	}
}

func makeSharedNetworkFlowHandle(key sharedNetworkListenerKey, value sharedNetworkOriginalValue) SharedNetworkFlowHandle {
	return SharedNetworkFlowHandle{
		originalKey: sharedNetworkOriginalKey{
			InterfaceIndex: value.InterfaceIndex,
			Family:         key.Family,
			Protocol:       key.Protocol,
			ClientPort:     key.ClientPort,
			OriginalPort:   value.Port,
			ClientAddr:     key.ClientAddr,
			OriginalAddr:   value.Addr,
		},
		replyKey: sharedNetworkReplyKey{
			InterfaceIndex: value.InterfaceIndex,
			Family:         key.Family,
			Protocol:       key.Protocol,
			ClientPort:     key.ClientPort,
			ListenerPort:   key.ListenerPort,
			ClientAddr:     key.ClientAddr,
			TokenAddr:      key.TokenAddr,
		},
		listenerKey: key,
	}
}
