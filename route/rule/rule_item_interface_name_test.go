package rule

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
)

type testNetworkManager struct {
	adapter.NetworkManager
	finder control.InterfaceFinder
}

func (m *testNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return m.finder
}

func TestInterfaceNameItem(t *testing.T) {
	finder := control.NewDefaultInterfaceFinder()
	nm := &testNetworkManager{finder: finder}

	item := NewInterfaceNameItem(nm, []string{"ipsec*"})

	// 1. Google VPN not running -> match false
	finder.UpdateInterfaces([]control.Interface{
		{
			Index: 1,
			Name:  "lo",
			Flags: net.FlagUp,
		},
		{
			Index: 2,
			Name:  "wlan0",
			Flags: net.FlagUp,
		},
	})
	require.False(t, item.Match(&adapter.InboundContext{}))

	// 2. Google VPN interface exists but is DOWN -> match false
	finder.UpdateInterfaces([]control.Interface{
		{
			Index: 10,
			Name:  "ipsec0",
			Flags: 0,
		},
	})
	require.False(t, item.Match(&adapter.InboundContext{}))

	// 3. Google VPN is turned ON (ipsec0 is UP) -> match true
	finder.UpdateInterfaces([]control.Interface{
		{
			Index: 10,
			Name:  "ipsec0",
			Flags: net.FlagUp,
		},
	})
	require.True(t, item.Match(&adapter.InboundContext{}))

	// 4. Google VPN reconnects as ipsec1 -> match true
	finder.UpdateInterfaces([]control.Interface{
		{
			Index: 11,
			Name:  "ipsec1",
			Flags: net.FlagUp,
		},
	})
	require.True(t, item.Match(&adapter.InboundContext{}))

	// 5. Google VPN disconnected -> match false
	finder.UpdateInterfaces([]control.Interface{})
	require.False(t, item.Match(&adapter.InboundContext{}))
}
