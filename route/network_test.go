package route

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

type networkTestInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
	myInterfaces []string
}

func (m *networkTestInterfaceMonitor) MyInterfaces() []string {
	return m.myInterfaces
}

type networkTestPauseManager struct {
	pause.Manager
	networkPauseCount atomic.Int32
}

func (m *networkTestPauseManager) NetworkPause() {
	m.networkPauseCount.Add(1)
}

func TestNetworkManagerCommitsUnderlyingReplacementOnly(t *testing.T) {
	manager := &NetworkManager{}
	wifi := &control.Interface{
		Name:      "wlan0",
		Index:     10,
		MTU:       1500,
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
	}

	require.True(t, manager.commitDefaultInterface(wifi))
	require.False(t, manager.commitDefaultInterface(wifi), "VPN-status-only change must not commit a new generation")
	require.False(t, manager.commitDefaultInterface(&control.Interface{
		Name:      "wlan0",
		Index:     10,
		MTU:       1400,
		Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.3/24")},
	}), "address and metadata update must not commit a new generation")
	require.False(t, manager.commitDefaultInterface(wifi), "same underlying recovery must not commit a new generation")
	require.True(t, manager.commitDefaultInterface(&control.Interface{Name: "rmnet0", Index: 20}), "underlying replacement must commit exactly once")
	require.False(t, manager.commitDefaultInterface(&control.Interface{Name: "rmnet0", Index: 20}), "duplicate replacement update must not commit twice")
}

func TestNetworkManagerIgnoresTUNSelfInterface(t *testing.T) {
	var canceled atomic.Bool
	manager := &NetworkManager{
		interfaceMonitor: &networkTestInterfaceMonitor{myInterfaces: []string{"tun0"}},
		interfaceUpdateCancel: func() {
			canceled.Store(true)
		},
	}

	manager.notifyInterfaceUpdate(&control.Interface{Name: "tun0", Index: 100}, 0)

	require.False(t, canceled.Load())
	require.False(t, manager.defaultInterfaceKnown)
}

func TestNetworkManagerDefaultLossCancelsPendingUpdate(t *testing.T) {
	pauseManager := &networkTestPauseManager{}
	var canceled atomic.Bool
	manager := &NetworkManager{
		logger:       log.NewNOPFactory().NewLogger("network"),
		pauseManager: pauseManager,
		interfaceUpdateCancel: func() {
			canceled.Store(true)
		},
		defaultInterfaceName:  "wlan0",
		defaultInterfaceIndex: 10,
		defaultInterfaceKnown: true,
	}

	manager.notifyInterfaceUpdate(nil, 0)

	require.True(t, canceled.Load())
	require.Equal(t, int32(1), pauseManager.networkPauseCount.Load())
	require.True(t, manager.defaultInterfaceKnown, "transient loss must retain the last underlying identity")
	require.Equal(t, "wlan0", manager.defaultInterfaceName)
}
