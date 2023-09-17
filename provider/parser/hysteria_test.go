package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestHysteriaBuildQUICOptions(t *testing.T) {
	options := (&HysteriaOption{
		ReceiveWindowConn:   65536,
		ReceiveWindow:       32768,
		DisableMTUDiscovery: true,
	}).Build().(*option.HysteriaOutboundOptions)
	require.Equal(t, uint64(65536), options.ConnectionReceiveWindow.Value())
	require.Equal(t, uint64(32768), options.StreamReceiveWindow.Value())
	require.True(t, options.DisablePathMTUDiscovery)
}

func TestHysteriaBuildDefaultReceiveWindows(t *testing.T) {
	options := (&HysteriaOption{}).Build().(*option.HysteriaOutboundOptions)
	require.Nil(t, options.ConnectionReceiveWindow)
	require.Nil(t, options.StreamReceiveWindow)
	require.Zero(t, options.ConnectionReceiveWindow.Value())
	require.Zero(t, options.StreamReceiveWindow.Value())
	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "connection_receive_window")
	require.NotContains(t, string(encoded), "stream_receive_window")
}
