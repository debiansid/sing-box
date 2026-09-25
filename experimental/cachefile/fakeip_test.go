package cachefile

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestFakeIPResetWithMissingBuckets(t *testing.T) {
	t.Parallel()

	cache := New(context.Background(), logger.NOP(), option.CacheFileOptions{Path: filepath.Join(t.TempDir(), "cache.db")})
	scope := adapter.NewScope(context.Background(), logger.NOP())
	require.NoError(t, cache.Start(adapter.StartStateInitialize, scope))
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	require.NoError(t, cache.FakeIPReset())

	address := netip.MustParseAddr("198.18.0.2")
	require.NoError(t, cache.FakeIPStore(address, "a.example.com"))
	require.NoError(t, cache.FakeIPReset())
	_, loaded := cache.FakeIPLoad(address)
	require.False(t, loaded)
	_, loaded = cache.FakeIPLoadDomain("a.example.com", false)
	require.False(t, loaded)
}
