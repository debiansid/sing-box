package parser

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestOverrideDialerOptionPreservesExistingDetour(t *testing.T) {
	options := overrideDialerOption(option.DialerOptions{
		Detour: "config-out",
	}, &option.OverrideDialerOptions{
		Detour: stringPtr("override"),
	})

	require.Equal(t, "config-out", options.Detour)
}

func TestOverrideDialerOptionAppliesProviderOverrideDetour(t *testing.T) {
	options := overrideDialerOption(option.DialerOptions{}, &option.OverrideDialerOptions{
		Detour: stringPtr("upstream"),
	})

	require.Equal(t, "upstream", options.Detour)
}

func TestOverrideDialerOptionAllowsConfigOverrideDetour(t *testing.T) {
	options := overrideDialerOption(option.DialerOptions{}, &option.OverrideDialerOptions{
		Detour: stringPtr("config-out"),
	})

	require.Equal(t, "config-out", options.Detour)
}

func stringPtr(value string) *string {
	return &value
}
