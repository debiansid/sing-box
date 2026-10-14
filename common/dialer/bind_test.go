package dialer

import (
	"net"
	"testing"

	"github.com/sagernet/sing/common/control"
)

func TestResolveInterfaceWildcard(t *testing.T) {
	finder := control.NewDefaultInterfaceFinder()
	finder.UpdateInterfaces([]control.Interface{
		{
			Index: 10,
			Name:  "ipsec0",
			Flags: net.FlagUp,
		},
		{
			Index: 12,
			Name:  "docker0",
			Flags: 0,
		},
		{
			Index: 20,
			Name:  "ipsec1",
			Flags: net.FlagUp,
		},
	})

	name, idx, err := resolveInterface(finder, "ipsec*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "ipsec1" || idx != 20 {
		t.Fatalf("expected ipsec1 (idx 20), got %s (idx %d)", name, idx)
	}

	finder.UpdateInterfaces([]control.Interface{
		{
			Index: 10,
			Name:  "ipsec0",
			Flags: net.FlagUp,
		},
		{
			Index: 20,
			Name:  "ipsec1",
			Flags: 0,
		},
	})
	name, idx, err = resolveInterface(finder, "ipsec*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "ipsec0" || idx != 10 {
		t.Fatalf("expected ipsec0 (idx 10), got %s (idx %d)", name, idx)
	}

	_, _, err = resolveInterface(finder, "wg*")
	if err == nil {
		t.Fatal("expected error for non-matching pattern wg*, got nil")
	}
}

func TestBindToInterfaceRejectsBadPattern(t *testing.T) {
	if _, err := bindToInterface(nil, "ipsec*["); err == nil {
		t.Fatal("expected malformed bind_interface pattern to be rejected")
	}
}
