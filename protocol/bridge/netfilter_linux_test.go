package bridge

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func TestResetBridgeRouteTableGuardsBeforeCleanup(t *testing.T) {
	var operations []string
	blackhole := *bridgeBlackholeDefault(2201, unix.AF_INET)
	stale := netlink.Route{
		Table: 2201,
		Dst:   &net.IPNet{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},
	}
	err := resetBridgeRouteTableWith(
		2201,
		[]int{unix.AF_INET},
		func(route *netlink.Route) error {
			operations = append(operations, "blackhole")
			if route.Type != unix.RTN_BLACKHOLE || !isDefaultDestination(route.Dst) {
				t.Fatalf("unexpected guard route: %+v", route)
			}
			return nil
		},
		func(int, *netlink.Route, uint64) ([]netlink.Route, error) {
			operations = append(operations, "list")
			return []netlink.Route{blackhole, stale}, nil
		},
		func(route *netlink.Route) error {
			operations = append(operations, "delete")
			if isDefaultDestination(route.Dst) {
				t.Fatal("blackhole guard was deleted")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"blackhole", "list", "delete"}
	if len(operations) != len(want) {
		t.Fatalf("unexpected operation sequence: %v", operations)
	}
	for index := range want {
		if operations[index] != want[index] {
			t.Fatalf("route cleanup was not fail-closed: %v", operations)
		}
	}
}

func TestResetBridgeRouteTableStopsWhenGuardFails(t *testing.T) {
	guardErr := errors.New("blackhole failed")
	listed := false
	err := resetBridgeRouteTableWith(
		2201,
		[]int{unix.AF_INET},
		func(*netlink.Route) error { return guardErr },
		func(int, *netlink.Route, uint64) ([]netlink.Route, error) {
			listed = true
			return nil, nil
		},
		func(*netlink.Route) error { return nil },
	)
	if !errors.Is(err, guardErr) || listed {
		t.Fatalf("cleanup continued without a blackhole guard: listed=%v err=%v", listed, err)
	}
}
