//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestBypassCIDRPolicyControlFailureRollsBack(t *testing.T) {
	current := dualStackCIDRPrefixes{ipv4: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	next := dualStackCIDRPrefixes{ipv6: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}}
	control := tcControl{Flags: 1<<4 | 1<<5 | 1<<12 | 1<<13 | 1<<14 | 1<<15 | 1<<8}
	controlErr := errors.New("control update failed")
	var transitions [][2]dualStackCIDRPrefixes
	committed, committedControl, changed, err := updateBypassCIDRPolicyTransaction(
		current,
		next,
		control,
		func(from, to dualStackCIDRPrefixes) (bool, error) {
			transitions = append(transitions, [2]dualStackCIDRPrefixes{from, to})
			return true, nil
		},
		func(tcControl) error { return controlErr },
	)
	if !errors.Is(err, controlErr) || changed {
		t.Fatalf("unexpected transaction result: changed=%v err=%v", changed, err)
	}
	if len(transitions) != 2 || !equalDualStackPrefixes(transitions[1][0], next) || !equalDualStackPrefixes(transitions[1][1], current) {
		t.Fatalf("old map policy was not restored: %+v", transitions)
	}
	if !equalDualStackPrefixes(committed, current) || committedControl != control {
		t.Fatalf("committed Go baseline advanced after control failure: policy=%+v control=%+v", committed, committedControl)
	}
}

func TestBypassCIDRPolicyRollbackFailureThenRetryConverges(t *testing.T) {
	current := dualStackCIDRPrefixes{ipv4: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	next := dualStackCIDRPrefixes{ipv4: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
	staticFlags := uint32(1<<4 | 1<<5 | 1<<12 | 1<<13 | 1<<14 | 1<<15)
	control := tcControl{Flags: staticFlags | 1<<8}
	controlErr := errors.New("control update failed")
	rollbackErr := errors.New("rollback failed")
	call := 0
	committed, committedControl, _, err := updateBypassCIDRPolicyTransaction(
		current,
		next,
		control,
		func(_, _ dualStackCIDRPrefixes) (bool, error) {
			call++
			if call == 2 {
				return false, rollbackErr
			}
			return true, nil
		},
		func(tcControl) error { return controlErr },
	)
	if !errors.Is(err, controlErr) || !errors.Is(err, rollbackErr) || !policyRollbackFailed(err) {
		t.Fatalf("rollback failure was not retained: %v", err)
	}
	if !equalDualStackPrefixes(committed, current) || committedControl != control {
		t.Fatal("failed transaction advanced committed baseline")
	}
	committed, committedControl, changed, err := updateBypassCIDRPolicyTransaction(
		committed,
		next,
		committedControl,
		func(_, to dualStackCIDRPrefixes) (bool, error) {
			if !equalDualStackPrefixes(to, next) {
				t.Fatalf("retry did not converge to latest desired policy: %+v", to)
			}
			return true, nil
		},
		func(tcControl) error { return nil },
	)
	if err != nil || !changed || !equalDualStackPrefixes(committed, next) {
		t.Fatalf("retry did not commit latest desired policy: changed=%v policy=%+v err=%v", changed, committed, err)
	}
	if committedControl.Flags&staticFlags != control.Flags&staticFlags {
		t.Fatalf("local UID/package or shared source CIDR/MAC policy flags changed: %#x", committedControl.Flags)
	}
}

func equalDualStackPrefixes(left, right dualStackCIDRPrefixes) bool {
	return slices.Equal(left.ipv4, right.ipv4) && slices.Equal(left.ipv6, right.ipv6)
}
