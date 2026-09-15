//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

func TestSharedUDPReplacementIgnoresDelayedClose(t *testing.T) {
	var table sharedUDPClientTable
	key := udpSessionKey{
		Source:         netip.MustParseAddrPort("192.0.2.10:53000"),
		Scope:          udpSessionScopeSharedRewrite,
		InterfaceIndex: 1,
	}
	destination := netip.MustParseAddrPort("203.0.113.80:443")
	redirect := netip.MustParseAddr("127.128.0.1")
	table.setBinding(key, destination, redirect, false)
	first := table.loadOrCreate(key)
	second := table.renew(key)
	if first == second {
		t.Fatal("replacement reused state owned by the previous UDP session")
	}
	table.deleteShared(key, first)
	if current, loaded := table.load(key); !loaded || current != second {
		t.Fatal("delayed close removed replacement shared UDP state")
	}
	if binding, loaded := second.redirectBinding(destination); !loaded || binding.address != redirect {
		t.Fatal("replacement lost the shared UDP reply binding")
	}
}

func TestUpdateSharedRewriteFlowPressure(t *testing.T) {
	usage := commonEBPF.MapUsage{Capacity: 100}
	active, rounds, entered, exited := updateSharedFlowPressure(false, 0, usage)
	if active || rounds != 0 || entered || exited {
		t.Fatal("empty map unexpectedly entered pressure mode")
	}
	usage.Entries = 70
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if !active || !entered || exited {
		t.Fatal("70% map usage did not enter pressure mode")
	}
	usage.Entries = 50
	for expected := 1; expected < sharedFlowPressureExitRounds; expected++ {
		active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
		if !active || rounds != expected || entered || exited {
			t.Fatalf("unexpected pressure exit state at round %d", expected)
		}
	}
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if active || rounds != 0 || entered || !exited {
		t.Fatal("pressure mode did not exit after stable low usage")
	}
}

func TestFlowUsagePressure(t *testing.T) {
	usage := commonEBPF.MapUsage{Capacity: 100}
	if flowUsagePressure(false, usage) {
		t.Fatal("empty flow usage unexpectedly entered pressure mode")
	}
	usage.Entries = 70
	if !flowUsagePressure(false, usage) {
		t.Fatal("70% flow usage did not enter pressure mode")
	}
	usage.Entries = 50
	if flowUsagePressure(true, usage) {
		t.Fatal("50% flow usage did not reach the pressure exit threshold")
	}
	usage.Entries = 49
	if flowUsagePressure(true, usage) {
		t.Fatal("flow usage pressure did not clear below exit threshold")
	}
}

func TestSharedFlowWakeMaintainsPressureSweeps(t *testing.T) {
	usage := commonEBPF.MapUsage{Entries: 80, Capacity: 100}
	knownPressure, sweepRequested := updateSharedFlowWakeState(true, true, false, usage)
	if !knownPressure || !sweepRequested {
		t.Fatalf("pressure wake did not request a maintenance sweep: known=%v requested=%v", knownPressure, sweepRequested)
	}

	usage.Entries = 40
	knownPressure, sweepRequested = updateSharedFlowWakeState(true, true, false, usage)
	if knownPressure || !sweepRequested {
		t.Fatalf("pressure recovery wake stopped maintenance before exit rounds: known=%v requested=%v", knownPressure, sweepRequested)
	}
}

func TestSharedFlowWakeContinuesIncompleteScan(t *testing.T) {
	usage := commonEBPF.MapUsage{Entries: 0, Capacity: 100}
	knownPressure, sweepRequested := updateSharedFlowWakeState(false, false, true, usage)
	if knownPressure || !sweepRequested {
		t.Fatalf("incomplete scan wake was not scheduled: known=%v requested=%v", knownPressure, sweepRequested)
	}
}

func TestSharedRewriteReadyIgnoresInactiveRuntime(t *testing.T) {
	shared := &sharedRewrite{}
	shared.setDataPlane(newSharedKernelRuntime(sharedKernelRuntimeHooks{}, 0))
	shared.sharedRewriteReady([]string{"wlan0(tcx)"})
	if shared.janitorCancel != nil || shared.janitorDone != nil {
		t.Fatal("stale ready callback started the shared flow janitor")
	}
}
