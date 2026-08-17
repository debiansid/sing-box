//go:build with_ebpf && ebpf_debug && (linux || android)

package ebpf

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

func TestEBPFDebugStateSnapshot(t *testing.T) {
	var state eBPFDebugState
	state.observe(ebpfDebugTaskSharedFlowSweep, 5*time.Millisecond, nil)
	state.observe(ebpfDebugTaskSharedFlowSweep, 9*time.Millisecond, errors.New("test"))
	policy, err := ECommon.CompileBypassCIDRPolicy([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/25"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("2001:db8::/32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	state.observeBypassPolicyCompile(time.Now().Add(-time.Millisecond), 3, policy, nil)
	state.observeBypassPolicyUpdate(time.Now().Add(-time.Millisecond), nil)
	snapshot := state.snapshot()
	metric := snapshot.Maintenance[ebpfDebugTaskSharedFlowSweep]
	if !snapshot.Build || metric.Runs != 2 || metric.Errors != 1 ||
		metric.TotalDurationNanos != uint64(14*time.Millisecond) ||
		metric.MaxDurationNanos != uint64(9*time.Millisecond) ||
		metric.LastDurationNanos != uint64(9*time.Millisecond) {
		t.Fatalf("unexpected eBPF debug snapshot: %+v", snapshot)
	}
	if snapshot.GoRuntime.Goroutines == 0 || snapshot.GoRuntime.SysBytes == 0 {
		t.Fatalf("incomplete Go runtime snapshot: %+v", snapshot.GoRuntime)
	}
	if snapshot.BypassPolicy.RawPrefixes != 3 || snapshot.BypassPolicy.IPv4Prefixes != 1 ||
		snapshot.BypassPolicy.IPv6Prefixes != 1 || snapshot.BypassPolicy.Compile.Runs != 1 ||
		snapshot.BypassPolicy.Update.Runs != 1 {
		t.Fatalf("unexpected bypass policy snapshot: %+v", snapshot.BypassPolicy)
	}
	var localWriter eBPFDebugUDPWriterState
	if !state.localUDPBindingMiss.observe(&localWriter, false) ||
		state.localUDPBindingMiss.observe(&localWriter, false) {
		t.Fatal("unexpected local UDP binding miss session classification")
	}
	var sharedWriter eBPFDebugUDPWriterState
	if !state.sharedUDPBindingMiss.observe(&sharedWriter, true) {
		t.Fatal("unexpected shared UDP binding miss session classification")
	}
	snapshot = state.snapshot()
	if snapshot.UDPBindingMiss.Local.UnconnectedPackets != 2 ||
		snapshot.UDPBindingMiss.Local.UnconnectedSessions != 1 ||
		snapshot.UDPBindingMiss.Shared.ConnectedPackets != 1 ||
		snapshot.UDPBindingMiss.Shared.ConnectedSessions != 1 {
		t.Fatalf("unexpected UDP binding miss snapshot: %+v", snapshot.UDPBindingMiss)
	}
}

func TestEBPFDebugPProfMux(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine?debug=1", nil)
	response := httptest.NewRecorder()
	newEBPFDebugPProfMux().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.Len() == 0 {
		t.Fatalf("unexpected pprof response: status=%d length=%d", response.Code, response.Body.Len())
	}
}

func TestEBPFDebugPProfRejectsInvalidPort(t *testing.T) {
	t.Setenv(ebpfDebugPProfPortEnv, "invalid")
	if release, err := acquireEBPFDebugPProf(nil); err == nil || release != nil {
		t.Fatalf("unexpected pprof result: release=%v err=%v", release != nil, err)
	}
}
