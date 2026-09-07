//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

type vpnPayloadPlatformStub bool

func (s vpnPayloadPlatformStub) UsePlatformAutoDetectInterfaceControl() bool {
	return bool(s)
}

type vpnPayloadMonitorStub struct {
	enabled      bool
	myInterfaces []string
}

func (s vpnPayloadMonitorStub) AndroidVPNEnabled() bool { return s.enabled }
func (s vpnPayloadMonitorStub) MyInterfaces() []string  { return s.myInterfaces }

func TestTCPVPNPayloadContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if !adapter.IsVPNPayloadContext(tcPathContext(ctx, commonEBPF.TCPathShared, true)) {
		t.Fatal("shared TCP path did not receive VPN payload intent")
	}
	if adapter.IsVPNPayloadContext(tcPathContext(ctx, commonEBPF.TCPathDelivery, true)) {
		t.Fatal("non-shared TCP path received VPN payload intent")
	}
	if adapter.IsVPNPayloadContext(tcPathContext(ctx, commonEBPF.TCPathShared, false)) {
		t.Fatal("disabled Android VPN capability produced VPN payload intent")
	}
}

func TestVPNPayloadPlatformGate(t *testing.T) {
	t.Parallel()

	platform := vpnPayloadPlatformStub(true)
	monitor := vpnPayloadMonitorStub{myInterfaces: []string{"tun0"}}
	if !vpnPayloadEnabledForPlatform(true, platform, monitor) {
		t.Fatal("active Android platform TUN was not detected")
	}
	if vpnPayloadEnabledForPlatform(false, platform, monitor) {
		t.Fatal("non-Android platform entered VPN payload path")
	}
	if vpnPayloadEnabledForPlatform(true, vpnPayloadPlatformStub(false), monitor) {
		t.Fatal("platform without protect capability entered VPN payload path")
	}
	if vpnPayloadEnabledForPlatform(true, platform, vpnPayloadMonitorStub{}) {
		t.Fatal("inactive Android VPN entered VPN payload path")
	}
}

func TestUDPDirectBindingUsesCommittedAttachmentGeneration(t *testing.T) {
	inbound := &Inbound{tcDataPlane: &tcDataPlane{attachments: []*tcInterfaceAttachment{
		{
			interfaceIndex: 2,
			role:           tcInterfaceRole{shared: true},
			generation:     7,
		},
	}}}
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	state, attachmentLoaded, accepted := inbound.setUDPDirectBinding(
		client,
		destination,
		nil,
		0,
		commonEBPF.TCPathShared,
		2,
	)
	if !attachmentLoaded || !accepted || state.tcAttachmentGeneration() != 7 {
		t.Fatalf("unexpected UDP attachment binding: loaded=%v accepted=%v state=%+v", attachmentLoaded, accepted, state)
	}
	if _, attachmentLoaded, _ = inbound.setUDPDirectBinding(
		netip.MustParseAddrPort("192.0.2.11:53001"),
		destination,
		nil,
		0,
		commonEBPF.TCPathShared,
		3,
	); attachmentLoaded {
		t.Fatal("stale assignment ifindex resolved against the committed attachments")
	}
}
