//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"golang.org/x/sys/unix"
)

func TestTCXUnsupportedError(t *testing.T) {
	if !tcxUnsupportedError(CiliumEBPF.ErrNotSupported) ||
		!tcxUnsupportedError(errors.Join(errors.New("attach"), unix.EOPNOTSUPP)) ||
		!tcxUnsupportedError(unix.ENOSYS) {
		t.Fatal("expected unsupported TCX errors to be classified")
	}
	if tcxUnsupportedError(unix.EPERM) || tcxUnsupportedError(unix.EINVAL) {
		t.Fatal("permission and interface-specific errors must not disable TCX globally")
	}
}

func TestTCVethNamesFitLinuxLimit(t *testing.T) {
	redirectName, deliveryName, err := nextTCVethNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(redirectName) > 15 || len(deliveryName) > 15 {
		t.Fatalf("delivery link names exceed Linux limit: %q %q", redirectName, deliveryName)
	}
	if redirectName == deliveryName {
		t.Fatal("delivery link names are identical")
	}
}

func TestRetainLocalAttachmentStatesDuringHandoff(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"wlan2": {
			index:   2,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{shared: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("", desired, attachments)

	state, loaded := desired["rmnet_data1"]
	if !loaded {
		t.Fatal("local attachment was not retained while default interface was unavailable")
	}
	if state.index != 19 || state.framing != commonEBPF.TCLinkFramingRawIP || !state.role.local {
		t.Fatalf("unexpected retained local state: %+v", state)
	}
	if _, loaded = desired["wlan2"]; !loaded {
		t.Fatal("shared attachment was dropped while retaining local attachment")
	}
}

func TestRetainLocalAttachmentStatesDoesNotOverrideNewDefault(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"rmnet_data2": {
			index:   20,
			framing: commonEBPF.TCLinkFramingRawIP,
			role:    tcInterfaceRole{local: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("rmnet_data2", desired, attachments)

	if _, loaded := desired["rmnet_data1"]; loaded {
		t.Fatal("stale local attachment was retained after a new default interface appeared")
	}
}

func TestTCAttachmentGenerationStability(t *testing.T) {
	dataPlane := new(tcDataPlane)
	local := &tcInterfaceAttachment{
		interfaceName:  "rmnet_data1",
		interfaceIndex: 19,
		framing:        commonEBPF.TCLinkFramingRawIP,
		role:           tcInterfaceRole{local: true},
	}
	shared := &tcInterfaceAttachment{
		interfaceName:  "wlan2",
		interfaceIndex: 2,
		framing:        commonEBPF.TCLinkFramingEthernet,
		role:           tcInterfaceRole{shared: true},
	}
	attachments := []*tcInterfaceAttachment{local, shared}
	dataPlane.refreshAttachmentGenerations(attachments, nil, nil)
	localGeneration := local.generation
	sharedGeneration := shared.generation
	if localGeneration == 0 || sharedGeneration == 0 || localGeneration == sharedGeneration {
		t.Fatalf("invalid initial attachment generations: local=%d shared=%d", localGeneration, sharedGeneration)
	}

	previous := map[string]*tcInterfaceAttachment{local.interfaceName: local, shared.interfaceName: shared}
	previousRoles := map[string]tcInterfaceRole{local.interfaceName: local.role, shared.interfaceName: shared.role}
	shared.attachmentType = "clsact" // A health repair may replace filter handles without replacing the attachment.
	dataPlane.refreshAttachmentGenerations(attachments, previous, previousRoles)
	if local.generation != localGeneration || shared.generation != sharedGeneration {
		t.Fatal("unchanged or health-repaired attachments changed generation")
	}
}

func TestTCAttachmentGenerationChangesOnReplacement(t *testing.T) {
	dataPlane := new(tcDataPlane)
	previous := &tcInterfaceAttachment{
		interfaceName:  "wlan2",
		interfaceIndex: 2,
		framing:        commonEBPF.TCLinkFramingEthernet,
		role:           tcInterfaceRole{shared: true},
	}
	dataPlane.refreshAttachmentGenerations([]*tcInterfaceAttachment{previous}, nil, nil)
	previousGeneration := previous.generation
	previousAttachments := map[string]*tcInterfaceAttachment{previous.interfaceName: previous}
	previousRoles := map[string]tcInterfaceRole{previous.interfaceName: previous.role}

	ifindexReplacement := &tcInterfaceAttachment{
		interfaceName:  previous.interfaceName,
		interfaceIndex: 3,
		framing:        previous.framing,
		role:           previous.role,
	}
	dataPlane.refreshAttachmentGenerations([]*tcInterfaceAttachment{ifindexReplacement}, previousAttachments, previousRoles)
	if ifindexReplacement.generation == previousGeneration {
		t.Fatal("ifindex replacement retained the previous attachment generation")
	}

	framingReplacement := &tcInterfaceAttachment{
		interfaceName:  ifindexReplacement.interfaceName,
		interfaceIndex: ifindexReplacement.interfaceIndex,
		framing:        commonEBPF.TCLinkFramingRawIP,
		role:           ifindexReplacement.role,
	}
	dataPlane.refreshAttachmentGenerations(
		[]*tcInterfaceAttachment{framingReplacement},
		map[string]*tcInterfaceAttachment{ifindexReplacement.interfaceName: ifindexReplacement},
		map[string]tcInterfaceRole{ifindexReplacement.interfaceName: ifindexReplacement.role},
	)
	if framingReplacement.generation == ifindexReplacement.generation {
		t.Fatal("framing replacement retained the previous attachment generation")
	}

	framingGeneration := framingReplacement.generation
	previousRole := framingReplacement.role
	framingReplacement.role.local = true
	dataPlane.refreshAttachmentGenerations(
		[]*tcInterfaceAttachment{framingReplacement},
		map[string]*tcInterfaceAttachment{framingReplacement.interfaceName: framingReplacement},
		map[string]tcInterfaceRole{framingReplacement.interfaceName: previousRole},
	)
	if framingReplacement.generation == framingGeneration {
		t.Fatal("role replacement retained an old attachment generation")
	}
}

func TestUDPAttachmentGenerationResolution(t *testing.T) {
	dataPlane := &tcDataPlane{attachments: []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			role:           tcInterfaceRole{local: true},
			generation:     7,
		},
		{
			interfaceName:  "wlan2",
			interfaceIndex: 2,
			role:           tcInterfaceRole{shared: true},
			generation:     8,
		},
	}}
	if generation, loaded := dataPlane.udpAttachmentGeneration(commonEBPF.TCPathShared, 2); !loaded || generation != 8 {
		t.Fatalf("unexpected shared attachment generation: %d loaded=%v", generation, loaded)
	}
	if generation, loaded := dataPlane.udpAttachmentGeneration(commonEBPF.TCPathDelivery, 999); !loaded || generation != 7 {
		t.Fatalf("unexpected local attachment generation: %d loaded=%v", generation, loaded)
	}
	if _, loaded := dataPlane.udpAttachmentGeneration(commonEBPF.TCPathShared, 3); loaded {
		t.Fatal("unknown shared ifindex resolved an attachment generation")
	}
}

func TestInvalidatedAttachmentGenerations(t *testing.T) {
	testCases := []struct {
		name        string
		previous    []uint64
		current     []uint64
		invalidated []uint64
	}{
		{name: "unchanged", previous: []uint64{7, 8}, current: []uint64{7, 8}},
		{name: "health repair", previous: []uint64{7}, current: []uint64{7}},
		{name: "local replacement", previous: []uint64{7, 8}, current: []uint64{8, 9}, invalidated: []uint64{7}},
		{name: "shared removal", previous: []uint64{7, 8}, current: []uint64{7}, invalidated: []uint64{8}},
		{name: "ifindex replacement", previous: []uint64{7}, current: []uint64{8}, invalidated: []uint64{7}},
		{name: "framing replacement", previous: []uint64{7}, current: []uint64{8}, invalidated: []uint64{7}},
		{name: "role replacement", previous: []uint64{7}, current: []uint64{8}, invalidated: []uint64{7}},
		{name: "addition", previous: []uint64{7}, current: []uint64{7, 8}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			previous := make(map[uint64]struct{}, len(testCase.previous))
			for _, generation := range testCase.previous {
				previous[generation] = struct{}{}
			}
			attachments := make([]*tcInterfaceAttachment, 0, len(testCase.current))
			for _, generation := range testCase.current {
				attachments = append(attachments, &tcInterfaceAttachment{generation: generation})
			}
			invalidated := invalidatedAttachmentGenerations(previous, attachments)
			if len(invalidated) != len(testCase.invalidated) {
				t.Fatalf("unexpected invalidated generations: %v", invalidated)
			}
			for _, generation := range testCase.invalidated {
				if _, loaded := invalidated[generation]; !loaded {
					t.Fatalf("generation %d was not invalidated: %v", generation, invalidated)
				}
			}
		})
	}
}

func TestTCReconcileFailureDoesNotInvalidateGenerations(t *testing.T) {
	attachment := &tcInterfaceAttachment{generation: 7}
	dataPlane := &tcDataPlane{attachments: []*tcInterfaceAttachment{attachment}}
	invalidated, err := dataPlane.reconcile("", nil, nil)
	if err == nil {
		t.Fatal("closed data plane reconcile unexpectedly succeeded")
	}
	if len(invalidated) != 0 {
		t.Fatalf("failed reconcile invalidated attachment generations: %v", invalidated)
	}
	if dataPlane.attachments[0] != attachment || attachment.generation != 7 {
		t.Fatal("failed reconcile changed the committed attachment state")
	}
}
