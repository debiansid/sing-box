//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestSharedRewriteRetiresReplacedAndRemovedAttachmentsOnce(t *testing.T) {
	kept := &sharedRewriteAttachment{interfaceName: "kept", interfaceIndex: 1}
	repaired := &sharedRewriteAttachment{interfaceName: "repaired", interfaceIndex: 2}
	recreated := &sharedRewriteAttachment{interfaceName: "recreated", interfaceIndex: 3}
	removed := &sharedRewriteAttachment{interfaceName: "removed", interfaceIndex: 4}
	current := map[string]*sharedRewriteAttachment{
		"kept": kept, "repaired": repaired, "recreated": recreated, "removed": removed,
	}
	candidate := map[string]*sharedRewriteAttachment{
		"kept":      kept,
		"repaired":  {interfaceName: "repaired", interfaceIndex: 2},
		"recreated": {interfaceName: "recreated", interfaceIndex: 5},
		"added":     {interfaceName: "added", interfaceIndex: 6},
	}
	retired := retiredSharedRewriteAttachments(current, candidate)
	counts := make(map[*sharedRewriteAttachment]int)
	for _, attachment := range retired {
		counts[attachment]++
	}
	if len(retired) != 3 || counts[repaired] != 1 || counts[recreated] != 1 || counts[removed] != 1 {
		t.Fatalf("each replaced or removed attachment must retire once: %+v", counts)
	}
	if len(current) != 4 || len(candidate) != 4 || candidate["kept"] != kept {
		t.Fatal("retirement selection mutated staged or current ownership")
	}
	if retired := retiredSharedRewriteAttachments(candidate, candidate); len(retired) != 0 {
		t.Fatal("unchanged topology retired an active attachment")
	}
}
