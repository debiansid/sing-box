//go:build with_ebpf && (linux || android)

package dialer

import (
	"errors"
	"syscall"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
)

type selfBypassTestNetwork struct {
	adapter.NetworkManager
	lookups int
}

func (n *selfBypassTestNetwork) EBPFSelfBypass() *commonEBPF.SelfBypass {
	n.lookups++
	return nil
}

func TestEndpointSelfBypassPreservesSocketControl(t *testing.T) {
	n := &selfBypassTestNetwork{}
	var controlErr error
	calls := 0
	chain := AppendEBPFSelfBypass(n, func(string, string, syscall.RawConn) error {
		calls++
		return controlErr
	})
	if err := chain("udp", "203.0.113.1:4500", nil); err != nil || calls != 1 || n.lookups != 1 {
		t.Fatal("underlying/protect callback did not precede self-bypass", err)
	}
	controlErr = errors.New("protect failed")
	if err := chain("udp", "203.0.113.1:4500", nil); !errors.Is(err, controlErr) || n.lookups != 1 {
		t.Fatal("protect failure was not propagated", err)
	}
	// Registration alone must not call any NetworkManager routing/protect
	// method (the embedded interface is nil). It only identifies core cookies.
	if err := AppendEBPFSelfBypass(n, nil)("udp", "198.51.100.1:443", nil); err != nil {
		t.Fatal(err)
	}
}
