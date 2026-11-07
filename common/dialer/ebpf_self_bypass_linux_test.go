//go:build with_ebpf && (linux || android)

package dialer

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

type halfCloseTestConn struct {
	net.Conn
	readClosed, writeClosed bool
	closes                  int
}

func (c *halfCloseTestConn) CloseRead() error  { c.readClosed = true; return nil }
func (c *halfCloseTestConn) CloseWrite() error { c.writeClosed = true; return nil }
func (c *halfCloseTestConn) Close() error      { c.closes++; return nil }

func TestSelfBypassPreservesHalfClose(t *testing.T) {
	underlying := &halfCloseTestConn{}
	cleanups := 0
	wrapped := &selfBypassConn{Conn: underlying, cleanup: func() { cleanups++ }}
	if err := N.CloseWrite(wrapped); err != nil {
		t.Fatal(err)
	}
	if err := N.CloseRead(wrapped); err != nil {
		t.Fatal(err)
	}
	if !underlying.writeClosed || !underlying.readClosed || cleanups != 0 || underlying.closes != 0 {
		t.Fatal("half close must reach the socket without unregistering it")
	}
	if N.UnwrapReader(wrapped) != underlying || N.UnwrapWriter(wrapped) != underlying {
		t.Fatal("I/O capabilities must remain accessible")
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Go(func() { _ = wrapped.Close() })
	}
	wait.Wait()
	if cleanups != 1 || underlying.closes != 1 {
		t.Fatal("full close must run exactly once")
	}
}

type noSelfBypassNetworkManager struct{ adapter.NetworkManager }

func (noSelfBypassNetworkManager) EBPFSelfBypass() *commonEBPF.SelfBypass { return nil }

func TestSelfBypassWithoutLocalInboundIsInert(t *testing.T) {
	if AppendEBPFSelfBypass(noSelfBypassNetworkManager{}, nil) != nil {
		t.Fatal("no tracker must mean no socket control callback")
	}
}

func TestSelfBypassCleanupModeContract(t *testing.T) {
	if !selfBypassNeedsUserspaceCleanup("userspace_unregister") {
		t.Fatal("userspace unregister mode must install close cleanup")
	}
	if selfBypassNeedsUserspaceCleanup("socket_release") {
		t.Fatal("kernel release mode must not install duplicate userspace cleanup")
	}
}

type selfBypassNetworkManager struct {
	adapter.NetworkManager
	tracker *commonEBPF.SelfBypass
}

func (m selfBypassNetworkManager) EBPFSelfBypass() *commonEBPF.SelfBypass { return m.tracker }

// The rollback dialer moves the chain into ControlContext; Go would ignore a
// Control left beside it, dropping registration and interface binding.
func TestSelfBypassRollbackDialerKeepsControlChain(t *testing.T) {
	tracker, err := commonEBPF.NewSelfBypass()
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := listener.Addr().String()
	listener.Close()
	controlErr := errors.New("control failed")
	var calls int
	dialer, rollback := ebpfSelfBypassDialer(selfBypassNetworkManager{tracker: tracker}, net.Dialer{
		Control: func(string, string, syscall.RawConn) error {
			calls++
			return controlErr
		},
	})
	_, err = dialer.Dial("tcp4", refused)
	rollback()
	if calls != 1 || !errors.Is(err, controlErr) {
		t.Fatalf("control chain was not applied: calls=%d err=%v", calls, err)
	}
}
