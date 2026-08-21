//go:build with_ebpf && (linux || android)

package route

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestDynamicSocketProtectFunc(t *testing.T) {
	manager := new(NetworkManager)
	protect := adapter.SocketProtectFunc(manager)
	if err := protect("tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}

	var called atomic.Int32
	if err := manager.RegisterSocketProtectFunc(func(string, string, syscall.RawConn) error {
		called.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := protect("tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Fatalf("unexpected protector call count: %d", called.Load())
	}

	if err := manager.RegisterSocketProtectFunc(func(string, string, syscall.RawConn) error { return nil }); err == nil {
		t.Fatal("expected duplicate protector registration to fail")
	}
	manager.UnregisterSocketProtectFunc()
	if err := protect("tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 1 {
		t.Fatalf("protector called after unregister: %d", called.Load())
	}
}

func TestDynamicSocketProtectContextFunc(t *testing.T) {
	manager := new(NetworkManager)
	var sharedCalls atomic.Int32
	var normalCalls atomic.Int32
	if err := manager.RegisterSocketProtectContextFunc(func(ctx context.Context, _ string, _ string, _ syscall.RawConn) error {
		if adapter.IsSharedNetworkContext(ctx) {
			sharedCalls.Add(1)
		} else {
			normalCalls.Add(1)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	protect := adapter.SocketProtectFuncContext(manager)
	if err := protect(context.Background(), "tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if err := protect(adapter.WithSharedNetworkContext(context.Background()), "tcp4", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if normalCalls.Load() != 1 || sharedCalls.Load() != 1 {
		t.Fatalf("unexpected context dispatch: normal=%d shared=%d", normalCalls.Load(), sharedCalls.Load())
	}
}
