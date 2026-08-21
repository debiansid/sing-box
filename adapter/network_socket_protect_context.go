package adapter

import (
	"context"
	"syscall"
)

// SocketProtectFuncContext returns the context-aware socket protection hook
// when the network manager provides one. The plain callback remains the
// fallback for older network manager implementations.
func SocketProtectFuncContext(networkManager NetworkManager) SocketProtectContextFunc {
	if protectManager, loaded := networkManager.(SocketProtectContextManager); loaded {
		return protectManager.SocketProtectFuncContext()
	}
	protectFunc := SocketProtectFunc(networkManager)
	if protectFunc == nil {
		return nil
	}
	return func(_ context.Context, network, address string, conn syscall.RawConn) error {
		return protectFunc(network, address, conn)
	}
}
