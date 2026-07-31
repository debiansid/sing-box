//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "ebpf.h"

static int singbox_ebpf_shared_network_prepare(
	const uint8_t *object,
	size_t object_size,
	int bypass_ipv4_map_fd,
	int bypass_ipv6_map_fd,
	uint32_t map_capacity,
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_prepare(
		object,
		object_size,
		bypass_ipv4_map_fd,
		bypass_ipv6_map_fd,
		map_capacity,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_shared_network_close(
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	_ "embed"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
)

//go:embed native/shared_network.bpf.o
var sharedNetworkObject []byte

type SharedNetworkBackend struct {
	access   sync.RWMutex
	runtime  *C.struct_sb_ebpf_shared_network_runtime
	control  sharedNetworkControl
	hostIPv4 []netip.Prefix
	hostIPv6 []netip.Prefix
}

func PrepareSharedNetwork(cgroupBackend *CgroupBackend, config SharedNetworkConfig) (*SharedNetworkBackend, error) {
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	if cgroupBackend == nil {
		return nil, errBackendClosed
	}
	if config.MapCapacity == 0 || config.MapCapacity > MaxConfigurableMapCapacity {
		return nil, E.New("invalid shared-network map capacity: ", config.MapCapacity)
	}
	if config.ListenerPort == 0 {
		return nil, E.New("missing shared-network listener port")
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing shared-network redirect address")
	}
	if len(sharedNetworkObject) == 0 {
		return nil, E.New("missing embedded shared-network eBPF object")
	}

	runtimeState := (*C.struct_sb_ebpf_shared_network_runtime)(C.calloc(
		1,
		C.size_t(C.sizeof_struct_sb_ebpf_shared_network_runtime),
	))
	if runtimeState == nil {
		return nil, E.New("allocate shared-network token runtime")
	}
	cgroupBackend.access.RLock()
	if cgroupBackend.runtime == nil {
		cgroupBackend.access.RUnlock()
		C.free(unsafe.Pointer(runtimeState))
		return nil, errBackendClosed
	}
	hijackDNS := cgroupBackend.hijackDNS
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_prepare(
		(*C.uint8_t)(unsafe.Pointer(&sharedNetworkObject[0])),
		C.size_t(len(sharedNetworkObject)),
		C.int(cgroupBackend.bypassIPv4CIDRMapFD),
		C.int(cgroupBackend.bypassIPv6CIDRMapFD),
		C.uint32_t(config.MapCapacity),
		runtimeState,
		&savedErrno,
	)
	cgroupBackend.access.RUnlock()
	if result != 0 {
		C.free(unsafe.Pointer(runtimeState))
		return nil, eBPFOperationError(
			"prepare shared-network programs",
			syscall.Errno(savedErrno),
		)
	}

	backend := &SharedNetworkBackend{runtime: runtimeState}
	backend.control.ListenerPort = config.ListenerPort
	if config.EnableTCP {
		backend.control.Flags |= sharedNetworkFlagTCP
	}
	if config.EnableUDP {
		backend.control.Flags |= sharedNetworkFlagUDP
	}
	if hijackDNS {
		backend.control.Flags |= sharedNetworkFlagDNSHijack
	}
	if redirectIPv4.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv4
		backend.control.TokenIPv4Prefix = redirectIPv4.Addr().As4()
		backend.control.TokenIPv4PrefixBits = uint8(redirectIPv4.Bits())
	}
	if redirectIPv6.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv6
		backend.control.TokenIPv6Prefix = redirectIPv6.Addr().As16()
		backend.control.TokenIPv6PrefixBits = uint8(redirectIPv6.Bits())
	}
	if err := backend.updateControl(false); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "initialize shared-network control")
	}
	return backend, nil
}

func (b *SharedNetworkBackend) updateControl(enabled bool) error {
	if b == nil || b.runtime == nil {
		return errBackendClosed
	}
	control := b.control
	if enabled {
		control.Enabled = 1
	}
	key := uint32(0)
	return updateMap(
		int(b.runtime.control_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&control),
	)
}

func (b *SharedNetworkBackend) Enable() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.updateControl(true)
}

func (b *SharedNetworkBackend) Disable() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	return b.updateControl(false)
}

func (b *SharedNetworkBackend) IngressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.ingress_prog_fd)
}

func (b *SharedNetworkBackend) EgressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.egress_prog_fd)
}

func (b *SharedNetworkBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	_ = b.updateControl(false)
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_close(b.runtime, &savedErrno)
	if b.runtime.control_map_fd < 0 &&
		b.runtime.ingress_prog_fd < 0 &&
		b.runtime.egress_prog_fd < 0 {
		C.free(unsafe.Pointer(b.runtime))
		b.runtime = nil
		b.hostIPv4 = nil
		b.hostIPv6 = nil
	}
	if result != 0 {
		return E.Cause(syscall.Errno(savedErrno), "close shared-network runtime")
	}
	return nil
}

func (b *SharedNetworkBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
