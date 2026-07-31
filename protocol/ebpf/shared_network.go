//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	udpnat "github.com/sagernet/sing/common/udpnat2"
)

type sharedNetwork struct {
	inbound         *Inbound
	interfaces      []string
	sharedBackend   *ECommon.SharedNetworkBackend
	tcManager       *sharedTCManager
	listeners       internalListenerSet
	udpNat          *udpnat.Service
	udpClientTable  udpClientTable
	udpWarnings     udpWarningLimiters
	mapCapacity     uint32
	lifecycleAccess sync.RWMutex
	backendAccess   sync.RWMutex
}

func newSharedNetwork(inbound *Inbound, options option.EBPFSharedNetworkOptions) *sharedNetwork {
	shared := &sharedNetwork{
		inbound:     inbound,
		interfaces:  append([]string(nil), options.IncludeInterface...),
		mapCapacity: inbound.sharedNetworkMapCapacity,
	}
	shared.udpNat = udpnat.New(shared, shared.preparePacketConnection, inbound.udpTimeout, false)
	return shared
}

func (s *sharedNetwork) Start(cgroupBackend *ECommon.CgroupBackend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort: s.listeners.selectedPort(),
		EnableTCP:    s.inbound.enableTCP,
		EnableUDP:    s.inbound.enableUDP,
		RedirectIPv4: s.inbound.redirectIPv4Prefix,
		RedirectIPv6: s.inbound.redirectIPv6Prefix,
		MapCapacity:  s.mapCapacity,
	})
	if err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.setSharedBackend(backend)
	s.tcManager = &sharedTCManager{
		backend:        backend,
		logger:         s.inbound.logger,
		interfaces:     s.interfaces,
		enableIPv4:     s.inbound.redirectIPv4Prefix.IsValid(),
		networkMonitor: s.inbound.networkManager.NetworkMonitor(),
		attachments:    make(map[string]*sharedTCAttachment),
	}
	if err = s.tcManager.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	s.inbound.logger.Info(
		"eBPF shared-network ready: interfaces=[", s.tcManager.InterfaceString(),
		"], listen_port=", s.listeners.selectedPort(),
		", dns_mode=", s.inbound.dnsMode,
		", tc_priority=", sharedNetworkTCPriority,
		", map_capacity=", s.mapCapacity,
		", programs=[tc/ingress, tc/egress]",
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	return s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.redirectIPv6Prefix.IsValid(),
		s.newListener,
	)
}

func (s *sharedNetwork) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	listenAddress := netip.IPv4Unspecified()
	if ipv6Listener {
		listenAddress = netip.IPv6Unspecified()
	}
	return listener.New(listener.Options{
		Context: s.inbound.ctx,
		Logger:  s.inbound.logger,
		Network: []string{network},
		Listen: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(listenAddress)),
			ListenPort: port,
		},
		ConnectionHandler:    s,
		OOBPacketHandler:     s,
		DisablePacketOutput:  true,
		DisableConnectionLog: true,
		SocketControl:        s.inbound.socketControl(ipv6Listener),
	})
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.udpNat.Purge()
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	if manager := s.tcManager; manager != nil {
		manager.Wake()
	}
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	s.udpNat.Purge()
	if s.tcManager != nil {
		if err := s.tcManager.Close(); err != nil {
			return err
		}
		s.tcManager = nil
	}
	var backendErr error
	if backend := s.sharedBackendInstance(); backend != nil {
		backendErr = backend.Close()
		if backend.IsClosed() {
			s.setSharedBackend(nil)
		}
	}
	return E.Errors(backendErr, s.closeListeners())
}

func (s *sharedNetwork) closeListeners() error {
	return s.listeners.close()
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	return s.tcManager == nil && s.sharedBackendInstance() == nil && s.listeners.isClosed()
}

func (s *sharedNetwork) sharedBackendInstance() *ECommon.SharedNetworkBackend {
	s.backendAccess.RLock()
	defer s.backendAccess.RUnlock()
	return s.sharedBackend
}

func (s *sharedNetwork) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
}
