//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func (i *Inbound) newListener(network string, ipv6Listener bool, port uint16) *listener.Listener {
	listenAddress := netip.IPv4Unspecified()
	if ipv6Listener {
		listenAddress = netip.IPv6Unspecified()
	}
	return listener.New(listener.Options{
		Context: i.ctx,
		Logger:  i.logger,
		Network: []string{network},
		Listen: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(listenAddress)),
			ListenPort: port,
		},
		ConnectionHandler:    i,
		OOBPacketHandler:     i,
		DisablePacketOutput:  true,
		DisableConnectionLog: true,
		SocketControl:        i.socketControl(ipv6Listener),
	})
}

func (i *Inbound) startListeners() error {
	return i.listeners.start(
		i.enableTCP,
		i.enableUDP,
		i.redirectIPv4Prefix.IsValid(),
		i.redirectIPv6Prefix.IsValid(),
		i.newListener,
	)
}

func (i *Inbound) closeListeners() error {
	return i.listeners.close()
}

func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		conn.Close()
		return
	}
	original, err := backend.TakeOriginal(
		ECommon.ProtocolTCP,
		M.SocksaddrFromNet(conn.LocalAddr()).AddrPort(),
	)
	if err != nil {
		i.logger.ErrorContext(ctx, "lookup TCP original destination: ", err)
		conn.Close()
		return
	}
	metadata.Inbound = i.Tag()
	metadata.InboundType = i.Type()
	metadata.Destination = M.SocksaddrFromNetIP(original.Destination)
	metadata.Source, err = restoreOriginalSource(metadata.Source, original.Destination.Addr(), original.UID)
	if err != nil {
		i.logger.DebugContext(ctx, "restore TCP original source: ", err)
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.logger.Warn("read UDP redirect address: ", err)
		return
	}
	client := source.AddrPort()
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
	cached, loaded := i.udpClientTable.cachedOriginal(client, redirectAddress)
	original := cached.original
	if !loaded {
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if err != nil {
			i.logger.Warn("lookup UDP original destination: ", err)
			return
		}
	}
	releasedRedirects := i.udpClientTable.setBinding(
		client,
		original.Destination,
		redirectAddress,
		original.ConnectedUDP,
		original.UID,
	)
	i.deleteUDPRedirects(releasedRedirects)
	i.udpNat.NewPacket([][]byte{buffer.Bytes()}, source, M.SocksaddrFromNetIP(original.Destination), original.ConnectedUDP)
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	if clientState, loaded := i.udpClientTable.load(source.AddrPort()); loaded {
		metadata.UDPConnect = clientState.isConnected()
		var err error
		metadata.Source, err = restoreOriginalSource(source, destination.Addr, clientState.sourceUID())
		if err != nil {
			i.logger.DebugContext(ctx, "restore UDP original source: ", err)
		}
	}
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	connectedUDP, _ := userData.(bool)
	ctx := log.ContextWithNewID(i.ctx)
	client := source.AddrPort()
	clientState := i.udpClientTable.loadOrCreate(client)
	clientState.setConnected(connectedUDP)
	writer := &udpPacketWriter{
		inbound:     i,
		client:      client,
		clientState: clientState,
	}
	return true, ctx, writer, func(error) {
		i.deleteUDPRedirects(i.udpClientTable.delete(writer.client, writer.clientState))
	}
}

func (i *Inbound) deleteUDPRedirects(redirectAddresses []netip.Addr) {
	if len(redirectAddresses) == 0 {
		return
	}
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	for _, redirectAddress := range redirectAddresses {
		redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
		if err := backend.DeleteRedirect(ECommon.ProtocolUDP, redirectDestination); err != nil {
			i.logger.Warn("delete UDP redirect mapping for ", redirectDestination, ": ", err)
		}
	}
}

func (i *Inbound) socketControl(ipv6Listener bool) control.Func {
	return func(network string, address string, rawConn syscall.RawConn) error {
		if ipv6Listener {
			return control.Raw(rawConn, func(fd uintptr) error {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
					return err
				}
				if strings.HasPrefix(network, "udp") {
					return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
				}
				return nil
			})
		}
		if network == "udp4" {
			return control.Raw(rawConn, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			})
		}
		return nil
	}
}

type udpPacketWriter struct {
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
}

func (w *udpPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	redirectAddress, loaded := w.clientState.redirectAddress(destination.AddrPort())
	if !loaded {
		return E.New("missing UDP redirect binding for ", destination)
	}
	var udpConn *net.UDPConn
	var controlMessage []byte
	if redirectAddress.Is4() {
		listener4 := w.inbound.listeners.udp(false)
		if listener4 == nil {
			return E.New("IPv4 eBPF listener is unavailable")
		}
		udpConn = listener4.UDPConn()
		controlMessage = (&ipv4.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	} else {
		listener6 := w.inbound.listeners.udp(true)
		if listener6 == nil {
			return E.New("IPv6 eBPF listener is unavailable")
		}
		udpConn = listener6.UDPConn()
		controlMessage = (&ipv6.ControlMessage{Src: net.IP(redirectAddress.AsSlice())}).Marshal()
	}
	_, _, err := udpConn.WriteMsgUDPAddrPort(buffer.Bytes(), controlMessage, w.client)
	return err
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	var controlMessage4 ipv4.ControlMessage
	if err := controlMessage4.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage4.Dst); loaded && address.Is4() {
			return address.Unmap(), nil
		}
	}
	var controlMessage6 ipv6.ControlMessage
	if err := controlMessage6.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage6.Dst); loaded && address.Is6() && !address.Is4In6() {
			return address, nil
		}
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}
