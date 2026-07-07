package snell

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SnellInboundOptions](registry, C.TypeSnell, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	router   adapter.ConnectionRouterEx
	logger   logger.ContextLogger
	listener *listener.Listener
	service  snellprotocol.Service
	users    []option.SnellUser
	version  int
	obfsMode string
	udpNat   *quicProxyNATService
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter:  inbound.NewAdapter(C.TypeSnell, tag),
		ctx:      ctx,
		router:   uot.NewRouter(router, logger),
		logger:   logger,
		users:    options.Users,
		version:  options.Version,
		obfsMode: options.ObfsOptions.ObfsMode,
	}
	if options.Version == 5 && options.ObfsOptions.ObfsMode != "" && options.ObfsOptions.ObfsMode != "none" && options.ObfsOptions.ObfsMode != "http" {
		return nil, E.New("snell: version 5 only supports http obfs")
	}
	authentication := snellprotocol.MultiUserAuthenticationUserKey
	if options.MultiUserAuthentication == "psk" {
		authentication = snellprotocol.MultiUserAuthenticationPSK
	}
	var userList []int
	var keyList [][]byte
	if len(options.Users) > 0 {
		userList = make([]int, len(options.Users))
		keyList = make([][]byte, len(options.Users))
		for index, user := range options.Users {
			userList[index] = index
			if authentication == snellprotocol.MultiUserAuthenticationPSK {
				keyList[index] = []byte(user.PSK)
			} else {
				keyList[index] = []byte(user.UserKey)
			}
		}
	}
	var err error
	switch options.Version {
	case 5:
		serviceOptions := snellv5.ServiceOptions{
			PSK:                     []byte(options.PSK),
			Handler:                 inbound,
			MultiUserAuthentication: authentication,
		}
		if len(options.Users) > 0 {
			var service *snellv5.MultiService[int]
			service, err = snellv5.NewMultiService[int](serviceOptions)
			if err != nil {
				return nil, err
			}
			err = service.UpdateUsers(userList, keyList)
			inbound.service = service
		} else {
			inbound.service, err = snellv5.NewService(serviceOptions)
		}
	case 6:
		var mode snellv6.Mode
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if err != nil {
			return nil, err
		}
		serviceOptions := snellv6.ServerOptions{
			PSK:                     []byte(options.PSK),
			Mode:                    mode,
			Handler:                 inbound,
			MultiUserAuthentication: authentication,
		}
		if len(options.Users) > 0 {
			var service *snellv6.MultiService[int]
			service, err = snellv6.NewMultiService[int](serviceOptions)
			if err != nil {
				return nil, err
			}
			err = service.UpdateUsers(userList, keyList)
			inbound.service = service
		} else {
			inbound.service, err = snellv6.NewService(serviceOptions)
		}
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", options.Version)
	}
	if err != nil {
		return nil, err
	}
	networks := []string{N.NetworkTCP}
	listenerOptions := listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           networks,
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	}
	if options.Version == 5 {
		networks = append(networks, N.NetworkUDP)
		listenerOptions.Network = networks
		listenerOptions.PacketHandler = (*inboundPacketHandler)(inbound)
		inbound.udpNat = newQUICProxyNATService((*inboundUDPHandler)(inbound), inbound.preparePacketConnection, snellprotocol.QUICProxySessionIdleTimeout)
	}
	inbound.listener = listener.New(listenerOptions)
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	if h.udpNat != nil {
		h.udpNat.Close()
	}
	return h.listener.Close()
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.obfsMode == "http" {
		conn = obfs.NewHTTPObfsServer(conn)
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := adapter.ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	h.newConnection(ctx, conn, *metadata, onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_, metadata := adapter.ExtendContext(ctx)
	if source.IsValid() {
		metadata.Source = source
	}
	if destination.IsValid() {
		metadata.Destination = destination
	}
	h.newPacketConnection(ctx, conn, *metadata, onClose)
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	if len(h.users) > 0 {
		userIndex, loaded := auth.UserFromContext[int](ctx)
		if !loaded {
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		user := h.users[userIndex].Name
		if user == "" {
			user = F.ToString(userIndex)
		} else {
			metadata.User = user
		}
		h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	if len(h.users) > 0 {
		userIndex, loaded := auth.UserFromContext[int](ctx)
		if !loaded {
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		user := h.users[userIndex].Name
		if user == "" {
			user = F.ToString(userIndex)
		} else {
			metadata.User = user
		}
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection from ", metadata.Source)
	} else {
		h.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

type inboundUDPHandler Inbound

func (h *inboundUDPHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	(*Inbound)(h).NewPacketConnectionEx(ctx, conn, source, destination, onClose)
}

func (h *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, session *snellprotocol.QUICProxySession) (context.Context, N.PacketWriter) {
	ctx := log.ContextWithNewID(h.ctx)
	ctx = session.Context(ctx)
	return ctx, &quicProxyResponseWriter{
		writer:     h.listener.PacketWriter(),
		clientAddr: source,
	}
}

type quicProxyResponseWriter struct {
	writer     N.PacketWriter
	clientAddr M.Socksaddr
}

func (w *quicProxyResponseWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	return w.writer.WritePacket(buffer, w.clientAddr)
}

type inboundPacketHandler Inbound

type quicProxyInitParser interface {
	ParseQUICProxyInit(data []byte) (*snellprotocol.QUICProxySession, []byte, error)
}

func (h *inboundPacketHandler) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	defer buffer.Release()
	data := buffer.Bytes()
	if len(data) == 0 || h.udpNat == nil {
		return
	}
	if entry, loaded := h.udpNat.Session(source); loaded {
		session := entry.session
		session.Touch()
		payload := data
		if !snellprotocol.IsQUICLooking(data[0]) {
			var err error
			payload, err = session.DecodeDuplicateInit(data)
			if err != nil {
				h.logger.Error("quic proxy: decode duplicate init: ", err)
				return
			}
		}
		if len(payload) > 0 {
			h.udpNat.NewPacket(entry, payload)
		}
		return
	}
	if snellprotocol.IsQUICLooking(data[0]) {
		h.logger.Debug("quic proxy: discard packet without session from ", source)
		return
	}
	parser, loaded := h.service.(quicProxyInitParser)
	if !loaded {
		h.logger.Error("quic proxy: service does not support init parsing")
		return
	}
	session, payload, err := parser.ParseQUICProxyInit(data)
	if err != nil {
		h.logger.Error("quic proxy: parse init from ", source, ": ", err)
		return
	}
	// A valid QUIC session always starts with a non-empty Initial packet. Do not
	// retain metadata-only init frames: without a packet there is no UDP NAT
	// entry whose close callback could remove the session.
	if len(payload) == 0 {
		h.logger.Debug("quic proxy: discard empty init from ", source)
		return
	}
	h.logger.Info("quic proxy: new session from ", source, " to ", session.Target())
	if !h.udpNat.NewSessionPacket(source, session, payload) {
		h.logger.Debug("quic proxy: session already replaced for ", source)
	}
}
