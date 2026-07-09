package group

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"golang.org/x/sync/singleflight"
)

const defaultFallbackMaxAttempts = 3

func RegisterFallback(registry *outbound.Registry) {
	outbound.Register[option.FallbackOutboundOptions](registry, C.TypeFallback, NewFallback)
}

var (
	_ adapter.OutboundGroup           = (*Fallback)(nil)
	_ adapter.URLTestGroup            = (*Fallback)(nil)
	_ adapter.InterfaceUpdateListener = (*Fallback)(nil)
)

type Fallback struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	interval                     time.Duration
	recoveryInterval             time.Duration
	idleTimeout                  time.Duration
	maxAttempts                  int
	group                        *FallbackGroup
	interruptExternalConnections bool
}

func NewFallback(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FallbackOutboundOptions) (adapter.Outbound, error) {
	outbound := &Fallback{
		Adapter:                      outbound.NewAdapter(C.TypeFallback, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		recoveryInterval:             time.Duration(options.RecoveryInterval),
		idleTimeout:                  time.Duration(options.IdleTimeout),
		maxAttempts:                  int(options.MaxAttempts),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}
	return outbound, nil
}

func (s *Fallback) Start() error {
	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	group, err := NewFallbackGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.interval, s.recoveryInterval, s.idleTimeout, s.maxAttempts, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	s.group = group
	return nil
}

func (s *Fallback) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *Fallback) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *Fallback) Now() string {
	if outbound := s.group.SelectedOutbound(N.NetworkTCP); outbound != nil {
		return outbound.Tag()
	} else if outbound := s.group.SelectedOutbound(N.NetworkUDP); outbound != nil {
		return outbound.Tag()
	}
	return s.tags[0]
}

func (s *Fallback) All() []string {
	return s.tags
}

func (s *Fallback) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *Fallback) CheckOutbounds() {
	s.group.CheckOutbounds(true)
}

func (s *Fallback) InterfaceUpdated() {
	group := s.group
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go group.CheckOutbounds(true)
}

func (s *Fallback) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	switch N.NetworkName(network) {
	case N.NetworkTCP, N.NetworkUDP:
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	candidates := s.group.Candidates(network)
	if len(candidates) == 0 {
		return nil, E.New("missing supported outbound")
	}
	var errors []error
	for _, detour := range candidates {
		if ctx.Err() != nil {
			break
		}
		conn, err := detour.DialContext(ctx, network, destination)
		if err == nil {
			if len(errors) > 0 {
				s.group.reportFailure()
			}
			return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
		}
		s.logger.ErrorContext(ctx, "outbound ", detour.Tag(), ": ", err)
		s.group.history.DeleteURLTestHistory(RealTag(detour))
		errors = append(errors, E.Cause(err, detour.Tag()))
	}
	s.group.reportFailure()
	if len(errors) == 0 {
		return nil, ctx.Err()
	}
	return nil, E.Errors(errors...)
}

func (s *Fallback) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	candidates := s.group.Candidates(N.NetworkUDP)
	if len(candidates) == 0 {
		return nil, E.New("missing supported outbound")
	}
	var errors []error
	for _, detour := range candidates {
		if ctx.Err() != nil {
			break
		}
		conn, err := detour.ListenPacket(ctx, destination)
		if err == nil {
			if len(errors) > 0 {
				s.group.reportFailure()
			}
			return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
		}
		s.logger.ErrorContext(ctx, "outbound ", detour.Tag(), ": ", err)
		s.group.history.DeleteURLTestHistory(RealTag(detour))
		errors = append(errors, E.Cause(err, detour.Tag()))
	}
	s.group.reportFailure()
	if len(errors) == 0 {
		return nil, ctx.Err()
	}
	return nil, E.Errors(errors...)
}

func (s *Fallback) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *Fallback) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

type FallbackGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	interval                     time.Duration
	recoveryInterval             time.Duration
	idleTimeout                  time.Duration
	maxAttempts                  int
	history                      *urltest.HistoryStorage
	notifyHistory                *urltest.HistoryStorage
	checkGroup                   singleflight.Group
	selectedAccess               sync.RWMutex
	selectedOutboundTCP          adapter.Outbound
	selectedOutboundUDP          adapter.Outbound
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	lastActive                   common.TypedValue[time.Time]
	lastFullCheck                common.TypedValue[time.Time]
}

func NewFallbackGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, recoveryInterval time.Duration, idleTimeout time.Duration, maxAttempts int, interruptExternalConnections bool) (*FallbackGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	if recoveryInterval == 0 {
		recoveryInterval = C.DefaultFallbackRecovery
		if recoveryInterval > interval {
			recoveryInterval = interval
		}
	} else if recoveryInterval > interval {
		return nil, E.New("recovery_interval must be less or equal than interval")
	}
	if maxAttempts == 0 {
		maxAttempts = defaultFallbackMaxAttempts
	}
	return &FallbackGroup{
		ctx:                          ctx,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		link:                         link,
		interval:                     interval,
		recoveryInterval:             recoveryInterval,
		idleTimeout:                  idleTimeout,
		maxAttempts:                  maxAttempts,
		history:                      urltest.NewHistoryStorage(),
		notifyHistory:                service.PtrFromContext[urltest.HistoryStorage](ctx),
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}, nil
}

func (g *FallbackGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started = true
	g.lastActive.Store(time.Now())
	g.performUpdateCheck()
	go g.CheckOutbounds(false)
}

func (g *FallbackGroup) Touch() {
	if !g.started {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.recoveryInterval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.recoveryInterval, func() {
		go g.CheckOutbounds(true)
	})
	go g.loopCheck(ticker, g.close)
}

func (g *FallbackGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	g.history.Close()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	close(g.close)
	return nil
}

func (g *FallbackGroup) Select(network string) (adapter.Outbound, bool) {
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		if g.history.LoadURLTestHistory(RealTag(detour)) != nil {
			return detour, true
		}
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		return detour, false
	}
	return nil, false
}

func (g *FallbackGroup) SelectedOutbound(network string) adapter.Outbound {
	g.selectedAccess.RLock()
	defer g.selectedAccess.RUnlock()
	if network == N.NetworkTCP {
		return g.selectedOutboundTCP
	}
	return g.selectedOutboundUDP
}

func (g *FallbackGroup) Candidates(network string) []adapter.Outbound {
	start := g.indexOf(g.SelectedOutbound(network))
	candidates := make([]adapter.Outbound, 0, g.maxAttempts)
	for _, detour := range g.outbounds[start:] {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		candidates = append(candidates, detour)
		if len(candidates) == g.maxAttempts {
			break
		}
	}
	return candidates
}

func (g *FallbackGroup) indexOf(detour adapter.Outbound) int {
	if detour == nil {
		return 0
	}
	for i, it := range g.outbounds {
		if it == detour {
			return i
		}
	}
	return 0
}

func (g *FallbackGroup) recoveryIndex() int {
	g.selectedAccess.RLock()
	defer g.selectedAccess.RUnlock()
	index := g.indexOf(g.selectedOutboundTCP)
	if udpIndex := g.indexOf(g.selectedOutboundUDP); udpIndex > index {
		index = udpIndex
	}
	return index
}

func (g *FallbackGroup) reportFailure() {
	g.performUpdateCheck()
	go g.CheckOutbounds(true)
}

func (g *FallbackGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		if time.Since(g.lastFullCheck.Load()) >= g.interval {
			g.CheckOutbounds(false)
		} else {
			g.checkRecovery()
		}
	}
}

func (g *FallbackGroup) checkRecovery() {
	index := g.recoveryIndex()
	if index == 0 {
		return
	}
	_, _ = g.urlTest(g.ctx, false, g.outbounds[:index])
}

func (g *FallbackGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force, nil)
}

func (g *FallbackGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	return g.urlTest(ctx, false, nil)
}

func (g *FallbackGroup) urlTest(ctx context.Context, force bool, candidates []adapter.Outbound) (map[string]uint16, error) {
	result, err, _ := g.checkGroup.Do("", func() (any, error) {
		return g.urlTestOnce(ctx, force, candidates)
	})
	if err != nil {
		return nil, err
	}
	return result.(map[string]uint16), nil
}

func (g *FallbackGroup) urlTestOnce(ctx context.Context, force bool, candidates []adapter.Outbound) (any, error) {
	if candidates == nil {
		candidates = g.outbounds
		g.lastFullCheck.Store(time.Now())
	}
	result := make(map[string]uint16)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	testTime := time.Now()
	for _, detour := range candidates {
		tag := detour.Tag()
		realTag := RealTag(detour)
		if checked[realTag] {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && time.Since(history.Time) < g.interval {
			continue
		}
		checked[realTag] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			testCtx, cancel := context.WithTimeout(g.ctx, C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(testCtx, g.link, p)
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				g.history.DeleteURLTestHistory(realTag)
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
				g.history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
					Time:  testTime,
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	g.performUpdateCheck()
	return result, nil
}

func (g *FallbackGroup) performUpdateCheck() {
	var updated bool
	g.selectedAccess.Lock()
	if outbound, exists := g.Select(N.NetworkTCP); outbound != nil && (g.selectedOutboundTCP == nil || (exists && outbound != g.selectedOutboundTCP)) {
		if g.selectedOutboundTCP != nil {
			updated = true
		}
		g.selectedOutboundTCP = outbound
	}
	if outbound, exists := g.Select(N.NetworkUDP); outbound != nil && (g.selectedOutboundUDP == nil || (exists && outbound != g.selectedOutboundUDP)) {
		if g.selectedOutboundUDP != nil {
			updated = true
		}
		g.selectedOutboundUDP = outbound
	}
	g.selectedAccess.Unlock()
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
		if g.notifyHistory != nil {
			g.notifyHistory.NotifyUpdated()
		}
	}
}
