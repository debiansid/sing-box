//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

const (
	udpClientShardCount = 16
	udpReplyAliasLimit  = 64
)

type udpClientTable struct {
	clientShards [udpClientShardCount]udpClientShard
}

type udpClientShard struct {
	access  sync.RWMutex
	clients map[netip.AddrPort]*udpClientState
}

type udpClientState struct {
	access               sync.RWMutex
	sourceMAC            net.HardwareAddr
	socketCookie         uint64
	path                 uint8
	attachmentGeneration uint64
	bindings             map[netip.AddrPort]udpRedirectBinding
	replyAliasCount      uint16
	sessionID            uint64
	sessionCloser        io.Closer
	sessionClosing       bool
	closed               bool
}

type udpRedirectBinding struct {
	replyAlias bool
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	state, loaded := shard.clients[client]
	shard.access.RUnlock()
	return state, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if state, loaded := t.load(client); loaded {
		return state
	}
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[client]; loaded {
		return state
	}
	if shard.clients == nil {
		shard.clients = make(map[netip.AddrPort]*udpClientState)
	}
	state := &udpClientState{bindings: make(map[netip.AddrPort]udpRedirectBinding)}
	shard.clients[client] = state
	return state
}

func (t *udpClientTable) clientShard(client netip.AddrPort) *udpClientShard {
	port := client.Port()
	return &t.clientShards[(port^port>>8)&(udpClientShardCount-1)]
}

func (t *udpClientTable) setDirectBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
	socketCookie uint64,
	path uint8,
	attachmentGeneration uint64,
) (*udpClientState, bool) {
	if attachmentGeneration == 0 {
		return nil, false
	}
	state := t.loadOrCreate(client)
	state.access.Lock()
	defer state.access.Unlock()
	if state.closed || state.sessionClosing ||
		state.path != 0 && (state.path != path || state.attachmentGeneration != attachmentGeneration) {
		return nil, false
	}
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.socketCookie = socketCookie
	state.path = path
	state.attachmentGeneration = attachmentGeneration
	state.bindings[destination] = udpRedirectBinding{}
	return state, true
}

func (t *udpClientTable) beginSession(client netip.AddrPort, expected *udpClientState) (uint64, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return 0, false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.sessionClosing || expected.attachmentGeneration == 0 {
		return 0, false
	}
	expected.sessionID++
	if expected.sessionID == 0 {
		expected.sessionID++
	}
	expected.sessionCloser = nil
	expected.sessionClosing = false
	return expected.sessionID, true
}

func (t *udpClientTable) attachSession(
	client netip.AddrPort,
	expected *udpClientState,
	sessionID uint64,
	closer io.Closer,
) bool {
	if closer == nil {
		return false
	}
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.sessionID != sessionID || expected.sessionClosing || expected.sessionCloser != nil {
		return false
	}
	expected.sessionCloser = closer
	return true
}

func (t *udpClientTable) sessionActive(
	client netip.AddrPort,
	expected *udpClientState,
	sessionID uint64,
) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.RLock()
	defer expected.access.RUnlock()
	return !expected.closed && !expected.sessionClosing && expected.sessionID == sessionID
}

func (t *udpClientTable) endSession(client netip.AddrPort, expected *udpClientState, sessionID uint64) {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expected {
		return
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.sessionID != sessionID {
		return
	}
	delete(shard.clients, client)
	expected.closeLocked()
}

func (t *udpClientTable) invalidateAttachmentGenerations(generations map[uint64]struct{}) error {
	if len(generations) == 0 {
		return nil
	}
	var closers []io.Closer
	for shardIndex := range t.clientShards {
		shard := &t.clientShards[shardIndex]
		shard.access.Lock()
		for client, state := range shard.clients {
			state.access.Lock()
			_, invalidated := generations[state.attachmentGeneration]
			if invalidated {
				delete(shard.clients, client)
				if state.sessionCloser != nil {
					closers = append(closers, state.sessionCloser)
				}
				state.closeLocked()
			}
			state.access.Unlock()
		}
		shard.access.Unlock()
	}
	// A closer may synchronously run onClose and re-enter the client table.
	var closeErr error
	for _, closer := range closers {
		closeErr = errors.Join(closeErr, closer.Close())
	}
	return closeErr
}

func (s *udpClientState) requestSessionClose(sessionID uint64) error {
	s.access.Lock()
	if s.closed || s.sessionID != sessionID || s.sessionClosing {
		s.access.Unlock()
		return nil
	}
	s.sessionClosing = true
	closer := s.sessionCloser
	s.access.Unlock()
	if closer == nil {
		return nil
	}
	return closer.Close()
}

func (t *udpClientTable) setDirectReplyBinding(
	client netip.AddrPort,
	expected *udpClientState,
	sessionID uint64,
	destination netip.AddrPort,
) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.sessionID != sessionID || expected.sessionClosing {
		return false
	}
	if _, loaded := expected.bindings[destination]; loaded {
		return true
	}
	if expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.bindings[destination] = udpRedirectBinding{replyAlias: true}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expected {
		return
	}
	delete(shard.clients, client)
	expected.access.Lock()
	expected.closeLocked()
	expected.access.Unlock()
}

func (s *udpClientState) closeLocked() {
	s.closed = true
	s.sessionCloser = nil
	s.sessionClosing = true
	clear(s.bindings)
	s.replyAliasCount = 0
}

// udpReplySocketPool shares transparent reply sockets between all clients of
// an inbound. A socket bound to an original destination can send replies to any
// client, so keeping it at client-state scope needlessly multiplies sockets.
type udpReplySocketPool struct {
	shards [udpClientShardCount]udpReplySocketShard
	closed atomic.Bool
}

type udpReplySocketShard struct {
	access  sync.Mutex
	sockets map[netip.AddrPort]*net.UDPConn
}

func (p *udpReplySocketPool) get(
	source netip.AddrPort,
	create func(netip.AddrPort) (*net.UDPConn, error),
) (*net.UDPConn, error) {
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	shard := &p.shards[p.shardIndex(source)]
	shard.access.Lock()
	defer shard.access.Unlock()
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	if socket := shard.sockets[source]; socket != nil {
		return socket, nil
	}
	socket, err := create(source)
	if err != nil {
		return nil, err
	}
	if shard.sockets == nil {
		shard.sockets = make(map[netip.AddrPort]*net.UDPConn)
	}
	shard.sockets[source] = socket
	return socket, nil
}

func (p *udpReplySocketPool) shardIndex(source netip.AddrPort) int {
	port := source.Port()
	return int((port ^ port>>8) & (udpClientShardCount - 1))
}

func (p *udpReplySocketPool) close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.closeSockets()
}

func (p *udpReplySocketPool) closeSockets() error {
	var closeErr error
	for index := range p.shards {
		shard := &p.shards[index]
		shard.access.Lock()
		for source, socket := range shard.sockets {
			closeErr = errors.Join(closeErr, socket.Close())
			delete(shard.sockets, source)
		}
		shard.access.Unlock()
	}
	return closeErr
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) hasAddressFamily(ipv4 bool) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	for destination := range s.bindings {
		if destination.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}

func (s *udpClientState) processSocketCookie() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.socketCookie
}

func (s *udpClientState) tcPath() uint8 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.path
}

func (s *udpClientState) tcAttachmentGeneration() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.attachmentGeneration
}
