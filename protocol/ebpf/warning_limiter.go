//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
)

const packetWarningInterval = 10 * time.Second

type warningLimiter struct {
	access     sync.Mutex
	next       time.Time
	suppressed uint64
}

func (l *warningLimiter) allow(now time.Time) (bool, uint64) {
	l.access.Lock()
	defer l.access.Unlock()
	if now.Before(l.next) {
		l.suppressed++
		return false, 0
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.next = now.Add(packetWarningInterval)
	return true, suppressed
}

func (l *warningLimiter) warn(logger log.ContextLogger, message ...any) {
	allowed, suppressed := l.allow(time.Now())
	if !allowed {
		return
	}
	if suppressed > 0 {
		message = append(message, " (", suppressed, " similar warnings suppressed)")
	}
	logger.Warn(message...)
}

type udpWarningLimiters struct {
	packetInfo          warningLimiter
	originalDestination warningLimiter
	cleanup             warningLimiter
}
