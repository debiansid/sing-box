//go:build android

package settings

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/wifi"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

const (
	androidNL80211Family      = "nl80211"
	androidWIFIReadTimeout    = 3 * time.Second
	androidWIFIResyncInterval = 30 * time.Second
)

type androidWIFIMonitor struct {
	logger      logger.ContextLogger
	callback    func(adapter.WIFIState)
	cancel      context.CancelFunc
	done        chan struct{}
	stateAccess sync.RWMutex
	state       adapter.WIFIState
}

func newAndroidWIFIMonitor(logger logger.ContextLogger, callback func(adapter.WIFIState)) (WIFIMonitor, error) {
	return &androidWIFIMonitor{logger: logger, callback: callback}, nil
}

func readAndroidWIFIState(ctx context.Context) (adapter.WIFIState, error) {
	client, err := wifi.New()
	if err != nil {
		return adapter.WIFIState{}, err
	}
	defer client.Close()
	readCtx, cancel := context.WithTimeout(ctx, androidWIFIReadTimeout)
	defer cancel()
	deadline, _ := readCtx.Deadline()
	if err = client.SetDeadline(deadline); err != nil {
		return adapter.WIFIState{}, err
	}
	stopCancel := context.AfterFunc(readCtx, func() {
		_ = client.SetDeadline(time.Now())
	})
	defer stopCancel()
	interfaces, err := client.Interfaces()
	if err != nil {
		return adapter.WIFIState{}, err
	}
	return selectAndroidWIFIState(interfaces, client.BSS)
}

func selectAndroidWIFIState(interfaces []*wifi.Interface, readBSS func(*wifi.Interface) (*wifi.BSS, error)) (adapter.WIFIState, error) {
	var readErr error
	for _, networkInterface := range interfaces {
		if networkInterface.Type != wifi.InterfaceTypeStation {
			continue
		}
		bss, err := readBSS(networkInterface)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				readErr = errors.Join(readErr, err)
			}
			continue
		}
		return adapter.WIFIState{SSID: bss.SSID, BSSID: bss.BSSID.String()}, nil
	}
	return adapter.WIFIState{}, readErr
}

func (m *androidWIFIMonitor) read(ctx context.Context) (adapter.WIFIState, error) {
	state, err := readAndroidWIFIState(ctx)
	if err == nil {
		m.stateAccess.Lock()
		m.state = state
		m.stateAccess.Unlock()
	}
	return state, err
}

func (m *androidWIFIMonitor) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	state, err := m.read(ctx)
	if err == nil {
		return state
	}
	m.stateAccess.RLock()
	defer m.stateAccess.RUnlock()
	return m.state
}

func (m *androidWIFIMonitor) Start() error {
	if m.callback == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	state, err := m.read(ctx)
	var lastReadError string
	if err != nil {
		lastReadError = err.Error()
		m.logger.Warn("read initial WIFI state: ", err)
	}
	m.callback(state)
	go m.watch(ctx, state, lastReadError)
	return nil
}

func (m *androidWIFIMonitor) watch(ctx context.Context, lastState adapter.WIFIState, lastReadError string) {
	defer close(m.done)
	events, err := subscribeNL80211Events(ctx)
	var lastEventError string
	if err != nil {
		lastEventError = err.Error()
		m.logger.Warn("subscribe Android WIFI events: ", err)
	}
	ticker := time.NewTicker(androidWIFIResyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if events != nil {
				for range events {
				}
			}
			return
		case receiveErr, open := <-events:
			if !open {
				events = nil
				continue
			}
			if receiveErr != nil {
				for range events {
				}
				events = nil
				if message := receiveErr.Error(); message != lastEventError {
					lastEventError = message
					m.logger.Warn("receive Android WIFI events: ", receiveErr)
				}
				continue
			}
		case <-ticker.C:
			if events == nil {
				events, err = subscribeNL80211Events(ctx)
				if err != nil {
					if message := err.Error(); message != lastEventError {
						lastEventError = message
						m.logger.Warn("subscribe Android WIFI events: ", err)
					}
				} else {
					lastEventError = ""
				}
			}
		}
		state, err := m.read(ctx)
		if err != nil {
			if message := err.Error(); message != lastReadError {
				lastReadError = message
				m.logger.Warn("read WIFI state: ", err)
			}
			continue
		}
		if lastReadError != "" {
			m.logger.Info("read WIFI state recovered")
			lastReadError = ""
		}
		if state != lastState {
			lastState = state
			m.callback(state)
		}
	}
}

func subscribeNL80211Events(ctx context.Context) (<-chan error, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	family, err := conn.GetFamily(androidNL80211Family)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var joined bool
	var joinErr error
	for _, group := range family.Groups {
		if group.Name != "mlme" && group.Name != "config" {
			continue
		}
		if err = conn.JoinGroup(group.ID); err != nil {
			joinErr = errors.Join(joinErr, err)
		} else {
			joined = true
		}
	}
	if !joined {
		conn.Close()
		if joinErr != nil {
			return nil, joinErr
		}
		return nil, errors.New("nl80211 event groups unavailable")
	}
	events := make(chan error, 1)
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	go func() {
		defer close(events)
		defer stopCancel()
		defer conn.Close()
		for {
			if _, _, receiveErr := conn.Receive(); receiveErr != nil {
				if ctx.Err() == nil {
					select {
					case events <- receiveErr:
					case <-ctx.Done():
					}
				}
				return
			}
			select {
			case events <- nil:
			default:
			}
		}
	}()
	return events, nil
}

func (m *androidWIFIMonitor) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	if m.done != nil {
		<-m.done
	}
	return nil
}
