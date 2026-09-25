package clashapi

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type resourceDownloadOutbound struct {
	outbound.Adapter
	dial func(context.Context) (net.Conn, error)
}

func (o *resourceDownloadOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx)
}

type resourceDownloadManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *resourceDownloadManager) Default() adapter.Outbound { return m.outbound }

func TestExternalUIResourceDownloadContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	called := make(chan bool, 1)
	detour := &resourceDownloadOutbound{
		Adapter: outbound.NewAdapter("test", "test", []string{"tcp"}, nil),
		dial: func(dialCtx context.Context) (net.Conn, error) {
			called <- interrupt.IsResourceDownloadFromContext(dialCtx)
			cancel()
			return nil, context.Canceled
		},
	}
	server := &Server{ctx: ctx, logger: log.NewNOPFactory().NewLogger("test"), outbound: &resourceDownloadManager{outbound: detour}, externalUIDownloadURL: "https://example.com/dashboard.zip"}
	require.ErrorIs(t, server.downloadExternalUI(), context.Canceled)
	select {
	case marked := <-called:
		require.True(t, marked)
	default:
		t.Fatal("resource download did not use its outbound")
	}
}

func (o *resourceDownloadOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
