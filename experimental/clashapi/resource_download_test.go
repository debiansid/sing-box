package clashapi

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

type resourceDownloadOutbound struct {
	adapter.Outbound
	dial func(context.Context) (net.Conn, error)
}

func (o *resourceDownloadOutbound) Type() string { return "test" }
func (o *resourceDownloadOutbound) Tag() string  { return "test" }
func (o *resourceDownloadOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx)
}

type resourceDownloadOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *resourceDownloadOutboundManager) Default() adapter.Outbound { return m.outbound }
func TestExternalUIResourceDownloadContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	called := make(chan bool, 1)
	outbound := &resourceDownloadOutbound{dial: func(ctx context.Context) (net.Conn, error) {
		called <- interrupt.IsResourceDownloadFromContext(ctx)
		cancel()
		return nil, context.Canceled
	}}
	server := &Server{ctx: ctx, logger: log.NewNOPFactory().NewLogger("test"), outbound: &resourceDownloadOutboundManager{outbound: outbound}, externalUIDownloadURL: "https://example.com/dashboard.zip"}
	require.ErrorIs(t, server.downloadExternalUI(), context.Canceled)
	require.True(t, <-called)
}
