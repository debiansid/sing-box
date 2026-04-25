package clashapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type resourceDownloadOutbound struct {
	outbound.Adapter
	N.Dialer
	policies chan bool
}

func (o *resourceDownloadOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.policies <- interrupt.IsResourceDownloadFromContext(ctx)
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

type resourceDownloadManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *resourceDownloadManager) Default() adapter.Outbound { return m.outbound }

func (m *resourceDownloadManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, tag == m.outbound.Tag()
}

func TestExternalUIResourceDownloadContext(t *testing.T) {
	for _, detour := range []string{"", "download"} {
		for _, termination := range []string{"cancel", "deadline"} {
			t.Run(detour+"/"+termination, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if termination == "cancel" {
						cancel()
					}
					<-r.Context().Done()
				}))
				defer httpServer.Close()
				downloadOutbound := &resourceDownloadOutbound{
					Adapter:  outbound.NewAdapter("test", "download", []string{N.NetworkTCP}, nil),
					policies: make(chan bool, 1),
				}
				server := &Server{
					ctx: ctx, logger: log.NewNOPFactory().NewLogger("test"),
					outbound:                 &resourceDownloadManager{outbound: downloadOutbound},
					externalUIDownloadURL:    httpServer.URL,
					externalUIDownloadDetour: detour,
				}
				expected := context.Canceled
				if termination == "deadline" {
					expected = context.DeadlineExceeded
				}
				require.ErrorIs(t, server.downloadExternalUI(), expected)
				select {
				case protected := <-downloadOutbound.policies:
					require.True(t, protected)
				default:
					t.Fatal("external UI download did not use the outbound")
				}
			})
		}
	}
}
