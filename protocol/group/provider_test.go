package group

import (
	"context"
	"net"
	"regexp"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testOutbound string

func (t testOutbound) Type() string {
	return "test"
}

func (t testOutbound) Tag() string {
	return string(t)
}

func (t testOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (t testOutbound) Dependencies() []string {
	return nil
}

func (t testOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}

func (t testOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

func TestFilterProviderOutboundsIncludeOrder(t *testing.T) {
	outbounds := newTestOutbounds("manual", "jp-1", "hk-1", "sg-1", "hk-2", "us-1", "jp-2")
	filtered := filterProviderOutbounds(outbounds, nil, nil)
	sortProviderOutbounds(filtered, []*regexp.Regexp{
		regexp.MustCompile("hk"),
		regexp.MustCompile("jp"),
	})

	assertTestOutboundTags(t, filtered, []string{"hk-1", "hk-2", "jp-1", "jp-2", "manual", "sg-1", "us-1"})
}

func TestFilterProviderOutboundsIncludeOrderKeepsOriginalOrder(t *testing.T) {
	outbounds := newTestOutbounds("sg-1", "hk-1", "jp-1", "hk-2")
	filtered := filterProviderOutbounds(outbounds, nil, nil)
	sortProviderOutbounds(filtered, nil)

	assertTestOutboundTags(t, filtered, []string{"sg-1", "hk-1", "jp-1", "hk-2"})
}

func TestFilterProviderOutboundsExcludeBeforeIncludeOrder(t *testing.T) {
	outbounds := newTestOutbounds("hk-1", "jp-1", "hk-2", "sg-1", "us-1")
	filtered := filterProviderOutbounds(
		outbounds,
		regexp.MustCompile("hk-2"),
		regexp.MustCompile("hk|jp|sg"),
	)
	sortProviderOutbounds(filtered, []*regexp.Regexp{
		regexp.MustCompile("sg"),
		regexp.MustCompile("hk"),
	})

	assertTestOutboundTags(t, filtered, []string{"sg-1", "hk-1", "jp-1"})
}

func newTestOutbounds(tags ...string) []adapter.Outbound {
	outbounds := make([]adapter.Outbound, 0, len(tags))
	for _, tag := range tags {
		outbounds = append(outbounds, testOutbound(tag))
	}
	return outbounds
}

func assertTestOutboundTags(t *testing.T, outbounds []adapter.Outbound, expected []string) {
	t.Helper()
	if len(outbounds) != len(expected) {
		t.Fatalf("expected %d outbounds, got %d", len(expected), len(outbounds))
	}
	for i, outbound := range outbounds {
		if outbound.Tag() != expected[i] {
			t.Fatalf("expected outbound[%d] tag %q, got %q", i, expected[i], outbound.Tag())
		}
	}
}
