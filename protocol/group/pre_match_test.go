package group

import (
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

type preMatchTestOutbound struct {
	adapter.Outbound
	tag string
}

func (o *preMatchTestOutbound) Tag() string {
	return o.tag
}

func (o *preMatchTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}
