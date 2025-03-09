//go:build with_embedded_tor

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/tor"
)

func registerTorOutbound(registry *outbound.Registry) {
	tor.RegisterOutbound(registry)
}
