//go:build !with_embedded_tor

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
)

func registerTorOutbound(registry *outbound.Registry) {
}
