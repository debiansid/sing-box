package rule

import (
	"net"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"
)

var _ RuleItem = (*InterfaceNameItem)(nil)

type InterfaceNameItem struct {
	networkManager adapter.NetworkManager
	patterns       []string
}

func NewInterfaceNameItem(networkManager adapter.NetworkManager, patterns []string) *InterfaceNameItem {
	return &InterfaceNameItem{
		networkManager: networkManager,
		patterns:       patterns,
	}
}

func (r *InterfaceNameItem) Match(metadata *adapter.InboundContext) bool {
	finder := r.networkManager.InterfaceFinder()
	if finder == nil {
		return false
	}
	interfaces := finder.Interfaces()
	for _, pattern := range r.patterns {
		hasWildcard := strings.Contains(pattern, "*") || strings.Contains(pattern, "?")
		for _, iif := range interfaces {
			if iif.Flags&net.FlagUp == 0 {
				continue
			}
			if hasWildcard {
				if matched, _ := filepath.Match(pattern, iif.Name); matched {
					return true
				}
			} else if iif.Name == pattern {
				return true
			}
		}
	}
	return false
}

func (r *InterfaceNameItem) String() string {
	if len(r.patterns) == 1 {
		return F.ToString("interface_name=", r.patterns[0])
	}
	return F.ToString("interface_name=[", strings.Join(r.patterns, " "), "]")
}
