package outboundprovider

import (
	"context"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ action = (*actionGroup)(nil)

func init() {
	registerAction("group", func() action {
		return &actionGroup{}
	})
}

type actionGroupOptions struct {
	Rules     option.Listable[string] `json:"rules,omitempty"`
	BlackMode bool                    `json:"black_mode,omitempty"`
	Outbound  option.Outbound         `json:"outbound"`
}

type actionGroup struct {
	outboundMatchers []outboundMatcher
	blackMode        bool
	outbound         option.Outbound
}

func (a *actionGroup) UnmarshalJSON(content []byte) error {
	var options actionGroupOptions
	err := json.Unmarshal(content, &options)
	if err != nil {
		return err
	}
	if len(options.Rules) > 0 {
		a.outboundMatchers = make([]outboundMatcher, 0, len(options.Rules))
		for i, rule := range options.Rules {
			matcher, err := newOutboundMatcher(rule)
			if err != nil {
				return E.Cause(err, "invalid rule[", i, "]: ", rule)
			}
			a.outboundMatchers = append(a.outboundMatchers, matcher)
		}
	}
	a.blackMode = options.BlackMode
	switch options.Outbound.Type {
	case C.TypeSelector:
	case C.TypeURLTest:
	default:
		return E.New("invalid outbound type: ", options.Outbound.Type)
	}
	a.outbound = options.Outbound
	return nil
}

func (a *actionGroup) apply(_ context.Context, _ adapter.Router, logger log.ContextLogger, processor *processor) error {
	var outbounds []string
	processor.ForeachOutbounds(func(outbound *option.Outbound) bool {
		for _, matcher := range a.outboundMatchers {
			if matcher.match(outbound) {
				if !a.blackMode {
					outbounds = append(outbounds, outbound.Tag)
				}
				return true
			}
		}
		if a.blackMode {
			outbounds = append(outbounds, outbound.Tag)
		}
		return true
	})
	if len(outbounds) == 0 {
		return E.New("no outbounds matched")
	}
	outbound := a.outbound
	switch outbound.Type {
	case C.TypeSelector:
		outbound.SelectorOptions.Outbounds = outbounds
	case C.TypeURLTest:
		outbound.URLTestOptions.Outbounds = outbounds
	}
	processor.AddGroupOutbound(outbound)
	logger.Debug("add group outbound: ", outbound.Tag)
	return nil
}
