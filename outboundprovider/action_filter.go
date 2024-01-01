package outboundprovider

import (
	"context"
	"encoding/json"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ action = (*actionFilter)(nil)

func init() {
	registerAction("filter", func() action {
		return &actionFilter{}
	})
}

type actionFilterOptions struct {
	Rules     option.Listable[string] `json:"rules"`
	WhiteMode bool                    `json:"white_mode,omitempty"`
}

type actionFilter struct {
	outboundMatchers []outboundMatcher
	whiteMode        bool
}

func (a *actionFilter) UnmarshalJSON(content []byte) error {
	var options actionFilterOptions
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
	a.whiteMode = options.WhiteMode
	return nil
}

func (a *actionFilter) apply(_ context.Context, _ adapter.Router, logger log.ContextLogger, processor *processor) error {
	var deleteOutbounds []string
	processor.ForeachOutbounds(func(outbound *option.Outbound) bool {
		for _, matcher := range a.outboundMatchers {
			if matcher.match(outbound) {
				if !a.whiteMode {
					deleteOutbounds = append(deleteOutbounds, outbound.Tag)
				}
				return true
			}
		}
		if a.whiteMode {
			deleteOutbounds = append(deleteOutbounds, outbound.Tag)
		}
		return true
	})
	if len(deleteOutbounds) == 0 {
		return nil
	}
	for _, tag := range deleteOutbounds {
		logger.Debug("filter outbound: ", tag)
		processor.DeleteOutbound(tag)
	}
	return nil
}
