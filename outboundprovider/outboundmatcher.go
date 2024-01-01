package outboundprovider

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type outboundMatcher interface {
	match(outbound *option.Outbound) bool
}

type outboundTagMatcher regexp.Regexp

func (m *outboundTagMatcher) match(outbound *option.Outbound) bool {
	return (*regexp.Regexp)(m).MatchString(outbound.Tag)
}

type outboundTypeMatcher string

func (m outboundTypeMatcher) match(outbound *option.Outbound) bool {
	return string(m) == outbound.Type
}

func newOutboundMatcher(s string) (outboundMatcher, error) {
	var ss string
	switch {
	case strings.HasPrefix(s, "type:"):
		ss = strings.TrimPrefix(s, "type:")
		return outboundTypeMatcher(ss), nil
	case strings.HasPrefix(s, "tag:"):
		ss = strings.TrimPrefix(s, "tag:")
		fallthrough
	default:
		ss = s
		regex, err := regexp.Compile(ss)
		if err != nil {
			return nil, E.Cause(err, "invalid rule: ", s)
		}
		return (*outboundTagMatcher)(regex), nil
	}
}
