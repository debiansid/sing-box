package group

import (
	"regexp"
	"sort"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/json/badoption"
)

func buildIncludeOrder(includeOrder []*badoption.Regexp) []*regexp.Regexp {
	if len(includeOrder) == 0 {
		return nil
	}
	regexps := make([]*regexp.Regexp, 0, len(includeOrder))
	for _, include := range includeOrder {
		if include != nil {
			regexps = append(regexps, (*regexp.Regexp)(include))
		}
	}
	return regexps
}

func filterProviderOutbounds(outbounds []adapter.Outbound, exclude *regexp.Regexp, include *regexp.Regexp) []adapter.Outbound {
	var filtered []adapter.Outbound
	for _, detour := range outbounds {
		tag := detour.Tag()
		if exclude != nil && exclude.MatchString(tag) {
			continue
		}
		if include != nil && !include.MatchString(tag) {
			continue
		}
		filtered = append(filtered, detour)
	}
	return filtered
}

func sortProviderOutbounds(outbounds []adapter.Outbound, includeOrder []*regexp.Regexp) {
	if len(includeOrder) > 0 {
		sort.SliceStable(outbounds, func(i, j int) bool {
			return includeOrderIndex(outbounds[i].Tag(), includeOrder) < includeOrderIndex(outbounds[j].Tag(), includeOrder)
		})
	}
}

func includeOrderIndex(tag string, includeOrder []*regexp.Regexp) int {
	for i, include := range includeOrder {
		if include.MatchString(tag) {
			return i
		}
	}
	return len(includeOrder)
}
