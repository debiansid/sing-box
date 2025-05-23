package constant

const (
	RuleTypeDefault = "default"
	RuleTypeLogical = "logical"
)

const (
	LogicalTypeAnd = "and"
	LogicalTypeOr  = "or"
)

const (
	RuleSetTypeInline   = "inline"
	RuleSetTypeLocal    = "local"
	RuleSetTypeRemote   = "remote"
	RuleSetFormatSource = "source"
	RuleSetFormatBinary = "binary"
)

const (
	RuleSetVersion1 = 1 + iota
	RuleSetVersion2
	RuleSetVersion3
	RuleSetVersionCurrent = RuleSetVersion3
)

const (
	RuleActionTypeRoute                    = "route"
	RuleActionTypeRouteOptions             = "route-options"
	RuleActionTypeDirect                   = "direct"
	RuleActionTypeReject                   = "reject"
	RuleActionTypeHijackDNS                = "hijack-dns"
	RuleActionTypeSniff                    = "sniff"
	RuleActionTypeSniffOverrideDestination = "sniff-override-destination"
	RuleActionTypeResolve                  = "resolve"
	RuleActionTypePredefined               = "predefined"
)

const (
	RuleActionRejectMethodDefault = "default"
	RuleActionRejectMethodDrop    = "drop"
)

type DomainMatchStrategy = uint8

const (
	DomainMatchStrategyAsIS DomainMatchStrategy = iota
	DomainMatchStrategyPreferFQDN
	DomainMatchStrategyPreferSniffHost
	DomainMatchStrategyFQDNOnly
	DomainMatchStrategySniffHostOnly
)
