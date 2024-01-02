package option

type SelectorOutboundOptions struct {
	Outbounds                 []string                       `json:"outbounds"`
	Default                   string                         `json:"default,omitempty"`
	InterruptExistConnections bool                           `json:"interrupt_exist_connections,omitempty"`
	Providers                 Listable[GroupProviderOptions] `json:"providers,omitempty"`
}

type URLTestOutboundOptions struct {
	Outbounds                 []string                       `json:"outbounds"`
	URL                       string                         `json:"url,omitempty"`
	Interval                  Duration                       `json:"interval,omitempty"`
	Tolerance                 uint16                         `json:"tolerance,omitempty"`
	IdleTimeout               Duration                       `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool                           `json:"interrupt_exist_connections,omitempty"`
	Providers                 Listable[GroupProviderOptions] `json:"providers,omitempty"`
}

type GroupProviderOptions struct {
	Tag     string           `json:"tag"`
	Rules   Listable[string] `json:"rules"`
	Logical string           `json:"logical,omitempty"`
	Invert  bool             `json:"invert,omitempty"`
}
