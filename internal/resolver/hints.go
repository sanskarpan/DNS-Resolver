package resolver

import "time"

type RootServer struct {
	Name                string    `json:"name"`
	IPv4                string    `json:"ipv4"`
	IPv6                string    `json:"ipv6,omitempty"`
	LastLatency         int64     `json:"last_latency_ms"`
	LastSeen            time.Time `json:"last_seen,omitempty"`
	State               string    `json:"state"`
	StateCode           int       `json:"state_code"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastFailure         time.Time `json:"last_failure,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	TotalSuccesses      uint64    `json:"total_successes"`
	TotalFailures       uint64    `json:"total_failures"`
}

type UpstreamStatus struct {
	Server              string    `json:"server"`
	ServerName          string    `json:"server_name,omitempty"`
	LastLatency         int64     `json:"last_latency_ms"`
	LastSeen            time.Time `json:"last_seen,omitempty"`
	State               string    `json:"state"`
	StateCode           int       `json:"state_code"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastFailure         time.Time `json:"last_failure,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	TotalSuccesses      uint64    `json:"total_successes"`
	TotalFailures       uint64    `json:"total_failures"`
}

func DefaultRootHints() []RootServer {
	return []RootServer{
		{Name: "a.root-servers.net", IPv4: "198.41.0.4", IPv6: "2001:503:ba3e::2:30", State: "closed"},
		{Name: "b.root-servers.net", IPv4: "170.247.170.2", IPv6: "2801:1b8:10::b", State: "closed"},
		{Name: "c.root-servers.net", IPv4: "192.33.4.12", IPv6: "2001:500:2::c", State: "closed"},
		{Name: "d.root-servers.net", IPv4: "199.7.91.13", IPv6: "2001:500:2d::d", State: "closed"},
		{Name: "e.root-servers.net", IPv4: "192.203.230.10", IPv6: "2001:500:a8::e", State: "closed"},
		{Name: "f.root-servers.net", IPv4: "192.5.5.241", IPv6: "2001:500:2f::f", State: "closed"},
		{Name: "g.root-servers.net", IPv4: "192.112.36.4", IPv6: "2001:500:12::d0d", State: "closed"},
		{Name: "h.root-servers.net", IPv4: "198.97.190.53", IPv6: "2001:500:1::53", State: "closed"},
		{Name: "i.root-servers.net", IPv4: "192.36.148.17", IPv6: "2001:7fe::53", State: "closed"},
		{Name: "j.root-servers.net", IPv4: "192.58.128.30", IPv6: "2001:503:c27::2:30", State: "closed"},
		{Name: "k.root-servers.net", IPv4: "193.0.14.129", IPv6: "2001:7fd::1", State: "closed"},
		{Name: "l.root-servers.net", IPv4: "199.7.83.42", IPv6: "2001:500:9f::42", State: "closed"},
		{Name: "m.root-servers.net", IPv4: "202.12.27.33", IPv6: "2001:dc3::35", State: "closed"},
	}
}

func RootHintIPs() []string {
	hints := DefaultRootHints()
	ips := make([]string, 0, len(hints))
	for _, h := range hints {
		if h.IPv4 != "" {
			ips = append(ips, h.IPv4)
		}
	}
	return ips
}
