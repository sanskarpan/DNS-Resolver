package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"dnsresolver/internal/protocol"
)

func (r *Resolver) resolveRecursive(ctx context.Context, queryID, qname string, qtype uint16, cfg Config) (*protocol.Message, []ResolutionEvent, error) {
	servers := RootHintIPs()
	cnameDepth := 0
	steps := 0
	events := make([]ResolutionEvent, 0, 16)
	visitedCNAME := map[string]struct{}{}
	visitedStates := map[string]struct{}{}
	qnameMinimizationEnabled := cfg.QNAMEMinimization

	for steps < cfg.MaxRecursionDepth {
		steps++
		queryName := qname
		queryType := qtype
		if qnameMinimizationEnabled {
			queryName = MinimizedQNameForHop(qname, steps-1)
			if queryName != normalizeFQDN(qname) {
				queryType = protocol.TypeNS
			}
		}
		state := referralStateKey(queryName, queryType, servers)
		if _, seen := visitedStates[state]; seen {
			return nil, events, fmt.Errorf("referral loop detected")
		}
		visitedStates[state] = struct{}{}

		var (
			resp      *protocol.Message
			hopEvents []ResolutionEvent
			err       error
		)
		if r.queryFunc != nil {
			resp, hopEvents, err = r.queryFunc(ctx, queryID, steps, queryName, queryType, servers)
		} else {
			resp, hopEvents, err = r.queryFastest(ctx, queryID, steps, queryName, queryType, servers, cfg)
		}
		events = append(events, hopEvents...)
		if err != nil {
			return nil, events, err
		}
		if resp == nil {
			return nil, events, errors.New("nil response")
		}

		if resp.Header.RCode == protocol.RCodeNameError {
			if queryName != normalizeFQDN(qname) {
				// Some authorities do not support minimized names.
				qnameMinimizationEnabled = false
				continue
			}
			return resp, events, nil
		}

		if target, ok := findCNAME(resp, qname); ok && qtype != protocol.TypeCNAME {
			if cnameDepth >= cfg.MaxCNAMEDepth {
				return nil, events, fmt.Errorf("cname depth exceeded")
			}
			n := strings.ToLower(normalizeFQDN(target))
			if _, exists := visitedCNAME[n]; exists {
				return nil, events, fmt.Errorf("cname loop detected")
			}
			visitedCNAME[n] = struct{}{}
			cnameDepth++
			events = append(events, ResolutionEvent{QueryID: queryID, Timestamp: time.Now().UTC(), Step: len(events) + 1, StepType: "cname_follow", Query: qname, QueryType: protocol.TypeToString(qtype), Success: true})
			qname = target
			servers = RootHintIPs()
			steps = 0
			continue
		}

		if hasAnswer(resp, qname, qtype) {
			return resp, events, nil
		}
		if shouldCacheAsNODATA(resp, qname, qtype) {
			return resp, events, nil
		}
		// Treat non-NOERROR/NXDOMAIN responses as terminal upstream outcomes.
		if resp.Header.RCode != protocol.RCodeNoError {
			return resp, events, nil
		}

		nextServers := r.nextReferralServers(ctx, resp, cfg)
		if len(nextServers) == 0 {
			// If no referral path remains and the response is authoritative or contains
			// useful sections, treat it as terminal (e.g. NODATA without SOA).
			if resp.Header.AA || len(resp.Answers) > 0 || len(resp.Authorities) > 0 {
				return resp, events, nil
			}
			return nil, events, fmt.Errorf("no next referral servers")
		}
		servers = nextServers
	}
	return nil, events, fmt.Errorf("recursion depth exceeded")
}

func referralStateKey(qname string, qtype uint16, servers []string) string {
	s := append([]string(nil), servers...)
	sort.Strings(s)
	return normalizeFQDN(qname) + "|" + protocol.TypeToString(qtype) + "|" + strings.Join(s, ",")
}

func hasAnswer(msg *protocol.Message, qname string, qtype uint16) bool {
	qname = normalizeFQDN(qname)
	for _, rr := range msg.Answers {
		if normalizeFQDN(rr.Name) == qname && rr.Type == qtype {
			return true
		}
		if rr.Type == protocol.TypeCNAME && qtype == protocol.TypeCNAME {
			return true
		}
	}
	return false
}

func findCNAME(msg *protocol.Message, qname string) (string, bool) {
	qname = normalizeFQDN(qname)
	for _, rr := range msg.Answers {
		if rr.Type != protocol.TypeCNAME || normalizeFQDN(rr.Name) != qname {
			continue
		}
		if c, ok := rr.Data.(protocol.CNAMEData); ok {
			return normalizeFQDN(c.Name), true
		}
	}
	return "", false
}

func (r *Resolver) nextReferralServers(ctx context.Context, msg *protocol.Message, cfg Config) []string {
	zone := "."
	nsNames := make(map[string]struct{})
	for _, rr := range append(append([]protocol.ResourceRecord{}, msg.Authorities...), msg.Answers...) {
		if rr.Type != protocol.TypeNS {
			continue
		}
		zone = rr.Name
		if ns, ok := rr.Data.(protocol.NSData); ok {
			nsNames[normalizeFQDN(ns.Name)] = struct{}{}
		}
	}
	if len(nsNames) == 0 {
		return nil
	}

	glueCandidates := append(append([]protocol.ResourceRecord{}, msg.Additionals...), msg.Answers...)
	validGlue, rejected := FilterGlueByBailiwick(zone, glueCandidates)
	for i := 0; i < rejected; i++ {
		r.incSecurityCounter("bailiwick_rejected")
	}
	servers := make([]string, 0, len(validGlue))
	seen := map[string]struct{}{}
	for _, rr := range validGlue {
		if _, ok := nsNames[normalizeFQDN(rr.Name)]; !ok && len(nsNames) > 0 {
			continue
		}
		ip := glueIP(rr)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		servers = append(servers, ip)
	}

	if len(servers) == 0 {
		servers = r.resolveNSHostnames(ctx, nsNames, cfg.UpstreamTimeout)
		return servers
	}
	return servers
}

func (r *Resolver) resolveNSHostnames(ctx context.Context, nsNames map[string]struct{}, timeout time.Duration) []string {
	if len(nsNames) == 0 || r.lookupIPs == nil {
		return nil
	}
	names := make([]string, 0, len(nsNames))
	for name := range nsNames {
		names = append(names, strings.TrimSuffix(normalizeFQDN(name), "."))
	}
	sort.Strings(names)

	seen := map[string]struct{}{}
	servers := make([]string, 0, len(names))
	for _, host := range names {
		lookupCtx := ctx
		cancel := func() {}
		if timeout > 0 {
			lookupCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		ips, err := r.lookupIPs(lookupCtx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			addr := ip.String()
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			servers = append(servers, addr)
		}
	}
	return servers
}

func glueIP(rr protocol.ResourceRecord) string {
	switch d := rr.Data.(type) {
	case protocol.AData:
		return net.IP(d.Address[:]).String()
	case protocol.AAAAData:
		return net.IP(d.Address[:]).String()
	default:
		return ""
	}
}
