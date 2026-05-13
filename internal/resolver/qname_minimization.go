package resolver

import "strings"

func QNAMEMinimizationSteps(qname string) []string {
	full := normalizeFQDN(qname)
	if full == "." {
		return []string{"."}
	}
	trim := strings.TrimSuffix(full, ".")
	labels := strings.Split(trim, ".")
	if len(labels) == 0 {
		return []string{full}
	}
	out := make([]string, 0, len(labels))
	for i := len(labels) - 1; i >= 0; i-- {
		part := strings.Join(labels[i:], ".") + "."
		out = append(out, part)
	}
	return out
}

func MinimizedQNameForHop(qname string, hop int) string {
	steps := QNAMEMinimizationSteps(qname)
	if hop < 0 {
		hop = 0
	}
	if hop >= len(steps) {
		return normalizeFQDN(qname)
	}
	return steps[hop]
}
