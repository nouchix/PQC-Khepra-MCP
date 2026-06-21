package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// ZoneTransferResult reports whether a nameserver allowed an AXFR zone
// transfer — a critical misconfiguration that leaks the entire DNS zone
// (every subdomain, internal hostnames, mail servers) to anyone who asks.
type ZoneTransferResult struct {
	Nameserver  string   `json:"nameserver"`
	Vulnerable  bool     `json:"vulnerable"`
	RecordCount int      `json:"record_count"`
	LeakedNames []string `json:"leaked_names,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// TestZoneTransfer attempts an AXFR against each nameserver for domain.
// A successful, non-empty transfer means the zone is fully exposed.
func TestZoneTransfer(domain string, nameservers []string, timeout time.Duration) []ZoneTransferResult {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	results := make([]ZoneTransferResult, 0, len(nameservers))
	for _, ns := range nameservers {
		results = append(results, attemptAXFR(domain, ns, timeout))
	}
	return results
}

func attemptAXFR(domain, nameserver string, timeout time.Duration) ZoneTransferResult {
	res := ZoneTransferResult{Nameserver: nameserver}

	addrs, err := net.LookupHost(nameserver)
	if err != nil || len(addrs) == 0 {
		res.Error = fmt.Sprintf("could not resolve nameserver: %v", err)
		return res
	}
	server := net.JoinHostPort(addrs[0], "53")

	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	query := buildQuery(typeAXFR, domain)
	prefixed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(prefixed[:2], uint16(len(query)))
	copy(prefixed[2:], query)
	if _, err := conn.Write(prefixed); err != nil {
		res.Error = err.Error()
		return res
	}

	seenNames := make(map[string]bool)
	soaCount := 0
	for msgCount := 0; msgCount < 200; msgCount++ {
		raw, err := readTCPMessage(conn)
		if err != nil {
			if err == io.EOF && res.RecordCount > 0 {
				break
			}
			if msgCount == 0 {
				res.Error = err.Error()
				return res
			}
			break
		}
		msg, perr := parseMessage(raw)
		if perr != nil {
			break
		}
		if msg.RCode() != 0 {
			res.Error = fmt.Sprintf("server refused AXFR (rcode=%d)", msg.RCode())
			return res
		}
		for _, rr := range msg.Answers {
			res.RecordCount++
			if rr.Type == typeSOA {
				soaCount++
			}
			if !seenNames[rr.Name] && len(res.LeakedNames) < 50 {
				seenNames[rr.Name] = true
				res.LeakedNames = append(res.LeakedNames, rr.Name)
			}
		}
		// A complete AXFR begins and ends with an SOA record for the zone.
		if soaCount >= 2 {
			break
		}
		if len(msg.Answers) == 0 {
			break
		}
	}

	if res.RecordCount > 0 {
		res.Vulnerable = true
	} else if res.Error == "" {
		res.Error = "no records returned (transfer likely refused)"
	}
	return res
}
