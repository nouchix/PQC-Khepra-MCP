package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Minimal RFC 1035 message codec. Used only for record types the Go stdlib
// resolver does not expose (CAA, SOA) and for AXFR zone-transfer probing.
// No external library, no compression on the wire we generate (only decoded
// on responses, where it's mandatory to support).

const (
	classIN = 1

	typeA     = 1
	typeNS    = 2
	typeCNAME = 5
	typeSOA   = 6
	typeMX    = 15
	typeTXT   = 16
	typeAAAA  = 28
	typeSRV   = 33
	typeCAA   = 257
	typeAXFR  = 252
)

func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	buf := make([]byte, 0, len(name)+2)
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) > 63 {
				label = label[:63]
			}
			buf = append(buf, byte(len(label)))
			buf = append(buf, []byte(label)...)
		}
	}
	buf = append(buf, 0)
	return buf
}

func buildQuery(qtype uint16, name string) []byte {
	id := uint16(rand.Intn(65536))
	msg := make([]byte, 0, 32+len(name))
	msg = append(msg, byte(id>>8), byte(id))
	msg = append(msg, 0x01, 0x00) // standard query, recursion desired
	msg = append(msg, 0x00, 0x01) // QDCOUNT=1
	msg = append(msg, 0x00, 0x00) // ANCOUNT=0
	msg = append(msg, 0x00, 0x00) // NSCOUNT=0
	msg = append(msg, 0x00, 0x00) // ARCOUNT=0
	msg = append(msg, encodeName(name)...)
	msg = append(msg, byte(qtype>>8), byte(qtype))
	msg = append(msg, 0x00, classIN)
	return msg
}

// decodeName decodes a (possibly compressed) domain name starting at offset
// and returns the name plus the offset immediately following it in the
// *original* (uncompressed-pointer) stream.
func decodeName(msg []byte, offset int) (string, int, error) {
	var labels []string
	jumps := 0
	cursor := offset
	returnOffset := -1

	for {
		if cursor >= len(msg) {
			return "", 0, fmt.Errorf("dns: name offset out of range")
		}
		length := int(msg[cursor])
		if length == 0 {
			cursor++
			break
		}
		if length&0xC0 == 0xC0 {
			if cursor+1 >= len(msg) {
				return "", 0, fmt.Errorf("dns: truncated compression pointer")
			}
			if jumps == 0 {
				returnOffset = cursor + 2
			}
			jumps++
			if jumps > 20 {
				return "", 0, fmt.Errorf("dns: too many compression jumps")
			}
			ptr := (length&0x3F)<<8 | int(msg[cursor+1])
			cursor = ptr
			continue
		}
		cursor++
		if cursor+length > len(msg) {
			return "", 0, fmt.Errorf("dns: label out of range")
		}
		labels = append(labels, string(msg[cursor:cursor+length]))
		cursor += length
	}

	if returnOffset == -1 {
		returnOffset = cursor
	}
	return strings.Join(labels, "."), returnOffset, nil
}

type resourceRecord struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	RData       []byte
	RDataOffset int // absolute offset of RData within msg, for names embedded in rdata (SOA, NS, MX, CNAME)
}

type message struct {
	ID      uint16
	Flags   uint16
	Answers []resourceRecord
}

func (m *message) RCode() uint16   { return m.Flags & 0x000F }
func (m *message) Truncated() bool { return m.Flags&0x0200 != 0 }

func parseMessage(msg []byte) (*message, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns: message too short")
	}
	m := &message{
		ID:    binary.BigEndian.Uint16(msg[0:2]),
		Flags: binary.BigEndian.Uint16(msg[2:4]),
	}
	qd := binary.BigEndian.Uint16(msg[4:6])
	an := binary.BigEndian.Uint16(msg[6:8])
	ns := binary.BigEndian.Uint16(msg[8:10])
	ar := binary.BigEndian.Uint16(msg[10:12])

	offset := 12
	for i := 0; i < int(qd); i++ {
		_, next, err := decodeName(msg, offset)
		if err != nil {
			return nil, err
		}
		offset = next + 4 // QTYPE + QCLASS
	}

	total := int(an) + int(ns) + int(ar)
	for i := 0; i < total; i++ {
		name, next, err := decodeName(msg, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+10 > len(msg) {
			return nil, fmt.Errorf("dns: truncated RR header")
		}
		rtype := binary.BigEndian.Uint16(msg[offset : offset+2])
		rclass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
		rdlen := binary.BigEndian.Uint16(msg[offset+8 : offset+10])
		offset += 10
		if offset+int(rdlen) > len(msg) {
			return nil, fmt.Errorf("dns: truncated RDATA")
		}
		rr := resourceRecord{
			Name:        name,
			Type:        rtype,
			Class:       rclass,
			TTL:         ttl,
			RData:       msg[offset : offset+int(rdlen)],
			RDataOffset: offset,
		}
		if i < int(an) {
			m.Answers = append(m.Answers, rr)
		}
		offset += int(rdlen)
	}
	return m, nil
}

func exchangeUDP(server string, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeTCP(server string, query []byte, timeout time.Duration) (net.Conn, []byte, error) {
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	prefixed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(prefixed[:2], uint16(len(query)))
	copy(prefixed[2:], query)
	if _, err := conn.Write(prefixed); err != nil {
		conn.Close()
		return nil, nil, err
	}
	resp, err := readTCPMessage(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, resp, nil
}

func readTCPMessage(conn net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// rawQuery performs a single query, falling back to TCP if the UDP response
// is truncated. It returns the parsed message plus the raw response buffer
// (needed by callers that must resolve compressed names embedded in RDATA,
// e.g. SOA's MNAME/RNAME).
func rawQuery(ctx context.Context, server string, qtype uint16, name string, timeout time.Duration) (*message, []byte, error) {
	query := buildQuery(qtype, name)

	respBytes, err := exchangeUDP(server, query, timeout)
	if err == nil {
		msg, perr := parseMessage(respBytes)
		if perr == nil && !msg.Truncated() {
			return msg, respBytes, nil
		}
	}

	conn, tcpResp, terr := exchangeTCP(server, query, timeout)
	if terr != nil {
		if err != nil {
			return nil, nil, fmt.Errorf("udp: %v, tcp: %v", err, terr)
		}
		return nil, nil, terr
	}
	defer conn.Close()
	msg, perr := parseMessage(tcpResp)
	if perr != nil {
		return nil, nil, perr
	}
	return msg, tcpResp, nil
}

func queryCAA(ctx context.Context, server, domain string) ([]CAARecord, error) {
	msg, _, err := rawQuery(ctx, server, typeCAA, domain, 5*time.Second)
	if err != nil {
		return nil, err
	}
	var out []CAARecord
	for _, rr := range msg.Answers {
		if rr.Type != typeCAA || len(rr.RData) < 2 {
			continue
		}
		flag := rr.RData[0]
		tagLen := int(rr.RData[1])
		if 2+tagLen > len(rr.RData) {
			continue
		}
		tag := string(rr.RData[2 : 2+tagLen])
		value := string(rr.RData[2+tagLen:])
		out = append(out, CAARecord{Flag: flag, Tag: tag, Value: value})
	}
	return out, nil
}

func querySOA(ctx context.Context, server, domain string) (*SOARecord, error) {
	msg, raw, err := rawQuery(ctx, server, typeSOA, domain, 5*time.Second)
	if err != nil {
		return nil, err
	}
	for _, rr := range msg.Answers {
		if rr.Type != typeSOA {
			continue
		}
		return parseSOARData(raw, rr.RDataOffset)
	}
	return nil, fmt.Errorf("dns: no SOA record returned")
}

// parseSOARData decodes SOA RDATA: MNAME, RNAME (both possibly-compressed
// names), then 5 x uint32 (serial, refresh, retry, expire, minimum).
func parseSOARData(msg []byte, offset int) (*SOARecord, error) {
	mname, next, err := decodeName(msg, offset)
	if err != nil {
		return nil, err
	}
	rname, next2, err := decodeName(msg, next)
	if err != nil {
		return nil, err
	}
	if next2+20 > len(msg) {
		return nil, fmt.Errorf("dns: truncated SOA RDATA")
	}
	return &SOARecord{
		PrimaryNS:  mname,
		AdminEmail: rname,
		Serial:     binary.BigEndian.Uint32(msg[next2 : next2+4]),
		Refresh:    binary.BigEndian.Uint32(msg[next2+4 : next2+8]),
		Retry:      binary.BigEndian.Uint32(msg[next2+8 : next2+12]),
		Expire:     binary.BigEndian.Uint32(msg[next2+12 : next2+16]),
		MinimumTTL: binary.BigEndian.Uint32(msg[next2+16 : next2+20]),
	}, nil
}
