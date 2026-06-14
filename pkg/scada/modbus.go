// Package scada provides a minimal Modbus TCP client for reading ESP32 sensor registers.
// No external dependencies — pure net/io/encoding/binary.
package scada

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	dialTimeout = 3 * time.Second
	rwTimeout   = 3 * time.Second
)

// ReadHoldingRegisters reads `quantity` holding registers (FC03) starting at `startAddr`.
// startAddr is the 0-based protocol address (register 0 = Modbus 40001).
func ReadHoldingRegisters(host string, port int, unitID byte, startAddr, quantity uint16) ([]uint16, error) {
	pdu := []byte{
		0x03,
		byte(startAddr >> 8), byte(startAddr),
		byte(quantity >> 8), byte(quantity),
	}
	resp, err := mbapRoundTrip(host, port, unitID, pdu)
	if err != nil {
		return nil, err
	}
	// resp[0] = FC, resp[1] = byteCount, resp[2:] = data
	if len(resp) < 2 {
		return nil, fmt.Errorf("FC03 response too short")
	}
	byteCount := int(resp[1])
	if len(resp) < 2+byteCount {
		return nil, fmt.Errorf("FC03 data truncated")
	}
	regs := make([]uint16, byteCount/2)
	for i := range regs {
		regs[i] = binary.BigEndian.Uint16(resp[2+i*2:])
	}
	return regs, nil
}

// ReadDiscreteInputs reads `quantity` discrete inputs (FC02) starting at `startAddr`.
// Returns one bool per discrete input, in order.
func ReadDiscreteInputs(host string, port int, unitID byte, startAddr, quantity uint16) ([]bool, error) {
	pdu := []byte{
		0x02,
		byte(startAddr >> 8), byte(startAddr),
		byte(quantity >> 8), byte(quantity),
	}
	resp, err := mbapRoundTrip(host, port, unitID, pdu)
	if err != nil {
		return nil, err
	}
	if len(resp) < 2 {
		return nil, fmt.Errorf("FC02 response too short")
	}
	byteCount := int(resp[1])
	if len(resp) < 2+byteCount {
		return nil, fmt.Errorf("FC02 data truncated")
	}
	inputs := make([]bool, quantity)
	for i := uint16(0); i < quantity; i++ {
		b := resp[2+i/8]
		inputs[i] = (b>>uint(i%8))&1 == 1
	}
	return inputs, nil
}

// WriteCoil writes a single coil (FC05). value true = 0xFF00, false = 0x0000.
func WriteCoil(host string, port int, unitID byte, coilAddr uint16, value bool) error {
	v := uint16(0x0000)
	if value {
		v = 0xFF00
	}
	pdu := []byte{
		0x05,
		byte(coilAddr >> 8), byte(coilAddr),
		byte(v >> 8), byte(v),
	}
	_, err := mbapRoundTrip(host, port, unitID, pdu)
	return err
}

// mbapRoundTrip sends a PDU wrapped in an MBAP header and returns the response PDU.
// The caller gets bytes starting at the Function Code byte.
func mbapRoundTrip(host string, port int, unitID byte, pdu []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", host, port, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(rwTimeout)) //nolint:errcheck

	// MBAP header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + PDU
	mbap := make([]byte, 7+len(pdu))
	mbap[0], mbap[1] = 0x00, 0x01         // Transaction ID
	mbap[2], mbap[3] = 0x00, 0x00         // Protocol ID
	length := uint16(1 + len(pdu))        // Unit ID byte + PDU
	mbap[4], mbap[5] = byte(length>>8), byte(length)
	mbap[6] = unitID
	copy(mbap[7:], pdu)

	if _, err := conn.Write(mbap); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// Read response MBAP header (6 bytes) + Unit ID (1)
	respHdr := make([]byte, 7)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		return nil, fmt.Errorf("read response header: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(respHdr[4:6])) - 1 // minus Unit ID already read
	if respLen <= 0 {
		return nil, fmt.Errorf("invalid response length %d", respLen)
	}

	respPDU := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respPDU); err != nil {
		return nil, fmt.Errorf("read response PDU: %w", err)
	}

	// Check for exception response (FC | 0x80)
	if len(respPDU) > 0 && respPDU[0]&0x80 != 0 {
		code := byte(0)
		if len(respPDU) > 1 {
			code = respPDU[1]
		}
		return nil, fmt.Errorf("modbus exception FC=0x%02x code=%d", respPDU[0]&0x7f, code)
	}

	return respPDU, nil
}
