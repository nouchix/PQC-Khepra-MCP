// Package hub — shared utilities for fleet/kasa/imhotep/scan HTTP handlers.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package hub

import (
	"net"
	"time"
)

// dialTimeout attempts a TCP connection to addr, returning the net.Conn on success.
// Used for TOFU connectivity tests against fleet assets.
func dialTimeout(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 2*time.Second)
}

