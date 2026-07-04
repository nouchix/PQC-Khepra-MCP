package flight

// reader.go — recent frame reader for SouHimBou AI threat detection.
//
// Reads the last N frames from the flight log NDJSON file without loading
// the entire file into memory. Used by KASA threat scorer and Ouroboros WAFEye.
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// Recent returns the last n FlightFrames from the flight log.
// Returns an empty slice (not an error) if the log file does not exist yet.
func (r *Recorder) Recent(n int) ([]FlightFrame, error) {
	if r == nil || r.path == "" {
		return nil, nil
	}

	f, err := os.Open(r.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("flight/reader: open %s: %w", r.path, err)
	}
	defer f.Close()

	// Stream-scan all lines and keep a rolling window of the last n.
	ring := make([]FlightFrame, n)
	head := 0
	count := 0

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var frame FlightFrame
		if err := json.Unmarshal(line, &frame); err != nil {
			continue // skip malformed lines
		}
		ring[head%n] = frame
		head++
		count++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("flight/reader: scan: %w", err)
	}

	if count == 0 {
		return nil, nil
	}

	// Reconstruct ordered slice
	size := count
	if size > n {
		size = n
	}
	out := make([]FlightFrame, size)
	if count <= n {
		// Haven't wrapped yet — frames are in order from 0 to count-1
		copy(out, ring[:count])
	} else {
		// Ring has wrapped — oldest entry is at (head % n)
		start := head % n
		for i := 0; i < size; i++ {
			out[i] = ring[(start+i)%n]
		}
	}
	return out, nil
}
