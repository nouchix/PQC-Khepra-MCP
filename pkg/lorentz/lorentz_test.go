package lorentz

import (
	"strings"
	"testing"
	"time"
)

func TestStampNow(t *testing.T) {
	stamp := StampNow()
	if stamp == "" {
		t.Error("StampNow returned empty string")
	}

	// Verify RFC3339 format
	_, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		t.Errorf("StampNow returned invalid format: %v", err)
	}

	if !strings.HasSuffix(stamp, "Z") {
		t.Error("StampNow should return UTC time (Z suffix)")
	}
}
