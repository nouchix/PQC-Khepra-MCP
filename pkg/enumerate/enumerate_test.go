package enumerate

import (
    "net"
    "testing"
)

func TestGetPrivateIPs(t *testing.T) {
    ips := getPrivateIPs()
    if ips == nil {
        t.Fatalf("expected slice, got nil")
    }
    for _, ip := range ips {
        if net.ParseIP(ip) == nil {
            t.Errorf("invalid ip: %s", ip)
        }
    }
}

func TestGetUptimeInfo(t *testing.T) {
    uptime, boot := getUptimeInfo()
    if uptime < 0 {
        t.Fatalf("negative uptime: %d", uptime)
    }
    // Boot time may be zero on unsupported platforms; just ensure types are valid
    _ = boot
}
