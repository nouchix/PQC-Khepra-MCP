package arsenal

import (
	"fmt"
	"os/exec"
	"runtime"
)

// DeployFirewall implements OS-agnostic firewall rules.
// Currently supports Windows (netsh) and Linux (iptables).
func DeployFirewall(port string, direction string) error {
	if direction != "inbound" {
		return fmt.Errorf("only inbound blocking supported for safety")
	}

	switch runtime.GOOS {
	case "windows":
		ruleName := fmt.Sprintf("KhepraBlockPort%s", port)
		// netsh advfirewall firewall add rule name="KhepraBlockPort80" dir=in action=block protocol=TCP localport=80
		cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=in",
			"action=block",
			"protocol=TCP",
			"localport="+port)

		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("windows firewall failed: %v | output: %s", err, out)
		}
		return nil
	case "linux":
		// iptables -A INPUT -p tcp --dport 80 -j DROP
		cmd := exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables failed: %v | output: %s", err, out)
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
