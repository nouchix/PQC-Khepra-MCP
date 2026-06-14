//go:build darwin

package agent

import "fmt"

// Run starts the ASAF agent. On macOS use launchd or run directly.
func Run(baseDir string) {
	fmt.Println("[agent] Run: use 'sudo launchctl load /Library/LaunchDaemons/com.nouchix.asaf.plist' on macOS.")
}

// InstallService registers the agent as a launchd daemon.
// Requires a .plist file at /Library/LaunchDaemons/com.nouchix.asaf.plist and root privileges.
func InstallService(exePath string) error {
	return fmt.Errorf("InstallService: deploy com.nouchix.asaf.plist to /Library/LaunchDaemons/ then run 'sudo launchctl load' — see docs/macos-install.md")
}

// RemoveService unloads and removes the launchd daemon.
// Requires root privileges: 'sudo launchctl unload /Library/LaunchDaemons/com.nouchix.asaf.plist'.
func RemoveService() error {
	return fmt.Errorf("RemoveService: run 'sudo launchctl unload /Library/LaunchDaemons/com.nouchix.asaf.plist' to remove the daemon")
}
