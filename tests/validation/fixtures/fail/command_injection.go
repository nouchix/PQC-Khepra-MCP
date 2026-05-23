// Command injection vulnerabilities - should FAIL validation
package executor

import (
	"fmt"
	"os/exec"
)

// ❌ FAIL: Command injection via fmt.Sprintf
func RunCommandUnsafe(filename string) error {
	// VULNERABLE: User input in fmt.Sprintf with exec.Command
	cmd := exec.Command("sh", "-c", fmt.Sprintf("cat %s", filename))
	return cmd.Run()
}

// ❌ FAIL: Command injection via string concatenation
func ProcessFileUnsafe(path string, operation string) error {
	// VULNERABLE: Concatenating user input into command
	cmdStr := "process-file " + operation + " " + path
	cmd := exec.Command("sh", "-c", cmdStr)
	return cmd.Run()
}

// ❌ FAIL: Another command injection example
func BackupDatabaseUnsafe(dbName string) error {
	// VULNERABLE: Using fmt.Sprintf to build command with user input
	backupCmd := fmt.Sprintf("pg_dump %s > /backups/%s.sql", dbName, dbName)
	cmd := exec.Command("bash", "-c", backupCmd)
	return cmd.Run()
}
