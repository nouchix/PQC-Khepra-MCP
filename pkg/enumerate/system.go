package enumerate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
)

const (
	// psCommand is the PowerShell flag used to pass an inline script.
	psCommand = "-Command"

	// errUnsupportedOSFmt is the format string for unsupported-OS errors.
	// Use errUnsupportedOS() rather than repeating this literal inline.
	errUnsupportedOSFmt = "unsupported OS: %s"
)

// errUnsupportedOS returns a formatted error for the current OS.
func errUnsupportedOS() error { return fmt.Errorf(errUnsupportedOSFmt, runtime.GOOS) }

// collectField runs fn and, if it succeeds, stores the result via set.
// On failure it logs a warning and leaves the destination unchanged.
func collectField[T any](label string, fn func() (T, error), set func(T)) {
	v, err := fn()
	if err != nil {
		fmt.Printf("[WARN] Failed to collect %s: %v\n", label, err)
		return
	}
	set(v)
}

// CollectSystemIntelligence gathers comprehensive system information
// including processes, services, kernel modules, users, and startup items.
func CollectSystemIntelligence() (audit.SystemIntelligence, error) {
	si := audit.SystemIntelligence{
		Processes:         []audit.ProcessInfo{},
		Services:          []audit.ServiceInfo{},
		KernelModules:     []audit.KernelModule{},
		InstalledSoftware: []audit.Software{},
		Users:             []audit.UserInfo{},
		CronJobs:          []audit.CronJob{},
		StartupItems:      []audit.StartupItem{},
	}

	collectField("processes", collectProcesses, func(v []audit.ProcessInfo) { si.Processes = v })
	collectField("services", collectServices, func(v []audit.ServiceInfo) { si.Services = v })
	if runtime.GOOS == "linux" {
		collectField("kernel modules", collectKernelModules, func(v []audit.KernelModule) { si.KernelModules = v })
	}
	collectField("installed software", collectInstalledSoftware, func(v []audit.Software) { si.InstalledSoftware = v })
	collectField("users", collectUsers, func(v []audit.UserInfo) { si.Users = v })
	collectField("cron jobs", collectCronJobs, func(v []audit.CronJob) { si.CronJobs = v })
	collectField("startup items", collectStartupItems, func(v []audit.StartupItem) { si.StartupItems = v })

	return si, nil
}

// collectProcesses collects information about running processes
func collectProcesses() ([]audit.ProcessInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return collectProcessesLinux()
	case "windows":
		return collectProcessesWindows()
	case "darwin":
		return collectProcessesDarwin()
	default:
		return nil, errUnsupportedOS()
	}
}

func collectProcessesLinux() ([]audit.ProcessInfo, error) {
	var processes []audit.ProcessInfo

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}

		procInfo, err := getLinuxProcessInfo(pid)
		if err != nil {
			continue
		}

		processes = append(processes, procInfo)
	}

	return processes, nil
}

func getLinuxProcessInfo(pid int) (audit.ProcessInfo, error) {
	procInfo := audit.ProcessInfo{PID: pid}

	// Read /proc/PID/stat for process name and PPID
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return procInfo, err
	}
	statStr := string(statData)
	if start := strings.IndexByte(statStr, '('); start >= 0 {
		if end := strings.LastIndexByte(statStr, ')'); end > start {
			procInfo.Name = statStr[start+1 : end]
			if fields := strings.Fields(statStr[end+1:]); len(fields) >= 2 {
				procInfo.PPID, _ = strconv.Atoi(fields[1])
			}
		}
	}

	// Read /proc/PID/cmdline
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if cmdlineData, err := os.ReadFile(cmdlinePath); err == nil {
		procInfo.CmdLine = strings.TrimSpace(strings.ReplaceAll(string(cmdlineData), "\x00", " "))
	}

	// Read /proc/PID/status for UID → username and VmRSS → memory
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if statusData, err := os.ReadFile(statusPath); err == nil {
		parseLinuxProcStatus(string(statusData), &procInfo)
	}

	// Resolve executable path and compute SHA-256
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	if exeTarget, err := os.Readlink(exePath); err == nil {
		procInfo.ExecutablePath = exeTarget
		if fileData, err := os.ReadFile(exeTarget); err == nil {
			hash := sha256.Sum256(fileData)
			procInfo.FileHash = hex.EncodeToString(hash[:])
		}
	}

	return procInfo, nil
}

// parseLinuxProcStatus extracts UID→username and VmRSS→MemoryMB from the
// text contents of /proc/<pid>/status, updating procInfo in-place.
func parseLinuxProcStatus(data string, procInfo *audit.ProcessInfo) {
	for _, line := range strings.Split(data, "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			if fields := strings.Fields(line); len(fields) >= 2 {
				uid, _ := strconv.Atoi(fields[1])
				if u, err := user.LookupId(fmt.Sprintf("%d", uid)); err == nil {
					procInfo.User = u.Username
				}
			}
		case strings.HasPrefix(line, "VmRSS:"):
			if fields := strings.Fields(line); len(fields) >= 2 {
				kb, _ := strconv.ParseFloat(fields[1], 64)
				procInfo.MemoryMB = kb / 1024
			}
		}
	}
}

func collectProcessesWindows() ([]audit.ProcessInfo, error) {
	cmd := exec.Command("powershell", psCommand,
		"Get-Process | Select-Object Id,ProcessName,Path,StartTime | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var processes []audit.ProcessInfo
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}

		pid, _ := strconv.Atoi(strings.Trim(fields[0], "\""))
		name := strings.Trim(fields[1], "\"")
		path := strings.Trim(fields[2], "\"")

		procInfo := audit.ProcessInfo{
			PID:            pid,
			Name:           name,
			ExecutablePath: path,
		}

		processes = append(processes, procInfo)
	}

	return processes, nil
}

func collectProcessesDarwin() ([]audit.ProcessInfo, error) {
	cmd := exec.Command("ps", "-eo", "pid,ppid,comm,args,user")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var processes []audit.ProcessInfo
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		name := fields[2]
		user := fields[len(fields)-1]
		cmdline := strings.Join(fields[3:len(fields)-1], " ")

		procInfo := audit.ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    name,
			CmdLine: cmdline,
			User:    user,
		}

		processes = append(processes, procInfo)
	}

	return processes, nil
}

// collectServices collects information about system services
func collectServices() ([]audit.ServiceInfo, error) {
	switch runtime.GOOS {
	case "linux":
		return collectServicesLinux()
	case "windows":
		return collectServicesWindows()
	case "darwin":
		return collectServicesDarwin()
	default:
		return nil, errUnsupportedOS()
	}
}

func collectServicesLinux() ([]audit.ServiceInfo, error) {
	var services []audit.ServiceInfo

	// Use systemctl to list services
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		if !strings.HasSuffix(fields[0], ".service") {
			continue
		}

		name := strings.TrimSuffix(fields[0], ".service")
		state := fields[2]

		service := audit.ServiceInfo{
			Name:  name,
			State: state,
		}

		services = append(services, service)
	}

	return services, nil
}

func collectServicesWindows() ([]audit.ServiceInfo, error) {
	cmd := exec.Command("powershell", psCommand,
		"Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var services []audit.ServiceInfo
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		name := strings.Trim(fields[0], "\"")
		displayName := strings.Trim(fields[1], "\"")
		state := strings.Trim(fields[2], "\"")
		startMode := strings.Trim(fields[3], "\"")

		service := audit.ServiceInfo{
			Name:        name,
			DisplayName: displayName,
			State:       state,
			StartMode:   startMode,
		}

		services = append(services, service)
	}

	return services, nil
}

func collectServicesDarwin() ([]audit.ServiceInfo, error) {
	cmd := exec.Command("launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var services []audit.ServiceInfo
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[2]
		state := "unknown"
		if fields[0] != "-" {
			state = "running"
		}

		service := audit.ServiceInfo{
			Name:  name,
			State: state,
		}

		services = append(services, service)
	}

	return services, nil
}

// collectKernelModules collects loaded kernel modules (Linux only)
func collectKernelModules() ([]audit.KernelModule, error) {
	var modules []audit.KernelModule

	file, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[0]
		size, _ := strconv.Atoi(fields[1])

		// Parse "used by" list
		var usedBy []string
		if len(fields) >= 4 && fields[3] != "-" {
			usedBy = strings.Split(strings.Trim(fields[3], ","), ",")
		}

		module := audit.KernelModule{
			Name:   name,
			Size:   size,
			UsedBy: usedBy,
			Hidden: false, // Will be detected by rootkit scanner
		}

		modules = append(modules, module)
	}

	// Detect hidden modules by comparing /proc/modules with /sys/module
	sysModules, err := os.ReadDir("/sys/module")
	if err == nil {
		procModuleNames := make(map[string]bool)
		for _, m := range modules {
			procModuleNames[m.Name] = true
		}

		for _, sysModule := range sysModules {
			if !procModuleNames[sysModule.Name()] {
				// Hidden module detected!
				modules = append(modules, audit.KernelModule{
					Name:   sysModule.Name(),
					Hidden: true,
				})
			}
		}
	}

	return modules, scanner.Err()
}

// collectInstalledSoftware collects list of installed software
func collectInstalledSoftware() ([]audit.Software, error) {
	switch runtime.GOOS {
	case "linux":
		return collectInstalledSoftwareLinux()
	case "windows":
		return collectInstalledSoftwareWindows()
	case "darwin":
		return collectInstalledSoftwareDarwin()
	default:
		return nil, errUnsupportedOS()
	}
}

func collectInstalledSoftwareLinux() ([]audit.Software, error) {
	var software []audit.Software

	// Try dpkg for Debian-based systems
	cmd := exec.Command("dpkg", "-l")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "ii") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 3 {
				software = append(software, audit.Software{
					Name:    fields[1],
					Version: fields[2],
				})
			}
		}
		return software, nil
	}

	// Try rpm for Red Hat-based systems
	cmd = exec.Command("rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\n")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				software = append(software, audit.Software{
					Name:    fields[0],
					Version: fields[1],
				})
			}
		}
		return software, nil
	}

	return software, nil
}

func collectInstalledSoftwareWindows() ([]audit.Software, error) {
	cmd := exec.Command("powershell", psCommand,
		"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var software []audit.Software
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 3 {
			name := strings.Trim(fields[0], "\"")
			version := strings.Trim(fields[1], "\"")
			publisher := strings.Trim(fields[2], "\"")

			if name != "" {
				software = append(software, audit.Software{
					Name:      name,
					Version:   version,
					Publisher: publisher,
				})
			}
		}
	}

	return software, nil
}

func collectInstalledSoftwareDarwin() ([]audit.Software, error) {
	cmd := exec.Command("system_profiler", "SPApplicationsDataType", "-xml")
	if _, err := cmd.Output(); err != nil {
		return nil, err
	}

	// system_profiler XML is not parsed here. Application names are read
	// directly from /Applications as a fast, dependency-free fallback.
	var software []audit.Software

	apps, err := os.ReadDir("/Applications")
	if err != nil {
		return nil, err
	}

	for _, app := range apps {
		if strings.HasSuffix(app.Name(), ".app") {
			software = append(software, audit.Software{
				Name: strings.TrimSuffix(app.Name(), ".app"),
			})
		}
	}

	return software, nil
}

// collectUsers collects system user accounts
func collectUsers() ([]audit.UserInfo, error) {
	switch runtime.GOOS {
	case "linux", "darwin":
		return collectUsersUnix()
	case "windows":
		return collectUsersWindows()
	default:
		return nil, errUnsupportedOS()
	}
}

func collectUsersUnix() ([]audit.UserInfo, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []audit.UserInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		username := fields[0]
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		homeDir := fields[5]
		shell := fields[6]

		// Determine if user is privileged
		privileged := (uid == 0)

		// Get groups
		groups := []string{}
		groupsCmd := exec.Command("id", "-Gn", username)
		if groupsOutput, err := groupsCmd.Output(); err == nil {
			groups = strings.Fields(string(groupsOutput))
		}

		userInfo := audit.UserInfo{
			Username:   username,
			UID:        uid,
			GID:        gid,
			Groups:     groups,
			HomeDir:    homeDir,
			Shell:      shell,
			Privileged: privileged,
		}

		users = append(users, userInfo)
	}

	return users, scanner.Err()
}

func collectUsersWindows() ([]audit.UserInfo, error) {
	cmd := exec.Command("net", "user")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var users []audit.UserInfo
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		usernames := strings.Fields(line)
		for _, username := range usernames {
			if username == "" || username == "User" || username == "accounts" {
				continue
			}

			userInfo := audit.UserInfo{
				Username: username,
			}

			users = append(users, userInfo)
		}
	}

	return users, nil
}

// collectCronJobs collects scheduled tasks
func collectCronJobs() ([]audit.CronJob, error) {
	switch runtime.GOOS {
	case "linux":
		return collectCronJobsLinux()
	case "darwin":
		return collectCronJobsDarwin()
	case "windows":
		return collectCronJobsWindows()
	default:
		return nil, errUnsupportedOS()
	}
}

// collectCronDJobs reads all crontab files under /etc/cron.d and parses them as root jobs.
func collectCronDJobs() []audit.CronJob {
	files, err := os.ReadDir("/etc/cron.d")
	if err != nil {
		return nil
	}
	var jobs []audit.CronJob
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/etc/cron.d", f.Name()))
		if err == nil {
			jobs = append(jobs, parseCrontab(string(data), "root")...)
		}
	}
	return jobs
}

// isNoLoginShell returns true for shells that prevent interactive login.
// Accounts with these shells cannot own personal crontabs; querying them
// via `crontab -l -u <user>` produces only PAM journal noise.
func isNoLoginShell(shell string) bool {
	switch filepath.Base(shell) {
	case "nologin", "false", "sync", "halt", "shutdown":
		return true
	}
	return false
}

func collectCronJobsLinux() ([]audit.CronJob, error) {
	var cronJobs []audit.CronJob

	// System crontab
	if data, err := os.ReadFile("/etc/crontab"); err == nil {
		cronJobs = append(cronJobs, parseCrontab(string(data), "root")...)
	}

	// System cron.d directory
	cronJobs = append(cronJobs, collectCronDJobs()...)

	// User crontabs — only check interactive users (UID >= 1000) and root (UID 0).
	// System service accounts (UID 1-999: daemon, sys, www-data, messagebus, etc.)
	// have no personal crontabs; calling `crontab -l -u <svcacct>` on each Ouroboros
	// tick creates one journal entry per account per cycle (20+ entries/10s) because
	// PAM logs every invocation. Filter them out here.
	users, _ := collectUsersUnix()
	for _, u := range users {
		// Skip any account that cannot log in interactively — they cannot have
		// personal crontabs and `crontab -l -u <them>` just generates PAM journal
		// noise every Ouroboros tick (20+ entries / 10 s).
		// Covers: UID 1-999 service accounts AND nobody (UID 65534) AND any
		// custom service account whose shell is nologin/false regardless of UID.
		if isNoLoginShell(u.Shell) {
			continue
		}
		if u.UID > 0 && u.UID < 1000 {
			continue
		}
		if output, err := exec.Command("crontab", "-u", u.Username, "-l").Output(); err == nil {
			cronJobs = append(cronJobs, parseCrontab(string(output), u.Username)...)
		}
	}

	return cronJobs, nil
}

func parseCrontab(content, user string) []audit.CronJob {
	var jobs []audit.CronJob
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		schedule := strings.Join(fields[0:5], " ")
		command := strings.Join(fields[5:], " ")

		job := audit.CronJob{
			User:     user,
			Schedule: schedule,
			Command:  command,
		}

		jobs = append(jobs, job)
	}

	return jobs
}

func collectCronJobsDarwin() ([]audit.CronJob, error) {
	return collectCronJobsLinux() // macOS uses similar cron system
}

func collectCronJobsWindows() ([]audit.CronJob, error) {
	cmd := exec.Command("schtasks", "/query", "/fo", "LIST", "/v")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var cronJobs []audit.CronJob
	lines := strings.Split(string(output), "\n")

	var currentTask audit.CronJob
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "TaskName:") {
			if currentTask.Command != "" {
				cronJobs = append(cronJobs, currentTask)
			}
			currentTask = audit.CronJob{}
		} else if strings.HasPrefix(line, "Run As User:") {
			currentTask.User = strings.TrimSpace(strings.TrimPrefix(line, "Run As User:"))
		} else if strings.HasPrefix(line, "Task To Run:") {
			currentTask.Command = strings.TrimSpace(strings.TrimPrefix(line, "Task To Run:"))
		} else if strings.HasPrefix(line, "Schedule:") {
			currentTask.Schedule = strings.TrimSpace(strings.TrimPrefix(line, "Schedule:"))
		}
	}

	if currentTask.Command != "" {
		cronJobs = append(cronJobs, currentTask)
	}

	return cronJobs, nil
}

// collectStartupItems collects autostart mechanisms
func collectStartupItems() ([]audit.StartupItem, error) {
	switch runtime.GOOS {
	case "linux":
		return collectStartupItemsLinux()
	case "windows":
		return collectStartupItemsWindows()
	case "darwin":
		return collectStartupItemsDarwin()
	default:
		return nil, errUnsupportedOS()
	}
}

func collectStartupItemsLinux() ([]audit.StartupItem, error) {
	var items []audit.StartupItem

	// Systemd services
	cmd := exec.Command("systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "enabled" {
				items = append(items, audit.StartupItem{
					Name: fields[0],
					Type: "systemd",
				})
			}
		}
	}

	// /etc/rc.local
	if _, err := os.Stat("/etc/rc.local"); err == nil {
		items = append(items, audit.StartupItem{
			Name: "rc.local",
			Path: "/etc/rc.local",
			Type: "rc.local",
		})
	}

	return items, nil
}

func collectStartupItemsWindows() ([]audit.StartupItem, error) {
	var items []audit.StartupItem

	// Registry Run keys
	runKeys := []string{
		"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	}

	for _, key := range runKeys {
		cmd := exec.Command("reg", "query", key)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				items = append(items, audit.StartupItem{
					Name: fields[0],
					Path: strings.Join(fields[2:], " "),
					Type: "registry",
				})
			}
		}
	}

	return items, nil
}

func collectStartupItemsDarwin() ([]audit.StartupItem, error) {
	var items []audit.StartupItem

	// LaunchAgents and LaunchDaemons
	launchPaths := []string{
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
	}

	for _, dir := range launchPaths {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".plist") {
				items = append(items, audit.StartupItem{
					Name: strings.TrimSuffix(file.Name(), ".plist"),
					Path: filepath.Join(dir, file.Name()),
					Type: "launchd",
				})
			}
		}
	}

	return items, nil
}

// CollectHostInfo collects detailed host system information
func CollectHostInfo() (audit.InfoHost, error) {
	info := audit.InfoHost{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err == nil {
		info.Hostname = hostname
	}

	// Get OS version and family
	osVersion, osFamily := getOSVersion()
	info.OSVersion = osVersion
	info.OSFamily = osFamily

	// Get kernel version
	info.Kernel = getKernelVersion()

	// Get private IPs
	info.PrivateIPs = getPrivateIPs()

	// Get uptime and boot time
	uptime, bootTime := getUptimeInfo()
	info.Uptime = uptime
	info.BootTime = bootTime

	return info, nil
}

func getOSVersion() (string, string) {
	switch runtime.GOOS {
	case "linux":
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			var version, family string
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "VERSION=") {
					version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
				} else if strings.HasPrefix(line, "ID=") {
					family = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
				}
			}
			return version, family
		}
		return "unknown", "linux"

	case "windows":
		cmd := exec.Command("cmd", "/c", "ver")
		output, _ := cmd.Output()
		return strings.TrimSpace(string(output)), "windows"

	case "darwin":
		cmd := exec.Command("sw_vers", "-productVersion")
		output, _ := cmd.Output()
		return strings.TrimSpace(string(output)), "darwin"

	default:
		return "unknown", runtime.GOOS
	}
}

func getKernelVersion() string {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("uname", "-r")
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	case "windows":
		cmd := exec.Command("cmd", "/c", "ver")
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return "unknown"
}

func getPrivateIPs() []string {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipNet.IP.IsLoopback() {
				continue
			}

			ips = append(ips, ipNet.IP.String())
		}
	}

	return ips
}

func getUptimeInfo() (int64, time.Time) {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) > 0 {
				uptime, _ := strconv.ParseFloat(fields[0], 64)
				bootTime := time.Now().Add(-time.Duration(uptime) * time.Second)
				return int64(uptime), bootTime
			}
		}

	case "windows":
		// Windows uptime collection not implemented here; return zero values.
		// Implement with Windows-specific APIs if precise uptime is required.
		return 0, time.Time{}

	case "darwin":
		cmd := exec.Command("sysctl", "-n", "kern.boottime")
		output, err := cmd.Output()
		if err == nil {
			// Parse output like: { sec = 1234567890, usec = 0 }
			line := string(output)
			if strings.Contains(line, "sec =") {
				parts := strings.Split(line, "sec = ")
				if len(parts) > 1 {
					secStr := strings.TrimSpace(strings.Split(parts[1], ",")[0])
					sec, _ := strconv.ParseInt(secStr, 10, 64)
					bootTime := time.Unix(sec, 0)
					uptime := time.Since(bootTime).Seconds()
					return int64(uptime), bootTime
				}
			}
		}
	}

	return 0, time.Time{}
}
