// Package mcp — container security profiles for sandboxed execution.
//
// Provides Seccomp and AppArmor profiles for Docker-based tool execution.
// These profiles enforce mandatory access control on containers running
// in the Phantom sandbox.
//
// AD-011: Container Hardening Standards
//   - Seccomp: Whitelist-only syscall policy (deny-by-default)
//   - AppArmor: Filesystem and network isolation
//   - No new privileges escalation
//   - Read-only root filesystem
//   - Dropped capabilities

package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ─── Seccomp Profile ───────────────────────────────────────────────────────────

// SeccompProfile defines a Docker-compatible seccomp security profile.
type SeccompProfile struct {
	DefaultAction string         `json:"defaultAction"`
	Architectures []string       `json:"architectures"`
	Syscalls      []SeccompRule  `json:"syscalls"`
}

// SeccompRule defines an individual syscall filter rule.
type SeccompRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// DefaultSeccompProfile returns a hardened seccomp profile for sandboxed tool execution.
// This profile follows a deny-by-default posture, only allowing syscalls
// that are necessary for Go process execution and file I/O.
func DefaultSeccompProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"},
		Syscalls: []SeccompRule{
			// Process lifecycle
			{Names: []string{"exit", "exit_group", "futex", "nanosleep", "clock_nanosleep"}, Action: "SCMP_ACT_ALLOW"},
			// Memory management
			{Names: []string{"mmap", "mprotect", "munmap", "brk", "mremap"}, Action: "SCMP_ACT_ALLOW"},
			// File operations (read-only oriented)
			{Names: []string{
				"read", "write", "close", "fstat", "stat", "lstat",
				"openat", "newfstatat", "pread64", "readlinkat",
				"getdents64", "fcntl", "lseek", "ioctl",
				"epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
			}, Action: "SCMP_ACT_ALLOW"},
			// Process info
			{Names: []string{
				"getpid", "getppid", "getuid", "getgid", "geteuid", "getegid",
				"gettid", "getrlimit", "prlimit64",
			}, Action: "SCMP_ACT_ALLOW"},
			// Signals
			{Names: []string{"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack"}, Action: "SCMP_ACT_ALLOW"},
			// Thread/concurrency (Go runtime)
			{Names: []string{
				"clone", "clone3", "set_robust_list", "sched_getaffinity",
				"sched_yield", "tgkill",
			}, Action: "SCMP_ACT_ALLOW"},
			// Time
			{Names: []string{"clock_gettime", "gettimeofday"}, Action: "SCMP_ACT_ALLOW"},
			// Pipe/socket (for stdout/stderr IPC)
			{Names: []string{"pipe", "pipe2", "dup", "dup2", "dup3"}, Action: "SCMP_ACT_ALLOW"},
			// Network (BLOCKED by default — sandboxed tools should not phone home)
			// Explicitly deny dangerous syscalls
			{Names: []string{
				"socket", "connect", "accept", "bind", "listen",
				"sendto", "recvfrom", "sendmsg", "recvmsg",
			}, Action: "SCMP_ACT_ERRNO"},
			// Execution (BLOCKED — no child process spawning)
			{Names: []string{"execve", "execveat"}, Action: "SCMP_ACT_ERRNO"},
			// Filesystem modification (BLOCKED)
			{Names: []string{"unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2"}, Action: "SCMP_ACT_ERRNO"},
			// Privilege escalation (BLOCKED)
			{Names: []string{"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"}, Action: "SCMP_ACT_ERRNO"},
			// Kernel module loading (BLOCKED)
			{Names: []string{"init_module", "finit_module", "delete_module"}, Action: "SCMP_ACT_ERRNO"},
			// Ptrace (BLOCKED — no debugging from inside container)
			{Names: []string{"ptrace", "process_vm_readv", "process_vm_writev"}, Action: "SCMP_ACT_ERRNO"},
			// Mount/unmount (BLOCKED)
			{Names: []string{"mount", "umount2", "pivot_root", "chroot"}, Action: "SCMP_ACT_ERRNO"},
		},
	}
}

// NetworkAllowedSeccompProfile returns a seccomp profile that allows network access.
// Use for tools that need to make outbound HTTP calls (e.g., NVD/EPSS enrichment).
func NetworkAllowedSeccompProfile() *SeccompProfile {
	profile := DefaultSeccompProfile()
	// Replace the network ERRNO rule with ALLOW
	for i, rule := range profile.Syscalls {
		if len(rule.Names) > 0 && rule.Names[0] == "socket" {
			profile.Syscalls[i].Action = "SCMP_ACT_ALLOW"
			break
		}
	}
	return profile
}

// WriteSeccompProfile writes the seccomp profile to a temporary file
// and returns the path. The caller is responsible for cleanup.
func WriteSeccompProfile(profile *SeccompProfile, dir string) (string, error) {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal seccomp profile: %w", err)
	}
	path := filepath.Join(dir, "seccomp-profile.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("write seccomp profile: %w", err)
	}
	return path, nil
}

// ─── AppArmor Profile ──────────────────────────────────────────────────────────

// AppArmorProfile defines the AppArmor confinement profile for sandboxed containers.
type AppArmorProfile struct {
	Name  string
	Rules string
}

// DefaultAppArmorProfile returns a hardened AppArmor profile for Phantom containers.
func DefaultAppArmorProfile() *AppArmorProfile {
	return &AppArmorProfile{
		Name: "khepra-phantom",
		Rules: `#include <tunables/global>

profile khepra-phantom flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # ─── FILESYSTEM ───────────────────────────────────────────
  # Deny all filesystem access by default, then whitelist
  deny /** w,           # deny write everywhere
  deny /root/** rwklx,  # deny all access to /root
  deny /etc/shadow r,   # deny shadow file
  deny /etc/passwd w,   # deny passwd modification

  # Allow read access to project files (bind-mounted)
  /project/** r,
  /var/lib/phantom/data/** rw,
  /var/lib/phantom/keys/** r,

  # Allow reading shared libraries
  /lib/** r,
  /usr/lib/** r,
  /app/** r,
  /app/mcp-runner ix,  # allow execution of runner binary

  # Temp files for Go runtime
  /tmp/** rw,

  # Proc filesystem (needed by Go runtime)
  /proc/self/** r,
  /proc/sys/net/core/somaxconn r,
  /sys/kernel/mm/transparent_hugepage/hpage_pmd_size r,

  # ─── NETWORK ──────────────────────────────────────────────
  # Deny all network by default
  deny network inet stream,
  deny network inet dgram,
  deny network inet6 stream,
  deny network inet6 dgram,

  # ─── CAPABILITIES ────────────────────────────────────────
  deny capability dac_override,
  deny capability dac_read_search,
  deny capability net_admin,
  deny capability net_raw,
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,

  # ─── SIGNALS ──────────────────────────────────────────────
  signal (receive) set=(kill, term, int) peer=unconfined,
}
`,
	}
}

// NetworkAllowedAppArmorProfile returns an AppArmor profile that permits outbound connections.
func NetworkAllowedAppArmorProfile() *AppArmorProfile {
	profile := DefaultAppArmorProfile()
	profile.Name = "khepra-phantom-net"
	// Replace deny network rules with limited allow
	profile.Rules = `#include <tunables/global>

profile khepra-phantom-net flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  deny /** w,
  deny /root/** rwklx,
  deny /etc/shadow r,
  deny /etc/passwd w,

  /project/** r,
  /var/lib/phantom/data/** rw,
  /var/lib/phantom/keys/** r,
  /lib/** r,
  /usr/lib/** r,
  /app/** r,
  /app/mcp-runner ix,
  /tmp/** rw,
  /proc/self/** r,
  /sys/kernel/mm/transparent_hugepage/hpage_pmd_size r,

  # Allow outbound TCP only (for NVD/EPSS API calls)
  network inet stream,
  network inet6 stream,
  deny network inet dgram,
  deny network inet6 dgram,

  deny capability dac_override,
  deny capability net_admin,
  deny capability net_raw,
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,

  signal (receive) set=(kill, term, int) peer=unconfined,
}
`
	return profile
}

// WriteAppArmorProfile writes the AppArmor profile to a file.
func WriteAppArmorProfile(profile *AppArmorProfile, dir string) (string, error) {
	path := filepath.Join(dir, fmt.Sprintf("apparmor-%s", profile.Name))
	if err := os.WriteFile(path, []byte(profile.Rules), 0600); err != nil {
		return "", fmt.Errorf("write apparmor profile: %w", err)
	}
	return path, nil
}

// ─── Container Security Flags ──────────────────────────────────────────────────

// ContainerSecurityFlags returns Docker CLI arguments for security hardening.
// These are appended to the `docker run` command in DockerSandbox.Run().
func ContainerSecurityFlags(seccompPath string, apparmorProfile string) []string {
	flags := []string{
		"--no-new-privileges",   // Prevent privilege escalation via setuid/setgid
		"--cap-drop=ALL",        // Drop all Linux capabilities
		"--cap-add=SETUID",      // Re-add only what's needed for non-root user switching
		"--cap-add=SETGID",
		"--read-only",           // Read-only root filesystem
		"--tmpfs=/tmp:rw,noexec,nosuid,size=64m",  // Writable tmp with size limit
	}
	if seccompPath != "" {
		flags = append(flags, fmt.Sprintf("--security-opt=seccomp=%s", seccompPath))
	}
	if apparmorProfile != "" {
		flags = append(flags, fmt.Sprintf("--security-opt=apparmor=%s", apparmorProfile))
	}
	return flags
}
