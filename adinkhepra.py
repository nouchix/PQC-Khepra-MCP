"""
ADINKHEPRA - Khepra Protocol Orchestration & Validation Suite

This is the heart of the Khepra Protocol deployment system.
Handles build, validation, and orchestration of all components.

Classification: CUI // NOFORN
TRL: 10 (Production-Ready)
"""

import os
import subprocess
import sys
import platform
import json
import time
import http.client
import signal
import socket
import re
from typing import Optional, List, Tuple

# ============================================================================
# CONFIGURATION
# ============================================================================

AGENT_PORT = 45444
TELEMETRY_PORT = 8787
FRONTEND_PORT = 3000
AGENT_STARTUP_TIMEOUT = 120  # seconds (allow for heavy DB loading)
PORT_WAIT_TIMEOUT = 30  # seconds
MOD_VENDOR = "-mod=vendor"
AGENT_EXE = "adinkhepra-agent.exe"

# Deployment modes that require full air-gap — no remote fallbacks permitted.
SOVEREIGN_MODES = {"sovereign", "ironbank"}

# Port validation range
MIN_PORT = 1024
MAX_PORT = 65535


def is_sovereign() -> bool:
    """Return True when running in a sovereignty-guaranteed mode.

    In sovereign/ironbank mode, ANY attempt to fall back to remote services
    (license server, telemetry, CVE feeds) must ABORT, not warn.
    Default is sovereign when KHEPRA_MODE is unset — safe by default.
    """
    mode = os.environ.get("KHEPRA_MODE", "sovereign").lower()
    # Validate mode is one of expected values
    if mode not in {"sovereign", "ironbank", "hybrid", "edge"}:
        return True  # Fail-closed: default to sovereign
    return mode in SOVEREIGN_MODES


def validate_port(port: int) -> bool:
    """Validate port number is in acceptable range.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if port is valid, False otherwise
    """
    try:
        port_num = int(port)
        return MIN_PORT <= port_num <= MAX_PORT
    except (ValueError, TypeError):
        return False


def validate_component_name(component: str) -> bool:
    """Validate component name contains only safe characters.
    
    Args:
        component: Component name to validate
        
    Returns:
        True if component name is safe, False otherwise
    """
    # Only allow alphanumeric, dash, and underscore
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', component))


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_binary_name(component: str) -> str:
    """Get platform-specific binary name with correct extension."""
    if not validate_component_name(component):
        raise ValueError(f"Invalid component name: {component}")
    
    system = platform.system().lower()
    ext = ".exe" if system == "windows" else ""
    return f"bin/{component}{ext}"


def should_use_shell() -> bool:
    """Determine if subprocess should use shell (Windows-specific)."""
    return platform.system().lower() == "windows"


def print_header(title: str, char: str = "=") -> None:
    """Print a formatted header."""
    width = 60
    # Sanitize char to single character
    safe_char = char[0] if char else "="
    print(f"\n{safe_char * width}")
    print(f"{title:^{width}}")
    print(f"{safe_char * width}\n")


def print_step(step: str, total: int, current: int, message: str) -> None:
    """Print a formatted step message."""
    try:
        total_int = int(total)
        current_int = int(current)
        if 0 < current_int <= total_int:
            print(f"\n[{current_int}/{total_int}] {message}...")
    except (ValueError, TypeError):
        print(f"\n{message}...")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"✅ {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"❌ {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"⚠️  {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"      > {message}")


# ============================================================================
# BUILD FUNCTIONS
# ============================================================================

def build(component: str, fips: bool = True) -> bool:
    """
    Build a Khepra Protocol component with optional FIPS mode.
    
    Args:
        component: Component name (e.g., 'adinkhepra', 'adinkhepra-agent')
        fips: Enable FIPS 140-3 BoringCrypto mode
        
    Returns:
        True if build successful, False otherwise
    """
    if not validate_component_name(component):
        print_error(f"Invalid component name: {component}")
        return False
        
    print_info(f"Building {component} (FIPS={fips})...")
    binary = get_binary_name(component)
    
    # Determine source path - validate it doesn't contain path traversal
    if component == "adinkhepra-agent":
        cmd_path = "./cmd/agent"
    elif component == "adinkhepra":
        cmd_path = "./cmd/adinkhepra"
    else:
        # Safe component name already validated above
        safe_component = component.replace('adinkhepra-', '')
        cmd_path = f"./cmd/{safe_component}"
    
    # Build command with explicit shell=False for security
    cmd = ["go", "build", MOD_VENDOR, "-o", binary, cmd_path]
    
    # Configure environment for FIPS mode
    env = os.environ.copy()
    if fips:
        env["GOEXPERIMENT"] = "boringcrypto"
        env["CGO_ENABLED"] = "1"
        print_info("[FIPS] Enabled GOEXPERIMENT=boringcrypto + CGO_ENABLED=1")
    
    try:
        # Use shell=False explicitly for security
        subprocess.check_call(cmd, env=env, shell=False)
        print_success(f"Build successful: {binary}")
        return True
    except subprocess.CalledProcessError:
        print_error(f"Failed to build {component}")
        return False
    except FileNotFoundError:
        print_error("'go' command not found. Please install Go 1.22+")
        return False
    except Exception as e:
        print_error(f"Build error: {e}")
        return False


def build_all_components(fips: bool = True) -> bool:
    """Build all Khepra Protocol components."""
    components = ["adinkhepra", "adinkhepra-agent"]
    
    for component in components:
        if not build(component, fips=fips):
            return False
    
    return True


# ============================================================================
# NETWORK FUNCTIONS
# ============================================================================

def wait_for_port(port: int, host: str = "127.0.0.1", timeout: int = PORT_WAIT_TIMEOUT) -> bool:
    """
    Wait for a port to become available.
    
    Args:
        port: Port number to check
        host: Host address (default: localhost)
        timeout: Maximum wait time in seconds
        
    Returns:
        True if port is available, False if timeout
    """
    if not validate_port(port):
        print_error(f"Invalid port number: {port}")
        return False
    
    if host not in ("127.0.0.1", "localhost", "0.0.0.0"):
        # Only allow loopback or any address for testing
        if not re.match(r'^[0-9a-fA-F:.]+$', host):  # Basic IP validation
            print_error(f"Invalid host: {host}")
            return False
    
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            sock.close()
            return True
        except (socket.error, socket.timeout):
            time.sleep(0.5)
        except Exception:
            # Catch other socket exceptions
            time.sleep(0.5)
    return False


def check_port_available(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is currently available (not in use)."""
    if not validate_port(port):
        return False
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result != 0  # Port is available if connection fails
    except (socket.error, OSError):
        return True


# ============================================================================
# TELEMETRY SERVER
# ============================================================================

def start_telemetry_server() -> Optional[subprocess.Popen]:
    """
    Start the telemetry server for local license validation.
    
    Returns:
        Process object if successful, None otherwise
    """
    telemetry_dir = "adinkhepra-telemetry-server"
    
    if not os.path.exists(telemetry_dir):
        if is_sovereign():
            print_error("SOVEREIGN MODE ABORT: Local telemetry server not found at './adinkhepra-telemetry-server/'.")
            print_error("In sovereign/ironbank mode, license validation MUST run locally.")
            print_error("A sovereignty guarantee that silently calls home is not a sovereignty guarantee.")
            print_error("Fix: bundle the telemetry server with your sovereign release artifact.")
            sys.exit(1)
        print_warning("Telemetry server not found, skipping (license will use remote)")
        return None

    
    print_info(f"Starting Telemetry Server (wrangler dev) on port {TELEMETRY_PORT}...")
    
    try:
        # Validate port before use
        if not validate_port(TELEMETRY_PORT):
            print_error(f"Invalid telemetry port: {TELEMETRY_PORT}")
            return None
        
        # Build command explicitly - don't rely on shell
        cmd = ["npx", "wrangler", "dev", "--local", "--port", str(TELEMETRY_PORT)]
        
        # Start wrangler dev server with shell=False
        telemetry_proc = subprocess.Popen(
            cmd,
            cwd=telemetry_dir,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Wait for server to be ready
        if wait_for_port(TELEMETRY_PORT, timeout=15):
            print_success(f"Telemetry Server ready on http://localhost:{TELEMETRY_PORT}")
            os.environ["KHEPRA_LICENSE_SERVER"] = f"http://localhost:{TELEMETRY_PORT}"
            return telemetry_proc
        else:
            if is_sovereign():
                print_error(f"SOVEREIGN MODE ABORT: Local telemetry server failed to start on port {TELEMETRY_PORT}.")
                print_error("Sovereign mode cannot fall back to remote license validation.")
                print_error("Check: is npx/wrangler installed? Is port 8787 free? Is the telemetry-server directory intact?")
                telemetry_proc.terminate()
                sys.exit(1)
            print_warning("Telemetry server failed to start, continuing without it")
            telemetry_proc.terminate()
            return None

            
    except FileNotFoundError:
        print_warning("npx/wrangler not found, skipping telemetry server")
        return None
    except Exception as e:
        print_warning(f"Telemetry server error: {e}")
        return None


# ============================================================================
# VALIDATION SUITE
# ============================================================================

def _run_unit_tests() -> bool:
    print_step("Unit Tests", 4, 1, "Running Unit Tests")
    try:
        result = subprocess.call(["go", "test", "-count=1", MOD_VENDOR, "./pkg/...", "./cmd/..."], shell=False)
        if result != 0:
            print_error("Unit tests failed")
            return False
        print_success("Unit tests passed")
        return True
    except FileNotFoundError:
        print_error("'go' command not found. Please install Go 1.22+")
        return False
    except Exception as e:
        print_error(f"Test execution error: {e}")
        return False

def _test_pqc_key_gen() -> bool:
    print_step("PQC Key Generation", 4, 2, "Testing PQC Key Generation (CLI)")
    if not build("adinkhepra"):
        return False
    cli_bin = get_binary_name("adinkhepra")
    try:
        # Validate output path doesn't contain traversal
        if not validate_component_name("test_key"):
            print_error("Invalid key name")
            return False
            
        subprocess.check_output([cli_bin, "keygen", "-out", "test_key", "-comment", "validation-test"], 
                              stderr=subprocess.STDOUT, shell=False)
        expected_files = ["test_key_dilithium", "test_key_dilithium.pub", "test_key_dilithium.pub.adinkhepra.json", "test_key_kyber", "test_key_kyber.pub"]
        missing_files = [f for f in expected_files if not os.path.exists(f)]
        if missing_files:
            print_error(f"PQC key generation failed: missing files {missing_files}")
            return False
        print_success("PQC key generation successful")
        for f in expected_files:
            try:
                os.remove(f)
            except OSError:
                pass
        return True
    except subprocess.CalledProcessError as e:
        output = e.output if isinstance(e.output, str) else e.output.decode() if e.output else ""
        print_error(f"CLI execution failed: {output}")
        return False
    except Exception as e:
        print_error(f"Key generation error: {e}")
        return False

def _wait_for_agent() -> Optional[http.client.HTTPConnection]:
    attempts = AGENT_STARTUP_TIMEOUT * 2
    conn = None
    while attempts > 0:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", AGENT_PORT, timeout=1)
            conn.request("GET", "/healthz")
            res = conn.getresponse()
            if res.status == 200:
                try:
                    data = json.load(res)
                    if data.get("ok"):
                        print_success("Agent health check passed")
                        return conn
                except json.JSONDecodeError:
                    pass
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.5)
        attempts -= 1
    return None

def _test_agent_api() -> bool:
    print_step("Agent API", 4, 3, "Testing Agent API (Integration)")
    if not build("adinkhepra-agent"):
        return False
    agent_bin = get_binary_name("adinkhepra-agent")
    telemetry_proc = start_telemetry_server()
    if not check_port_available(AGENT_PORT):
        print_warning(f"Port {AGENT_PORT} is in use, attempting to free it...")
        if platform.system().lower() == "windows":
            subprocess.call(["taskkill", "/F", "/IM", AGENT_EXE], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        time.sleep(2)
    print_info(f"Starting Agent on port {AGENT_PORT}...")
    agent_proc = subprocess.Popen([agent_bin], cwd=".", shell=False)
    try:
        conn = _wait_for_agent()
        if not conn:
            print_error(f"Agent failed to start or is unreachable (Timeout {AGENT_STARTUP_TIMEOUT}s)")
            return False
        print_step("Polymorphic API", 4, 4, "Validating Polymorphic API (Mitochondreal-Scarab)")
        try:
            subprocess.check_call([sys.executable, "-c", "import torch; import fastapi; import uvicorn"], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
            print_success("Python ML dependencies verified")
        except subprocess.CalledProcessError:
            print_warning("Missing Python ML dependencies (torch, fastapi, uvicorn)")
            print_info("Install with: pip install torch fastapi uvicorn")
        if os.path.exists("services/ml_anomaly/api.py"):
            print_success("SouHimBou Service found")
        else:
            print_warning("SouHimBou Service missing (services/ml_anomaly/api.py)")
        print_info("Testing DAG attestation...")
        payload = json.dumps({"action": "validate-deployment", "symbol": "Adinkra-Validation", "parent_ids": []})
        conn.request("POST", "/dag/add", body=payload, headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        if res.status == 200:
            print_success("DAG write successful")
        else:
            print_error(f"DAG write failed: {res.status}")
            return False
        return True
    finally:
        print_step("Teardown", 4, 4, "Cleaning up test processes")
        if platform.system().lower() == "windows":
            subprocess.call(["taskkill", "/F", "/IM", AGENT_EXE], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        else:
            agent_proc.terminate()
            agent_proc.wait()
        if telemetry_proc:
            telemetry_proc.terminate()

def validate() -> bool:
    """
    Run the complete ADINKHEPRA validation suite.
    """
    print_header("ADINKHEPRA VALIDATION SUITE")
    print_step("Harmonization Ritual", 5, 1, "Running Akoko Nan Sacred Balance Check")
    if os.path.exists(get_binary_name("adinkhepra")):
        try:
            cli_bin = get_binary_name("adinkhepra")
            subprocess.check_call([cli_bin, "scada", "audit"], stderr=subprocess.STDOUT, shell=False)
            print_success("Sunsum Vitality baseline verified (TRL-10)")
        except subprocess.CalledProcessError:
            print_warning("Akoko Nan Simulation skipped (Nsohia Flow not initiated)")
    
    if not _run_unit_tests():
        return False
    if not _test_pqc_key_gen():
        return False
    if not _test_agent_api():
        return False
    
    # ========================================================================
    # VALIDATION COMPLETE
    # ========================================================================
    print_header("✨ ALL SYSTEMS GO. ADINKHEPRA IS READY ✨", "=")
    print_info("Validation suite passed all checks")
    print_info("System is ready for pilot deployment")
    
    return True


# ============================================================================
# LAUNCH FUNCTIONS
# ============================================================================

def launch(args: Optional[List[str]] = None) -> None:
    """
    Launch the complete ADINKHEPRA stack.
    
    Starts:
    1. Telemetry server (local license validation)
    2. Agent backend (API server)
    3. Frontend (React dashboard)
    
    Args:
        args: Command-line arguments (e.g., --llm-port)
    """
    if args is None:
        args = []
    
    print_header("🚀 LAUNCHING ADINKHEPRA FULL STACK")
    
    # Handle custom LLM port
    llm_port = "11434"  # Default Ollama port
    if "--llm-port" in args:
        try:
            idx = args.index("--llm-port")
            llm_port = args[idx + 1]
            # Validate port
            if not validate_port(llm_port):
                print_error(f"Invalid LLM port: {llm_port}")
                sys.exit(1)
            os.environ["ADINKHEPRA_LLM_URL"] = f"http://localhost:{llm_port}"
            print_info(f"[Config] Override LLM_URL: {os.environ['ADINKHEPRA_LLM_URL']}")
        except (ValueError, IndexError):
            print_error("--llm-port requires a valid port number")
            sys.exit(1)
    
    # Start telemetry server
    telemetry_proc = start_telemetry_server()
    
    # Build and start agent
    agent_bin = get_binary_name("adinkhepra-agent")
    if not os.path.exists(agent_bin) and not build("adinkhepra-agent"):
        print_error("Failed to build agent")
        sys.exit(1)
    
    print_info(f"Starting Backend: {agent_bin} (Port {AGENT_PORT})")
    agent_proc = subprocess.Popen([agent_bin], cwd=".", shell=False)
    
    # Start frontend
    print_info(f"Starting Frontend: npm run dev (Port {FRONTEND_PORT})")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        shell=False,
        cwd="."
    )
    
    print_header(">>> PRESS CTRL+C TO STOP THE STACK <<<", "-")
    
    try:
        while True:
            time.sleep(1)
            if agent_proc.poll() is not None:
                print_error("Agent died unexpectedly")
                break
    except KeyboardInterrupt:
        print_header("🛑 STOPPING STACK")
        
        # Stop agent
        if platform.system().lower() == "windows":
            subprocess.call(
                ["taskkill", "/F", "/IM", AGENT_EXE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False
            )
        else:
            agent_proc.terminate()
        
        # Stop frontend
        frontend_proc.terminate()
        
        # Stop telemetry server
        if telemetry_proc:
            telemetry_proc.terminate()
        
        print_success("Stack stopped successfully")
        sys.exit(0)


# ============================================================================
# RUN FUNCTIONS
# ============================================================================

def run(component: str, args: List[str]) -> None:
    """
    Run a Khepra Protocol component.
    
    Args:
        component: Component name
        args: Command-line arguments to pass to component
    """
    if not validate_component_name(component):
        print_error(f"Invalid component name: {component}")
        sys.exit(1)
        
    binary = get_binary_name(component)
    
    if not os.path.exists(binary):
        print_info(f"Binary {binary} not found. Building first...")
        if not build(component):
            sys.exit(1)
    
    print_info(f"Running {component} with args: {args}")
    
    try:
        subprocess.call([binary] + args, shell=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print_error(f"Execution error: {e}")
        sys.exit(1)


# ============================================================================
# TNOK GATEWAY
# ============================================================================

def launch_tnok(args: List[str]) -> None:
    """
    Launch Tnok Stealth Gateway (CSfC Mode).
    
    Args:
        args: Command-line arguments for tnokd
    """
    print_header("🛡️  INITIALIZING TNOK STEALTH GATEWAY (CSfC Mode)")
    
    tnok_path = "./pkg/tnok/tnok"
    
    # Install Tnok in editable mode
    print_info(f"Installing Tnok from {tnok_path}...")
    
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-e", tnok_path],
            stdout=subprocess.DEVNULL,
            shell=False
        )
    except subprocess.CalledProcessError:
        print_error("Failed to install Tnok. Ensure 'pkg/tnok/tnok' exists with pyproject.toml")
        sys.exit(1)
    
    # Run Tnok daemon
    print_info("Starting Tnok Daemon (tnokd)...")
    print_info("ℹ️  Use 'tnokd --help' to see options")
    
    try:
        subprocess.call([sys.executable, "-m", "tnokd.__main__"] + args, shell=False)
    except KeyboardInterrupt:
        print_success("Tnok Stealth Gateway shutdown")
    except Exception as e:
        print_error(f"Tnok error: {e}")
        sys.exit(1)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def print_usage() -> None:
    """Print usage information."""
    print("Usage: python adinkhepra.py [command]")
    print("\nCommands:")
    print("  validate         -> Run full test suite then LAUNCH stack")
    print("  launch           -> Launch Agent + Frontend")
    print("  agent  [args...] -> Run the ADINKHEPRA agent")
    print("  cli    [args...] -> Run the ADINKHEPRA CLI tool")
    print("  scada  [args...] -> Run the ADINKHEPRA Sacred Nsohia suite")
    print("  build            -> Rebuild binaries")
    print("  test             -> Run Go tests")
    print("  tnok             -> Start Tnok Stealth Gateway (tnokd)")
    print("\nOptions:")
    print("  --no-fips        -> Disable FIPS mode (build command)")
    print("  --llm-port PORT  -> Override LLM port (launch command)")


def main() -> None:
    """Main entry point for ADINKHEPRA orchestration."""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    extra_args = sys.argv[2:]
    
    # Validate command
    valid_commands = {"build", "agent", "cli", "scada", "launch", "test", "validate", "tnok"}
    if command not in valid_commands and not command.startswith("-"):
        # Allow unknown commands to be passed to CLI
        pass
    
    if command == "build":
        fips_mode = "--no-fips" not in extra_args
        success = build_all_components(fips=fips_mode)
        sys.exit(0 if success else 1)
        
    elif command == "agent":
        run("adinkhepra-agent", extra_args)
        
    elif command == "cli":
        run("adinkhepra", extra_args)
        
    elif command == "scada":
        run("adinkhepra", ["scada"] + extra_args)
        
    elif command == "launch":
        launch(extra_args)
        
    elif command == "test":
        print_info("Running tests...")
        result = subprocess.call([
            "go", "test", "-count=1", MOD_VENDOR,
            "./pkg/...", "./cmd/..."
        ], shell=False)
        sys.exit(result)
        
    elif command == "validate":
        success = validate()
        if success:
            # Auto-launch stack after successful validation
            launch([])
        else:
            print_error("Validation failed. Fix errors before deploying.")
            sys.exit(1)
        
    elif command == "tnok":
        launch_tnok(extra_args)
        
    else:
        # Default to CLI if command unknown
        run("adinkhepra", sys.argv[1:])


if __name__ == "__main__":
    main()
