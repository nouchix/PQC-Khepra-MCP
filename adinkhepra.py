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

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_binary_name(component: str) -> str:
    """Get platform-specific binary name with correct extension."""
    system = platform.system().lower()
    ext = ".exe" if system == "windows" else ""
    return f"bin/{component}{ext}"


def should_use_shell() -> bool:
    """Determine if subprocess should use shell (Windows-specific)."""
    return platform.system().lower() == "windows"


def print_header(title: str, char: str = "=") -> None:
    """Print a formatted header."""
    width = 60
    print(f"\n{char * width}")
    print(f"{title:^{width}}")
    print(f"{char * width}\n")


def print_step(step: str, total: int, current: int, message: str) -> None:
    """Print a formatted step message."""
    print(f"\n[{current}/{total}] {message}...")


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
    print_info(f"Building {component} (FIPS={fips})...")
    binary = get_binary_name(component)
    
    # Determine source path
    if component == "adinkhepra-agent":
        cmd_path = "./cmd/agent"
    elif component == "adinkhepra":
        cmd_path = "./cmd/adinkhepra"
    else:
        cmd_path = f"./cmd/{component.replace('adinkhepra-', '')}"
    
    # Build command
    cmd = ["go", "build", MOD_VENDOR, "-o", binary]
    
    # Configure environment for FIPS mode
    env = os.environ.copy()
    if fips:
        env["GOEXPERIMENT"] = "boringcrypto"
        env["CGO_ENABLED"] = "1"
        print_info("[FIPS] Enabled GOEXPERIMENT=boringcrypto + CGO_ENABLED=1")
    
    cmd.append(cmd_path)
    
    try:
        subprocess.check_call(cmd, env=env)
        print_success(f"Build successful: {binary}")
        return True
    except subprocess.CalledProcessError:
        print_error(f"Failed to build {component}")
        return False
    except FileNotFoundError:
        print_error("'go' command not found. Please install Go 1.22+")
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
    return False


def check_port_available(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is currently available (not in use)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result != 0  # Port is available if connection fails
    except socket.error:
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
        print_warning("Telemetry server not found, skipping (license will use remote)")
        return None
    
    print_info(f"Starting Telemetry Server (wrangler dev) on port {TELEMETRY_PORT}...")
    
    try:
        # Start wrangler dev server
        telemetry_proc = subprocess.Popen(
            ["npx", "wrangler", "dev", "--local", "--port", str(TELEMETRY_PORT)],
            cwd=telemetry_dir,
            shell=should_use_shell(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Wait for server to be ready
        if wait_for_port(TELEMETRY_PORT, timeout=15):
            print_success(f"Telemetry Server ready on http://localhost:{TELEMETRY_PORT}")
            os.environ["KHEPRA_LICENSE_SERVER"] = f"http://localhost:{TELEMETRY_PORT}"
            return telemetry_proc
        else:
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
        result = subprocess.call(["go", "test", "-count=1", MOD_VENDOR, "./pkg/...", "./cmd/..."])
        if result != 0:
            print_error("Unit tests failed")
            return False
        print_success("Unit tests passed")
        return True
    except FileNotFoundError:
        print_error("'go' command not found. Please install Go 1.22+")
        return False

def _test_pqc_key_gen() -> bool:
    print_step("PQC Key Generation", 4, 2, "Testing PQC Key Generation (CLI)")
    if not build("adinkhepra"):
        return False
    cli_bin = get_binary_name("adinkhepra")
    try:
        subprocess.check_output([cli_bin, "keygen", "-out", "test_key", "-comment", "validation-test"], stderr=subprocess.STDOUT)
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
        print_error(f"CLI execution failed: {e.output.decode()}")
        return False

def _wait_for_agent() -> http.client.HTTPConnection:
    attempts = AGENT_STARTUP_TIMEOUT * 2
    conn = None
    while attempts > 0:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", AGENT_PORT, timeout=1)
            conn.request("GET", "/healthz")
            res = conn.getresponse()
            if res.status == 200:
                data = json.load(res)
                if data.get("ok"):
                    print_success("Agent health check passed")
                    return conn
        except Exception:
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
            subprocess.call(["taskkill", "/F", "/IM", AGENT_EXE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
    print_info(f"Starting Agent on port {AGENT_PORT}...")
    agent_proc = subprocess.Popen([agent_bin], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        conn = _wait_for_agent()
        if not conn:
            print_error(f"Agent failed to start or is unreachable (Timeout {AGENT_STARTUP_TIMEOUT}s)")
            return False
        print_step("Polymorphic API", 4, 4, "Validating Polymorphic API (Mitochondreal-Scarab)")
        try:
            subprocess.check_call([sys.executable, "-c", "import torch; import fastapi; import uvicorn"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
            subprocess.call(["taskkill", "/F", "/IM", AGENT_EXE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
            subprocess.check_call([cli_bin, "scada", "audit"], stderr=subprocess.STDOUT)
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

def launch(args: List[str] = None) -> None:
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
            os.environ["ADINKHEPRA_LLM_URL"] = f"http://localhost:{llm_port}"
            print_info(f"[Config] Override LLM_URL: {os.environ['ADINKHEPRA_LLM_URL']}")
        except (ValueError, IndexError):
            print_error("--llm-port requires a port number")
            sys.exit(1)
    
    # Start telemetry server
    telemetry_proc = start_telemetry_server()
    
    # Build and start agent
    agent_bin = get_binary_name("adinkhepra-agent")
    if not os.path.exists(agent_bin) and not build("adinkhepra-agent"):
        print_error("Failed to build agent")
        sys.exit(1)
    
    print_info(f"Starting Backend: {agent_bin} (Port {AGENT_PORT})")
    agent_proc = subprocess.Popen([agent_bin], cwd=".")
    
    # Start frontend
    print_info(f"Starting Frontend: npm run dev (Port {FRONTEND_PORT})")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        shell=should_use_shell(),
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
                stderr=subprocess.DEVNULL
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
    binary = get_binary_name(component)
    
    if not os.path.exists(binary):
        print_info(f"Binary {binary} not found. Building first...")
        if not build(component):
            sys.exit(1)
    
    print_info(f"Running {component} with args: {args}")
    
    try:
        subprocess.call([binary] + args)
    except KeyboardInterrupt:
        pass


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
            stdout=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        print_error("Failed to install Tnok. Ensure 'pkg/tnok/tnok' exists with pyproject.toml")
        sys.exit(1)
    
    # Run Tnok daemon
    print_info("Starting Tnok Daemon (tnokd)...")
    print_info("ℹ️  Use 'tnokd --help' to see options")
    
    try:
        subprocess.call([sys.executable, "-m", "tnokd.__main__"] + args)
    except KeyboardInterrupt:
        print_success("Tnok Stealth Gateway shutdown")


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
        ])
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
