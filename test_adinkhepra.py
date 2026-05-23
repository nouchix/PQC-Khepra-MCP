"""
Test Suite for ADINKHEPRA Validation & Orchestration

Tests the core validation suite functionality including:
- Build system
- Network utilities
- Validation suite
- Component orchestration

Classification: CUI // NOFORN
"""

import unittest
import os
import sys
import tempfile
import shutil
import socket
import time
from unittest.mock import patch, MagicMock, call
import subprocess

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import adinkhepra


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions."""
    
    def test_get_binary_name_windows(self):
        """Test binary name generation on Windows."""
        with patch('platform.system', return_value='Windows'):
            result = adinkhepra.get_binary_name('adinkhepra')
            self.assertEqual(result, 'bin/adinkhepra.exe')
    
    def test_get_binary_name_linux(self):
        """Test binary name generation on Linux."""
        with patch('platform.system', return_value='Linux'):
            result = adinkhepra.get_binary_name('adinkhepra')
            self.assertEqual(result, 'bin/adinkhepra')
    
    def test_should_use_shell_windows(self):
        """Test shell detection on Windows."""
        with patch('platform.system', return_value='Windows'):
            self.assertTrue(adinkhepra.should_use_shell())
    
    def test_should_use_shell_linux(self):
        """Test shell detection on Linux."""
        with patch('platform.system', return_value='Linux'):
            self.assertFalse(adinkhepra.should_use_shell())


class TestNetworkFunctions(unittest.TestCase):
    """Test network utility functions."""
    
    def test_check_port_available_free_port(self):
        """Test port availability check for free port."""
        # Use a very high port number that's likely free
        result = adinkhepra.check_port_available(65432)
        self.assertTrue(result)
    
    def test_check_port_available_in_use(self):
        """Test port availability check for port in use."""
        # Create a temporary server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', 0))  # Bind to any available port
        server_socket.listen(1)
        port = server_socket.getsockname()[1]
        
        try:
            result = adinkhepra.check_port_available(port)
            self.assertFalse(result)
        finally:
            server_socket.close()
    
    def test_wait_for_port_timeout(self):
        """Test port waiting with timeout."""
        # Use a port that will never be available
        result = adinkhepra.wait_for_port(65431, timeout=1)
        self.assertFalse(result)
    
    def test_wait_for_port_success(self):
        """Test port waiting with successful connection."""
        # Create a server in a separate thread
        import threading
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', 0))
        port = server_socket.getsockname()[1]
        server_socket.listen(1)
        
        def server_thread():
            time.sleep(0.5)  # Small delay before accepting
        
        thread = threading.Thread(target=server_thread)
        thread.start()
        
        try:
            result = adinkhepra.wait_for_port(port, timeout=2)
            self.assertTrue(result)
        finally:
            server_socket.close()
            thread.join()


class TestBuildFunctions(unittest.TestCase):
    """Test build system functions."""
    
    @patch('subprocess.check_call')
    def test_build_success(self, mock_check_call):
        """Test successful build."""
        mock_check_call.return_value = 0
        
        result = adinkhepra.build('adinkhepra', fips=False)
        
        self.assertTrue(result)
        mock_check_call.assert_called_once()
        
        # Verify command structure
        args = mock_check_call.call_args[0][0]
        self.assertEqual(args[0], 'go')
        self.assertEqual(args[1], 'build')
        self.assertIn('-mod=vendor', args)
    
    @patch('subprocess.check_call')
    def test_build_with_fips(self, mock_check_call):
        """Test build with FIPS mode enabled."""
        mock_check_call.return_value = 0
        
        result = adinkhepra.build('adinkhepra', fips=True)
        
        self.assertTrue(result)
        
        # Verify FIPS environment variables
        env = mock_check_call.call_args[1]['env']
        self.assertEqual(env['GOEXPERIMENT'], 'boringcrypto')
        self.assertEqual(env['CGO_ENABLED'], '1')
    
    @patch('subprocess.check_call')
    def test_build_failure(self, mock_check_call):
        """Test build failure handling."""
        mock_check_call.side_effect = subprocess.CalledProcessError(1, 'go')
        
        result = adinkhepra.build('adinkhepra')
        
        self.assertFalse(result)
    
    @patch('subprocess.check_call')
    def test_build_go_not_found(self, mock_check_call):
        """Test build when Go is not installed."""
        mock_check_call.side_effect = FileNotFoundError()
        
        result = adinkhepra.build('adinkhepra')
        
        self.assertFalse(result)
    
    @patch('adinkhepra.build')
    def test_build_all_components_success(self, mock_build):
        """Test building all components successfully."""
        mock_build.return_value = True
        
        result = adinkhepra.build_all_components(fips=False)
        
        self.assertTrue(result)
        self.assertEqual(mock_build.call_count, 2)  # adinkhepra + agent
    
    @patch('adinkhepra.build')
    def test_build_all_components_failure(self, mock_build):
        """Test building all components with failure."""
        mock_build.return_value = False
        
        result = adinkhepra.build_all_components()
        
        self.assertFalse(result)


class TestTelemetryServer(unittest.TestCase):
    """Test telemetry server functions."""
    
    @patch('os.path.exists')
    def test_start_telemetry_server_missing_dir(self, mock_exists):
        """Test telemetry server when directory is missing."""
        mock_exists.return_value = False
        
        result = adinkhepra.start_telemetry_server()
        
        self.assertIsNone(result)
    
    @patch('adinkhepra.wait_for_port')
    @patch('subprocess.Popen')
    @patch('os.path.exists')
    def test_start_telemetry_server_success(self, mock_exists, mock_popen, mock_wait):
        """Test successful telemetry server start."""
        mock_exists.return_value = True
        mock_wait.return_value = True
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        
        result = adinkhepra.start_telemetry_server()
        
        self.assertIsNotNone(result)
        self.assertEqual(result, mock_proc)
        self.assertIn('KHEPRA_LICENSE_SERVER', os.environ)
    
    @patch('adinkhepra.wait_for_port')
    @patch('subprocess.Popen')
    @patch('os.path.exists')
    def test_start_telemetry_server_timeout(self, mock_exists, mock_popen, mock_wait):
        """Test telemetry server start timeout."""
        mock_exists.return_value = True
        mock_wait.return_value = False
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        
        result = adinkhepra.start_telemetry_server()
        
        self.assertIsNone(result)
        mock_proc.terminate.assert_called_once()


class TestValidationSuite(unittest.TestCase):
    """Test validation suite functionality."""
    
    @patch('subprocess.call')
    def test_validate_unit_tests_pass(self, mock_call):
        """Test validation with passing unit tests."""
        mock_call.return_value = 0
        
        # Mock other validation steps
        with patch('adinkhepra.build', return_value=True), \
             patch('subprocess.check_output'), \
             patch('os.path.exists', return_value=True), \
             patch('os.remove'), \
             patch('subprocess.Popen'), \
             patch('adinkhepra.wait_for_port', return_value=True), \
             patch('adinkhepra.check_port_available', return_value=True), \
             patch('http.client.HTTPConnection'):
            
            # This will fail at some point, but we're testing the unit test step
            try:
                adinkhepra.validate()
            except:
                pass
            
            # Verify unit tests were called
            calls = [c for c in mock_call.call_args_list if 'test' in str(c)]
            self.assertGreater(len(calls), 0)
    
    @patch('subprocess.call')
    def test_validate_unit_tests_fail(self, mock_call):
        """Test validation with failing unit tests."""
        mock_call.return_value = 1
        
        result = adinkhepra.validate()
        
        self.assertFalse(result)


class TestPrintFunctions(unittest.TestCase):
    """Test print utility functions."""
    
    def test_print_header(self):
        """Test header printing."""
        # Should not raise exception
        adinkhepra.print_header("Test Header")
        adinkhepra.print_header("Test", char="-")
    
    def test_print_step(self):
        """Test step printing."""
        adinkhepra.print_step("Test Step", 5, 1, "Testing")
    
    def test_print_messages(self):
        """Test message printing functions."""
        adinkhepra.print_success("Success message")
        adinkhepra.print_error("Error message")
        adinkhepra.print_warning("Warning message")
        adinkhepra.print_info("Info message")


class TestIntegration(unittest.TestCase):
    """Integration tests for ADINKHEPRA orchestration."""
    
    @patch('subprocess.call')
    @patch('adinkhepra.build')
    def test_run_component(self, mock_build, mock_call):
        """Test running a component."""
        mock_build.return_value = True
        mock_call.return_value = 0
        
        with patch('os.path.exists', return_value=False):
            adinkhepra.run('adinkhepra', ['--help'])
        
        mock_build.assert_called_once()
        mock_call.assert_called_once()
    
    @patch('subprocess.Popen')
    @patch('adinkhepra.build')
    @patch('os.path.exists')
    def test_launch_stack(self, mock_exists, mock_build, mock_popen):
        """Test launching the full stack."""
        mock_exists.return_value = True
        mock_build.return_value = True
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc
        
        # Simulate KeyboardInterrupt after short delay
        def interrupt(*args, **kwargs):
            time.sleep(0.1)
            raise KeyboardInterrupt()
        
        with patch('time.sleep', side_effect=interrupt), \
             patch('adinkhepra.start_telemetry_server', return_value=None):
            
            try:
                adinkhepra.launch([])
            except SystemExit:
                pass
        
        # Verify components were started
        self.assertGreater(mock_popen.call_count, 0)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    def test_empty_args(self):
        """Test handling of empty arguments."""
        with patch('sys.argv', ['adinkhepra.py']):
            with self.assertRaises(SystemExit):
                adinkhepra.main()
    
    def test_unknown_command(self):
        """Test handling of unknown command."""
        with patch('sys.argv', ['adinkhepra.py', 'unknown-command']), \
             patch('adinkhepra.run'):
            
            try:
                adinkhepra.main()
            except:
                pass
    
    @patch('subprocess.call')
    def test_test_command(self, mock_call):
        """Test the 'test' command."""
        mock_call.return_value = 0
        
        with patch('sys.argv', ['adinkhepra.py', 'test']):
            try:
                adinkhepra.main()
            except SystemExit as e:
                self.assertEqual(e.code, 0)


class TestConstants(unittest.TestCase):
    """Test configuration constants."""
    
    def test_constants_defined(self):
        """Test that all required constants are defined."""
        self.assertTrue(hasattr(adinkhepra, 'AGENT_PORT'))
        self.assertTrue(hasattr(adinkhepra, 'TELEMETRY_PORT'))
        self.assertTrue(hasattr(adinkhepra, 'FRONTEND_PORT'))
        self.assertTrue(hasattr(adinkhepra, 'AGENT_STARTUP_TIMEOUT'))
        self.assertTrue(hasattr(adinkhepra, 'PORT_WAIT_TIMEOUT'))
    
    def test_port_values(self):
        """Test port configuration values."""
        self.assertEqual(adinkhepra.AGENT_PORT, 45444)
        self.assertEqual(adinkhepra.TELEMETRY_PORT, 8787)
        self.assertEqual(adinkhepra.FRONTEND_PORT, 3000)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
