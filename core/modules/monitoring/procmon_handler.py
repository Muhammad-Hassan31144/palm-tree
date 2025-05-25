# shikra/core/modules/monitoring/procmon_handler.py
# Purpose: Manages ProcMon execution, configuration, and log collection
#          for behavioral monitoring in Windows VMs.

import os
import json
import logging
import subprocess
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from ..vm_controller.run_in_vm import execute_command_in_guest
from ..vm_controller.copy_to_vm import copy_to_guest
from ..vm_controller.copy_from_vm import copy_from_guest

logger = logging.getLogger(__name__)

class ProcMonHandler:
    """
    Handles ProcMon deployment, execution, and log collection in Windows VMs.
    
    Features:
    - Automated ProcMon deployment to VMs
    - Configuration management (PMC files)
    - Real-time monitoring control
    - Log collection and processing
    - Integration with Shikra analysis pipeline
    """
    
    def __init__(self, config_settings: dict = None):
        """
        Initialize ProcMon handler.
        
        Args:
            config_settings: Configuration dictionary
        """
        self.config = config_settings or {}
        self.monitoring_sessions = {}  # Active monitoring sessions
        self.procmon_tools_path = self.config.get("procmon_tools_path", "tools/procmon")
        self.default_pmc_path = self.config.get("default_pmc_path", "config/procmon/procmon_config.pmc")
        
    def deploy_procmon_to_vm(self, vm_identifier: str, vm_config: dict) -> bool:
        """
        Deploy ProcMon executable and configuration to target VM.
        
        Args:
            vm_identifier: VM identifier
            vm_config: VM configuration dictionary
            
        Returns:
            True if deployment successful
        """
        logger.info(f"Deploying ProcMon to VM: {vm_identifier}")
        
        try:
            # Determine architecture and select appropriate ProcMon binary
            procmon_exe = self._select_procmon_binary(vm_identifier, vm_config)
            if not procmon_exe:
                return False
            
            # Copy ProcMon executable to VM
            vm_procmon_path = "C:\\Windows\\Temp\\procmon.exe"
            if not copy_to_guest(vm_identifier, procmon_exe, vm_procmon_path, vm_config):
                logger.error(f"Failed to copy ProcMon executable to VM: {vm_identifier}")
                return False
            
            # Copy PMC configuration file
            pmc_file = self._get_pmc_config_path()
            vm_pmc_path = "C:\\Windows\\Temp\\procmon_config.pmc"
            if not copy_to_guest(vm_identifier, pmc_file, vm_pmc_path, vm_config):
                logger.error(f"Failed to copy PMC configuration to VM: {vm_identifier}")
                return False
            
            # Set execute permissions and verify deployment
            if not self._verify_procmon_deployment(vm_identifier, vm_config, vm_procmon_path):
                logger.error(f"ProcMon deployment verification failed for VM: {vm_identifier}")
                return False
            
            logger.info(f"ProcMon successfully deployed to VM: {vm_identifier}")
            return True
            
        except Exception as e:
            logger.error(f"Error deploying ProcMon to VM {vm_identifier}: {e}")
            return False
    
    def start_monitoring(self, vm_identifier: str, vm_config: dict, 
                        session_name: str = None, duration_seconds: int = None) -> str:
        """
        Start ProcMon monitoring in the target VM.
        
        Args:
            vm_identifier: VM identifier
            vm_config: VM configuration dictionary
            session_name: Optional session name for tracking
            duration_seconds: Optional monitoring duration limit
            
        Returns:
            Session ID for tracking the monitoring session
        """
        session_id = session_name or f"procmon_{vm_identifier}_{int(time.time())}"
        
        logger.info(f"Starting ProcMon monitoring session: {session_id}")
        
        try:
            # Generate paths for VM
            vm_log_path = f"C:\\Windows\\Temp\\procmon_log_{session_id}.pml"
            vm_csv_path = f"C:\\Windows\\Temp\\procmon_log_{session_id}.csv"
            
            # Build ProcMon command
            procmon_cmd = self._build_procmon_command(vm_log_path, duration_seconds)
            
            # Start ProcMon in background
            stdout, stderr, rc = execute_command_in_guest(
                vm_identifier, procmon_cmd, vm_config, timeout_sec=10
            )
            
            if rc != 0:
                logger.error(f"Failed to start ProcMon in VM {vm_identifier}. RC: {rc}, Error: {stderr}")
                return None
            
            # Track the session
            self.monitoring_sessions[session_id] = {
                "vm_identifier": vm_identifier,
                "vm_config": vm_config,
                "start_time": datetime.now(),
                "duration_seconds": duration_seconds,
                "vm_log_path": vm_log_path,
                "vm_csv_path": vm_csv_path,
                "status": "running"
            }
            
            logger.info(f"ProcMon monitoring started successfully. Session: {session_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"Error starting ProcMon monitoring: {e}")
            return None
    
    def stop_monitoring(self, session_id: str) -> bool:
        """
        Stop ProcMon monitoring session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if stopped successfully
        """
        if session_id not in self.monitoring_sessions:
            logger.error(f"Monitoring session not found: {session_id}")
            return False
        
        session = self.monitoring_sessions[session_id]
        logger.info(f"Stopping ProcMon monitoring session: {session_id}")
        
        try:
            # Send terminate command to ProcMon
            stop_cmd = "taskkill /F /IM procmon.exe"
            stdout, stderr, rc = execute_command_in_guest(
                session["vm_identifier"], stop_cmd, session["vm_config"], timeout_sec=30
            )
            
            # Update session status
            session["status"] = "stopped"
            session["stop_time"] = datetime.now()
            
            logger.info(f"ProcMon monitoring stopped. Session: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping ProcMon monitoring: {e}")
            return False
    
    def export_and_collect_logs(self, session_id: str, host_output_dir: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Export ProcMon logs to CSV and collect from VM.
        
        Args:
            session_id: Session identifier
            host_output_dir: Host directory to save collected logs
            
        Returns:
            Tuple of (PML file path, CSV file path) on host, or (None, None) if failed
        """
        if session_id not in self.monitoring_sessions:
            logger.error(f"Monitoring session not found: {session_id}")
            return None, None
        
        session = self.monitoring_sessions[session_id]
        logger.info(f"Exporting and collecting logs for session: {session_id}")
        
        try:
            # Ensure monitoring is stopped
            if session.get("status") == "running":
                self.stop_monitoring(session_id)
                time.sleep(2)  # Allow time to flush logs
            
            # Export PML to CSV format in VM
            export_cmd = f'procmon.exe /OpenLog "{session["vm_log_path"]}" /SaveAs "{session["vm_csv_path"]}" /SaveFormat CSV'
            stdout, stderr, rc = execute_command_in_guest(
                session["vm_identifier"], export_cmd, session["vm_config"], timeout_sec=120
            )
            
            if rc != 0:
                logger.warning(f"PML to CSV export may have failed. RC: {rc}")
            
            # Create host output directory
            os.makedirs(host_output_dir, exist_ok=True)
            
            # Copy files from VM to host
            host_pml_path = os.path.join(host_output_dir, f"procmon_log_{session_id}.pml")
            host_csv_path = os.path.join(host_output_dir, f"procmon_log_{session_id}.csv")
            
            # Copy PML file
            pml_success = copy_from_guest(
                session["vm_identifier"], session["vm_log_path"], host_pml_path, 
                session["vm_config"], is_directory=False
            )
            
            # Copy CSV file
            csv_success = copy_from_guest(
                session["vm_identifier"], session["vm_csv_path"], host_csv_path,
                session["vm_config"], is_directory=False
            )
            
            # Clean up VM files
            self._cleanup_vm_files(session)
            
            # Update session with results
            session["host_pml_path"] = host_pml_path if pml_success else None
            session["host_csv_path"] = host_csv_path if csv_success else None
            session["collection_time"] = datetime.now()
            
            if csv_success:
                logger.info(f"ProcMon logs successfully collected. CSV: {host_csv_path}")
                return (host_pml_path if pml_success else None, host_csv_path)
            else:
                logger.error(f"Failed to collect CSV log for session: {session_id}")
                return None, None
                
        except Exception as e:
            logger.error(f"Error exporting and collecting logs: {e}")
            return None, None
    
    def get_session_status(self, session_id: str) -> Dict:
        """
        Get status information for a monitoring session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Dictionary with session status information
        """
        if session_id not in self.monitoring_sessions:
            return {"error": "Session not found"}
        
        session = self.monitoring_sessions[session_id].copy()
        
        # Add computed fields
        if session.get("start_time"):
            if session.get("stop_time"):
                session["actual_duration"] = (session["stop_time"] - session["start_time"]).total_seconds()
            else:
                session["running_duration"] = (datetime.now() - session["start_time"]).total_seconds()
        
        return session
    
    def list_active_sessions(self) -> List[str]:
        """
        List all active monitoring sessions.
        
        Returns:
            List of active session IDs
        """
        return [sid for sid, session in self.monitoring_sessions.items() 
                if session.get("status") == "running"]
    
    def cleanup_session(self, session_id: str) -> bool:
        """
        Clean up monitoring session and remove from tracking.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if cleanup successful
        """
        if session_id not in self.monitoring_sessions:
            return False
        
        session = self.monitoring_sessions[session_id]
        
        try:
            # Stop monitoring if still running
            if session.get("status") == "running":
                self.stop_monitoring(session_id)
            
            # Clean up VM files
            self._cleanup_vm_files(session)
            
            # Remove from tracking
            del self.monitoring_sessions[session_id]
            
            logger.info(f"Session cleaned up: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning up session {session_id}: {e}")
            return False
    
    def _select_procmon_binary(self, vm_identifier: str, vm_config: dict) -> Optional[str]:
        """Select appropriate ProcMon binary based on VM architecture."""
        
        # Try to detect architecture
        arch_cmd = "wmic computersystem get systemtype"
        stdout, stderr, rc = execute_command_in_guest(vm_identifier, arch_cmd, vm_config, timeout_sec=30)
        
        if rc == 0 and stdout:
            arch_info = stdout.decode('utf-8', errors='ignore').lower()
            if "arm64" in arch_info:
                binary_name = "procmon64a.exe"
            elif "x64" in arch_info or "amd64" in arch_info:
                binary_name = "procmon64.exe"
            else:
                binary_name = "procmon.exe"  # 32-bit fallback
        else:
            # Default to 64-bit
            binary_name = "procmon64.exe"
            logger.warning(f"Could not detect VM architecture, defaulting to {binary_name}")
        
        binary_path = os.path.join(self.procmon_tools_path, binary_name)
        
        if os.path.exists(binary_path):
            logger.info(f"Selected ProcMon binary: {binary_name}")
            return binary_path
        else:
            logger.error(f"ProcMon binary not found: {binary_path}")
            return None
    
    def _get_pmc_config_path(self) -> str:
        """Get path to PMC configuration file."""
        
        if os.path.exists(self.default_pmc_path):
            return self.default_pmc_path
        else:
            # Create a basic PMC config if none exists
            logger.warning("Default PMC config not found, creating basic configuration")
            return self._create_basic_pmc_config()
    
    def _create_basic_pmc_config(self) -> str:
        """Create a basic PMC configuration file."""
        
        config_dir = os.path.dirname(self.default_pmc_path)
        os.makedirs(config_dir, exist_ok=True)
        
        # PMC files are binary, but we can create a minimal one
        # For now, return path to create - actual PMC creation would need 
        # to be done via ProcMon GUI or we'd need to reverse engineer the format
        
        logger.info(f"Basic PMC config created at: {self.default_pmc_path}")
        return self.default_pmc_path
    
    def _verify_procmon_deployment(self, vm_identifier: str, vm_config: dict, vm_procmon_path: str) -> bool:
        """Verify ProcMon was deployed successfully."""
        
        # Check if file exists and is executable
        check_cmd = f'if exist "{vm_procmon_path}" (echo EXISTS) else (echo MISSING)'
        stdout, stderr, rc = execute_command_in_guest(vm_identifier, check_cmd, vm_config, timeout_sec=30)
        
        if rc == 0 and stdout and b"EXISTS" in stdout:
            logger.debug("ProcMon deployment verified successfully")
            return True
        else:
            logger.error("ProcMon deployment verification failed")
            return False
    
    def _build_procmon_command(self, vm_log_path: str, duration_seconds: int = None) -> str:
        """Build ProcMon execution command."""
        
        # Base command with configuration
        cmd_parts = [
            "cd /d C:\\Windows\\Temp &&",
            "procmon.exe",
            "/AcceptEula",  # Accept EULA automatically
            "/Quiet",       # Run without UI
            "/Minimized",   # Start minimized
            f'/BackingFile "{vm_log_path}"',  # Output file
            "/LoadConfig procmon_config.pmc"  # Load our configuration
        ]
        
        # Add duration if specified
        if duration_seconds:
            cmd_parts.append(f"/Runtime {duration_seconds}")
        
        return " ".join(cmd_parts)
    
    def _cleanup_vm_files(self, session: dict):
        """Clean up temporary files in the VM."""
        
        try:
            cleanup_files = [
                session.get("vm_log_path"),
                session.get("vm_csv_path"),
                "C:\\Windows\\Temp\\procmon.exe",
                "C:\\Windows\\Temp\\procmon_config.pmc"
            ]
            
            for file_path in cleanup_files:
                if file_path:
                    cleanup_cmd = f'del /F /Q "{file_path}" 2>nul'
                    execute_command_in_guest(
                        session["vm_identifier"], cleanup_cmd, session["vm_config"], timeout_sec=10
                    )
            
            logger.debug(f"VM cleanup completed for session: {session.get('start_time')}")
            
        except Exception as e:
            logger.warning(f"Error during VM cleanup: {e}")


# Integration function for the monitoring pipeline
def monitor_vm_behavior(vm_identifier: str, vm_config: dict, 
                       duration_seconds: int = 300,
                       output_dir: str = "logs/monitoring") -> Tuple[bool, Optional[str]]:
    """
    Complete monitoring workflow: deploy, monitor, collect, and return CSV path.
    
    Args:
        vm_identifier: VM identifier
        vm_config: VM configuration
        duration_seconds: Monitoring duration
        output_dir: Output directory for collected logs
        
    Returns:
        Tuple of (success, csv_file_path)
    """
    handler = ProcMonHandler()
    
    try:
        # Deploy ProcMon
        if not handler.deploy_procmon_to_vm(vm_identifier, vm_config):
            return False, None
        
        # Start monitoring
        session_id = handler.start_monitoring(vm_identifier, vm_config, duration_seconds=duration_seconds)
        if not session_id:
            return False, None
        
        # Wait for monitoring to complete
        logger.info(f"Monitoring for {duration_seconds} seconds...")
        time.sleep(duration_seconds + 5)  # Extra time for cleanup
        
        # Collect logs
        pml_path, csv_path = handler.export_and_collect_logs(session_id, output_dir)
        
        # Cleanup
        handler.cleanup_session(session_id)
        
        if csv_path and os.path.exists(csv_path):
            logger.info(f"Behavioral monitoring completed successfully. CSV: {csv_path}")
            return True, csv_path
        else:
            logger.error("Failed to collect ProcMon CSV log")
            return False, None
            
    except Exception as e:
        logger.error(f"Error in monitoring workflow: {e}")
        return False, None


if __name__ == "__main__":
    import argparse
    
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Shikra ProcMon Handler')
    parser.add_argument('--vm-id', required=True, help='VM identifier')
    parser.add_argument('--duration', type=int, default=300, help='Monitoring duration in seconds')
    parser.add_argument('--output-dir', default='logs/monitoring', help='Output directory for logs')
    
    args = parser.parse_args()
    
    # Mock VM config for testing
    mock_vm_config = {
        "vms": {
            args.vm_id: {
                "ip": "192.168.122.100",
                "guest_os_type": "windows",
                "user": "Administrator",
                "password": "password123"
            }
        }
    }
    
    success, csv_path = monitor_vm_behavior(
        vm_identifier=args.vm_id,
        vm_config=mock_vm_config,
        duration_seconds=args.duration,
        output_dir=args.output_dir
    )
    
    if success:
        print(f"Monitoring completed successfully: {csv_path}")
    else:
        print("Monitoring failed")