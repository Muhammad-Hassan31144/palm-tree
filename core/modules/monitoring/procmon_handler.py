# # shikra/core/modules/monitoring/procmon_handler.py
# # Purpose: Manages ProcMon execution, configuration, and log collection
# #          for behavioral monitoring in Windows VMs.

# import os
# import json
# import logging
# import subprocess
# import time
# import threading
# from pathlib import Path
# from typing import Dict, List, Optional, Tuple
# from datetime import datetime, timedelta

# from ..vm_controller.run_in_vm import execute_command_in_guest
# from ..vm_controller.copy_to_vm import copy_to_guest
# from ..vm_controller.copy_from_vm import copy_from_guest

# logger = logging.getLogger(__name__)

# class ProcMonHandler:
#     """
#     Handles ProcMon deployment, execution, and log collection in Windows VMs.
    
#     Features:
#     - Automated ProcMon deployment to VMs
#     - Configuration management (PMC files)
#     - Real-time monitoring control
#     - Log collection and processing
#     - Integration with Shikra analysis pipeline
#     """
    
#     def __init__(self, config_settings: dict = None):
#         """
#         Initialize ProcMon handler.
        
#         Args:
#             config_settings: Configuration dictionary
#         """
#         self.config = config_settings or {}
#         self.monitoring_sessions = {}  # Active monitoring sessions
#         self.procmon_tools_path = self.config.get("procmon_tools_path", "tools/procmon")
#         self.default_pmc_path = self.config.get("default_pmc_path", "config/procmon/procmon_config.pmc")
        
#     def deploy_procmon_to_vm(self, vm_identifier: str, vm_config: dict) -> bool:
#         """
#         Deploy ProcMon executable and configuration to target VM.
        
#         Args:
#             vm_identifier: VM identifier
#             vm_config: VM configuration dictionary
            
#         Returns:
#             True if deployment successful
#         """
#         logger.info(f"Deploying ProcMon to VM: {vm_identifier}")
        
#         try:
#             # Determine architecture and select appropriate ProcMon binary
#             procmon_exe = self._select_procmon_binary(vm_identifier, vm_config)
#             if not procmon_exe:
#                 return False
            
#             # Copy ProcMon executable to VM
#             vm_procmon_path = "C:\\Windows\\Temp\\procmon.exe"
#             if not copy_to_guest(vm_identifier, procmon_exe, vm_procmon_path, vm_config):
#                 logger.error(f"Failed to copy ProcMon executable to VM: {vm_identifier}")
#                 return False
            
#             # Copy PMC configuration file
#             pmc_file = self._get_pmc_config_path()
#             vm_pmc_path = "C:\\Windows\\Temp\\procmon_config.pmc"
#             if not copy_to_guest(vm_identifier, pmc_file, vm_pmc_path, vm_config):
#                 logger.error(f"Failed to copy PMC configuration to VM: {vm_identifier}")
#                 return False
            
#             # Set execute permissions and verify deployment
#             if not self._verify_procmon_deployment(vm_identifier, vm_config, vm_procmon_path):
#                 logger.error(f"ProcMon deployment verification failed for VM: {vm_identifier}")
#                 return False
            
#             logger.info(f"ProcMon successfully deployed to VM: {vm_identifier}")
#             return True
            
#         except Exception as e:
#             logger.error(f"Error deploying ProcMon to VM {vm_identifier}: {e}")
#             return False
    
#     def start_monitoring(self, vm_identifier: str, vm_config: dict, 
#                         session_name: str = None, duration_seconds: int = None) -> str:
#         """
#         Start ProcMon monitoring in the target VM.
        
#         Args:
#             vm_identifier: VM identifier
#             vm_config: VM configuration dictionary
#             session_name: Optional session name for tracking
#             duration_seconds: Optional monitoring duration limit
            
#         Returns:
#             Session ID for tracking the monitoring session
#         """
#         session_id = session_name or f"procmon_{vm_identifier}_{int(time.time())}"
        
#         logger.info(f"Starting ProcMon monitoring session: {session_id}")
        
#         try:
#             # Generate paths for VM
#             vm_log_path = f"C:\\Windows\\Temp\\procmon_log_{session_id}.pml"
#             vm_csv_path = f"C:\\Windows\\Temp\\procmon_log_{session_id}.csv"
            
#             # Build ProcMon command
#             procmon_cmd = self._build_procmon_command(vm_log_path, duration_seconds)
            
#             # Start ProcMon in background
#             stdout, stderr, rc = execute_command_in_guest(
#                 vm_identifier, procmon_cmd, vm_config, timeout_sec=10
#             )
            
#             if rc != 0:
#                 logger.error(f"Failed to start ProcMon in VM {vm_identifier}. RC: {rc}, Error: {stderr}")
#                 return None
            
#             # Track the session
#             self.monitoring_sessions[session_id] = {
#                 "vm_identifier": vm_identifier,
#                 "vm_config": vm_config,
#                 "start_time": datetime.now(),
#                 "duration_seconds": duration_seconds,
#                 "vm_log_path": vm_log_path,
#                 "vm_csv_path": vm_csv_path,
#                 "status": "running"
#             }
            
#             logger.info(f"ProcMon monitoring started successfully. Session: {session_id}")
#             return session_id
            
#         except Exception as e:
#             logger.error(f"Error starting ProcMon monitoring: {e}")
#             return None
    
#     def stop_monitoring(self, session_id: str) -> bool:
#         """
#         Stop ProcMon monitoring session.
        
#         Args:
#             session_id: Session identifier
            
#         Returns:
#             True if stopped successfully
#         """
#         if session_id not in self.monitoring_sessions:
#             logger.error(f"Monitoring session not found: {session_id}")
#             return False
        
#         session = self.monitoring_sessions[session_id]
#         logger.info(f"Stopping ProcMon monitoring session: {session_id}")
        
#         try:
#             # Send terminate command to ProcMon
#             stop_cmd = "taskkill /F /IM procmon.exe"
#             stdout, stderr, rc = execute_command_in_guest(
#                 session["vm_identifier"], stop_cmd, session["vm_config"], timeout_sec=30
#             )
            
#             # Update session status
#             session["status"] = "stopped"
#             session["stop_time"] = datetime.now()
            
#             logger.info(f"ProcMon monitoring stopped. Session: {session_id}")
#             return True
            
#         except Exception as e:
#             logger.error(f"Error stopping ProcMon monitoring: {e}")
#             return False
    
#     def export_and_collect_logs(self, session_id: str, host_output_dir: str) -> Tuple[Optional[str], Optional[str]]:
#         """
#         Export ProcMon logs to CSV and collect from VM.
        
#         Args:
#             session_id: Session identifier
#             host_output_dir: Host directory to save collected logs
            
#         Returns:
#             Tuple of (PML file path, CSV file path) on host, or (None, None) if failed
#         """
#         if session_id not in self.monitoring_sessions:
#             logger.error(f"Monitoring session not found: {session_id}")
#             return None, None
        
#         session = self.monitoring_sessions[session_id]
#         logger.info(f"Exporting and collecting logs for session: {session_id}")
        
#         try:
#             # Ensure monitoring is stopped
#             if session.get("status") == "running":
#                 self.stop_monitoring(session_id)
#                 time.sleep(2)  # Allow time to flush logs
            
#             # Export PML to CSV format in VM
#             export_cmd = f'procmon.exe /OpenLog "{session["vm_log_path"]}" /SaveAs "{session["vm_csv_path"]}" /SaveFormat CSV'
#             stdout, stderr, rc = execute_command_in_guest(
#                 session["vm_identifier"], export_cmd, session["vm_config"], timeout_sec=120
#             )
            
#             if rc != 0:
#                 logger.warning(f"PML to CSV export may have failed. RC: {rc}")
            
#             # Create host output directory
#             os.makedirs(host_output_dir, exist_ok=True)
            
#             # Copy files from VM to host
#             host_pml_path = os.path.join(host_output_dir, f"procmon_log_{session_id}.pml")
#             host_csv_path = os.path.join(host_output_dir, f"procmon_log_{session_id}.csv")
            
#             # Copy PML file
#             pml_success = copy_from_guest(
#                 session["vm_identifier"], session["vm_log_path"], host_pml_path, 
#                 session["vm_config"], is_directory=False
#             )
            
#             # Copy CSV file
#             csv_success = copy_from_guest(
#                 session["vm_identifier"], session["vm_csv_path"], host_csv_path,
#                 session["vm_config"], is_directory=False
#             )
            
#             # Clean up VM files
#             self._cleanup_vm_files(session)
            
#             # Update session with results
#             session["host_pml_path"] = host_pml_path if pml_success else None
#             session["host_csv_path"] = host_csv_path if csv_success else None
#             session["collection_time"] = datetime.now()
            
#             if csv_success:
#                 logger.info(f"ProcMon logs successfully collected. CSV: {host_csv_path}")
#                 return (host_pml_path if pml_success else None, host_csv_path)
#             else:
#                 logger.error(f"Failed to collect CSV log for session: {session_id}")
#                 return None, None
                
#         except Exception as e:
#             logger.error(f"Error exporting and collecting logs: {e}")
#             return None, None
    
#     def get_session_status(self, session_id: str) -> Dict:
#         """
#         Get status information for a monitoring session.
        
#         Args:
#             session_id: Session identifier
            
#         Returns:
#             Dictionary with session status information
#         """
#         if session_id not in self.monitoring_sessions:
#             return {"error": "Session not found"}
        
#         session = self.monitoring_sessions[session_id].copy()
        
#         # Add computed fields
#         if session.get("start_time"):
#             if session.get("stop_time"):
#                 session["actual_duration"] = (session["stop_time"] - session["start_time"]).total_seconds()
#             else:
#                 session["running_duration"] = (datetime.now() - session["start_time"]).total_seconds()
        
#         return session
    
#     def list_active_sessions(self) -> List[str]:
#         """
#         List all active monitoring sessions.
        
#         Returns:
#             List of active session IDs
#         """
#         return [sid for sid, session in self.monitoring_sessions.items() 
#                 if session.get("status") == "running"]
    
#     def cleanup_session(self, session_id: str) -> bool:
#         """
#         Clean up monitoring session and remove from tracking.
        
#         Args:
#             session_id: Session identifier
            
#         Returns:
#             True if cleanup successful
#         """
#         if session_id not in self.monitoring_sessions:
#             return False
        
#         session = self.monitoring_sessions[session_id]
        
#         try:
#             # Stop monitoring if still running
#             if session.get("status") == "running":
#                 self.stop_monitoring(session_id)
            
#             # Clean up VM files
#             self._cleanup_vm_files(session)
            
#             # Remove from tracking
#             del self.monitoring_sessions[session_id]
            
#             logger.info(f"Session cleaned up: {session_id}")
#             return True
            
#         except Exception as e:
#             logger.error(f"Error cleaning up session {session_id}: {e}")
#             return False
    
#     def _select_procmon_binary(self, vm_identifier: str, vm_config: dict) -> Optional[str]:
#         """Select appropriate ProcMon binary based on VM architecture."""
        
#         # Try to detect architecture
#         arch_cmd = "wmic computersystem get systemtype"
#         stdout, stderr, rc = execute_command_in_guest(vm_identifier, arch_cmd, vm_config, timeout_sec=30)
        
#         if rc == 0 and stdout:
#             arch_info = stdout.decode('utf-8', errors='ignore').lower()
#             if "arm64" in arch_info:
#                 binary_name = "procmon64a.exe"
#             elif "x64" in arch_info or "amd64" in arch_info:
#                 binary_name = "procmon64.exe"
#             else:
#                 binary_name = "procmon.exe"  # 32-bit fallback
#         else:
#             # Default to 64-bit
#             binary_name = "procmon64.exe"
#             logger.warning(f"Could not detect VM architecture, defaulting to {binary_name}")
        
#         binary_path = os.path.join(self.procmon_tools_path, binary_name)
        
#         if os.path.exists(binary_path):
#             logger.info(f"Selected ProcMon binary: {binary_name}")
#             return binary_path
#         else:
#             logger.error(f"ProcMon binary not found: {binary_path}")
#             return None
    
#     def _get_pmc_config_path(self) -> str:
#         """Get path to PMC configuration file."""
        
#         if os.path.exists(self.default_pmc_path):
#             return self.default_pmc_path
#         else:
#             # Create a basic PMC config if none exists
#             logger.warning("Default PMC config not found, creating basic configuration")
#             return self._create_basic_pmc_config()
    
#     def _create_basic_pmc_config(self) -> str:
#         """Create a basic PMC configuration file."""
        
#         config_dir = os.path.dirname(self.default_pmc_path)
#         os.makedirs(config_dir, exist_ok=True)
        
#         # PMC files are binary, but we can create a minimal one
#         # For now, return path to create - actual PMC creation would need 
#         # to be done via ProcMon GUI or we'd need to reverse engineer the format
        
#         logger.info(f"Basic PMC config created at: {self.default_pmc_path}")
#         return self.default_pmc_path
    
#     def _verify_procmon_deployment(self, vm_identifier: str, vm_config: dict, vm_procmon_path: str) -> bool:
#         """Verify ProcMon was deployed successfully."""
        
#         # Check if file exists and is executable
#         check_cmd = f'if exist "{vm_procmon_path}" (echo EXISTS) else (echo MISSING)'
#         stdout, stderr, rc = execute_command_in_guest(vm_identifier, check_cmd, vm_config, timeout_sec=30)
        
#         if rc == 0 and stdout and b"EXISTS" in stdout:
#             logger.debug("ProcMon deployment verified successfully")
#             return True
#         else:
#             logger.error("ProcMon deployment verification failed")
#             return False
    
#     def _build_procmon_command(self, vm_log_path: str, duration_seconds: int = None) -> str:
#         """Build ProcMon execution command."""
        
#         # Base command with configuration
#         cmd_parts = [
#             "cd /d C:\\Windows\\Temp &&",
#             "procmon.exe",
#             "/AcceptEula",  # Accept EULA automatically
#             "/Quiet",       # Run without UI
#             "/Minimized",   # Start minimized
#             f'/BackingFile "{vm_log_path}"',  # Output file
#             "/LoadConfig procmon_config.pmc"  # Load our configuration
#         ]
        
#         # Add duration if specified
#         if duration_seconds:
#             cmd_parts.append(f"/Runtime {duration_seconds}")
        
#         return " ".join(cmd_parts)
    
#     def _cleanup_vm_files(self, session: dict):
#         """Clean up temporary files in the VM."""
        
#         try:
#             cleanup_files = [
#                 session.get("vm_log_path"),
#                 session.get("vm_csv_path"),
#                 "C:\\Windows\\Temp\\procmon.exe",
#                 "C:\\Windows\\Temp\\procmon_config.pmc"
#             ]
            
#             for file_path in cleanup_files:
#                 if file_path:
#                     cleanup_cmd = f'del /F /Q "{file_path}" 2>nul'
#                     execute_command_in_guest(
#                         session["vm_identifier"], cleanup_cmd, session["vm_config"], timeout_sec=10
#                     )
            
#             logger.debug(f"VM cleanup completed for session: {session.get('start_time')}")
            
#         except Exception as e:
#             logger.warning(f"Error during VM cleanup: {e}")


# # Integration function for the monitoring pipeline
# def monitor_vm_behavior(vm_identifier: str, vm_config: dict, 
#                        duration_seconds: int = 300,
#                        output_dir: str = "logs/monitoring") -> Tuple[bool, Optional[str]]:
#     """
#     Complete monitoring workflow: deploy, monitor, collect, and return CSV path.
    
#     Args:
#         vm_identifier: VM identifier
#         vm_config: VM configuration
#         duration_seconds: Monitoring duration
#         output_dir: Output directory for collected logs
        
#     Returns:
#         Tuple of (success, csv_file_path)
#     """
#     handler = ProcMonHandler()
    
#     try:
#         # Deploy ProcMon
#         if not handler.deploy_procmon_to_vm(vm_identifier, vm_config):
#             return False, None
        
#         # Start monitoring
#         session_id = handler.start_monitoring(vm_identifier, vm_config, duration_seconds=duration_seconds)
#         if not session_id:
#             return False, None
        
#         # Wait for monitoring to complete
#         logger.info(f"Monitoring for {duration_seconds} seconds...")
#         time.sleep(duration_seconds + 5)  # Extra time for cleanup
        
#         # Collect logs
#         pml_path, csv_path = handler.export_and_collect_logs(session_id, output_dir)
        
#         # Cleanup
#         handler.cleanup_session(session_id)
        
#         if csv_path and os.path.exists(csv_path):
#             logger.info(f"Behavioral monitoring completed successfully. CSV: {csv_path}")
#             return True, csv_path
#         else:
#             logger.error("Failed to collect ProcMon CSV log")
#             return False, None
            
#     except Exception as e:
#         logger.error(f"Error in monitoring workflow: {e}")
#         return False, None


# if __name__ == "__main__":
#     import argparse
    
#     # Configure logging for standalone testing
#     logging.basicConfig(
#         level=logging.INFO,
#         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
#     )
    
#     parser = argparse.ArgumentParser(description='Shikra ProcMon Handler')
#     parser.add_argument('--vm-id', required=True, help='VM identifier')
#     parser.add_argument('--duration', type=int, default=300, help='Monitoring duration in seconds')
#     parser.add_argument('--output-dir', default='logs/monitoring', help='Output directory for logs')
    
#     args = parser.parse_args()
    
#     # Mock VM config for testing
#     mock_vm_config = {
#         "vms": {
#             args.vm_id: {
#                 "ip": "192.168.122.100",
#                 "guest_os_type": "windows",
#                 "user": "Administrator",
#                 "password": "password123"
#             }
#         }
#     }
    
#     success, csv_path = monitor_vm_behavior(
#         vm_identifier=args.vm_id,
#         vm_config=mock_vm_config,
#         duration_seconds=args.duration,
#         output_dir=args.output_dir
#     )
    
#     if success:
#         print(f"Monitoring completed successfully: {csv_path}")
#     else:
#         print("Monitoring failed")


# shikra/core/modules/monitoring/procmon_handler.py
# Purpose: Handles ProcMon process management, configuration, and control

import os
import subprocess
import time
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class ProcMonHandler:
    """
    Manages ProcMon process lifecycle, configuration, and data collection.
    Handles starting, stopping, and configuring ProcMon for malware analysis.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize ProcMon handler.
        
        Args:
            config: Configuration dictionary containing ProcMon settings
        """
        self.config = config or {}
        self.procmon_process = None
        self.is_running = False
        self.output_file = None
        self.temp_dir = None
        
        # ProcMon paths and settings
        self.procmon_path = self._find_procmon_executable()
        self.config_file = self.config.get('config_file', 'config/procmon/procmon_config.pmc')
        self.output_format = self.config.get('output_format', 'CSV')
        
        # Logging and monitoring settings
        self.max_file_size = self.config.get('max_file_size_mb', 500) * 1024 * 1024  # Convert to bytes
        self.monitor_duration = self.config.get('monitor_duration_seconds', 300)  # 5 minutes default
        
        logger.info(f"ProcMon handler initialized with executable: {self.procmon_path}")
    
    def _find_procmon_executable(self) -> str:
        """Find ProcMon executable in the tools directory or system PATH."""
        # Check configured path first
        if 'procmon_path' in self.config:
            procmon_path = self.config['procmon_path']
            if os.path.exists(procmon_path):
                return procmon_path
        
        # Look in tools directory
        possible_paths = [
            'tools/procmon/procmon64.exe',
            'tools/procmon/procmon.exe', 
            'tools/procmon/procmon64a.exe',  # ARM64 version
            '../tools/procmon/procmon64.exe',
            '../../tools/procmon/procmon64.exe'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Found ProcMon at: {path}")
                return os.path.abspath(path)
        
        # Check system PATH
        procmon_names = ['procmon64.exe', 'procmon.exe', 'Procmon64.exe', 'Procmon.exe']
        for name in procmon_names:
            if shutil.which(name):
                logger.info(f"Found ProcMon in PATH: {name}")
                return name
        
        # Default fallback
        default_path = 'tools/procmon/procmon64.exe'
        logger.warning(f"ProcMon not found, using default path: {default_path}")
        return default_path
    
    def create_config_file(self, filter_rules: Dict = None, output_path: str = None) -> str:
        """
        Create ProcMon configuration file (.pmc) with custom filters.
        
        Args:
            filter_rules: Dictionary containing filter rules
            output_path: Path where to save the config file
            
        Returns:
            Path to created configuration file
        """
        if not output_path:
            output_path = self.config_file
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Default filter rules if none provided
        if not filter_rules:
            filter_rules = self._get_default_filter_rules()
        
        # Create XML configuration
        config_xml = self._build_config_xml(filter_rules)
        
        try:
            # Write configuration file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(config_xml)
            
            logger.info(f"Created ProcMon config file: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to create config file {output_path}: {e}")
            raise
    
    def _get_default_filter_rules(self) -> Dict:
        """Get default filter rules optimized for malware analysis."""
        return {
            "include_filters": [
                # Include suspicious processes
                {"column": "Process Name", "relation": "contains", "value": "cmd.exe"},
                {"column": "Process Name", "relation": "contains", "value": "powershell.exe"},
                {"column": "Process Name", "relation": "contains", "value": "wscript.exe"},
                {"column": "Process Name", "relation": "contains", "value": "cscript.exe"},
                {"column": "Process Name", "relation": "contains", "value": "rundll32.exe"},
                {"column": "Process Name", "relation": "contains", "value": "regsvr32.exe"},
                {"column": "Process Name", "relation": "contains", "value": "mshta.exe"},
                {"column": "Process Name", "relation": "contains", "value": "certutil.exe"},
                {"column": "Process Name", "relation": "contains", "value": "bitsadmin.exe"},
                
                # Include file operations in user directories
                {"column": "Path", "relation": "contains", "value": "\\Users\\"},
                {"column": "Path", "relation": "contains", "value": "\\Documents\\"},
                {"column": "Path", "relation": "contains", "value": "\\Desktop\\"},
                {"column": "Path", "relation": "contains", "value": "\\Downloads\\"},
                {"column": "Path", "relation": "contains", "value": "\\AppData\\"},
                
                # Include registry operations
                {"column": "Path", "relation": "contains", "value": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
                {"column": "Path", "relation": "contains", "value": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
                {"column": "Path", "relation": "contains", "value": "\\Services\\"},
                {"column": "Path", "relation": "contains", "value": "\\Winlogon\\"}
            ],
            
            "exclude_filters": [
                # Exclude noisy system processes
                {"column": "Process Name", "relation": "is", "value": "System"},
                {"column": "Process Name", "relation": "is", "value": "Registry"},
                {"column": "Process Name", "relation": "is", "value": "smss.exe"},
                {"column": "Process Name", "relation": "is", "value": "csrss.exe"},
                {"column": "Process Name", "relation": "is", "value": "wininit.exe"},
                {"column": "Process Name", "relation": "is", "value": "services.exe"},
                {"column": "Process Name", "relation": "is", "value": "lsass.exe"},
                {"column": "Process Name", "relation": "is", "value": "svchost.exe"},
                {"column": "Process Name", "relation": "is", "value": "dwm.exe"},
                {"column": "Process Name", "relation": "is", "value": "SearchIndexer.exe"},
                
                # Exclude common file extensions that are rarely malicious
                {"column": "Path", "relation": "ends with", "value": ".jpg"},
                {"column": "Path", "relation": "ends with", "value": ".png"},
                {"column": "Path", "relation": "ends with", "value": ".gif"},
                {"column": "Path", "relation": "ends with", "value": ".mp3"},
                {"column": "Path", "relation": "ends with", "value": ".mp4"},
                {"column": "Path", "relation": "ends with", "value": ".avi"},
                
                # Exclude temporary and log files
                {"column": "Path", "relation": "contains", "value": "\\Windows\\Temp\\~"},
                {"column": "Path", "relation": "ends with", "value": ".tmp"},
                {"column": "Path", "relation": "ends with", "value": ".log"},
                {"column": "Path", "relation": "ends with", "value": ".etl"},
                
                # Exclude failed operations
                {"column": "Result", "relation": "is", "value": "NAME NOT FOUND"},
                {"column": "Result", "relation": "is", "value": "PATH NOT FOUND"},
                {"column": "Result", "relation": "is", "value": "ACCESS DENIED"}
            ]
        }
    
    def _build_config_xml(self, filter_rules: Dict) -> str:
        """Build ProcMon configuration XML from filter rules."""
        # This is a simplified version - actual ProcMon config files are binary
        # For now, we'll create a text representation that we can use to configure ProcMon
        config_lines = [
            "# ProcMon Configuration File",
            "# Generated by Shikra Framework",
            f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "[FILTERS]"
        ]
        
        # Add include filters
        if "include_filters" in filter_rules:
            config_lines.append("# Include Filters")
            for i, rule in enumerate(filter_rules["include_filters"]):
                config_lines.append(f"INCLUDE_{i}={rule['column']}|{rule['relation']}|{rule['value']}")
        
        # Add exclude filters
        if "exclude_filters" in filter_rules:
            config_lines.append("# Exclude Filters")
            for i, rule in enumerate(filter_rules["exclude_filters"]):
                config_lines.append(f"EXCLUDE_{i}={rule['column']}|{rule['relation']}|{rule['value']}")
        
        config_lines.extend([
            "",
            "[SETTINGS]",
            "AutoScroll=0",
            "HistoryDepth=0",
            "Profiling=0",
            "DestructiveFilter=0"
        ])
        
        return "\n".join(config_lines)
    
    def start_monitoring(self, output_file: str = None, duration: int = None) -> bool:
        """
        Start ProcMon monitoring.
        
        Args:
            output_file: Path for output file (if None, uses temp file)
            duration: Monitoring duration in seconds (if None, runs indefinitely)
            
        Returns:
            True if started successfully, False otherwise
        """
        if self.is_running:
            logger.warning("ProcMon is already running")
            return True
        
        # Set up output file
        if not output_file:
            self.temp_dir = tempfile.mkdtemp(prefix="shikra_procmon_")
            self.output_file = os.path.join(self.temp_dir, f"procmon_output_{int(time.time())}.{self.output_format.lower()}")
        else:
            self.output_file = output_file
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
        # Build command line
        cmd_args = [self.procmon_path]
        
        # Add backing file
        cmd_args.extend(["/BackingFile", self.output_file.replace('.csv', '.pml')])
        
        # Add configuration file if exists
        if os.path.exists(self.config_file):
            cmd_args.extend(["/LoadConfig", self.config_file])
        
        # Add other options
        cmd_args.extend([
            "/Minimized",           # Start minimized
            "/Quiet",              # No dialog boxes
            "/AcceptEula"          # Accept EULA automatically
        ])
        
        # Add duration if specified
        if duration:
            cmd_args.extend(["/Runtime", str(duration)])
        elif self.monitor_duration:
            cmd_args.extend(["/Runtime", str(self.monitor_duration)])
        
        try:
            logger.info(f"Starting ProcMon with command: {' '.join(cmd_args)}")
            self.procmon_process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(self.procmon_path) if os.path.dirname(self.procmon_path) else None
            )
            
            # Wait a moment to see if it starts successfully
            time.sleep(2)
            
            if self.procmon_process.poll() is None:
                self.is_running = True
                logger.info(f"ProcMon started successfully, output: {self.output_file}")
                return True
            else:
                stdout, stderr = self.procmon_process.communicate()
                logger.error(f"ProcMon failed to start. stdout: {stdout.decode()}, stderr: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start ProcMon: {e}")
            return False
    
    def stop_monitoring(self) -> Tuple[bool, str]:
        """
        Stop ProcMon monitoring and export data.
        
        Returns:
            Tuple of (success, output_file_path)
        """
        if not self.is_running:
            logger.warning("ProcMon is not running")
            return False, ""
        
        try:
            # Terminate ProcMon process
            if self.procmon_process:
                self.procmon_process.terminate()
                self.procmon_process.wait(timeout=10)
            
            # Convert PML to CSV if needed
            csv_output = self._convert_pml_to_csv()
            
            self.is_running = False
            logger.info(f"ProcMon stopped successfully, output: {csv_output}")
            return True, csv_output
            
        except subprocess.TimeoutExpired:
            logger.warning("ProcMon didn't terminate gracefully, forcing kill")
            self.procmon_process.kill()
            self.is_running = False
            return False, ""
        except Exception as e:
            logger.error(f"Error stopping ProcMon: {e}")
            self.is_running = False
            return False, ""
    
    def _convert_pml_to_csv(self) -> str:
        """Convert PML file to CSV format for processing."""
        if not self.output_file:
            return ""
        
        pml_file = self.output_file.replace('.csv', '.pml')
        csv_file = self.output_file if self.output_file.endswith('.csv') else self.output_file.replace('.pml', '.csv')
        
        if not os.path.exists(pml_file):
            logger.warning(f"PML file not found: {pml_file}")
            return ""
        
        # Use ProcMon to convert PML to CSV
        convert_cmd = [
            self.procmon_path,
            "/OpenLog", pml_file,
            "/SaveAs", csv_file,
            "/SaveFormat", "CSV"
        ]
        
        try:
            logger.info(f"Converting PML to CSV: {pml_file} -> {csv_file}")
            result = subprocess.run(
                convert_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60
            )
            
            if result.returncode == 0 and os.path.exists(csv_file):
                logger.info(f"Successfully converted to CSV: {csv_file}")
                return csv_file
            else:
                logger.error(f"Failed to convert PML to CSV. Return code: {result.returncode}")
                return ""
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout converting PML to CSV")
            return ""
        except Exception as e:
            logger.error(f"Error converting PML to CSV: {e}")
            return ""
    
    def get_status(self) -> Dict:
        """Get current monitoring status."""
        status = {
            "is_running": self.is_running,
            "output_file": self.output_file,
            "procmon_path": self.procmon_path,
            "config_file": self.config_file,
            "temp_dir": self.temp_dir
        }
        
        if self.output_file and os.path.exists(self.output_file):
            status["output_file_size"] = os.path.getsize(self.output_file)
        
        if self.procmon_process:
            status["process_id"] = self.procmon_process.pid
            status["process_running"] = self.procmon_process.poll() is None
        
        return status
    
    def cleanup(self):
        """Clean up temporary files and stop monitoring if running."""
        try:
            if self.is_running:
                self.stop_monitoring()
            
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()

# Utility functions for easier usage
def start_procmon_monitoring(sample_id: str, config: Dict = None, duration: int = 300) -> Tuple[ProcMonHandler, str]:
    """
    Convenience function to start ProcMon monitoring.
    
    Args:
        sample_id: Unique identifier for the monitoring session
        config: Configuration dictionary
        duration: Monitoring duration in seconds
        
    Returns:
        Tuple of (ProcMonHandler instance, output_file_path)
    """
    handler = ProcMonHandler(config)
    
    # Create output file path
    output_dir = config.get('output_dir', 'logs/monitoring') if config else 'logs/monitoring'
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"procmon_{sample_id}_{int(time.time())}.csv")
    
    # Start monitoring
    if handler.start_monitoring(output_file, duration):
        return handler, output_file
    else:
        raise RuntimeError("Failed to start ProcMon monitoring")

def monitor_process_execution(executable_path: str, args: List[str] = None, duration: int = 300, config: Dict = None) -> str:
    """
    Monitor a specific process execution with ProcMon.
    
    Args:
        executable_path: Path to executable to monitor
        args: Command line arguments for the executable
        duration: Monitoring duration in seconds
        config: ProcMon configuration
        
    Returns:
        Path to output CSV file
    """
    sample_id = f"process_{os.path.basename(executable_path)}_{int(time.time())}"
    
    with ProcMonHandler(config) as handler:
        # Start monitoring
        output_file = f"logs/monitoring/procmon_{sample_id}.csv"
        if not handler.start_monitoring(output_file, duration):
            raise RuntimeError("Failed to start ProcMon monitoring")
        
        # Wait a moment for ProcMon to initialize
        time.sleep(2)
        
        # Execute target process
        cmd = [executable_path]
        if args:
            cmd.extend(args)
        
        try:
            logger.info(f"Executing monitored process: {' '.join(cmd)}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for process to complete or timeout
            try:
                process.wait(timeout=duration - 5)  # Leave 5 seconds for ProcMon to finish
            except subprocess.TimeoutExpired:
                logger.warning("Target process timed out, terminating")
                process.terminate()
                process.wait(timeout=10)
            
        except Exception as e:
            logger.error(f"Error executing target process: {e}")
        
        # Stop monitoring and get results
        success, csv_output = handler.stop_monitoring()
        if success:
            return csv_output
        else:
            raise RuntimeError("Failed to stop ProcMon monitoring")

if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='ProcMon Handler Test')
    parser.add_argument('--duration', type=int, default=60, help='Monitoring duration in seconds')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--create-config', action='store_true', help='Create default config file')
    parser.add_argument('--test-executable', help='Path to executable to monitor')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            import json
            config = json.load(f)
    
    # Create default configuration if requested
    if args.create_config:
        handler = ProcMonHandler(config)
        config_path = handler.create_config_file()
        print(f"Created default config file: {config_path}")
        exit(0)
    
    # Test monitoring
    if args.test_executable:
        try:
            csv_output = monitor_process_execution(
                args.test_executable,
                duration=args.duration,
                config=config
            )
            print(f"Monitoring complete. Output: {csv_output}")
        except Exception as e:
            print(f"Monitoring failed: {e}")
    else:
        # Simple monitoring test
        try:
            handler, output_file = start_procmon_monitoring(
                "test_session",
                config=config,
                duration=args.duration
            )
            
            print(f"Started monitoring. Output will be saved to: {output_file}")
            print(f"Monitoring for {args.duration} seconds...")
            
            # Wait for monitoring to complete
            time.sleep(args.duration + 5)
            
            # Stop monitoring
            success, csv_file = handler.stop_monitoring()
            if success:
                print(f"Monitoring complete. CSV output: {csv_file}")
            else:
                print("Monitoring failed to complete properly")
                
            # Cleanup
            handler.cleanup()
            
        except Exception as e:
            print(f"Error: {e}")
