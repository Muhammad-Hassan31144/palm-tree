# shikra/core/modules/vm_controller/vm_orchestrator.py
# Purpose: High-level VM management orchestrator for complete analysis workflows

import os
import time
import logging
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from pathlib import Path
from collections import defaultdict
import queue

from .run_in_vm import execute_command_in_guest
from .copy_to_vm import copy_to_guest
from .copy_from_vm import copy_from_guest
from .stealth import get_stealth_qemu_args, generate_random_mac_address
from ..monitoring.procmon_handler import ProcMonHandler
from ..monitoring.behavioral_monitor import BehavioralMonitor
from ..network.traffic_simulator import TrafficSimulator

logger = logging.getLogger(__name__)

class VMOrchestrator:
    """
    High-level VM management orchestrator that coordinates complete analysis workflows.
    Manages VM lifecycle, monitoring, data collection, and analysis coordination.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize VM orchestrator.
        
        Args:
            config: Configuration dictionary containing VM and analysis settings
        """
        self.config = config or {}
        self.session_id = f"vm_session_{int(time.time())}"
        
        # VM management
        self.active_vms = {}  # vm_id -> VM info
        self.vm_states = {}   # vm_id -> current state
        
        # Monitoring components
        self.monitors = {}    # vm_id -> BehavioralMonitor
        self.traffic_sim = None
        
        # Analysis coordination
        self.analysis_queue = queue.Queue()
        self.results_storage = defaultdict(dict)
        
        # Event callbacks
        self.event_callbacks = {
            "vm_started": [],
            "vm_stopped": [],
            "analysis_started": [],
            "analysis_completed": [],
            "alert_triggered": []
        }
        
        # Session tracking
        self.session_info = {
            "session_id": self.session_id,
            "start_time": datetime.now(),
            "vms_managed": 0,
            "analyses_completed": 0,
            "alerts_generated": 0,
            "errors": []
        }
        
        logger.info(f"VM Orchestrator initialized for session: {self.session_id}")
    
    def add_event_callback(self, event_type: str, callback: Callable):
        """Add callback for VM orchestration events."""
        if event_type in self.event_callbacks:
            self.event_callbacks[event_type].append(callback)
            logger.info(f"Added callback for event: {event_type}")
    
    def create_analysis_vm(self, vm_config: Dict) -> str:
        """
        Create and configure a VM for malware analysis.
        
        Args:
            vm_config: VM configuration dictionary
            
        Returns:
            VM identifier string
        """
        vm_id = vm_config.get("vm_id") or f"analysis_vm_{int(time.time())}"
        
        try:
            # Validate VM configuration
            required_fields = ["guest_os_type", "disk_image", "memory_mb"]
            for field in required_fields:
                if field not in vm_config:
                    raise ValueError(f"Missing required VM config field: {field}")
            
            # Apply stealth configuration if enabled
            if vm_config.get("enable_stealth", True):
                stealth_args = get_stealth_qemu_args(vm_config)
                vm_config["qemu_extra_args"] = vm_config.get("qemu_extra_args", []) + stealth_args
                
                # Generate random MAC address
                if vm_config.get("randomize_mac", True):
                    vm_config["mac_address"] = generate_random_mac_address()
            
            # Set up networking
            self._configure_vm_networking(vm_config)
            
            # Create VM directory structure
            vm_dir = os.path.join(self.config.get("vm_workspace", "workspace/vms"), vm_id)
            os.makedirs(vm_dir, exist_ok=True)
            vm_config["vm_directory"] = vm_dir
            
            # Store VM configuration
            self.active_vms[vm_id] = vm_config
            self.vm_states[vm_id] = "created"
            
            # Create VM-specific directories
            for subdir in ["logs", "captures", "results", "samples"]:
                os.makedirs(os.path.join(vm_dir, subdir), exist_ok=True)
            
            self.session_info["vms_managed"] += 1
            logger.info(f"Created analysis VM: {vm_id}")
            
            return vm_id
            
        except Exception as e:
            error_msg = f"Failed to create VM {vm_id}: {e}"
            logger.error(error_msg)
            self.session_info["errors"].append(error_msg)
            raise
    
    def _configure_vm_networking(self, vm_config: Dict):
        """Configure VM networking for analysis."""
        network_config = self.config.get("network", {})
        
        # Set up isolated network by default
        if "network_mode" not in vm_config:
            vm_config["network_mode"] = network_config.get("default_mode", "isolated")
        
        # Configure network interfaces
        if vm_config["network_mode"] == "isolated":
            # Isolated network with INetSim
            vm_config["network_config"] = {
                "type": "tap",
                "bridge": network_config.get("analysis_bridge", "br-analysis"),
                "isolated": True,
                "dns_server": network_config.get("inetsim_ip", "192.168.100.1")
            }
        elif vm_config["network_mode"] == "monitored":
            # Monitored internet access
            vm_config["network_config"] = {
                "type": "nat",
                "monitor_traffic": True,
                "filter_traffic": True
            }
        else:  # full_internet
            # Full internet access (dangerous)
            vm_config["network_config"] = {
                "type": "nat",
                "monitor_traffic": True,
                "filter_traffic": False
            }
    
    def start_vm(self, vm_id: str, wait_for_boot: bool = True) -> bool:
        """
        Start a VM and wait for it to be ready.
        
        Args:
            vm_id: VM identifier
            wait_for_boot: Whether to wait for VM to fully boot
            
        Returns:
            True if VM started successfully
        """
        if vm_id not in self.active_vms:
            logger.error(f"VM not found: {vm_id}")
            return False
        
        vm_config = self.active_vms[vm_id]
        
        try:
            # Build QEMU command
            qemu_cmd = self._build_qemu_command(vm_config)
            
            # Start VM process
            import subprocess
            vm_process = subprocess.Popen(
                qemu_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=vm_config["vm_directory"]
            )
            
            vm_config["process"] = vm_process
            vm_config["start_time"] = datetime.now()
            self.vm_states[vm_id] = "starting"
            
            # Wait for VM to boot if requested
            if wait_for_boot:
                if self._wait_for_vm_ready(vm_id, timeout=120):
                    self.vm_states[vm_id] = "running"
                    logger.info(f"VM started successfully: {vm_id}")
                    
                    # Trigger event callbacks
                    self._trigger_event("vm_started", {"vm_id": vm_id, "config": vm_config})
                    return True
                else:
                    logger.error(f"VM failed to boot within timeout: {vm_id}")
                    self.stop_vm(vm_id)
                    return False
            else:
                self.vm_states[vm_id] = "running"
                self._trigger_event("vm_started", {"vm_id": vm_id, "config": vm_config})
                return True
                
        except Exception as e:
            error_msg = f"Failed to start VM {vm_id}: {e}"
            logger.error(error_msg)
            self.session_info["errors"].append(error_msg)
            self.vm_states[vm_id] = "error"
            return False
    
    def _build_qemu_command(self, vm_config: Dict) -> List[str]:
        """Build QEMU command line arguments."""
        cmd = ["qemu-system-x86_64"]
        
        # Basic VM configuration
        cmd.extend(["-m", str(vm_config["memory_mb"])])
        cmd.extend(["-smp", str(vm_config.get("cpu_cores", 2))])
        cmd.extend(["-hda", vm_config["disk_image"]])
        
        # Machine type
        machine_type = vm_config.get("machine_type", "pc-q35-5.2")
        cmd.extend(["-M", machine_type])
        
        # Enable KVM if available
        if vm_config.get("enable_kvm", True):
            cmd.append("-enable-kvm")
        
        # Display configuration
        if vm_config.get("headless", True):
            cmd.extend(["-display", "none"])
            cmd.extend(["-vnc", ":1"])  # VNC on port 5901
        else:
            cmd.extend(["-display", "gtk"])
        
        # Network configuration
        self._add_network_args(cmd, vm_config)
        
        # USB and input devices
        cmd.extend(["-usb", "-device", "usb-tablet"])
        
        # Sound (disable for analysis)
        if not vm_config.get("enable_sound", False):
            cmd.extend(["-soundhw", "none"])
        
        # Snapshot mode for disposable analysis
        if vm_config.get("snapshot_mode", True):
            cmd.append("-snapshot")
        
        # Monitor interface
        monitor_socket = os.path.join(vm_config["vm_directory"], "monitor.sock")
        cmd.extend(["-monitor", f"unix:{monitor_socket},server,nowait"])
        
        # Add extra QEMU arguments (including stealth)
        extra_args = vm_config.get("qemu_extra_args", [])
        cmd.extend(extra_args)
        
        return cmd
    
    def _add_network_args(self, cmd: List[str], vm_config: Dict):
        """Add network configuration to QEMU command."""
        net_config = vm_config.get("network_config", {})
        
        if net_config.get("type") == "tap":
            # TAP interface for isolated network
            bridge = net_config.get("bridge", "br-analysis")
            mac_addr = vm_config.get("mac_address", generate_random_mac_address())
            
            cmd.extend([
                "-netdev", f"tap,id=net0,br={bridge}",
                "-device", f"virtio-net-pci,netdev=net0,mac={mac_addr}"
            ])
            
        elif net_config.get("type") == "nat":
            # NAT networking
            mac_addr = vm_config.get("mac_address", generate_random_mac_address())
            
            cmd.extend([
                "-netdev", "user,id=net0",
                "-device", f"virtio-net-pci,netdev=net0,mac={mac_addr}"
            ])
        else:
            # No networking
            cmd.extend(["-netdev", "none"])
    
    def _wait_for_vm_ready(self, vm_id: str, timeout: int = 120) -> bool:
        """Wait for VM to be ready for commands."""
        vm_config = self.active_vms[vm_id]
        start_time = time.time()
        
        # Give VM time to start booting
        time.sleep(10)
        
        while (time.time() - start_time) < timeout:
            try:
                # Try to execute a simple command
                stdout, stderr, rc = execute_command_in_guest(
                    vm_id, 
                    "echo test", 
                    {vm_id: vm_config},
                    timeout_sec=10
                )
                
                if rc == 0:
                    logger.info(f"VM {vm_id} is ready for commands")
                    return True
                    
            except Exception as e:
                logger.debug(f"VM {vm_id} not ready yet: {e}")
            
            time.sleep(5)
        
        logger.warning(f"VM {vm_id} did not become ready within {timeout} seconds")
        return False
    
    def stop_vm(self, vm_id: str, force: bool = False) -> bool:
        """
        Stop a VM gracefully or forcefully.
        
        Args:
            vm_id: VM identifier
            force: Whether to force stop the VM
            
        Returns:
            True if VM stopped successfully
        """
        if vm_id not in self.active_vms:
            logger.error(f"VM not found: {vm_id}")
            return False
        
        vm_config = self.active_vms[vm_id]
        
        try:
            # Stop monitoring if active
            if vm_id in self.monitors:
                self.monitors[vm_id].stop_monitoring()
                del self.monitors[vm_id]
            
            # Get VM process
            vm_process = vm_config.get("process")
            if not vm_process:
                logger.warning(f"No process found for VM {vm_id}")
                return True
            
            if force:
                # Force kill
                vm_process.kill()
                logger.info(f"Force stopped VM: {vm_id}")
            else:
                # Graceful shutdown
                try:
                    # Try to send shutdown command first
                    execute_command_in_guest(
                        vm_id,
                        "shutdown /s /t 0" if vm_config["guest_os_type"] == "windows" else "shutdown -h now",
                        {vm_id: vm_config},
                        timeout_sec=10
                    )
                    
                    # Wait for graceful shutdown
                    try:
                        vm_process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"VM {vm_id} did not shutdown gracefully, forcing stop")
                        vm_process.kill()
                        
                except Exception:
                    # If shutdown command fails, terminate process
                    vm_process.terminate()
                    try:
                        vm_process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        vm_process.kill()
            
            # Update state
            self.vm_states[vm_id] = "stopped"
            vm_config["stop_time"] = datetime.now()
            
            # Trigger event callbacks
            self._trigger_event("vm_stopped", {"vm_id": vm_id, "config": vm_config})
            
            logger.info(f"VM stopped: {vm_id}")
            return True
            
        except Exception as e:
            error_msg = f"Failed to stop VM {vm_id}: {e}"
            logger.error(error_msg)
            self.session_info["errors"].append(error_msg)
            return False
    
    def start_comprehensive_analysis(self, vm_id: str, sample_path: str, analysis_config: Dict = None) -> str:
        """
        Start comprehensive malware analysis on a VM.
        
        Args:
            vm_id: VM identifier
            sample_path: Path to malware sample
            analysis_config: Analysis configuration
            
        Returns:
            Analysis session ID
        """
        if vm_id not in self.active_vms or self.vm_states[vm_id] != "running":
            raise ValueError(f"VM {vm_id} is not running")
        
        analysis_config = analysis_config or {}
        analysis_id = f"analysis_{vm_id}_{int(time.time())}"
        
        try:
            # Create analysis workspace
            vm_config = self.active_vms[vm_id]
            analysis_dir = os.path.join(vm_config["vm_directory"], "analyses", analysis_id)
            os.makedirs(analysis_dir, exist_ok=True)
            
            # Copy sample to VM
            sample_name = os.path.basename(sample_path)
            guest_sample_path = f"C:\\Analysis\\{sample_name}" if vm_config["guest_os_type"] == "windows" else f"/tmp/{sample_name}"
            
            logger.info(f"Copying sample to VM {vm_id}: {sample_path} -> {guest_sample_path}")
            if not copy_to_guest(vm_id, sample_path, guest_sample_path, {vm_id: vm_config}):
                raise RuntimeError("Failed to copy sample to VM")
            
            # Start behavioral monitoring
            monitor = BehavioralMonitor(
                sample_id=analysis_id,
                config=analysis_config.get("monitoring", {})
            )
            
            # Add alert callback
            def analysis_alert_callback(alert):
                self.session_info["alerts_generated"] += 1
                self._trigger_event("alert_triggered", {"vm_id": vm_id, "alert": alert})
            
            monitor.add_alert_callback(analysis_alert_callback)
            self.monitors[vm_id] = monitor
            
            # Start traffic simulation if enabled
            if analysis_config.get("simulate_traffic", True):
                self._start_traffic_simulation(vm_id, analysis_config)
            
            # Start monitoring
            monitor_duration = analysis_config.get("monitor_duration", 300)  # 5 minutes default
            if not monitor.start_monitoring(monitor_duration):
                raise RuntimeError("Failed to start behavioral monitoring")
            
            # Execute sample
            execution_thread = threading.Thread(
                target=self._execute_sample_analysis,
                args=(vm_id, guest_sample_path, analysis_config, analysis_id),
                name=f"SampleExec-{analysis_id}",
                daemon=True
            )
            execution_thread.start()
            
            # Store analysis info
            self.results_storage[vm_id][analysis_id] = {
                "analysis_id": analysis_id,
                "sample_path": sample_path,
                "guest_sample_path": guest_sample_path,
                "start_time": datetime.now(),
                "config": analysis_config,
                "monitor": monitor,
                "execution_thread": execution_thread,
                "analysis_dir": analysis_dir,
                "status": "running"
            }
            
            self.session_info["analyses_completed"] += 1
            self._trigger_event("analysis_started", {"vm_id": vm_id, "analysis_id": analysis_id})
            
            logger.info(f"Started comprehensive analysis: {analysis_id} on VM {vm_id}")
            return analysis_id
            
        except Exception as e:
            error_msg = f"Failed to start analysis on VM {vm_id}: {e}"
            logger.error(error_msg)
            self.session_info["errors"].append(error_msg)
            raise
    
    def _start_traffic_simulation(self, vm_id: str, analysis_config: Dict):
        """Start background traffic simulation during analysis."""
        if not self.traffic_sim:
            self.traffic_sim = TrafficSimulator(analysis_config.get("traffic_simulation", {}))
        
        intensity = analysis_config.get("traffic_intensity", "low")
        duration = analysis_config.get("monitor_duration", 300) + 60  # Run longer than monitoring
        
        if self.traffic_sim.start_simulation(duration, intensity):
            logger.info(f"Started traffic simulation for VM {vm_id}")
        else:
            logger.warning("Failed to start traffic simulation")
    
    def _execute_sample_analysis(self, vm_id: str, sample_path: str, config: Dict, analysis_id: str):
        """Execute the malware sample and perform analysis steps."""
        vm_config = self.active_vms[vm_id]
        
        try:
            # Wait a moment for monitoring to initialize
            time.sleep(5)
            
            # Pre-execution steps
            self._run_pre_execution_steps(vm_id, config)
            
            # Execute the sample
            logger.info(f"Executing sample: {sample_path}")
            
            if vm_config["guest_os_type"] == "windows":
                # Windows execution
                execution_methods = config.get("execution_methods", ["direct"])
                
                for method in execution_methods:
                    if method == "direct":
                        execute_command_in_guest(vm_id, sample_path, {vm_id: vm_config}, timeout_sec=30)
                    elif method == "rundll32":
                        execute_command_in_guest(vm_id, f"rundll32 {sample_path},DllMain", {vm_id: vm_config}, timeout_sec=30)
                    elif method == "regsvr32":
                        execute_command_in_guest(vm_id, f"regsvr32 /s {sample_path}", {vm_id: vm_config}, timeout_sec=30)
                    
                    # Wait between execution methods
                    time.sleep(10)
            else:
                # Linux execution
                execute_command_in_guest(vm_id, f"chmod +x {sample_path} && {sample_path}", {vm_id: vm_config}, timeout_sec=30)
            
            # Post-execution monitoring
            monitor_time = config.get("post_execution_monitor", 60)
            logger.info(f"Monitoring post-execution activity for {monitor_time} seconds")
            time.sleep(monitor_time)
            
            # Run post-execution steps
            self._run_post_execution_steps(vm_id, config, analysis_id)
            
            # Mark analysis as completed
            if analysis_id in self.results_storage[vm_id]:
                self.results_storage[vm_id][analysis_id]["status"] = "completed"
                self.results_storage[vm_id][analysis_id]["end_time"] = datetime.now()
            
            logger.info(f"Sample execution completed: {analysis_id}")
            
        except Exception as e:
            error_msg = f"Error during sample execution {analysis_id}: {e}"
            logger.error(error_msg)
            
            if analysis_id in self.results_storage[vm_id]:
                self.results_storage[vm_id][analysis_id]["status"] = "error"
                self.results_storage[vm_id][analysis_id]["error"] = str(e)
    
    def _run_pre_execution_steps(self, vm_id: str, config: Dict):
        """Run pre-execution analysis steps."""
        vm_config = self.active_vms[vm_id]
        
        # Create analysis directories on guest
        if vm_config["guest_os_type"] == "windows":
            execute_command_in_guest(vm_id, "mkdir C:\\Analysis", {vm_id: vm_config}, timeout_sec=10)
            execute_command_in_guest(vm_id, "mkdir C:\\Analysis\\Logs", {vm_id: vm_config}, timeout_sec=10)
            
            # Disable Windows Defender if requested
            if config.get("disable_defender", True):
                execute_command_in_guest(
                    vm_id,
                    'powershell.exe "Set-MpPreference -DisableRealtimeMonitoring $true"',
                    {vm_id: vm_config},
                    timeout_sec=15
                )
        else:
            execute_command_in_guest(vm_id, "mkdir -p /tmp/analysis/logs", {vm_id: vm_config}, timeout_sec=10)
    
    def _run_post_execution_steps(self, vm_id: str, config: Dict, analysis_id: str):
        """Run post-execution analysis steps."""
        vm_config = self.active_vms[vm_id]
        analysis_dir = self.results_storage[vm_id][analysis_id]["analysis_dir"]
        
        # Collect system information
        self._collect_system_info(vm_id, analysis_dir)
        
        # Collect logs
        self._collect_guest_logs(vm_id, analysis_dir)
        
        # Take memory dump if configured
        if config.get("collect_memory_dump", False):
            self._collect_memory_dump(vm_id, analysis_dir)
        
        # Collect network captures
        self._collect_network_data(vm_id, analysis_dir)
    
    def _collect_system_info(self, vm_id: str, output_dir: str):
        """Collect system information from guest."""
        vm_config = self.active_vms[vm_id]
        
        info_commands = {
            "processes.txt": "tasklist /v" if vm_config["guest_os_type"] == "windows" else "ps aux",
            "network.txt": "netstat -an" if vm_config["guest_os_type"] == "windows" else "netstat -tulpn",
            "services.txt": "sc query" if vm_config["guest_os_type"] == "windows" else "systemctl list-units --type=service"
        }
        
        for filename, command in info_commands.items():
            try:
                stdout, stderr, rc = execute_command_in_guest(vm_id, command, {vm_id: vm_config}, timeout_sec=30)
                
                if rc == 0 and stdout:
                    output_file = os.path.join(output_dir, filename)
                    with open(output_file, 'wb') as f:
                        f.write(stdout)
                    logger.info(f"Collected system info: {filename}")
                    
            except Exception as e:
                logger.warning(f"Failed to collect {filename}: {e}")
    
    def _collect_guest_logs(self, vm_id: str, output_dir: str):
        """Collect logs from guest system."""
        vm_config = self.active_vms[vm_id]
        
        if vm_config["guest_os_type"] == "windows":
            # Windows Event Logs
            log_paths = [
                "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx"
            ]
        else:
            # Linux logs
            log_paths = [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/kern.log"
            ]
        
        logs_dir = os.path.join(output_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        
        for log_path in log_paths:
            try:
                log_name = os.path.basename(log_path)
                host_path = os.path.join(logs_dir, log_name)
                
                if copy_from_guest(vm_id, log_path, host_path, {vm_id: vm_config}):
                    logger.info(f"Collected log: {log_name}")
                else:
                    logger.warning(f"Failed to collect log: {log_path}")
                    
            except Exception as e:
                logger.warning(f"Error collecting log {log_path}: {e}")
    
    def _collect_memory_dump(self, vm_id: str, output_dir: str):
        """Collect memory dump from VM."""
        vm_config = self.active_vms[vm_id]
        
        try:
            # Use QEMU monitor to create memory dump
            monitor_socket = os.path.join(vm_config["vm_directory"], "monitor.sock")
            dump_file = os.path.join(output_dir, "memory_dump.raw")
            
            # Send monitor command to dump memory
            import socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(monitor_socket)
            sock.send(f"dump-guest-memory {dump_file}\n".encode())
            response = sock.recv(1024)
            sock.close()
            
            if os.path.exists(dump_file):
                logger.info(f"Collected memory dump: {dump_file}")
            else:
                logger.warning("Memory dump file not created")
                
        except Exception as e:
            logger.warning(f"Failed to collect memory dump: {e}")
    
    def _collect_network_data(self, vm_id: str, output_dir: str):
        """Collect network capture data."""
        # Network data collection would be handled by the network capture module
        # This is a placeholder for integration with network monitoring
        try:
            network_dir = os.path.join(output_dir, "network")
            os.makedirs(network_dir, exist_ok=True)
            
            # Copy PCAP files if they exist
            # This would be integrated with the network capture system
            
            logger.info("Network data collection placeholder")
            
        except Exception as e:
            logger.warning(f"Failed to collect network data: {e}")
    
    def get_analysis_results(self, vm_id: str, analysis_id: str = None) -> Dict:
        """
        Get analysis results for a VM or specific analysis.
        
        Args:
            vm_id: VM identifier
            analysis_id: Specific analysis ID (optional)
            
        Returns:
            Analysis results dictionary
        """
        if vm_id not in self.results_storage:
            return {"error": f"No results found for VM {vm_id}"}
        
        if analysis_id:
            if analysis_id in self.results_storage[vm_id]:
                analysis_data = self.results_storage[vm_id][analysis_id]
                
                # Get monitoring results if available
                if "monitor" in analysis_data and analysis_data["monitor"]:
                    monitoring_results = analysis_data["monitor"].get_live_statistics()
                    analysis_data["monitoring_results"] = monitoring_results
                
                return analysis_data
            else:
                return {"error": f"Analysis {analysis_id} not found"}
        else:
            # Return all analyses for the VM
            return dict(self.results_storage[vm_id])
    
    def wait_for_analysis_completion(self, vm_id: str, analysis_id: str, timeout: int = 600) -> bool:
        """
        Wait for analysis to complete.
        
        Args:
            vm_id: VM identifier
            analysis_id: Analysis identifier
            timeout: Timeout in seconds
            
        Returns:
            True if analysis completed successfully
        """
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            if vm_id in self.results_storage and analysis_id in self.results_storage[vm_id]:
                status = self.results_storage[vm_id][analysis_id].get("status", "unknown")
                
                if status in ["completed", "error"]:
                    return status == "completed"
            
            time.sleep(5)
        
        logger.warning(f"Analysis {analysis_id} did not complete within {timeout} seconds")
        return False
    
    def cleanup_session(self):
        """Clean up the orchestration session."""
        logger.info(f"Cleaning up session: {self.session_id}")
        
        # Stop all VMs
        for vm_id in list(self.active_vms.keys()):
            if self.vm_states.get(vm_id) == "running":
                self.stop_vm(vm_id, force=True)
        
        # Stop traffic simulation
        if self.traffic_sim and self.traffic_sim.is_running:
            self.traffic_sim.stop_simulation()
        
        # Stop all monitors
        for monitor in self.monitors.values():
            if monitor.is_monitoring:
                monitor.stop_monitoring()
        
        self.session_info["end_time"] = datetime.now()
        self.session_info["total_duration"] = (self.session_info["end_time"] - self.session_info["start_time"]).total_seconds()
        
        logger.info("Session cleanup completed")
    
    def _trigger_event(self, event_type: str, event_data: Dict):
        """Trigger event callbacks."""
        for callback in self.event_callbacks.get(event_type, []):
            try:
                callback(event_data)
            except Exception as e:
                logger.error(f"Error in event callback for {event_type}: {e}")
    
    def get_session_statistics(self) -> Dict:
        """Get session statistics."""
        stats = self.session_info.copy()
        
        # Add current status
        stats["active_vms"] = len([vm_id for vm_id, state in self.vm_states.items() if state == "running"])
        stats["total_vms"] = len(self.active_vms)
        stats["active_monitors"] = len([m for m in self.monitors.values() if m.is_monitoring])
        
        # Add VM status breakdown
        stats["vm_states"] = dict(self.vm_states)
        
        return stats
    
    def export_session_report(self, output_file: str = None) -> str:
        """Export comprehensive session report."""
        if not output_file:
            output_file = f"vm_orchestration_report_{self.session_id}.json"
        
        report = {
            "session_info": self.get_session_statistics(),
            "vm_configurations": {vm_id: {k: v for k, v in config.items() if k != "process"} 
                                for vm_id, config in self.active_vms.items()},
            "analysis_results": dict(self.results_storage),
            "traffic_simulation_stats": self.traffic_sim.get_statistics() if self.traffic_sim else None
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Session report exported to: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to export session report: {e}")
            return ""
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup_session()

# Utility functions
def run_complete_analysis(sample_path: str, vm_config: Dict, analysis_config: Dict = None) -> Dict:
    """
    Run a complete malware analysis workflow.
    
    Args:
        sample_path: Path to malware sample
        vm_config: VM configuration
        analysis_config: Analysis configuration
        
    Returns:
        Analysis results
    """
    with VMOrchestrator() as orchestrator:
        # Create and start VM
        vm_id = orchestrator.create_analysis_vm(vm_config)
        
        if not orchestrator.start_vm(vm_id):
            return {"error": "Failed to start VM"}
        
        # Run analysis
        analysis_id = orchestrator.start_comprehensive_analysis(vm_id, sample_path, analysis_config)
        
        # Wait for completion
        if orchestrator.wait_for_analysis_completion(vm_id, analysis_id):
            return orchestrator.get_analysis_results(vm_id, analysis_id)
        else:
            return {"error": "Analysis did not complete successfully"}

if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def sample_event_callback(event_data):
        event_type = event_data.get("event_type", "unknown")
        vm_id = event_data.get("vm_id", "unknown")
        print(f"🎯 Event: {event_type} for VM {vm_id}")
    
    parser = argparse.ArgumentParser(description='VM Orchestrator Test')
    parser.add_argument('--vm-config', help='VM configuration file')
    parser.add_argument('--sample', help='Malware sample path')
    parser.add_argument('--analysis-config', help='Analysis configuration file')
    parser.add_argument('--test-mode', action='store_true', help='Run in test mode')
    
    args = parser.parse_args()
    
    if args.test_mode:
        print("🧪 Running VM Orchestrator in test mode")
        
        # Create test VM configuration
        test_vm_config = {
            "vm_id": "test_vm",
            "guest_os_type": "windows",
            "disk_image": "images/windows10_analysis.qcow2",
            "memory_mb": 2048,
            "cpu_cores": 2,
            "enable_stealth": True,
            "headless": True
        }
        
        with VMOrchestrator() as orchestrator:
            # Add event callbacks
            for event_type in ["vm_started", "vm_stopped", "analysis_started", "analysis_completed"]:
                orchestrator.add_event_callback(event_type, sample_event_callback)
            
            try:
                print("📋 Creating test VM...")
                vm_id = orchestrator.create_analysis_vm(test_vm_config)
                print(f"✅ Created VM: {vm_id}")
                
                print("🚀 Starting VM...")
                if orchestrator.start_vm(vm_id):
                    print("✅ VM started successfully")
                    
                    # Test basic functionality
                    time.sleep(10)
                    
                    print("🛑 Stopping VM...")
                    if orchestrator.stop_vm(vm_id):
                        print("✅ VM stopped successfully")
                    
                else:
                    print("❌ Failed to start VM")
                
                # Print session statistics
                stats = orchestrator.get_session_statistics()
                print(f"\n📊 Session Statistics:")
                for key, value in stats.items():
                    if key not in ['start_time', 'end_time']:
                        print(f"   {key}: {value}")
                
            except Exception as e:
                print(f"❌ Error during test: {e}")
    
    else:
        print("Use --test-mode for basic functionality test")
        print("For full analysis, provide --vm-config and --sample parameters")
