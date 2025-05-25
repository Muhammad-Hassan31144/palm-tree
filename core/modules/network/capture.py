# shikra/modules/monitoring/network_capture.py
# Purpose: Provides functionalities for capturing network packets during malware analysis.
# Serves as a Python wrapper around packet capture tools like tcpdump and tshark.

import os
import time
import json
import signal
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Union, Any

logger = logging.getLogger(__name__)

class NetworkCapture:
    """
    Manages network packet capture using external tools like tcpdump or tshark.
    Integrates with Shikra's analysis framework.
    """

    def __init__(self,
                 capture_interface: str,
                 capture_tool: str = "tcpdump",
                 tool_path: Optional[str] = None,
                 config_data: Optional[Dict] = None):
        """
        Initialize the NetworkCapture instance.

        Args:
            capture_interface (str): Network interface to capture from (e.g., "eth0", "virbr0", "any").
            capture_tool (str): Capture tool to use ("tcpdump" or "tshark").
            tool_path (Optional[str]): Full path to capture tool. Auto-detected if None.
            config_data (Optional[Dict]): Configuration settings for capture operations.
        """
        self.interface = capture_interface
        self.capture_tool = capture_tool.lower()
        self.config = config_data if config_data else {}
        
        # Determine tool path
        if tool_path:
            self.tool_path = tool_path
        else:
            self.tool_path = self._find_capture_tool()
            
        self.capture_process: Optional[subprocess.Popen] = None
        self.output_pcap_file: Optional[Path] = None
        self.capture_start_time: Optional[datetime] = None
        self.capture_stats: Dict[str, Any] = {}
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_monitoring = False
        
        # Configuration settings
        self.default_snaplen = self.config.get("network_default_snaplen", 65535)
        self.default_buffer_size = self.config.get("network_default_buffer_size", "8M")
        self.capture_timeout = self.config.get("network_capture_timeout", 3600)
        self.stats_interval = self.config.get("network_stats_interval", 30)
        
        logger.info(f"NetworkCapture initialized. Interface: '{self.interface}', Tool: '{self.capture_tool}' at '{self.tool_path}'")

    def _find_capture_tool(self) -> str:
        """Find the capture tool executable."""
        import shutil
        
        tool_path = shutil.which(self.capture_tool)
        if tool_path:
            logger.debug(f"Found {self.capture_tool} at: {tool_path}")
            return tool_path
        
        # Try common installation paths
        common_paths = {
            "tcpdump": ["/usr/sbin/tcpdump", "/usr/bin/tcpdump", "/sbin/tcpdump"],
            "tshark": ["/usr/bin/tshark", "/usr/local/bin/tshark", "C:\\Program Files\\Wireshark\\tshark.exe"]
        }
        
        for path in common_paths.get(self.capture_tool, []):
            if os.path.exists(path) and os.access(path, os.X_OK):
                logger.debug(f"Found {self.capture_tool} at: {path}")
                return path
                
        logger.error(f"Could not find {self.capture_tool} executable")
        return self.capture_tool  # Fallback to command name

    def _check_tool_exists(self) -> bool:
        """Check if the capture tool is available and executable."""
        try:
            if self.capture_tool == "tcpdump":
                result = subprocess.run([self.tool_path, "--version"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or "tcpdump version" in result.stderr.lower():
                    return True
            elif self.capture_tool == "tshark":
                result = subprocess.run([self.tool_path, "--version"], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and "tshark" in result.stdout.lower():
                    return True
                    
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            logger.error(f"Error checking {self.capture_tool}: {e}")
            
        return False

    def _check_interface_exists(self) -> bool:
        """Check if the specified network interface exists."""
        try:
            if os.name == 'posix':  # Linux/Unix
                result = subprocess.run(['ip', 'link', 'show', self.interface], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return True
                    
                # Try with ifconfig as fallback
                result = subprocess.run(['ifconfig', self.interface], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
                
        except Exception as e:
            logger.warning(f"Could not verify interface existence: {e}")
            
        return True  # Assume interface exists if we can't verify

    def _build_tcpdump_command(self, output_file: Path, bpf_filter: Optional[str], 
                              snaplen: int, immediate_mode: bool, buffer_size: Optional[str],
                              additional_options: Optional[List[str]]) -> List[str]:
        """Build tcpdump command line arguments."""
        command = [self.tool_path, "-i", self.interface, "-w", str(output_file)]
        
        if snaplen > 0:
            command.extend(["-s", str(snaplen)])
        else:
            command.extend(["-s", "0"])
            
        if immediate_mode:
            command.append("-U")
            
        if buffer_size:
            command.extend(["-B", buffer_size])
            
        # Add timestamp precision
        command.append("-tttt")
        
        # Disable name resolution for performance
        command.extend(["-n", "-nn"])
        
        if additional_options:
            command.extend(additional_options)
            
        if bpf_filter:
            command.append(bpf_filter)
            
        return command

    def _build_tshark_command(self, output_file: Path, bpf_filter: Optional[str],
                             snaplen: int, additional_options: Optional[List[str]]) -> List[str]:
        """Build tshark command line arguments."""
        command = [self.tool_path, "-i", self.interface, "-w", str(output_file)]
        
        if snaplen > 0:
            command.extend(["-s", str(snaplen)])
            
        # Disable name resolution
        command.extend(["-n", "-N", "n"])
        
        # Set timestamp format
        command.extend(["-t", "ad"])
        
        if additional_options:
            command.extend(additional_options)
            
        if bpf_filter:
            command.extend(["-f", bpf_filter])
            
        return command

    def validate_bpf_filter(self, bpf_filter: str) -> bool:
        """Validate BPF filter syntax."""
        try:
            if self.capture_tool == "tcpdump":
                result = subprocess.run([self.tool_path, "-d", bpf_filter], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            elif self.capture_tool == "tshark":
                result = subprocess.run([self.tool_path, "-Y", bpf_filter, "-c", "0"], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
        except Exception as e:
            logger.error(f"Error validating BPF filter: {e}")
            
        return False

    def start_capture(self,
                      output_file: Union[str, Path],
                      bpf_filter: Optional[str] = None,
                      snaplen: Optional[int] = None,
                      immediate_mode: bool = True,
                      buffer_size: Optional[str] = None,
                      max_packets: Optional[int] = None,
                      max_duration: Optional[int] = None,
                      additional_options: Optional[List[str]] = None,
                      monitor_stats: bool = True) -> bool:
        """
        Start network packet capture.

        Args:
            output_file: Path to save captured packets (PCAP file).
            bpf_filter: Berkeley Packet Filter expression.
            snaplen: Snapshot length (bytes per packet).
            immediate_mode: Write packets immediately (tcpdump -U option).
            buffer_size: Capture buffer size (e.g., "8M").
            max_packets: Maximum number of packets to capture.
            max_duration: Maximum capture duration in seconds.
            additional_options: Additional command line options.
            monitor_stats: Whether to monitor capture statistics.

        Returns:
            bool: True if capture started successfully.
        """
        if not self._check_tool_exists():
            logger.error(f"Capture tool {self.capture_tool} not available")
            return False
            
        if self.is_capturing():
            logger.warning(f"Capture already in progress to {self.output_pcap_file}")
            return False
            
        if not self._check_interface_exists():
            logger.warning(f"Interface {self.interface} may not exist")

        self.output_pcap_file = Path(output_file)
        self.output_pcap_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Set defaults if not specified
        if snaplen is None:
            snaplen = self.default_snaplen
        if buffer_size is None:
            buffer_size = self.default_buffer_size

        # Validate BPF filter
        if bpf_filter and not self.validate_bpf_filter(bpf_filter):
            logger.error(f"Invalid BPF filter: {bpf_filter}")
            return False

        # Build command based on capture tool
        if self.capture_tool == "tcpdump":
            command = self._build_tcpdump_command(
                self.output_pcap_file, bpf_filter, snaplen, 
                immediate_mode, buffer_size, additional_options
            )
        elif self.capture_tool == "tshark":
            command = self._build_tshark_command(
                self.output_pcap_file, bpf_filter, snaplen, additional_options
            )
        else:
            logger.error(f"Unsupported capture tool: {self.capture_tool}")
            return False

        # Add packet/duration limits
        if max_packets:
            if self.capture_tool == "tcpdump":
                command.extend(["-c", str(max_packets)])
            elif self.capture_tool == "tshark":
                command.extend(["-c", str(max_packets)])
                
        if max_duration:
            if self.capture_tool == "tshark":
                command.extend(["-a", f"duration:{max_duration}"])

        logger.info(f"Starting {self.capture_tool} capture: {' '.join(command)}")
        
        try:
            self.capture_process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if os.name == 'posix' else None
            )
            
            self.capture_start_time = datetime.now()
            
            # Start monitoring thread
            if monitor_stats:
                self.stop_monitoring = False
                self.monitoring_thread = threading.Thread(target=self._monitor_capture)
                self.monitoring_thread.start()
            
            logger.info(f"Capture started with PID {self.capture_process.pid}. Output: {self.output_pcap_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start capture process: {e}")
            self.capture_process = None
            self.output_pcap_file = None
            return False

    def stop_capture(self, timeout: int = 10) -> bool:
        """
        Stop the currently running packet capture process.

        Args:
            timeout: Seconds to wait for graceful termination.

        Returns:
            bool: True if capture was stopped successfully.
        """
        if not self.is_capturing():
            logger.info("Network capture is not currently running")
            return True

        logger.info(f"Stopping capture process (PID: {self.capture_process.pid})")
        
        # Stop monitoring
        if self.monitoring_thread:
            self.stop_monitoring = True
            self.monitoring_thread.join(timeout=5)
            
        try:
            # Send SIGTERM to process group
            if os.name == 'posix':
                os.killpg(os.getpgid(self.capture_process.pid), signal.SIGTERM)
            else:
                self.capture_process.terminate()
                
            try:
                stdout, stderr = self.capture_process.communicate(timeout=timeout)
                logger.info("Capture process terminated gracefully")
                
                # Log capture statistics from stderr (tcpdump outputs stats there)
                if stderr:
                    stderr_text = stderr.decode(errors='ignore')
                    logger.debug(f"Capture stderr: {stderr_text}")
                    self._parse_capture_output(stderr_text)
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"Process did not terminate within {timeout}s, forcing kill")
                if os.name == 'posix':
                    os.killpg(os.getpgid(self.capture_process.pid), signal.SIGKILL)
                else:
                    self.capture_process.kill()
                self.capture_process.wait(timeout=5)
                logger.info("Capture process killed")
                
        except Exception as e:
            logger.error(f"Error stopping capture process: {e}")
            return False
        finally:
            self.capture_process = None
            
        # Get final statistics
        self._update_final_stats()
        
        logger.info(f"Network capture stopped. Data saved to {self.output_pcap_file}")
        return True

    def _monitor_capture(self):
        """Monitor capture process and update statistics."""
        while not self.stop_monitoring and self.is_capturing():
            try:
                # Update basic stats
                if self.output_pcap_file and self.output_pcap_file.exists():
                    file_size = self.output_pcap_file.stat().st_size
                    self.capture_stats.update({
                        "file_size_bytes": file_size,
                        "capture_duration_seconds": (datetime.now() - self.capture_start_time).total_seconds() if self.capture_start_time else 0,
                        "last_update": datetime.now().isoformat()
                    })
                    
                time.sleep(self.stats_interval)
                
            except Exception as e:
                logger.debug(f"Error in capture monitoring: {e}")
                break

    def _parse_capture_output(self, output: str):
        """Parse capture tool output for statistics."""
        try:
            if self.capture_tool == "tcpdump":
                # Parse tcpdump statistics from stderr
                # Example: "1234 packets captured\n5678 packets received by filter\n0 packets dropped by kernel"
                lines = output.strip().split('\n')
                for line in lines:
                    if "packets captured" in line:
                        count = int(line.split()[0])
                        self.capture_stats["packets_captured"] = count
                    elif "packets received by filter" in line:
                        count = int(line.split()[0])
                        self.capture_stats["packets_received"] = count
                    elif "packets dropped" in line:
                        count = int(line.split()[0])
                        self.capture_stats["packets_dropped"] = count
                        
        except Exception as e:
            logger.debug(f"Error parsing capture output: {e}")

    def _update_final_stats(self):
        """Update final capture statistics."""
        if self.output_pcap_file and self.output_pcap_file.exists():
            try:
                file_size = self.output_pcap_file.stat().st_size
                duration = (datetime.now() - self.capture_start_time).total_seconds() if self.capture_start_time else 0
                
                self.capture_stats.update({
                    "final_file_size_bytes": file_size,
                    "total_capture_duration_seconds": duration,
                    "capture_completed": True,
                    "completion_time": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.debug(f"Error updating final stats: {e}")

    def is_capturing(self) -> bool:
        """Check if a packet capture process is currently active."""
        return self.capture_process is not None and self.capture_process.poll() is None

    def wait_for_completion(self, timeout: Optional[int] = None) -> bool:
        """
        Wait for capture to complete.

        Args:
            timeout: Maximum seconds to wait. None for no timeout.

        Returns:
            bool: True if capture completed, False if timeout.
        """
        if not self.is_capturing():
            return True
            
        try:
            if timeout:
                self.capture_process.wait(timeout=timeout)
            else:
                self.capture_process.wait()
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"Capture did not complete within {timeout} seconds")
            return False

    def get_capture_stats(self, use_capinfos: bool = True) -> Dict[str, Any]:
        """
        Get comprehensive capture statistics.

        Args:
            use_capinfos: Whether to use capinfos for detailed statistics.

        Returns:
            Dict with capture statistics.
        """
        stats = self.capture_stats.copy()
        
        # Add basic file information
        if self.output_pcap_file and self.output_pcap_file.exists():
            file_stat = self.output_pcap_file.stat()
            stats.update({
                "output_file": str(self.output_pcap_file),
                "file_exists": True,
                "file_size_bytes": file_stat.st_size,
                "file_modified_time": datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            })
            
            # Get detailed stats with capinfos if available
            if use_capinfos:
                capinfos_stats = self._get_capinfos_stats()
                if capinfos_stats:
                    stats.update(capinfos_stats)
        else:
            stats.update({
                "output_file": str(self.output_pcap_file) if self.output_pcap_file else None,
                "file_exists": False,
                "file_size_bytes": 0
            })
            
        # Add capture configuration
        stats.update({
            "interface": self.interface,
            "capture_tool": self.capture_tool,
            "is_capturing": self.is_capturing(),
            "start_time": self.capture_start_time.isoformat() if self.capture_start_time else None
        })
        
        return stats

    def _get_capinfos_stats(self) -> Optional[Dict[str, Any]]:
        """Get detailed statistics using capinfos."""
        try:
            capinfos_path = self._find_capinfos()
            if not capinfos_path:
                return None
                
            result = subprocess.run(
                [capinfos_path, "-m", "-c", "-e", "-u", "-a", "-T", str(self.output_pcap_file)],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                logger.debug(f"capinfos failed: {result.stderr}")
                return None
                
            # Parse capinfos output
            stats = {}
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Convert numeric values
                    if key in ['Number of packets', 'File size', 'Data size']:
                        try:
                            stats[key.lower().replace(' ', '_')] = int(value.replace(',', ''))
                        except ValueError:
                            stats[key.lower().replace(' ', '_')] = value
                    elif key in ['Capture duration', 'Average packet rate', 'Average packet size']:
                        try:
                            stats[key.lower().replace(' ', '_')] = float(value.split()[0])
                        except (ValueError, IndexError):
                            stats[key.lower().replace(' ', '_')] = value
                    else:
                        stats[key.lower().replace(' ', '_')] = value
                        
            return stats
            
        except Exception as e:
            logger.debug(f"Error getting capinfos stats: {e}")
            return None

    def _find_capinfos(self) -> Optional[str]:
        """Find capinfos executable."""
        import shutil
        
        capinfos_path = shutil.which("capinfos")
        if capinfos_path:
            return capinfos_path
            
        # Try common paths
        common_paths = [
            "/usr/bin/capinfos",
            "/usr/local/bin/capinfos", 
            "C:\\Program Files\\Wireshark\\capinfos.exe"
        ]
        
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
                
        return None

    def create_filter_profile(self, profile_name: str, filters: Dict[str, Any]) -> str:
        """
        Create a reusable BPF filter profile.

        Args:
            profile_name: Name for the filter profile.
            filters: Dictionary with filter parameters.

        Returns:
            str: BPF filter string.
        """
        filter_parts = []
        
        # Host filters
        if 'hosts' in filters:
            host_filters = []
            for host in filters['hosts']:
                if filters.get('exclude_hosts', False):
                    host_filters.append(f"not host {host}")
                else:
                    host_filters.append(f"host {host}")
            if host_filters:
                filter_parts.append(f"({' or '.join(host_filters)})")
                
        # Port filters  
        if 'ports' in filters:
            port_filters = []
            for port in filters['ports']:
                if filters.get('exclude_ports', False):
                    port_filters.append(f"not port {port}")
                else:
                    port_filters.append(f"port {port}")
            if port_filters:
                filter_parts.append(f"({' or '.join(port_filters)})")
                
        # Protocol filters
        if 'protocols' in filters:
            proto_filters = []
            for proto in filters['protocols']:
                if filters.get('exclude_protocols', False):
                    proto_filters.append(f"not {proto}")
                else:
                    proto_filters.append(proto)
            if proto_filters:
                filter_parts.append(f"({' or '.join(proto_filters)})")
                
        # Network filters
        if 'networks' in filters:
            net_filters = []
            for network in filters['networks']:
                if filters.get('exclude_networks', False):
                    net_filters.append(f"not net {network}")
                else:
                    net_filters.append(f"net {network}")
            if net_filters:
                filter_parts.append(f"({' or '.join(net_filters)})")
        
        # Custom filter
        if 'custom' in filters:
            filter_parts.append(filters['custom'])
            
        # Combine with AND/OR logic
        logic = filters.get('logic', 'and').lower()
        if logic == 'or':
            bpf_filter = ' or '.join(filter_parts)
        else:
            bpf_filter = ' and '.join(filter_parts)
            
        logger.info(f"Created filter profile '{profile_name}': {bpf_filter}")
        return bpf_filter

    def get_interface_stats(self) -> Dict[str, Any]:
        """Get network interface statistics."""
        stats = {
            "interface": self.interface,
            "exists": False,
            "is_up": False,
            "stats": {}
        }
        
        try:
            if os.name == 'posix':
                # Get interface info using ip command
                result = subprocess.run(['ip', '-s', 'link', 'show', self.interface],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    stats["exists"] = True
                    output = result.stdout
                    
                    # Parse basic status
                    if "state UP" in output:
                        stats["is_up"] = True
                        
                    # Parse statistics
                    lines = output.split('\n')
                    for i, line in enumerate(lines):
                        if "RX:" in line and i + 1 < len(lines):
                            rx_line = lines[i + 1].strip().split()
                            if len(rx_line) >= 2:
                                stats["stats"]["rx_bytes"] = int(rx_line[0])
                                stats["stats"]["rx_packets"] = int(rx_line[1])
                        elif "TX:" in line and i + 1 < len(lines):
                            tx_line = lines[i + 1].strip().split()
                            if len(tx_line) >= 2:
                                stats["stats"]["tx_bytes"] = int(tx_line[0])
                                stats["stats"]["tx_packets"] = int(tx_line[1])
                                
        except Exception as e:
            logger.debug(f"Error getting interface stats: {e}")
            
        return stats

    def export_capture_info(self, output_file: Union[str, Path]) -> bool:
        """
        Export capture information and statistics to JSON.

        Args:
            output_file: Path to save capture information.

        Returns:
            bool: True if export successful.
        """
        try:
            capture_info = {
                "capture_session": {
                    "interface": self.interface,
                    "capture_tool": self.capture_tool,
                    "tool_path": self.tool_path,
                    "output_file": str(self.output_pcap_file) if self.output_pcap_file else None,
                    "start_time": self.capture_start_time.isoformat() if self.capture_start_time else None,
                    "is_capturing": self.is_capturing()
                },
                "statistics": self.get_capture_stats(),
                "interface_info": self.get_interface_stats(),
                "configuration": {
                    "default_snaplen": self.default_snaplen,
                    "default_buffer_size": self.default_buffer_size,
                    "capture_timeout": self.capture_timeout,
                    "stats_interval": self.stats_interval
                },
                "export_time": datetime.now().isoformat()
            }
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(capture_info, f, indent=2, default=str)
                
            logger.info(f"Capture information exported to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting capture info: {e}")
            return False


# Convenience function for quick capture operations
def quick_capture(interface: str,
                 output_file: Union[str, Path],
                 duration: int,
                 bpf_filter: Optional[str] = None,
                 capture_tool: str = "tcpdump") -> Dict[str, Any]:
    """
    Perform a quick network capture with minimal configuration.

    Args:
        interface: Network interface to capture from.
        output_file: Output PCAP file path.
        duration: Capture duration in seconds.
        bpf_filter: Optional BPF filter.
        capture_tool: Capture tool to use.

    Returns:
        Dict with capture results and statistics.
    """
    logger.info(f"Starting quick capture on {interface} for {duration}s")
    
    result = {
        "success": False,
        "interface": interface,
        "output_file": str(output_file),
        "duration_requested": duration,
        "capture_tool": capture_tool,
        "statistics": {},
        "errors": [],
        "timing": {
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "actual_duration": None
        }
    }
    
    start_time = time.time()
    
    try:
        capture = NetworkCapture(interface, capture_tool)
        
        if not capture.start_capture(
            output_file=output_file,
            bpf_filter=bpf_filter,
            max_duration=duration,
            immediate_mode=True
        ):
            result["errors"].append("Failed to start capture")
            return result
            
        # Wait for completion or timeout
        if capture.wait_for_completion(timeout=duration + 30):
            logger.info("Capture completed successfully")
        else:
            logger.warning("Capture timeout, stopping...")
            capture.stop_capture()
            
        # Get final statistics
        result["statistics"] = capture.get_capture_stats()
        result["success"] = True
        
    except Exception as e:
        error_msg = f"Exception during quick capture: {e}"
        logger.error(error_msg)
        result["errors"].append(error_msg)
        
    finally:
        end_time = time.time()
        result["timing"]["end_time"] = datetime.now().isoformat()
        result["timing"]["actual_duration"] = end_time - start_time
        
    return result


# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def test_network_capture():
        """Test network capture functionality."""
        print("\n" + "="*80)
        print("TESTING NETWORK CAPTURE")
        print("="*80)
        
        test_interface = "lo"  # Loopback interface
        test_output = Path("./test_capture.pcap")
        
        # Test configuration
        config = {
            "network_default_snaplen": 1500,
            "network_default_buffer_size": "4M",
            "network_capture_timeout": 60,
            "network_stats_interval": 5
        }
        
        print(f"1. Initializing NetworkCapture for interface: {test_interface}")
        capture = NetworkCapture(test_interface, config_data=config)
        
        print(f"   ✓ NetworkCapture initialized with {capture.capture_tool}")
        print(f"   Tool path: {capture.tool_path}")
        print(f"   Interface stats: {capture.get_interface_stats()}")
        
        # Test BPF filter validation
        print(f"\n2. Testing BPF filter validation...")
        valid_filter = "icmp or arp"
        invalid_filter = "invalid_protocol_xyz"
        
        if capture.validate_bpf_filter(valid_filter):
            print(f"   ✓ Valid filter accepted: {valid_filter}")
        else:
            print(f"   ✗ Valid filter rejected: {valid_filter}")
            
        if not capture.validate_bpf_filter(invalid_filter):
            print(f"   ✓ Invalid filter rejected: {invalid_filter}")
        else:
            print(f"   ✗ Invalid filter accepted: {invalid_filter}")
        
        # Test filter profile creation
        print(f"\n3. Testing filter profile creation...")
        filter_config = {
            "hosts": ["127.0.0.1", "localhost"],
            "protocols": ["icmp", "arp"],
            "ports": [22, 80, 443],
            "logic": "or"
        }
        
        bpf_filter = capture.create_filter_profile("test_profile", filter_config)
        print(f"   Created filter: {bpf_filter}")
        
        # Test capture start
        print(f"\n4. Starting capture...")
        print(f"   Output file: {test_output}")
        print(f"   Filter: {bpf_filter}")
        print(f"   Duration: 10 seconds")
        
        if capture.start_capture(
            output_file=test_output,
            bpf_filter=bpf_filter,
            snaplen=1500,
            max_duration=10,
            monitor_stats=True
        ):
            print(f"   ✓ Capture started (PID: {capture.capture_process.pid})")
            
            # Show initial stats
            initial_stats = capture.get_capture_stats(use_capinfos=False)
            print(f"   Initial stats: {initial_stats}")
            
            print(f"\n5. Generating test traffic...")
            print(f"   Run 'ping 127.0.0.1' in another terminal to generate traffic")
            
            # Wait a bit then check stats
            time.sleep(5)
            
            mid_stats = capture.get_capture_stats(use_capinfos=False)
            print(f"   Mid-capture stats: {mid_stats}")
            
            # Wait for completion
            print(f"\n6. Waiting for capture completion...")
            if capture.wait_for_completion(timeout=15):
                print(f"   ✓ Capture completed successfully")
            else:
                print(f"   ⚠ Capture timeout, stopping manually...")
                capture.stop_capture()
            
            # Get final stats
            final_stats = capture.get_capture_stats(use_capinfos=True)
            print(f"\n7. Final capture statistics:")
            for key, value in final_stats.items():
                print(f"   {key}: {value}")
                
            # Export capture info
            info_file = test_output.with_suffix('.json')
            if capture.export_capture_info(info_file):
                print(f"   ✓ Capture info exported to: {info_file}")
                
            # Verify output file
            if test_output.exists():
                file_size = test_output.stat().st_size
                print(f"   ✓ Output file created: {test_output} ({file_size} bytes)")
                
                # Clean up test files
                test_output.unlink()
                if info_file.exists():
                    info_file.unlink()
                print(f"   ✓ Test files cleaned up")
            else:
                print(f"   ✗ Output file not created")
                
        else:
            print(f"   ✗ Failed to start capture")

    def test_quick_capture():
        """Test quick capture functionality."""
        print("\n" + "="*80)
        print("TESTING QUICK CAPTURE")
        print("="*80)
        
        test_interface = "lo"
        test_output = Path("./quick_test.pcap")
        duration = 5
        
        print(f"Running quick capture on {test_interface} for {duration} seconds...")
        
        result = quick_capture(
            interface=test_interface,
            output_file=test_output,
            duration=duration,
            bpf_filter="icmp or arp",
            capture_tool="tcpdump"
        )
        
        print(f"\nQuick capture result:")
        print(f"  Success: {result['success']}")
        print(f"  Duration requested: {result['duration_requested']}s")
        print(f"  Actual duration: {result['timing']['actual_duration']:.2f}s")
        print(f"  Errors: {result['errors']}")
        
        if result['statistics']:
            print(f"  Statistics:")
            for key, value in result['statistics'].items():
                if isinstance(value, (int, float, str, bool)):
                    print(f"    {key}: {value}")
        
        # Clean up
        if test_output.exists():
            test_output.unlink()
            print(f"  ✓ Test file cleaned up")

    def test_multiple_tools():
        """Test different capture tools."""
        print("\n" + "="*80)
        print("TESTING MULTIPLE CAPTURE TOOLS")
        print("="*80)
        
        tools = ["tcpdump", "tshark"]
        test_interface = "lo"
        
        for tool in tools:
            print(f"\nTesting {tool}...")
            
            try:
                capture = NetworkCapture(test_interface, capture_tool=tool)
                
                if capture._check_tool_exists():
                    print(f"  ✓ {tool} available at: {capture.tool_path}")
                    
                    # Test filter validation
                    test_filter = "icmp"
                    if capture.validate_bpf_filter(test_filter):
                        print(f"  ✓ Filter validation works with {tool}")
                    else:
                        print(f"  ⚠ Filter validation failed with {tool}")
                        
                else:
                    print(f"  ✗ {tool} not available")
                    
            except Exception as e:
                print(f"  ✗ Error testing {tool}: {e}")

    def test_integration_scenario():
        """Test integration with malware analysis scenario."""
        print("\n" + "="*80)
        print("TESTING MALWARE ANALYSIS INTEGRATION")
        print("="*80)
        
        # Simulate malware analysis network capture
        print("Simulating network capture for malware analysis...")
        
        # Configuration for malware analysis
        malware_config = {
            "network_default_snaplen": 65535,  # Full packets
            "network_default_buffer_size": "16M",  # Large buffer
            "network_capture_timeout": 300,  # 5 minute timeout
            "network_stats_interval": 10  # Update every 10 seconds
        }
        
        # Create filters for suspicious traffic
        suspicious_filter_config = {
            "protocols": ["tcp", "udp", "icmp"],
            "exclude_hosts": ["127.0.0.1"],  # Exclude localhost
            "exclude_ports": [22, 53],  # Exclude SSH and DNS
            "custom": "not broadcast and not multicast",
            "logic": "and"
        }
        
        test_interface = "lo"
        output_file = Path("./malware_traffic.pcap")
        
        try:
            capture = NetworkCapture(test_interface, config_data=malware_config)
            
            # Create suspicious traffic filter
            suspicious_filter = capture.create_filter_profile(
                "malware_analysis", 
                suspicious_filter_config
            )
            
            print(f"Created filter for malware analysis: {suspicious_filter}")
            
            # This would normally run during malware execution
            print("In a real scenario, this would:")
            print("  1. Start capture before malware execution")
            print("  2. Run malware in isolated environment")
            print("  3. Stop capture after analysis period")
            print("  4. Export PCAP for network analysis module")
            
            # Simulate the workflow
            print(f"\nSimulated workflow:")
            print(f"  ✓ Filter created for suspicious traffic")
            print(f"  ✓ Capture would save to: {output_file}")
            print(f"  ✓ Statistics would be monitored every {malware_config['network_stats_interval']}s")
            print(f"  ✓ Capture would timeout after {malware_config['network_capture_timeout']}s")
            
            # Show how this integrates with other modules
            print(f"\nIntegration points:")
            print(f"  → PCAP file feeds into NetworkAnalyzer for C2 detection")
            print(f"  → Capture timing coordinates with Procmon/Noriben")
            print(f"  → Statistics help validate analysis completeness")
            
        except Exception as e:
            print(f"Error in integration test: {e}")

    # Command line interface
    parser = argparse.ArgumentParser(description="Test network capture functionality")
    parser.add_argument("--test-capture", action="store_true", help="Test basic capture functionality")
    parser.add_argument("--test-quick", action="store_true", help="Test quick capture")
    parser.add_argument("--test-tools", action="store_true", help="Test multiple capture tools")
    parser.add_argument("--test-integration", action="store_true", help="Test malware analysis integration")
    parser.add_argument("--test-all", action="store_true", help="Run all tests")
    parser.add_argument("--interface", default="lo", help="Network interface to use for testing")
    
    args = parser.parse_args()
    
    # Override default interface if specified
    if args.interface != "lo":
        # Update interface in test functions
        pass
    
    if args.test_all or len([arg for arg in vars(args).values() if arg]) == 0:
        test_network_capture()
        test_quick_capture()
        test_multiple_tools()
        test_integration_scenario()
    else:
        if args.test_capture:
            test_network_capture()
        if args.test_quick:
            test_quick_capture()
        if args.test_tools:
            test_multiple_tools()
        if args.test_integration:
            test_integration_scenario()
    
    print("\n" + "="*80)
    print("NETWORK CAPTURE TESTING COMPLETE")
    print("="*80)
    
    print("\nNote: Some tests may require:")
    print("  - Root/administrator privileges for packet capture")
    print("  - tcpdump and/or tshark to be installed")
    print("  - Active network interface for realistic testing")
    print("  - Traffic generation (ping, wget, etc.) for meaningful captures")