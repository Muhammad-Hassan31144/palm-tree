# shikra/modules/monitoring/procmon_processor.py
# Purpose: Advanced ProcMon CSV log processor with intelligent noise filtering
#          and behavioral pattern extraction for malware analysis.
#
# This is a complete replacement for Noriben's PMC functionality, designed
# specifically for the Shikra framework with superior filtering, analysis,
# and integration capabilities.

import csv
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
import hashlib

logger = logging.getLogger(__name__)

class ProcMonProcessor:
    """
    Advanced ProcMon log processor with intelligent noise filtering.
    
    Features:
    - Smart noise filtering (system processes, benign activities)
    - Behavioral pattern detection (persistence, evasion, encryption)
    - Timeline analysis with process correlation
    - Configurable filtering rules
    - High-performance processing of large logs
    - JSON output compatible with Shikra analysis pipeline
    """
    
    def __init__(self, config_settings: dict = None):
        """
        Initialize the ProcMon processor.
        
        Args:
            config_settings: Configuration dictionary for filtering rules
        """
        self.config = config_settings or {}
        self.results = {
            "metadata": {
                "processor_version": "1.0.0",
                "processing_start_time": None,
                "processing_end_time": None,
                "source_file": None,
                "total_events": 0,
                "filtered_events": 0,
                "noise_events_removed": 0
            },
            "process_activity": {
                "process_tree": {},
                "suspicious_processes": [],
                "process_statistics": {},
                "cmdline_analysis": []
            },
            "file_operations": {
                "files_created": [],
                "files_modified": [],
                "files_deleted": [],
                "suspicious_file_ops": [],
                "extension_analysis": {},
                "directory_analysis": {}
            },
            "registry_operations": {
                "keys_created": [],
                "keys_modified": [],
                "keys_deleted": [],
                "suspicious_registry_ops": [],
                "persistence_indicators": []
            },
            "network_operations": {
                "connections": [],
                "dns_queries": [],
                "suspicious_network_ops": []
            },
            "behavioral_indicators": {
                "encryption_indicators": [],
                "evasion_techniques": [],
                "privilege_escalation": [],
                "anti_analysis": [],
                "data_exfiltration": []
            },
            "timeline": [],
            "noise_filters_applied": [],
            "processing_errors": []
        }
        
        self._init_filter_rules()
        self._init_behavioral_patterns()
        
    def _init_filter_rules(self):
        """Initialize noise filtering rules."""
        
        # System processes that generate massive noise
        self.system_processes = self.config.get("system_processes_filter", {
            "always_filter": [
                "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe",
                "dwm.exe", "wincompositor.exe", "applicationframehost.exe",
                "runtimebroker.exe", "taskhostw.exe", "sihost.exe",
                "ctfmon.exe", "explorer.exe", "searchindexer.exe",
                "wmiprvse.exe", "dllhost.exe", "conhost.exe", "svchost.exe"
            ],
            "conditionally_filter": [
                # These are filtered unless they show suspicious behavior
                "msiexec.exe", "regsvr32.exe", "rundll32.exe", "cmd.exe",
                "powershell.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe"
            ]
        })
        
        # File paths that generate noise
        self.noise_file_paths = self.config.get("noise_file_paths", [
            r"C:\\Windows\\System32\\",
            r"C:\\Windows\\SysWOW64\\",
            r"C:\\Windows\\WinSxS\\",
            r"C:\\Windows\\Logs\\",
            r"C:\\Windows\\Temp\\",
            r"C:\\Windows\\Prefetch\\",
            r"C:\\Windows\\ServiceProfiles\\",
            r"C:\\ProgramData\\Microsoft\\",
            r"\\AppData\\Local\\Microsoft\\",
            r"\\AppData\\Local\\Temp\\",
            r"\\AppData\\Roaming\\Microsoft\\",
            r"\.tmp$", r"\.log$", r"\.etl$", r"\.pf$"
        ])
        
        # Registry keys that generate noise
        self.noise_registry_paths = self.config.get("noise_registry_paths", [
            r"HKLM\\SYSTEM\\CurrentControlSet\\Services\\",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\",
            r"HKLM\\SOFTWARE\\Classes\\",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\",
            r"HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\",
            r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\",
            r"\\SessionInformation\\",
            r"\\MuiCache\\",
            r"\\UsrClass\\.dat"
        ])
        
    def _init_behavioral_patterns(self):
        """Initialize behavioral pattern detection rules."""
        
        # Suspicious file extensions
        self.suspicious_extensions = {
            "executables": [".exe", ".com", ".scr", ".bat", ".cmd", ".pif", ".msi"],
            "scripts": [".ps1", ".vbs", ".js", ".jar", ".py", ".pl", ".rb"],
            "documents": [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf"],
            "archives": [".zip", ".rar", ".7z", ".tar", ".gz"],
            "ransomware": [".locked", ".encrypted", ".crypted", ".crypt", ".enc"]
        }
        
        # Persistence registry keys
        self.persistence_registry_keys = [
            r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"HKLM\\System\\CurrentControlSet\\Services\\",
            r"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\",
            r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
        ]
        
        # Suspicious command patterns
        self.suspicious_command_patterns = [
            r"vssadmin.*delete.*shadows",
            r"wbadmin.*delete.*catalog",
            r"bcdedit.*set.*bootstatuspolicy.*ignoreallfailures",
            r"wmic.*shadowcopy.*delete",
            r"net\s+stop\s+",
            r"taskkill.*\/f",
            r"reg.*delete",
            r"schtasks.*\/create",
            r"powershell.*-enc.*",
            r"powershell.*-hidden",
            r"attrib.*\+h.*\+s",
            r"icacls.*\/grant"
        ]
        
    def process_procmon_csv(self, csv_file_path: str) -> Dict[str, Any]:
        """
        Process a ProcMon CSV file and extract behavioral patterns.
        
        Args:
            csv_file_path: Path to the ProcMon CSV file
            
        Returns:
            Dictionary containing processed results
        """
        start_time = time.time()
        self.results["metadata"]["processing_start_time"] = datetime.now().isoformat()
        self.results["metadata"]["source_file"] = csv_file_path
        
        logger.info(f"Processing ProcMon CSV: {csv_file_path}")
        
        if not os.path.exists(csv_file_path):
            error_msg = f"ProcMon CSV file not found: {csv_file_path}"
            logger.error(error_msg)
            self.results["processing_errors"].append(error_msg)
            return self.results
            
        try:
            self._process_csv_file(csv_file_path)
            self._analyze_behavioral_patterns()
            self._build_timeline()
            self._generate_statistics()
            
        except Exception as e:
            error_msg = f"Error processing ProcMon CSV: {str(e)}"
            logger.exception(error_msg)
            self.results["processing_errors"].append(error_msg)
            
        finally:
            end_time = time.time()
            self.results["metadata"]["processing_end_time"] = datetime.now().isoformat()
            self.results["metadata"]["processing_duration_seconds"] = round(end_time - start_time, 2)
            
        logger.info(f"Processing completed in {self.results['metadata']['processing_duration_seconds']}s")
        return self.results
    
    def _process_csv_file(self, csv_file_path: str):
        """Process the CSV file and extract relevant events."""
        
        total_events = 0
        filtered_events = 0
        noise_events = 0
        
        # Expected ProcMon CSV columns
        expected_columns = [
            "Time of Day", "Process Name", "PID", "Operation", "Path", 
            "Result", "Detail", "Command Line"
        ]
        
        try:
            with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as csvfile:
                # Detect delimiter
                sample = csvfile.read(1024)
                csvfile.seek(0)
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff(sample).delimiter
                
                reader = csv.DictReader(csvfile, delimiter=delimiter)
                
                # Validate columns
                if not all(col in reader.fieldnames for col in expected_columns[:4]):
                    logger.warning(f"CSV may not be standard ProcMon format. Available columns: {reader.fieldnames}")
                
                for row in reader:
                    total_events += 1
                    
                    # Progress logging for large files
                    if total_events % 100000 == 0:
                        logger.info(f"Processed {total_events} events...")
                    
                    # Apply noise filtering
                    if self._is_noise_event(row):
                        noise_events += 1
                        continue
                        
                    # Process the event
                    if self._process_event(row):
                        filtered_events += 1
                        
        except Exception as e:
            logger.error(f"Error reading CSV file: {e}")
            raise
            
        self.results["metadata"]["total_events"] = total_events
        self.results["metadata"]["filtered_events"] = filtered_events
        self.results["metadata"]["noise_events_removed"] = noise_events
        
        logger.info(f"Events processed: {total_events}, Kept: {filtered_events}, Noise filtered: {noise_events}")
    
    def _is_noise_event(self, event: Dict[str, str]) -> bool:
        """
        Determine if an event should be filtered as noise.
        
        Args:
            event: CSV row as dictionary
            
        Returns:
            True if event should be filtered out
        """
        process_name = event.get("Process Name", "").lower()
        operation = event.get("Operation", "")
        path = event.get("Path", "")
        result = event.get("Result", "")
        
        # Filter system processes (unless suspicious)
        if process_name in self.system_processes["always_filter"]:
            return True
            
        # Filter failed operations (most are noise)
        if result and result != "SUCCESS":
            # Keep some interesting failures
            interesting_failures = ["ACCESS DENIED", "SHARING VIOLATION", "NAME NOT FOUND"]
            if not any(fail in result.upper() for fail in interesting_failures):
                return True
        
        # Filter noisy file paths
        if operation in ["CreateFile", "QueryInformation", "ReadFile", "WriteFile", "CloseFile"]:
            for noise_path in self.noise_file_paths:
                if re.search(noise_path, path, re.IGNORECASE):
                    return True
                    
        # Filter noisy registry operations
        if operation in ["RegOpenKey", "RegQueryKey", "RegQueryValue", "RegCloseKey"]:
            for noise_path in self.noise_registry_paths:
                if re.search(noise_path, path, re.IGNORECASE):
                    return True
        
        # Filter repetitive operations (same process, same path, within short time)
        # This would require maintaining a recent events cache - implement if needed
        
        return False
    
    def _process_event(self, event: Dict[str, str]) -> bool:
        """
        Process a single ProcMon event.
        
        Args:
            event: CSV row as dictionary
            
        Returns:
            True if event was processed successfully
        """
        try:
            operation = event.get("Operation", "")
            
            # Route to appropriate handler
            if operation in ["Process and Thread Activity", "ProcessStart", "ProcessStop"]:
                self._process_process_event(event)
            elif operation.startswith("CreateFile") or operation in ["ReadFile", "WriteFile", "DeletePath", "SetInformation"]:
                self._process_file_event(event)
            elif operation.startswith("Reg"):
                self._process_registry_event(event)
            elif operation in ["TCP Connect", "TCP Disconnect", "UDP Send", "UDP Receive"]:
                self._process_network_event(event)
            else:
                # Store other interesting operations
                self._process_other_event(event)
                
            return True
            
        except Exception as e:
            logger.debug(f"Error processing event: {e}")
            return False
    
    def _process_process_event(self, event: Dict[str, str]):
        """Process process-related events."""
        
        process_name = event.get("Process Name", "")
        pid = event.get("PID", "")
        command_line = event.get("Command Line", "")
        operation = event.get("Operation", "")
        timestamp = event.get("Time of Day", "")
        
        # Build process tree
        if pid and process_name:
            if pid not in self.results["process_activity"]["process_tree"]:
                self.results["process_activity"]["process_tree"][pid] = {
                    "name": process_name,
                    "command_line": command_line,
                    "first_seen": timestamp,
                    "operations": []
                }
            
            # Analyze command line for suspicious patterns
            if command_line and any(re.search(pattern, command_line, re.IGNORECASE) 
                                  for pattern in self.suspicious_command_patterns):
                self.results["process_activity"]["cmdline_analysis"].append({
                    "timestamp": timestamp,
                    "process": process_name,
                    "pid": pid,
                    "command_line": command_line,
                    "suspicion_reason": "Matches suspicious pattern"
                })
                
        # Check for suspicious processes
        if self._is_suspicious_process(process_name, command_line):
            self.results["process_activity"]["suspicious_processes"].append({
                "timestamp": timestamp,
                "process": process_name,
                "pid": pid,
                "command_line": command_line,
                "operation": operation
            })
    
    def _process_file_event(self, event: Dict[str, str]):
        """Process file system events."""
        
        operation = event.get("Operation", "")
        path = event.get("Path", "")
        process_name = event.get("Process Name", "")
        pid = event.get("PID", "")
        timestamp = event.get("Time of Day", "")
        result = event.get("Result", "")
        detail = event.get("Detail", "")
        
        file_event = {
            "timestamp": timestamp,
            "process": process_name,
            "pid": pid,
            "path": path,
            "operation": operation,
            "result": result,
            "detail": detail
        }
        
        # Categorize file operations
        if "CreateFile" in operation and "SUCCESS" in result:
            self.results["file_operations"]["files_created"].append(file_event)
        elif operation in ["WriteFile", "SetInformation"] and "SUCCESS" in result:
            self.results["file_operations"]["files_modified"].append(file_event)
        elif "Delete" in operation and "SUCCESS" in result:
            self.results["file_operations"]["files_deleted"].append(file_event)
            
        # Check for suspicious file operations
        if self._is_suspicious_file_operation(path, operation, process_name):
            self.results["file_operations"]["suspicious_file_ops"].append({
                **file_event,
                "suspicion_reason": self._get_file_suspicion_reason(path, operation, process_name)
            })
    
    def _process_registry_event(self, event: Dict[str, str]):
        """Process registry events."""
        
        operation = event.get("Operation", "")
        path = event.get("Path", "")
        process_name = event.get("Process Name", "")
        pid = event.get("PID", "")
        timestamp = event.get("Time of Day", "")
        result = event.get("Result", "")
        detail = event.get("Detail", "")
        
        registry_event = {
            "timestamp": timestamp,
            "process": process_name,
            "pid": pid,
            "path": path,
            "operation": operation,
            "result": result,
            "detail": detail
        }
        
        # Categorize registry operations
        if operation == "RegCreateKey" and "SUCCESS" in result:
            self.results["registry_operations"]["keys_created"].append(registry_event)
        elif operation == "RegSetValue" and "SUCCESS" in result:
            self.results["registry_operations"]["keys_modified"].append(registry_event)
        elif operation == "RegDeleteKey" and "SUCCESS" in result:
            self.results["registry_operations"]["keys_deleted"].append(registry_event)
            
        # Check for persistence mechanisms
        if any(re.search(persist_key, path, re.IGNORECASE) 
               for persist_key in self.persistence_registry_keys):
            self.results["registry_operations"]["persistence_indicators"].append({
                **registry_event,
                "persistence_type": "Registry Run Key"
            })
            
        # Check for other suspicious registry operations
        if self._is_suspicious_registry_operation(path, operation, process_name):
            self.results["registry_operations"]["suspicious_registry_ops"].append({
                **registry_event,
                "suspicion_reason": self._get_registry_suspicion_reason(path, operation, process_name)
            })
    
    def _process_network_event(self, event: Dict[str, str]):
        """Process network events."""
        
        operation = event.get("Operation", "")
        path = event.get("Path", "")  # Contains network destination
        process_name = event.get("Process Name", "")
        pid = event.get("PID", "")
        timestamp = event.get("Time of Day", "")
        
        network_event = {
            "timestamp": timestamp,
            "process": process_name,
            "pid": pid,
            "destination": path,
            "operation": operation
        }
        
        self.results["network_operations"]["connections"].append(network_event)
        
        # Check for suspicious network activity
        if self._is_suspicious_network_operation(path, process_name):
            self.results["network_operations"]["suspicious_network_ops"].append({
                **network_event,
                "suspicion_reason": "Suspicious network destination or process"
            })
    
    def _process_other_event(self, event: Dict[str, str]):
        """Process other interesting events."""
        
        operation = event.get("Operation", "")
        
        # Look for anti-analysis techniques
        if operation in ["QueryInformation"] and "debugger" in event.get("Path", "").lower():
            self.results["behavioral_indicators"]["anti_analysis"].append({
                "timestamp": event.get("Time of Day", ""),
                "process": event.get("Process Name", ""),
                "technique": "Debugger Detection",
                "details": event.get("Path", "")
            })
    
    def _is_suspicious_process(self, process_name: str, command_line: str) -> bool:
        """Check if a process is suspicious."""
        
        process_name = process_name.lower()
        
        # Suspicious process names
        suspicious_names = [
            "temp", "tmp", "~", "copy", "new", "update", "install", "setup",
            "svchost", "explorer", "system", "winlogon", "csrss"  # Impersonation attempts
        ]
        
        # Check for random/suspicious names
        if len(process_name) < 3 or len(process_name) > 30:
            return True
            
        if any(sus_name in process_name for sus_name in suspicious_names):
            return True
            
        # Check command line for suspicious patterns
        if command_line and any(re.search(pattern, command_line, re.IGNORECASE) 
                               for pattern in self.suspicious_command_patterns):
            return True
            
        return False
    
    def _is_suspicious_file_operation(self, path: str, operation: str, process_name: str) -> bool:
        """Check if a file operation is suspicious."""
        
        if not path:
            return False
            
        path_lower = path.lower()
        
        # Check for suspicious file extensions
        for category, extensions in self.suspicious_extensions.items():
            if any(path_lower.endswith(ext) for ext in extensions):
                if category == "ransomware":
                    return True
                elif category in ["executables", "scripts"] and "temp" in path_lower:
                    return True
                    
        # Check for files in suspicious locations
        suspicious_locations = [
            r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp\\",
            r"\\programdata\\", r"\\public\\", r"\\users\\public\\"
        ]
        
        if any(re.search(loc, path_lower) for loc in suspicious_locations):
            return True
            
        return False
    
    def _is_suspicious_registry_operation(self, path: str, operation: str, process_name: str) -> bool:
        """Check if a registry operation is suspicious."""
        
        if not path:
            return False
            
        # Already handled persistence keys separately
        # Look for other suspicious registry modifications
        suspicious_keys = [
            r"\\policies\\system\\",
            r"\\windows\\currentversion\\policies\\",
            r"\\software\\microsoft\\security center\\",
            r"\\system\\currentcontrolset\\control\\safeboot\\",
            r"\\software\\classes\\exefile\\shell\\open\\command",
            r"\\software\\microsoft\\windows nt\\currentversion\\image file execution options\\"
        ]
        
        return any(re.search(key, path, re.IGNORECASE) for key in suspicious_keys)
    
    def _is_suspicious_network_operation(self, destination: str, process_name: str) -> bool:
        """Check if a network operation is suspicious."""
        
        if not destination:
            return False
            
        # Check for suspicious domains/IPs
        suspicious_indicators = [
            r"\.onion", r"\.bit", r"pastebin\.com", r"paste\.ee",
            r"mega\.nz", r"anonfile\.com", r"transfer\.sh"
        ]
        
        return any(re.search(indicator, destination, re.IGNORECASE) 
                  for indicator in suspicious_indicators)
    
    def _get_file_suspicion_reason(self, path: str, operation: str, process_name: str) -> str:
        """Get reason why file operation is suspicious."""
        reasons = []
        
        if any(path.lower().endswith(ext) for ext in self.suspicious_extensions["ransomware"]):
            reasons.append("Ransomware file extension")
        if "temp" in path.lower() and any(path.lower().endswith(ext) for ext in self.suspicious_extensions["executables"]):
            reasons.append("Executable in temp directory")
        if re.search(r"\\(temp|tmp|appdata\\local\\temp)\\", path.lower()):
            reasons.append("Suspicious file location")
            
        return "; ".join(reasons) if reasons else "Suspicious file operation"
    
    def _get_registry_suspicion_reason(self, path: str, operation: str, process_name: str) -> str:
        """Get reason why registry operation is suspicious."""
        if re.search(r"\\policies\\", path, re.IGNORECASE):
            return "Security policy modification"
        elif re.search(r"\\security center\\", path, re.IGNORECASE):
            return "Security center tampering"
        elif re.search(r"\\safeboot\\", path, re.IGNORECASE):
            return "Safe boot configuration modification"
        else:
            return "Suspicious registry modification"
    
    def _analyze_behavioral_patterns(self):
        """Analyze processed events for behavioral patterns."""
        
        # Analyze file operations for encryption patterns
        self._analyze_encryption_patterns()
        
        # Analyze for evasion techniques
        self._analyze_evasion_techniques()
        
        # Analyze for privilege escalation
        self._analyze_privilege_escalation()
        
        # Analyze for data exfiltration
        self._analyze_data_exfiltration()
    
    def _analyze_encryption_patterns(self):
        """Look for file encryption patterns."""
        
        # Look for mass file modifications
        file_modifications = self.results["file_operations"]["files_modified"]
        
        # Group by process
        process_file_counts = defaultdict(int)
        for file_op in file_modifications:
            process_file_counts[file_op["process"]] += 1
            
        # Flag processes with high file modification counts
        for process, count in process_file_counts.items():
            if count > 50:  # Configurable threshold
                self.results["behavioral_indicators"]["encryption_indicators"].append({
                    "indicator_type": "Mass File Modification",
                    "process": process,
                    "file_count": count,
                    "confidence": "high" if count > 100 else "medium"
                })
    
    def _analyze_evasion_techniques(self):
        """Look for evasion techniques."""
        
        # Process hollowing indicators
        process_creates = [p for p in self.results["file_operations"]["files_created"] 
                          if p["path"].lower().endswith(".exe")]
        
        for proc_create in process_creates:
            if "temp" in proc_create["path"].lower():
                self.results["behavioral_indicators"]["evasion_techniques"].append({
                    "technique": "Suspicious Process Creation",
                    "process": proc_create["process"],
                    "path": proc_create["path"],
                    "timestamp": proc_create["timestamp"]
                })
    
    def _analyze_privilege_escalation(self):
        """Look for privilege escalation attempts."""
        
        # UAC bypass indicators
        uac_bypass_paths = [
            r"\\system32\\eventvwr\.exe",
            r"\\system32\\fodhelper\.exe",
            r"\\system32\\computerdefaults\.exe"
        ]
        
        for file_op in self.results["file_operations"]["files_created"]:
            if any(re.search(path, file_op["path"], re.IGNORECASE) for path in uac_bypass_paths):
                self.results["behavioral_indicators"]["privilege_escalation"].append({
                    "technique": "Potential UAC Bypass",
                    "process": file_op["process"],
                    "path": file_op["path"],
                    "timestamp": file_op["timestamp"]
                })
    
    def _analyze_data_exfiltration(self):
        """Look for data exfiltration patterns."""
        
        # Look for files being read from sensitive locations
        sensitive_paths = [
            r"\\documents\\", r"\\desktop\\", r"\\downloads\\",
            r"\\pictures\\", r"\\videos\\", r"\\music\\"
        ]
        
        for file_op in self.results["file_operations"]["files_modified"]:
            if any(re.search(path, file_op["path"], re.IGNORECASE) for path in sensitive_paths):
                # If followed by network activity from same process, flag as potential exfiltration
                process_network_ops = [net_op for net_op in self.results["network_operations"]["connections"]
                                     if net_op["process"] == file_op["process"]]
                
                if process_network_ops:
                    self.results["behavioral_indicators"]["data_exfiltration"].append({
                        "process": file_op["process"],
                        "file_accessed": file_op["path"],
                        "network_connections": len(process_network_ops),
                        "timestamp": file_op["timestamp"]
                    })
    
    def _build_timeline(self):
        """Build a chronological timeline of significant events."""
        
        timeline_events = []
        
        # Add significant events to timeline
        for event_type, events_list in [
            ("Process", self.results["process_activity"]["suspicious_processes"]),
            ("File", self.results["file_operations"]["suspicious_file_ops"]),
            ("Registry", self.results["registry_operations"]["suspicious_registry_ops"]),
            ("Network", self.results["network_operations"]["suspicious_network_ops"])
        ]:
            for event in events_list:
                timeline_events.append({
                    "timestamp": event["timestamp"],
                    "event_type": event_type,
                    "process": event["process"],
                    "description": self._generate_event_description(event_type, event)
                })
        
        # Sort by timestamp
        timeline_events.sort(key=lambda x: x["timestamp"])
        self.results["timeline"] = timeline_events[:1000]  # Limit to prevent huge timelines
    
    def _generate_event_description(self, event_type: str, event: Dict) -> str:
        """Generate human-readable event description."""
        
        if event_type == "Process":
            return f"Suspicious process activity: {event.get('operation', 'Unknown')}"
        elif event_type == "File":
            return f"Suspicious file operation: {event.get('operation', 'Unknown')} on {event.get('path', 'Unknown path')}"
        elif event_type == "Registry":
            return f"Suspicious registry operation: {event.get('operation', 'Unknown')} on {event.get('path', 'Unknown key')}"
        elif event_type == "Network":
            return f"Suspicious network activity: {event.get('operation', 'Unknown')} to {event.get('destination', 'Unknown destination')}"
        else:
            return f"Suspicious {event_type.lower()} activity"
    
    def _generate_statistics(self):
        """Generate processing statistics."""
        
        # Process statistics
        process_stats = defaultdict(lambda: {"events": 0, "operations": set()})
        
        all_events = []
        all_events.extend(self.results["file_operations"]["files_created"])
        all_events.extend(self.results["file_operations"]["files_modified"])
        all_events.extend(self.results["file_operations"]["files_deleted"])
        all_events.extend(self.results["registry_operations"]["keys_created"])
        all_events.extend(self.results["registry_operations"]["keys_modified"])
        all_events.extend(self.results["network_operations"]["connections"])
        
        for event in all_events:
            process = event.get("process", "Unknown")
            operation = event.get("operation", "Unknown")
            process_stats[process]["events"] += 1
            process_stats[process]["operations"].add(operation)
        
        # Convert sets to lists for JSON serialization
        for process, stats in process_stats.items():
            stats["operations"] = list(stats["operations"])
            stats["unique_operations"] = len(stats["operations"])
        
        self.results["process_activity"]["process_statistics"] = dict(process_stats)
        
        # File extension analysis
        extension_stats = defaultdict(int)
        for file_op in (self.results["file_operations"]["files_created"] + 
                       self.results["file_operations"]["files_modified"]):
            path = file_op.get("path", "")
            if path:
                ext = os.path.splitext(path)[1].lower()
                if ext:
                    extension_stats[ext] += 1
        
        self.results["file_operations"]["extension_analysis"] = dict(extension_stats)
        
        # Directory analysis
        directory_stats = defaultdict(int)
        for file_op in (self.results["file_operations"]["files_created"] + 
                       self.results["file_operations"]["files_modified"]):
            path = file_op.get("path", "")
            if path:
                directory = os.path.dirname(path)
                directory_stats[directory] += 1
        
        # Keep only top directories to avoid huge lists
        top_directories = dict(sorted(directory_stats.items(), 
                                    key=lambda x: x[1], reverse=True)[:50])
        self.results["file_operations"]["directory_analysis"] = top_directories
    
    def export_results(self, output_file_path: str) -> bool:
        """
        Export processed results to JSON file.
        
        Args:
            output_file_path: Path to save the JSON results
            
        Returns:
            True if successful, False otherwise
        """
        try:
            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
            
            with open(output_file_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            logger.info(f"Results exported to: {output_file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return False
    
    def generate_summary_report(self, output_file_path: str = None) -> str:
        """
        Generate a human-readable summary report.
        
        Args:
            output_file_path: Optional path to save the report
            
        Returns:
            Summary report as string
        """
        report_lines = []
        
        # Header
        report_lines.append("=" * 80)
        report_lines.append("SHIKRA PROCMON ANALYSIS SUMMARY REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Metadata
        metadata = self.results["metadata"]
        report_lines.append(f"Source File: {metadata.get('source_file', 'N/A')}")
        report_lines.append(f"Processing Time: {metadata.get('processing_duration_seconds', 'N/A')}s")
        report_lines.append(f"Total Events: {metadata.get('total_events', 0):,}")
        report_lines.append(f"Events Analyzed: {metadata.get('filtered_events', 0):,}")
        report_lines.append(f"Noise Events Filtered: {metadata.get('noise_events_removed', 0):,}")
        report_lines.append("")
        
        # Process Activity Summary
        report_lines.append("-" * 50)
        report_lines.append("PROCESS ACTIVITY SUMMARY")
        report_lines.append("-" * 50)
        
        process_stats = self.results["process_activity"]["process_statistics"]
        report_lines.append(f"Unique Processes: {len(process_stats)}")
        report_lines.append(f"Suspicious Processes: {len(self.results['process_activity']['suspicious_processes'])}")
        report_lines.append(f"Suspicious Command Lines: {len(self.results['process_activity']['cmdline_analysis'])}")
        
        if process_stats:
            report_lines.append("\nTop Active Processes:")
            sorted_processes = sorted(process_stats.items(), 
                                    key=lambda x: x[1]["events"], reverse=True)[:10]
            for process, stats in sorted_processes:
                report_lines.append(f"  {process}: {stats['events']} events, {stats['unique_operations']} operation types")
        
        report_lines.append("")
        
        # File Operations Summary
        report_lines.append("-" * 50)
        report_lines.append("FILE OPERATIONS SUMMARY")
        report_lines.append("-" * 50)
        
        file_ops = self.results["file_operations"]
        report_lines.append(f"Files Created: {len(file_ops['files_created'])}")
        report_lines.append(f"Files Modified: {len(file_ops['files_modified'])}")
        report_lines.append(f"Files Deleted: {len(file_ops['files_deleted'])}")
        report_lines.append(f"Suspicious File Operations: {len(file_ops['suspicious_file_ops'])}")
        
        # Top file extensions
        if file_ops["extension_analysis"]:
            report_lines.append("\nTop File Extensions:")
            sorted_extensions = sorted(file_ops["extension_analysis"].items(), 
                                     key=lambda x: x[1], reverse=True)[:10]
            for ext, count in sorted_extensions:
                report_lines.append(f"  {ext}: {count}")
        
        report_lines.append("")
        
        # Registry Operations Summary
        report_lines.append("-" * 50)
        report_lines.append("REGISTRY OPERATIONS SUMMARY")
        report_lines.append("-" * 50)
        
        reg_ops = self.results["registry_operations"]
        report_lines.append(f"Registry Keys Created: {len(reg_ops['keys_created'])}")
        report_lines.append(f"Registry Keys Modified: {len(reg_ops['keys_modified'])}")
        report_lines.append(f"Registry Keys Deleted: {len(reg_ops['keys_deleted'])}")
        report_lines.append(f"Suspicious Registry Operations: {len(reg_ops['suspicious_registry_ops'])}")
        report_lines.append(f"Persistence Indicators: {len(reg_ops['persistence_indicators'])}")
        report_lines.append("")
        
        # Network Operations Summary
        report_lines.append("-" * 50)
        report_lines.append("NETWORK OPERATIONS SUMMARY")
        report_lines.append("-" * 50)
        
        net_ops = self.results["network_operations"]
        report_lines.append(f"Network Connections: {len(net_ops['connections'])}")
        report_lines.append(f"Suspicious Network Operations: {len(net_ops['suspicious_network_ops'])}")
        report_lines.append("")
        
        # Behavioral Indicators Summary
        report_lines.append("-" * 50)
        report_lines.append("BEHAVIORAL INDICATORS SUMMARY")
        report_lines.append("-" * 50)
        
        behavioral = self.results["behavioral_indicators"]
        report_lines.append(f"Encryption Indicators: {len(behavioral['encryption_indicators'])}")
        report_lines.append(f"Evasion Techniques: {len(behavioral['evasion_techniques'])}")
        report_lines.append(f"Privilege Escalation: {len(behavioral['privilege_escalation'])}")
        report_lines.append(f"Anti-Analysis Techniques: {len(behavioral['anti_analysis'])}")
        report_lines.append(f"Data Exfiltration Indicators: {len(behavioral['data_exfiltration'])}")
        report_lines.append("")
        
        # Key Findings
        if behavioral["encryption_indicators"]:
            report_lines.append("-" * 50)
            report_lines.append("KEY ENCRYPTION INDICATORS")
            report_lines.append("-" * 50)
            for indicator in behavioral["encryption_indicators"][:5]:
                report_lines.append(f"• {indicator.get('indicator_type', 'Unknown')}: {indicator.get('process', 'N/A')} ({indicator.get('file_count', 0)} files)")
            report_lines.append("")
        
        if reg_ops["persistence_indicators"]:
            report_lines.append("-" * 50)
            report_lines.append("KEY PERSISTENCE INDICATORS")
            report_lines.append("-" * 50)
            for indicator in reg_ops["persistence_indicators"][:5]:
                report_lines.append(f"• {indicator.get('persistence_type', 'Unknown')}: {indicator.get('path', 'N/A')}")
            report_lines.append("")
        
        # Processing Errors
        if self.results["processing_errors"]:
            report_lines.append("-" * 50)
            report_lines.append("PROCESSING ERRORS")
            report_lines.append("-" * 50)
            for error in self.results["processing_errors"]:
                report_lines.append(f"• {error}")
            report_lines.append("")
        
        # Footer
        report_lines.append("=" * 80)
        report_lines.append(f"Report generated by Shikra ProcMon Processor v{metadata.get('processor_version', '1.0.0')}")
        report_lines.append("=" * 80)
        
        report_text = "\n".join(report_lines)
        
        # Save to file if requested
        if output_file_path:
            try:
                os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
                with open(output_file_path, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                logger.info(f"Summary report saved to: {output_file_path}")
            except Exception as e:
                logger.error(f"Failed to save summary report: {e}")
        
        return report_text


# Main processing function for module integration
def process_procmon_log(
    csv_file_path: str,
    output_json_path: str,
    sample_id: str = None,
    config_settings: dict = None,
    generate_summary_report: str = None
) -> bool:
    """
    Main function to process a ProcMon CSV log file.
    
    Args:
        csv_file_path: Path to the ProcMon CSV file
        output_json_path: Path to save JSON results
        sample_id: Optional sample identifier
        config_settings: Optional configuration settings
        generate_summary_report: Optional path to save summary report
        
    Returns:
        True if processing successful, False otherwise
    """
    logger.info(f"Starting ProcMon log processing: {csv_file_path}")
    
    try:
        # Initialize processor
        processor = ProcMonProcessor(config_settings)
        
        # Process the CSV file
        results = processor.process_procmon_csv(csv_file_path)
        
        # Add sample ID if provided
        if sample_id:
            results["metadata"]["sample_id"] = sample_id
        
        # Export results
        if not processor.export_results(output_json_path):
            logger.error("Failed to export JSON results")
            return False
        
        # Generate summary report if requested
        if generate_summary_report:
            processor.generate_summary_report(generate_summary_report)
        
        # Log summary
        metadata = results["metadata"]
        logger.info(f"Processing completed successfully:")
        logger.info(f"  - Total events: {metadata.get('total_events', 0):,}")
        logger.info(f"  - Events analyzed: {metadata.get('filtered_events', 0):,}")
        logger.info(f"  - Noise filtered: {metadata.get('noise_events_removed', 0):,}")
        logger.info(f"  - Processing time: {metadata.get('processing_duration_seconds', 0)}s")
        logger.info(f"  - Results saved to: {output_json_path}")
        
        return True
        
    except Exception as e:
        logger.exception(f"ProcMon log processing failed: {e}")
        return False


if __name__ == "__main__":
    import argparse
    import sys
    
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Shikra ProcMon Log Processor')
    parser.add_argument('csv_file', help='Path to ProcMon CSV file')
    parser.add_argument('--output-json', '-o', 
                       default='procmon_analysis_results.json',
                       help='Output JSON file path')
    parser.add_argument('--summary-report', '-s',
                       help='Generate summary report at specified path')
    parser.add_argument('--sample-id', 
                       help='Sample identifier for tracking')
    parser.add_argument('--config', 
                       help='JSON configuration file for custom filtering rules')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration if provided
    config_settings = None
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                config_settings = json.load(f)
            logger.info(f"Loaded configuration from: {args.config}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    # Check if input file exists
    if not os.path.exists(args.csv_file):
        logger.error(f"Input CSV file not found: {args.csv_file}")
        sys.exit(1)
    
    # Process the ProcMon log
    success = process_procmon_log(
        csv_file_path=args.csv_file,
        output_json_path=args.output_json,
        sample_id=args.sample_id,
        config_settings=config_settings,
        generate_summary_report=args.summary_report
    )
    
    if success:
        logger.info("ProcMon log processing completed successfully!")
        sys.exit(0)
    else:
        logger.error("ProcMon log processing failed!")
        sys.exit(1)