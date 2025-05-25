# shikra/core/modules/monitoring/procmon_processor.py
# Purpose: Advanced ProcMon log processor with behavioral analysis

import os
import csv
import json
import logging
import hashlib
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import xml.etree.ElementTree as ET

from .filter_engine import FilterEngine

logger = logging.getLogger(__name__)

class ProcMonProcessor:
    """
    Advanced processor for ProcMon logs with behavioral analysis capabilities.
    Processes CSV, XML, and PML formats from ProcMon with intelligent filtering.
    """
    
    def __init__(self, sample_id: str = None, config_data: Dict = None):
        """
        Initialize the ProcMon processor.
        
        Args:
            sample_id: Unique identifier for the sample being analyzed
            config_data: Configuration dictionary for processor settings
        """
        self.sample_id = sample_id or f"procmon_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.config = config_data or {}
        
        # Initialize filter engine
        self.filter_engine = FilterEngine(self.config.get('filter_config', {}))
        
        # Analysis results storage
        self.results = {
            "sample_id": self.sample_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_events": 0,
            "filtered_events": 0,
            "behavioral_indicators": [],
            "process_tree": {},
            "file_operations": defaultdict(list),
            "registry_operations": defaultdict(list),
            "network_operations": defaultdict(list),
            "suspicious_activities": [],
            "timeline": [],
            "statistics": {},
            "errors": []
        }
        
        # Behavioral patterns for detection
        self._load_detection_patterns()
        
        # Process tracking
        self.processes = {}  # PID -> process info
        self.process_hierarchy = defaultdict(list)  # PPID -> [child PIDs]
        
    def _load_detection_patterns(self):
        """Load malware detection patterns from configuration."""
        patterns_file = self.config.get('patterns_file', 'config/procmon/malware_patterns.json')
        try:
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    self.detection_patterns = json.load(f)
                logger.info(f"Loaded detection patterns from {patterns_file}")
            else:
                # Default patterns if file doesn't exist
                self.detection_patterns = self._get_default_patterns()
                logger.warning(f"Pattern file not found, using defaults")
        except Exception as e:
            logger.error(f"Failed to load detection patterns: {e}")
            self.detection_patterns = self._get_default_patterns()
    
    def _get_default_patterns(self) -> Dict:
        """Returns default malware detection patterns."""
        return {
            "file_patterns": {
                "ransomware_extensions": [
                    ".encrypted", ".locked", ".crypted", ".cerber", ".locky", 
                    ".wcry", ".wncry", ".zepto", ".thor", ".osiris"
                ],
                "suspicious_locations": [
                    "\\AppData\\Local\\Temp\\",
                    "\\Users\\Public\\",
                    "\\Windows\\Temp\\",
                    "\\ProgramData\\"
                ],
                "executable_drops": [
                    ".exe", ".dll", ".scr", ".bat", ".vbs", ".ps1"
                ]
            },
            "registry_patterns": {
                "persistence_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                ],
                "security_bypass": [
                    "DisableAntiSpyware",
                    "DisableRealtimeMonitoring", 
                    "DisableBehaviorMonitoring"
                ]
            },
            "process_patterns": {
                "system_tools": [
                    "vssadmin.exe", "wbadmin.exe", "bcdedit.exe",
                    "wmic.exe", "powershell.exe", "cmd.exe"
                ],
                "suspicious_args": [
                    "delete shadows", "delete catalog", "recoveryenabled no",
                    "-enc ", "-hidden", "bypass"
                ]
            },
            "network_patterns": {
                "tor_indicators": [
                    ".onion", "tor2web", "torproject"
                ],
                "c2_patterns": [
                    "pastebin.com", "ghostbin.co", "transfer.sh"
                ]
            }
        }
    
    def process_csv_log(self, csv_file_path: str) -> Dict:
        """
        Process ProcMon CSV log file.
        
        Args:
            csv_file_path: Path to the ProcMon CSV file
            
        Returns:
            Dictionary containing analysis results
        """
        if not os.path.exists(csv_file_path):
            error_msg = f"CSV file not found: {csv_file_path}"
            logger.error(error_msg)
            self.results["errors"].append(error_msg)
            return self.results
            
        logger.info(f"Processing ProcMon CSV: {csv_file_path}")
        
        try:
            with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Skip BOM if present
                content = f.read()
                if content.startswith('\ufeff'):
                    content = content[1:]
                    
                # Parse CSV
                csv_reader = csv.DictReader(content.splitlines())
                
                for row_num, row in enumerate(csv_reader, 1):
                    try:
                        self._process_event_row(row, row_num)
                    except Exception as e:
                        logger.debug(f"Error processing row {row_num}: {e}")
                        continue
                        
        except Exception as e:
            error_msg = f"Failed to process CSV file: {e}"
            logger.error(error_msg)
            self.results["errors"].append(error_msg)
            
        self._finalize_analysis()
        return self.results
    
    def _process_event_row(self, row: Dict, row_num: int):
        """Process a single event row from ProcMon CSV."""
        self.results["total_events"] += 1
        
        # Normalize field names (ProcMon CSV headers can vary)
        normalized_row = self._normalize_csv_fields(row)
        
        # Apply filtering
        if not self.filter_engine.should_process_event(normalized_row):
            return
            
        self.results["filtered_events"] += 1
        
        # Extract basic information
        event_info = {
            "timestamp": normalized_row.get("Time of Day", ""),
            "process_name": normalized_row.get("Process Name", ""),
            "pid": self._safe_int(normalized_row.get("PID", "0")),
            "operation": normalized_row.get("Operation", ""),
            "path": normalized_row.get("Path", ""),
            "result": normalized_row.get("Result", ""),
            "detail": normalized_row.get("Detail", ""),
            "row_number": row_num
        }
        
        # Track process information
        self._track_process(event_info)
        
        # Categorize and analyze the event
        self._categorize_event(event_info)
        
        # Check for behavioral indicators
        self._check_behavioral_patterns(event_info)
        
        # Add to timeline
        self.results["timeline"].append(event_info)
    
    def _normalize_csv_fields(self, row: Dict) -> Dict:
        """Normalize CSV field names to standard format."""
        field_mapping = {
            "Time of Day": ["Time of Day", "TimeOfDay", "Time"],
            "Process Name": ["Process Name", "ProcessName", "Process"],
            "PID": ["PID", "ProcessId", "Process ID"],
            "Operation": ["Operation", "Op"],
            "Path": ["Path", "Target", "File"],
            "Result": ["Result", "Status"],
            "Detail": ["Detail", "Details", "Description"]
        }
        
        normalized = {}
        for standard_name, possible_names in field_mapping.items():
            for possible_name in possible_names:
                if possible_name in row:
                    normalized[standard_name] = row[possible_name]
                    break
            if standard_name not in normalized:
                normalized[standard_name] = ""
                
        return normalized
    
    def _safe_int(self, value: str) -> int:
        """Safely convert string to integer."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0
    
    def _track_process(self, event_info: Dict):
        """Track process creation and hierarchy."""
        pid = event_info["pid"]
        process_name = event_info["process_name"]
        
        if pid not in self.processes:
            self.processes[pid] = {
                "name": process_name,
                "first_seen": event_info["timestamp"],
                "operations": Counter(),
                "files_accessed": set(),
                "registry_keys": set(),
                "network_activity": False
            }
        
        # Update process statistics
        self.processes[pid]["operations"][event_info["operation"]] += 1
        
        # Track file access
        if event_info["operation"] in ["CreateFile", "WriteFile", "ReadFile"]:
            self.processes[pid]["files_accessed"].add(event_info["path"])
            
        # Track registry access
        if event_info["operation"].startswith("Reg"):
            self.processes[pid]["registry_keys"].add(event_info["path"])
    
    def _categorize_event(self, event_info: Dict):
        """Categorize event by type and store appropriately."""
        operation = event_info["operation"]
        
        if operation in ["CreateFile", "WriteFile", "ReadFile", "DeleteFile", "SetDeleteInformationFile"]:
            self.results["file_operations"][operation].append(event_info)
            
        elif operation.startswith("Reg"):
            self.results["registry_operations"][operation].append(event_info)
            
        elif operation in ["TCP Send", "TCP Receive", "UDP Send", "UDP Receive"]:
            self.results["network_operations"][operation].append(event_info)
            event_info["pid"] = event_info["pid"]
            self.processes[event_info["pid"]]["network_activity"] = True
    
    def _check_behavioral_patterns(self, event_info: Dict):
        """Check event against behavioral patterns for malware indicators."""
        indicators = []
        
        # File-based indicators
        indicators.extend(self._check_file_patterns(event_info))
        
        # Registry-based indicators  
        indicators.extend(self._check_registry_patterns(event_info))
        
        # Process-based indicators
        indicators.extend(self._check_process_patterns(event_info))
        
        # Network-based indicators
        indicators.extend(self._check_network_patterns(event_info))
        
        # Add any found indicators
        for indicator in indicators:
            indicator["event"] = event_info
            self.results["behavioral_indicators"].append(indicator)
            
            # Also add to suspicious activities if high severity
            if indicator["severity"] in ["high", "critical"]:
                self.results["suspicious_activities"].append(indicator)
    
    def _check_file_patterns(self, event_info: Dict) -> List[Dict]:
        """Check for file-based malware patterns."""
        indicators = []
        path = event_info["path"].lower()
        operation = event_info["operation"]
        
        # Check for ransomware file extensions
        if operation == "CreateFile":
            for ext in self.detection_patterns["file_patterns"]["ransomware_extensions"]:
                if path.endswith(ext):
                    indicators.append({
                        "type": "ransomware_file_creation",
                        "severity": "critical",
                        "description": f"Created file with ransomware extension: {ext}",
                        "pattern_matched": ext
                    })
        
        # Check for suspicious file locations
        for location in self.detection_patterns["file_patterns"]["suspicious_locations"]:
            if location.lower() in path:
                indicators.append({
                    "type": "suspicious_file_location",
                    "severity": "medium",
                    "description": f"File operation in suspicious location: {location}",
                    "pattern_matched": location
                })
                break
        
        # Check for executable drops
        if operation == "CreateFile" and event_info["result"] == "SUCCESS":
            for ext in self.detection_patterns["file_patterns"]["executable_drops"]:
                if path.endswith(ext):
                    indicators.append({
                        "type": "executable_drop",
                        "severity": "high", 
                        "description": f"Executable dropped: {ext}",
                        "pattern_matched": ext
                    })
                    break
        
        return indicators
    
    def _check_registry_patterns(self, event_info: Dict) -> List[Dict]:
        """Check for registry-based malware patterns."""
        indicators = []
        path = event_info["path"]
        operation = event_info["operation"]
        
        if not operation.startswith("Reg"):
            return indicators
            
        # Check for persistence mechanisms
        for key in self.detection_patterns["registry_patterns"]["persistence_keys"]:
            if key in path:
                indicators.append({
                    "type": "persistence_registry",
                    "severity": "high",
                    "description": f"Registry persistence mechanism: {key}",
                    "pattern_matched": key
                })
                break
        
        # Check for security bypass attempts
        for pattern in self.detection_patterns["registry_patterns"]["security_bypass"]:
            if pattern in path or pattern in event_info["detail"]:
                indicators.append({
                    "type": "security_bypass_registry",
                    "severity": "critical",
                    "description": f"Security bypass attempt: {pattern}",
                    "pattern_matched": pattern
                })
                break
        
        return indicators
    
    def _check_process_patterns(self, event_info: Dict) -> List[Dict]:
        """Check for process-based malware patterns."""
        indicators = []
        process_name = event_info["process_name"].lower()
        detail = event_info["detail"].lower()
        
        # Check for system tool usage
        for tool in self.detection_patterns["process_patterns"]["system_tools"]:
            if tool in process_name:
                # Check for suspicious arguments
                for arg_pattern in self.detection_patterns["process_patterns"]["suspicious_args"]:
                    if arg_pattern in detail:
                        indicators.append({
                            "type": "suspicious_system_tool_usage",
                            "severity": "high",
                            "description": f"Suspicious use of {tool} with args: {arg_pattern}",
                            "pattern_matched": f"{tool} + {arg_pattern}"
                        })
                        break
        
        return indicators
    
    def _check_network_patterns(self, event_info: Dict) -> List[Dict]:
        """Check for network-based malware patterns."""
        indicators = []
        
        if not event_info["operation"].startswith(("TCP", "UDP")):
            return indicators
            
        path = event_info["path"].lower()
        detail = event_info["detail"].lower()
        
        # Check for Tor indicators
        for tor_indicator in self.detection_patterns["network_patterns"]["tor_indicators"]:
            if tor_indicator in path or tor_indicator in detail:
                indicators.append({
                    "type": "tor_network_activity",
                    "severity": "high",
                    "description": f"Tor network activity detected: {tor_indicator}",
                    "pattern_matched": tor_indicator
                })
                break
        
        # Check for C2 patterns
        for c2_pattern in self.detection_patterns["network_patterns"]["c2_patterns"]:
            if c2_pattern in path or c2_pattern in detail:
                indicators.append({
                    "type": "c2_communication",
                    "severity": "critical",
                    "description": f"Potential C2 communication: {c2_pattern}",
                    "pattern_matched": c2_pattern
                })
                break
        
        return indicators
    
    def _finalize_analysis(self):
        """Finalize analysis and generate statistics."""
        # Generate process tree
        self._build_process_tree()
        
        # Calculate statistics
        self.results["statistics"] = {
            "total_events": self.results["total_events"],
            "filtered_events": self.results["filtered_events"],
            "filter_efficiency": (1 - self.results["filtered_events"] / max(1, self.results["total_events"])) * 100,
            "unique_processes": len(self.processes),
            "behavioral_indicators": len(self.results["behavioral_indicators"]),
            "suspicious_activities": len(self.results["suspicious_activities"]),
            "file_operations_count": sum(len(ops) for ops in self.results["file_operations"].values()),
            "registry_operations_count": sum(len(ops) for ops in self.results["registry_operations"].values()),
            "network_operations_count": sum(len(ops) for ops in self.results["network_operations"].values())
        }
        
        # Sort timeline by timestamp
        self.results["timeline"].sort(key=lambda x: x.get("timestamp", ""))
        
        logger.info(f"Analysis complete: {self.results['statistics']}")
    
    def _build_process_tree(self):
        """Build process hierarchy tree."""
        # This would require Process and Thread events which contain PPID information
        # For now, we'll create a simplified version based on process tracking
        self.results["process_tree"] = {
            "processes": dict(self.processes),
            "hierarchy": dict(self.process_hierarchy)
        }
    
    def export_results(self, output_file: str = None) -> str:
        """Export analysis results to JSON file."""
        if not output_file:
            output_file = f"procmon_analysis_{self.sample_id}.json"
            
        try:
            # Convert sets to lists for JSON serialization
            serializable_results = self._make_json_serializable(self.results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, default=str)
                
            logger.info(f"Results exported to: {output_file}")
            return output_file
            
        except Exception as e:
            error_msg = f"Failed to export results: {e}"
            logger.error(error_msg)
            return ""
    
    def _make_json_serializable(self, obj):
        """Convert objects to JSON-serializable format."""
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, Counter):
            return dict(obj)
        elif isinstance(obj, defaultdict):
            return dict(obj)
        else:
            return obj

# Helper function for module usage
def process_procmon_log(csv_file_path: str, sample_id: str = None, config: Dict = None) -> Dict:
    """
    Convenience function to process a ProcMon log file.
    
    Args:
        csv_file_path: Path to ProcMon CSV file
        sample_id: Sample identifier
        config: Configuration dictionary
        
    Returns:
        Analysis results dictionary
    """
    processor = ProcMonProcessor(sample_id, config)
    return processor.process_csv_log(csv_file_path)

if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='ProcMon Log Processor')
    parser.add_argument('csv_file', help='Path to ProcMon CSV file')
    parser.add_argument('--sample-id', help='Sample ID for analysis')
    parser.add_argument('--output', help='Output JSON file path')
    parser.add_argument('--config', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Process the log
    processor = ProcMonProcessor(args.sample_id, config)
    results = processor.process_csv_log(args.csv_file)
    
    # Export results
    output_file = args.output or f"procmon_analysis_{args.sample_id or 'unknown'}.json"
    processor.export_results(output_file)
    
    print(f"Analysis complete. Results saved to: {output_file}")
    print(f"Statistics: {results['statistics']}")