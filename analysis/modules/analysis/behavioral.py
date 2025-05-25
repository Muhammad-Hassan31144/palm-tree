"""
Behavioral Analysis Module (behavioral.py)

Purpose:
This module analyzes behavioral data collected during malware execution to identify
malicious patterns, techniques, and indicators of compromise (IOCs). It processes
logs from monitoring tools like Noriben, Procmon, and custom process monitors.

Context in Shikra:
- Input: Raw behavioral logs from core/modules/monitor/ components
- Processing: Pattern detection, technique identification, IOC extraction
- Output: Structured analysis results for reporting modules

Key Functionalities:
The BehavioralAnalyzer class processes behavioral data to detect:
- Persistence mechanisms (registry modifications, startup folders, services)
- Process injection techniques (DLL injection, process hollowing)
- Ransomware behavior (file encryption patterns, shadow copy deletion)
- Data exfiltration activities (file access followed by network activity)
- Evasion techniques (anti-analysis, anti-VM detection)

Integration Points:
- Receives parsed data from core/modules/monitor/noriben_wrapper.py
- Uses YARA rules and behavioral signatures for detection
- Outputs structured results to reporting/modules/reporting/report_generator.py
"""

import logging
import re
import json
import os
import math
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import yara

# Configure logging for this module
logger = logging.getLogger(__name__)

class BehavioralAnalyzer:
    """
    Analyzes behavioral data from malware execution to identify malicious patterns,
    techniques, and indicators of compromise.
    
    This class serves as the primary behavioral analysis engine in Shikra,
    processing logs from various monitoring tools and applying detection logic
    to identify threats and extract actionable intelligence.
    """
    
    def __init__(self, rules_directory: Optional[Path] = None):
        """
        Initialize the behavioral analyzer with optional rules directory.
        
        Args:
            rules_directory (Optional[Path]): Path to directory containing
                                            behavioral detection rules and signatures
        """
        self.rules_directory = rules_directory
        self.detection_rules = {}
        self.analysis_results = {}
        self.yara_rules = None
        
        # Initialize behavioral patterns
        self._init_behavioral_patterns()
        
        if rules_directory:
            self._load_detection_rules()
            
        logger.info("BehavioralAnalyzer initialized")
    
    def _init_behavioral_patterns(self):
        """Initialize hardcoded behavioral patterns and signatures"""
        
        # Persistence registry keys
        self.persistence_registry_keys = [
            r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
            r'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
            r'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
            r'HKLM\\SYSTEM\\CurrentControlSet\\Services',
            r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
            r'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'
        ]
        
        # Persistence file paths
        self.persistence_file_paths = [
            r'.*\\Startup\\.*',
            r'.*\\Start Menu\\Programs\\Startup\\.*',
            r'.*\\System32\\Tasks\\.*',
            r'.*\\SysWOW64\\Tasks\\.*'
        ]
        
        # Process injection indicators
        self.injection_apis = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'OpenProcess', 'SetThreadContext', 'GetThreadContext',
            'SuspendThread', 'ResumeThread', 'QueueUserAPC',
            'SetWindowsHookEx', 'NtMapViewOfSection', 'ZwMapViewOfSection'
        ]
        
        # Ransomware file extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.vault',
            '.locky', '.cerber', '.zepto', '.thor', '.aaa', '.abc', '.xyz',
            '.zzz', '.micro', '.dharma', '.wallet', '.bitpay', '.karma'
        ]
        
        # Ransomware processes/commands
        self.ransomware_commands = [
            r'vssadmin.*delete.*shadows',
            r'wbadmin.*delete.*catalog',
            r'bcdedit.*set.*recoveryenabled.*no',
            r'wmic.*shadowcopy.*delete',
            r'cipher.*\/w:.*',
            r'schtasks.*\/delete.*\/tn.*'
        ]
        
        # Anti-analysis indicators
        self.evasion_indicators = [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'GetTickCount', 'QueryPerformanceCounter',
            'Sleep', 'GetSystemMetrics', 'GetModuleHandle',
            'FindWindow', 'RegQueryValueEx', 'GetComputerName',
            'GetUserName', 'GetVersion', 'IsProcessorFeaturePresent'
        ]
        
        # VM/Sandbox detection patterns
        self.vm_detection_patterns = [
            'VMware', 'VirtualBox', 'VBOX', 'QEMU', 'Xen',
            'vmmouse', 'vmtools', 'vboxservice', 'vmwareuser',
            'sandboxie', 'cuckoo', 'anubis', 'joebox'
        ]
        
        # MITRE ATT&CK mapping
        self.mitre_mapping = {
            'persistence_registry': ['T1547.001'],  # Registry Run Keys
            'persistence_startup': ['T1547.001'],   # Startup Folder
            'persistence_service': ['T1543.003'],   # Windows Service
            'persistence_scheduled_task': ['T1053.005'],  # Scheduled Task
            'process_injection_dll': ['T1055.001'], # DLL Injection
            'process_injection_hollow': ['T1055.012'], # Process Hollowing
            'process_injection_apc': ['T1055.004'], # APC Injection
            'ransomware_encryption': ['T1486'],     # Data Encrypted for Impact
            'ransomware_shadow_delete': ['T1490'], # Inhibit System Recovery
            'evasion_debugger_check': ['T1622'],   # Debugger Evasion
            'evasion_vm_check': ['T1497.001'],     # System Checks
            'data_staging': ['T1074.001'],         # Local Data Staging
            'data_exfiltration': ['T1041']         # Exfiltration Over C2 Channel
        }
    
    def _load_detection_rules(self):
        """
        Load behavioral detection rules from the specified directory.
        Rules can be YARA files, JSON patterns, or custom signature formats.
        """
        if not self.rules_directory or not self.rules_directory.exists():
            logger.warning("Rules directory not found, using default patterns only")
            return
            
        try:
            # Load YARA rules
            yara_files = list(self.rules_directory.glob("*.yar")) + list(self.rules_directory.glob("*.yara"))
            if yara_files:
                yara_filepaths = {str(f): str(f) for f in yara_files}
                self.yara_rules = yara.compile(filepaths=yara_filepaths)
                logger.info(f"Loaded {len(yara_files)} YARA rule files")
            
            # Load JSON rule files
            json_files = list(self.rules_directory.glob("*.json"))
            for json_file in json_files:
                try:
                    with open(json_file, 'r') as f:
                        rules = json.load(f)
                        self.detection_rules[json_file.stem] = rules
                        logger.info(f"Loaded rules from {json_file.name}")
                except Exception as e:
                    logger.error(f"Failed to load rules from {json_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Error loading detection rules: {e}")
    
    def analyze_execution_data(self, behavioral_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main analysis function that processes behavioral data and returns structured results.
        
        Args:
            behavioral_data (Dict[str, Any]): Parsed behavioral data from monitoring tools
                                            Contains process, file, registry, and network activity
        
        Returns:
            Dict[str, Any]: Comprehensive analysis results including detected techniques,
                          IOCs, threat score, and detailed findings
        """
        logger.info("Starting behavioral analysis of execution data")
        
        # Extract event categories from behavioral data
        process_events = behavioral_data.get('process_events', [])
        file_events = behavioral_data.get('file_events', [])
        registry_events = behavioral_data.get('registry_events', [])
        network_events = behavioral_data.get('network_events', [])
        system_events = behavioral_data.get('system_events', [])
        
        # Perform individual analyses
        persistence_mechanisms = self.detect_persistence_mechanisms(registry_events, file_events)
        process_injections = self.detect_process_injection(process_events)
        ransomware_analysis = self.detect_ransomware_behavior(file_events, process_events)
        data_exfiltration = self.detect_data_exfiltration(file_events, network_events)
        evasion_techniques = self.detect_evasion_techniques(process_events, system_events)
        
        # Compile all detected techniques
        detected_techniques = {
            'persistence_mechanisms': persistence_mechanisms,
            'process_injections': process_injections,
            'ransomware_behavior': ransomware_analysis,
            'data_exfiltration': data_exfiltration,
            'evasion_techniques': evasion_techniques
        }
        
        # Calculate threat score
        threat_score = self.calculate_threat_score(detected_techniques)
        
        # Extract IOCs
        all_events = process_events + file_events + registry_events + network_events + system_events
        iocs = self.extract_iocs({'detected_techniques': detected_techniques, 'all_events': all_events})
        
        # Generate timeline
        timeline = self.generate_timeline(all_events)
        
        # Map to MITRE ATT&CK
        mitre_mapping = self.map_to_mitre_attack(detected_techniques)
        
        # Compile final results
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'threat_score': threat_score,
            'classification': self._classify_threat(threat_score, detected_techniques),
            'detected_techniques': detected_techniques,
            'indicators_of_compromise': iocs,
            'timeline': timeline,
            'mitre_attack_mapping': mitre_mapping,
            'summary': {
                'total_events_analyzed': len(all_events),
                'persistence_mechanisms_found': len(persistence_mechanisms),
                'process_injections_found': len(process_injections),
                'ransomware_indicators': len(ransomware_analysis.get('indicators', [])),
                'evasion_techniques_found': len(evasion_techniques),
                'data_exfiltration_activities': len(data_exfiltration)
            }
        }
        
        self.analysis_results = analysis_results
        logger.info(f"Behavioral analysis completed with threat score: {threat_score}")
        
        return analysis_results
    
    def detect_persistence_mechanisms(self, registry_events: List[Dict], file_events: List[Dict]) -> List[Dict]:
        """
        Detect various persistence mechanisms used by malware.
        
        Analyzes registry modifications and file system changes to identify:
        - Registry Run keys modifications
        - Scheduled task creation
        - Service installation
        - Startup folder modifications
        - WMI event subscriptions
        
        Args:
            registry_events (List[Dict]): Registry modification events
            file_events (List[Dict]): File system activity events
            
        Returns:
            List[Dict]: Detected persistence mechanisms with details and severity
        """
        persistence_mechanisms = []
        
        # Check registry-based persistence
        for event in registry_events:
            key_path = event.get('key_path', '')
            operation = event.get('operation', '').lower()
            value_name = event.get('value_name', '')
            value_data = event.get('value_data', '')
            
            if operation in ['setvalue', 'createkey']:
                for persistence_key in self.persistence_registry_keys:
                    if re.search(persistence_key, key_path, re.IGNORECASE):
                        mechanism = {
                            'type': 'registry_persistence',
                            'technique': 'Registry Run Key',
                            'severity': 'high',
                            'registry_key': key_path,
                            'value_name': value_name,
                            'value_data': value_data,
                            'timestamp': event.get('timestamp'),
                            'process': event.get('process_name'),
                            'mitre_technique': 'T1547.001'
                        }
                        persistence_mechanisms.append(mechanism)
                        break
        
        # Check file-based persistence
        for event in file_events:
            file_path = event.get('file_path', '')
            operation = event.get('operation', '').lower()
            
            if operation in ['createfile', 'writefile']:
                for persistence_path in self.persistence_file_paths:
                    if re.search(persistence_path, file_path, re.IGNORECASE):
                        mechanism = {
                            'type': 'file_persistence',
                            'technique': 'Startup Folder',
                            'severity': 'medium',
                            'file_path': file_path,
                            'timestamp': event.get('timestamp'),
                            'process': event.get('process_name'),
                            'mitre_technique': 'T1547.001'
                        }
                        
                        # Detect scheduled tasks
                        if 'tasks' in file_path.lower():
                            mechanism['technique'] = 'Scheduled Task'
                            mechanism['mitre_technique'] = 'T1053.005'
                            mechanism['severity'] = 'high'
                        
                        persistence_mechanisms.append(mechanism)
                        break
        
        # Detect service installation
        service_events = [event for event in registry_events 
                         if 'services' in event.get('key_path', '').lower() and 
                         event.get('operation', '').lower() == 'createkey']
        
        for event in service_events:
            mechanism = {
                'type': 'service_persistence',
                'technique': 'Windows Service',
                'severity': 'high',
                'service_key': event.get('key_path'),
                'timestamp': event.get('timestamp'),
                'process': event.get('process_name'),
                'mitre_technique': 'T1543.003'
            }
            persistence_mechanisms.append(mechanism)
        
        logger.info(f"Detected {len(persistence_mechanisms)} persistence mechanisms")
        return persistence_mechanisms
    
    def detect_process_injection(self, process_events: List[Dict]) -> List[Dict]:
        """
        Identify process injection techniques.
        
        Analyzes process creation and memory manipulation events to detect:
        - DLL injection
        - Process hollowing
        - Atom bombing
        - Process doppelgänging
        - Thread hijacking
        
        Args:
            process_events (List[Dict]): Process-related events and API calls
            
        Returns:
            List[Dict]: Detected injection techniques with target processes and methods
        """
        injection_techniques = []
        process_api_calls = defaultdict(list)
        
        # Group API calls by process
        for event in process_events:
            if event.get('event_type') == 'api_call':
                process_id = event.get('process_id')
                process_api_calls[process_id].append(event)
        
        # Analyze API call patterns for each process
        for process_id, api_calls in process_api_calls.items():
            api_names = [call.get('api_name', '') for call in api_calls]
            
            # Detect DLL injection pattern
            if ('OpenProcess' in api_names and 
                'VirtualAllocEx' in api_names and 
                'WriteProcessMemory' in api_names and 
                'CreateRemoteThread' in api_names):
                
                injection = {
                    'type': 'dll_injection',
                    'technique': 'DLL Injection',
                    'severity': 'high',
                    'source_process_id': process_id,
                    'source_process': next((call.get('process_name') for call in api_calls), 'Unknown'),
                    'target_process_id': self._extract_target_process(api_calls, 'OpenProcess'),
                    'api_sequence': ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
                    'timestamp': api_calls[0].get('timestamp'),
                    'mitre_technique': 'T1055.001'
                }
                injection_techniques.append(injection)
            
            # Detect process hollowing pattern
            if ('CreateProcess' in api_names and 
                'NtUnmapViewOfSection' in api_names and 
                'VirtualAllocEx' in api_names and 
                'WriteProcessMemory' in api_names and 
                'SetThreadContext' in api_names):
                
                injection = {
                    'type': 'process_hollowing',
                    'technique': 'Process Hollowing',
                    'severity': 'critical',
                    'source_process_id': process_id,
                    'source_process': next((call.get('process_name') for call in api_calls), 'Unknown'),
                    'api_sequence': ['CreateProcess', 'NtUnmapViewOfSection', 'VirtualAllocEx', 
                                   'WriteProcessMemory', 'SetThreadContext'],
                    'timestamp': api_calls[0].get('timestamp'),
                    'mitre_technique': 'T1055.012'
                }
                injection_techniques.append(injection)
            
            # Detect APC injection pattern
            if ('OpenProcess' in api_names and 
                'VirtualAllocEx' in api_names and 
                'WriteProcessMemory' in api_calls and 
                'QueueUserAPC' in api_names):
                
                injection = {
                    'type': 'apc_injection',
                    'technique': 'APC Injection',
                    'severity': 'high',
                    'source_process_id': process_id,
                    'source_process': next((call.get('process_name') for call in api_calls), 'Unknown'),
                    'api_sequence': ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'QueueUserAPC'],
                    'timestamp': api_calls[0].get('timestamp'),
                    'mitre_technique': 'T1055.004'
                }
                injection_techniques.append(injection)
        
        logger.info(f"Detected {len(injection_techniques)} process injection techniques")
        return injection_techniques
    
    def detect_ransomware_behavior(self, file_events: List[Dict], process_events: List[Dict]) -> Dict[str, Any]:
        """
        Analyze patterns indicative of ransomware activity.
        
        Looks for characteristic ransomware behaviors:
        - Mass file encryption (extension changes, entropy analysis)
        - Shadow copy deletion
        - Ransom note creation
        - Backup service termination
        - Network communication to payment systems
        
        Args:
            file_events (List[Dict]): File system activity events
            process_events (List[Dict]): Process execution events
            
        Returns:
            Dict[str, Any]: Ransomware analysis results with confidence score and indicators
        """
        ransomware_indicators = []
        confidence_score = 0
        
        # Analyze file encryption patterns
        encrypted_files = []
        extension_changes = Counter()
        
        for event in file_events:
            file_path = event.get('file_path', '')
            operation = event.get('operation', '').lower()
            
            # Check for ransomware file extensions
            if operation in ['createfile', 'writefile']:
                for ext in self.ransomware_extensions:
                    if file_path.lower().endswith(ext):
                        encrypted_files.append({
                            'file_path': file_path,
                            'extension': ext,
                            'timestamp': event.get('timestamp'),
                            'process': event.get('process_name')
                        })
                        confidence_score += 15
                        break
            
            # Check for extension changes (original.ext -> original.ext.encrypted)
            if '.' in file_path and operation == 'movefile':
                original_ext = file_path.split('.')[-2] if len(file_path.split('.')) > 2 else ''
                new_ext = file_path.split('.')[-1]
                if new_ext in [ext.lstrip('.') for ext in self.ransomware_extensions]:
                    extension_changes[f"{original_ext} -> {new_ext}"] += 1
                    confidence_score += 10
        
        # Detect mass file modifications
        if len(encrypted_files) > 50:
            ransomware_indicators.append({
                'type': 'mass_encryption',
                'description': f'Mass file encryption detected ({len(encrypted_files)} files)',
                'severity': 'critical',
                'file_count': len(encrypted_files),
                'mitre_technique': 'T1486'
            })
            confidence_score += 30
        
        # Detect shadow copy deletion commands
        shadow_deletions = []
        for event in process_events:
            if event.get('event_type') == 'process_create':
                command_line = event.get('command_line', '')
                for cmd_pattern in self.ransomware_commands:
                    if re.search(cmd_pattern, command_line, re.IGNORECASE):
                        shadow_deletions.append({
                            'command': command_line,
                            'process': event.get('process_name'),
                            'timestamp': event.get('timestamp')
                        })
                        confidence_score += 25
                        break
        
        if shadow_deletions:
            ransomware_indicators.append({
                'type': 'shadow_deletion',
                'description': 'Shadow copy deletion commands detected',
                'severity': 'critical',
                'commands': shadow_deletions,
                'mitre_technique': 'T1490'
            })
        
        # Detect ransom note creation
        ransom_notes = []
        ransom_note_patterns = [
            r'.*readme.*\.txt', r'.*decrypt.*\.txt', r'.*recover.*\.txt',
            r'.*ransom.*\.txt', r'.*help.*\.txt', r'.*restore.*\.txt'
        ]
        
        for event in file_events:
            if event.get('operation', '').lower() == 'createfile':
                file_path = event.get('file_path', '')
                for pattern in ransom_note_patterns:
                    if re.search(pattern, file_path, re.IGNORECASE):
                        ransom_notes.append({
                            'file_path': file_path,
                            'timestamp': event.get('timestamp'),
                            'process': event.get('process_name')
                        })
                        confidence_score += 20
                        break
        
        if ransom_notes:
            ransomware_indicators.append({
                'type': 'ransom_notes',
                'description': 'Potential ransom notes created',
                'severity': 'high',
                'files': ransom_notes
            })
        
        # Calculate final confidence score (0-100)
        confidence_score = min(confidence_score, 100)
        
        return {
            'confidence_score': confidence_score,
            'classification': self._classify_ransomware(confidence_score),
            'indicators': ransomware_indicators,
            'encrypted_files': encrypted_files,
            'extension_changes': dict(extension_changes),
            'shadow_deletions': shadow_deletions,
            'ransom_notes': ransom_notes
        }
    
    def detect_data_exfiltration(self, file_events: List[Dict], network_events: List[Dict]) -> List[Dict]:
        """
        Identify potential data exfiltration activities.
        
        Correlates file access with network activity to detect:
        - Sensitive file access followed by network transmission
        - Data staging in temporary directories
        - Compression of documents before transmission
        - Use of legitimate cloud services for exfiltration
        
        Args:
            file_events (List[Dict]): File access and modification events
            network_events (List[Dict]): Network connection events
            
        Returns:
            List[Dict]: Potential exfiltration activities with file paths and destinations
        """
        exfiltration_activities = []
        
        # Define sensitive file patterns
        sensitive_patterns = [
            r'.*\.doc[xm]?$', r'.*\.xls[xm]?$', r'.*\.ppt[xm]?$',
            r'.*\.pdf$', r'.*\.txt$', r'.*\.csv$',
            r'.*\\Documents\\.*', r'.*\\Desktop\\.*',
            r'.*password.*', r'.*credential.*', r'.*secret.*'
        ]
        
        # Find sensitive file accesses
        sensitive_file_accesses = []
        for event in file_events:
            if event.get('operation', '').lower() in ['readfile', 'queryinformation']:
                file_path = event.get('file_path', '')
                for pattern in sensitive_patterns:
                    if re.search(pattern, file_path, re.IGNORECASE):
                        sensitive_file_accesses.append(event)
                        break
        
        # Find data staging activities
        staging_activities = []
        staging_locations = [r'.*\\temp\\.*', r'.*\\tmp\\.*', r'.*\\appdata\\.*']
        
        for event in file_events:
            if event.get('operation', '').lower() in ['createfile', 'writefile']:
                file_path = event.get('file_path', '')
                for location in staging_locations:
                    if re.search(location, file_path, re.IGNORECASE):
                        # Check if it's a compressed file
                        if any(file_path.lower().endswith(ext) for ext in ['.zip', '.rar', '.7z', '.tar']):
                            staging_activities.append({
                                'type': 'data_staging',
                                'file_path': file_path,
                                'operation': event.get('operation'),
                                'timestamp': event.get('timestamp'),
                                'process': event.get('process_name'),
                                'severity': 'medium'
                            })
                        break
        
        # Correlate file access with network activity
        time_window = timedelta(minutes=5)  # 5-minute correlation window
        
        for file_event in sensitive_file_accesses:
            file_timestamp = self._parse_timestamp(file_event.get('timestamp'))
            if not file_timestamp:
                continue
                
            # Look for network activity within time window
            for network_event in network_events:
                network_timestamp = self._parse_timestamp(network_event.get('timestamp'))
                if not network_timestamp:
                    continue
                
                time_diff = abs((network_timestamp - file_timestamp).total_seconds())
                if time_diff <= time_window.total_seconds():
                    exfiltration_activities.append({
                        'type': 'correlated_exfiltration',
                        'severity': 'high',
                        'file_access': {
                            'file_path': file_event.get('file_path'),
                            'timestamp': file_event.get('timestamp'),
                            'process': file_event.get('process_name')
                        },
                        'network_activity': {
                            'destination': network_event.get('destination_ip'),
                            'port': network_event.get('destination_port'),
                            'protocol': network_event.get('protocol'),
                            'timestamp': network_event.get('timestamp')
                        },
                        'time_correlation_seconds': time_diff,
                        'mitre_technique': 'T1041'
                    })
        
        # Add staging activities to results
        exfiltration_activities.extend(staging_activities)
        
        logger.info(f"Detected {len(exfiltration_activities)} potential data exfiltration activities")
        return exfiltration_activities
    
    def detect_evasion_techniques(self, process_events: List[Dict], system_events: List[Dict]) -> List[Dict]:
        """
        Identify anti-analysis and evasion techniques.
        
        Detects various evasion methods:
        - Anti-VM checks (hardware fingerprinting, timing attacks)
        - Anti-debugging techniques
        - Sandbox detection
        - Process name checks
        - Sleep/delay tactics
        
        Args:
            process_events (List[Dict]): Process and API call events
            system_events (List[Dict]): System-level events and queries
            
        Returns:
            List[Dict]: Detected evasion techniques with methods and effectiveness
        """
        evasion_techniques = []
        
        # Track API calls for evasion detection
        api_calls = [event for event in process_events if event.get('event_type') == 'api_call']
        
        # Detect anti-debugging techniques
        anti_debug_apis = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString']
        debug_checks = [call for call in api_calls if call.get('api_name') in anti_debug_apis]
        
        if debug_checks:
            evasion_techniques.append({
                'type': 'anti_debugging',
                'technique': 'Debugger Detection',
                'severity': 'medium',
                'api_calls': [call.get('api_name') for call in debug_checks],
                'count': len(debug_checks),
                'mitre_technique': 'T1622'
            })
        
        # Detect VM/Sandbox detection
        vm_detection_calls = []
        for call in api_calls:
            api_name = call.get('api_name', '')
            parameters = call.get('parameters', {})
            
            # Check for VM-related queries
            if api_name in ['RegQueryValueEx', 'GetSystemMetrics', 'GetComputerName']:
                for param_value in parameters.values():
                    if isinstance(param_value, str):
                        for vm_pattern in self.vm_detection_patterns:
                            if vm_pattern.lower() in param_value.lower():
                                vm_detection_calls.append(call)
                                break
        
        if vm_detection_calls:
            evasion_techniques.append({
                'type': 'vm_detection',
                'technique': 'Virtual Machine Detection',
                'severity': 'medium',
                'detection_methods': [call.get('api_name') for call in vm_detection_calls],
                'count': len(vm_detection_calls),
                'mitre_technique': 'T1497.001'
            })
        
        # Detect timing-based evasion
        sleep_calls = [call for call in api_calls if call.get('api_name') in ['Sleep', 'NtDelayExecution']]
        long_sleeps = []
        
        for call in sleep_calls:
            parameters = call.get('parameters', {})
            # Look for sleep duration parameter
            for param_name, param_value in parameters.items():
                if isinstance(param_value, (int, str)) and str(param_value).isdigit():
                    sleep_duration = int(param_value)
                    if sleep_duration > 30000:  # Sleep longer than 30 seconds
                        long_sleeps.append({
                            'api_call': call.get('api_name'),
                            'duration_ms': sleep_duration,
                            'timestamp': call.get('timestamp'),
                            'process': call.get('process_name')
                        })
        
        if long_sleeps:
            evasion_techniques.append({
                'type': 'timing_evasion',
                'technique': 'Timing-based Evasion',
                'severity': 'low',
                'sleep_calls': long_sleeps,
                'max_sleep_duration': max(sleep['duration_ms'] for sleep in long_sleeps),
                'mitre_technique': 'T1497.003'
            })
        
        # Detect process enumeration (potential sandbox detection)
        enum_apis = ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next', 'EnumProcesses']
        process_enum_calls = [call for call in api_calls if call.get('api_name') in enum_apis]
        
        if len(process_enum_calls) > 5:  # Threshold for suspicious enumeration
            evasion_techniques.append({
                'type': 'process_enumeration',
                'technique': 'Process Enumeration',
                'severity': 'low',
                'api_calls': [call.get('api_name') for call in process_enum_calls],
                'count': len(process_enum_calls),
                'mitre_technique': 'T1057'
            })
        
        # Detect file system queries (sandbox detection)
        file_queries = []
        for event in system_events:
            if event.get('event_type') == 'file_query':
                file_path = event.get('file_path', '')
                # Look for queries to sandbox-related files
                sandbox_files = ['sample', 'malware', 'virus', 'sandbox', 'analysis']
                if any(keyword in file_path.lower() for keyword in sandbox_files):
                    file_queries.append(event)
        
        if file_queries:
            evasion_techniques.append({
                'type': 'sandbox_detection',
                'technique': 'Sandbox File Detection',
                'severity': 'medium',
                'queried_files': [q.get('file_path') for q in file_queries],
                'count': len(file_queries)
            })
        
        logger.info(f"Detected {len(evasion_techniques)} evasion techniques")
        return evasion_techniques
    
    def extract_iocs(self, analysis_results: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise from analysis results.
        
        Compiles IOCs from various analysis components:
        - File paths and names
        - Registry keys and values
        - Network artifacts (IPs, domains, URLs)
        - Process names and command lines
        - Mutexes and named objects
        
        Args:
            analysis_results (Dict[str, Any]): Complete behavioral analysis results
            
        Returns:
            Dict[str, List[str]]: Categorized IOCs for threat intelligence and detection
        """
        iocs = {
            'file_paths': [],
            'file_names': [],
            'registry_keys': [],
            'registry_values': [],
            'process_names': [],
            'command_lines': [],
            'network_ips': [],
            'network_domains': [],
            'mutexes': [],
            'services': [],
            'scheduled_tasks': []
        }
        
        detected_techniques = analysis_results.get('detected_techniques', {})
        all_events = analysis_results.get('all_events', [])
        
        # Extract IOCs from persistence mechanisms
        for mechanism in detected_techniques.get('persistence_mechanisms', []):
            if mechanism.get('type') == 'registry_persistence':
                iocs['registry_keys'].append(mechanism.get('registry_key', ''))
                if mechanism.get('value_name'):
                    iocs['registry_values'].append(f"{mechanism['registry_key']}\\{mechanism['value_name']}")
            
            elif mechanism.get('type') == 'file_persistence':
                iocs['file_paths'].append(mechanism.get('file_path', ''))
                iocs['file_names'].append(os.path.basename(mechanism.get('file_path', '')))
            
            elif mechanism.get('type') == 'service_persistence':
                service_name = mechanism.get('service_key', '').split('\\')[-1]
                if service_name:
                    iocs['services'].append(service_name)
        
        # Extract IOCs from process injection
        for injection in detected_techniques.get('process_injections', []):
            if injection.get('source_process'):
                iocs['process_names'].append(injection['source_process'])
        
        # Extract IOCs from ransomware behavior
        ransomware_data = detected_techniques.get('ransomware_behavior', {})
        for encrypted_file in ransomware_data.get('encrypted_files', []):
            iocs['file_paths'].append(encrypted_file.get('file_path', ''))
            iocs['file_names'].append(os.path.basename(encrypted_file.get('file_path', '')))
        
        for ransom_note in ransomware_data.get('ransom_notes', []):
            iocs['file_paths'].append(ransom_note.get('file_path', ''))
            iocs['file_names'].append(os.path.basename(ransom_note.get('file_path', '')))
        
        # Extract IOCs from data exfiltration
        for exfil in detected_techniques.get('data_exfiltration', []):
            if exfil.get('type') == 'correlated_exfiltration':
                network_info = exfil.get('network_activity', {})
                if network_info.get('destination'):
                    # Determine if it's an IP or domain
                    dest = network_info['destination']
                    if self._is_ip_address(dest):
                        iocs['network_ips'].append(dest)
                    else:
                        iocs['network_domains'].append(dest)
        
        # Extract IOCs from all events
        for event in all_events:
            event_type = event.get('event_type', '')
            
            if event_type == 'process_create':
                process_name = event.get('process_name', '')
                command_line = event.get('command_line', '')
                if process_name:
                    iocs['process_names'].append(process_name)
                if command_line and len(command_line) > 10:  # Avoid short/common commands
                    iocs['command_lines'].append(command_line)
            
            elif event_type == 'network_connection':
                dest_ip = event.get('destination_ip', '')
                dest_domain = event.get('destination_domain', '')
                if dest_ip and self._is_ip_address(dest_ip):
                    iocs['network_ips'].append(dest_ip)
                if dest_domain:
                    iocs['network_domains'].append(dest_domain)
            
            elif event_type == 'mutex_create':
                mutex_name = event.get('mutex_name', '')
                if mutex_name:
                    iocs['mutexes'].append(mutex_name)
        
        # Remove duplicates and filter empty values
        for category in iocs:
            iocs[category] = list(set(filter(None, iocs[category])))
        
        logger.info(f"Extracted IOCs: {sum(len(v) for v in iocs.values())} total indicators")
        return iocs
    
    def calculate_threat_score(self, detected_techniques: Dict[str, List]) -> float:
        """
        Calculate an overall threat score based on detected techniques and behaviors.
        
        Weighs different types of malicious behavior:
        - Critical techniques (ransomware, data theft) = high weight
        - Persistence mechanisms = medium weight
        - Evasion techniques = medium weight
        - Process injection = high weight
        
        Args:
            detected_techniques (Dict[str, List]): All detected malicious techniques
            
        Returns:
            float: Threat score from 0-100 indicating maliciousness level
        """
        score = 0.0
        max_score = 100.0
        
        # Weight factors for different technique categories
        weights = {
            'persistence_mechanisms': 15,  # Each persistence mechanism adds 15 points
            'process_injections': 25,      # Each injection technique adds 25 points
            'ransomware_behavior': 40,     # Ransomware behavior adds up to 40 points
            'data_exfiltration': 20,       # Each exfiltration activity adds 20 points
            'evasion_techniques': 10       # Each evasion technique adds 10 points
        }
        
        # Calculate score for persistence mechanisms
        persistence_count = len(detected_techniques.get('persistence_mechanisms', []))
        score += min(persistence_count * weights['persistence_mechanisms'], 30)
        
        # Calculate score for process injections
        injection_count = len(detected_techniques.get('process_injections', []))
        score += min(injection_count * weights['process_injections'], 50)
        
        # Calculate score for ransomware behavior
        ransomware_data = detected_techniques.get('ransomware_behavior', {})
        if isinstance(ransomware_data, dict):
            confidence_score = ransomware_data.get('confidence_score', 0)
            # Use ransomware confidence score directly (already 0-100)
            score += (confidence_score / 100) * weights['ransomware_behavior']
        
        # Calculate score for data exfiltration
        exfiltration_count = len(detected_techniques.get('data_exfiltration', []))
        score += min(exfiltration_count * weights['data_exfiltration'], 40)
        
        # Calculate score for evasion techniques
        evasion_count = len(detected_techniques.get('evasion_techniques', []))
        score += min(evasion_count * weights['evasion_techniques'], 20)
        
        # Apply severity multipliers
        severity_bonus = 0
        for category, techniques in detected_techniques.items():
            if isinstance(techniques, list):
                for technique in techniques:
                    if isinstance(technique, dict):
                        severity = technique.get('severity', 'low')
                        if severity == 'critical':
                            severity_bonus += 5
                        elif severity == 'high':
                            severity_bonus += 3
                        elif severity == 'medium':
                            severity_bonus += 1
        
        score += min(severity_bonus, 15)  # Cap severity bonus at 15 points
        
        # Ensure score doesn't exceed maximum
        final_score = min(score, max_score)
        
        logger.info(f"Calculated threat score: {final_score:.2f}/100")
        return round(final_score, 2)
    
    def generate_timeline(self, all_events: List[Dict]) -> List[Dict]:
        """
        Create a chronological timeline of significant behavioral events.
        
        Processes and orders events by timestamp to show:
        - Initial execution and setup
        - Persistence establishment
        - Malicious payload execution
        - Data access and network activity
        - Cleanup and termination
        
        Args:
            all_events (List[Dict]): Combined events from all monitoring sources
            
        Returns:
            List[Dict]: Chronologically ordered significant events
        """
        timeline_events = []
        
        # Define significant event types and their importance
        significant_events = {
            'process_create': 'high',
            'registry_setvalue': 'medium',
            'file_create': 'medium',
            'file_delete': 'high',
            'network_connection': 'medium',
            'service_create': 'high',
            'mutex_create': 'low'
        }
        
        # Filter and process events
        for event in all_events:
            event_type = event.get('event_type', '')
            if event_type in significant_events:
                timeline_event = {
                    'timestamp': event.get('timestamp'),
                    'event_type': event_type,
                    'importance': significant_events[event_type],
                    'process_name': event.get('process_name', 'Unknown'),
                    'description': self._generate_event_description(event),
                    'details': event
                }
                timeline_events.append(timeline_event)
        
        # Sort events by timestamp
        timeline_events.sort(key=lambda x: self._parse_timestamp(x.get('timestamp', '')) or datetime.min)
        
        # Group events by time windows (5-minute intervals)
        grouped_timeline = []
        current_window = []
        window_start = None
        window_duration = timedelta(minutes=5)
        
        for event in timeline_events:
            event_time = self._parse_timestamp(event.get('timestamp'))
            if not event_time:
                continue
                
            if not window_start:
                window_start = event_time
                current_window = [event]
            elif event_time - window_start <= window_duration:
                current_window.append(event)
            else:
                # Close current window and start new one
                if current_window:
                    grouped_timeline.append({
                        'time_window': f"{window_start.strftime('%H:%M:%S')} - {(window_start + window_duration).strftime('%H:%M:%S')}",
                        'event_count': len(current_window),
                        'events': current_window,
                        'summary': self._summarize_window_events(current_window)
                    })
                
                window_start = event_time
                current_window = [event]
        
        # Add the last window
        if current_window:
            grouped_timeline.append({
                'time_window': f"{window_start.strftime('%H:%M:%S')} - {(window_start + window_duration).strftime('%H:%M:%S')}",
                'event_count': len(current_window),
                'events': current_window,
                'summary': self._summarize_window_events(current_window)
            })
        
        logger.info(f"Generated timeline with {len(grouped_timeline)} time windows")
        return grouped_timeline
    
    def map_to_mitre_attack(self, detected_techniques: Dict[str, List]) -> Dict[str, List[str]]:
        """
        Map detected behaviors to MITRE ATT&CK framework techniques.
        
        Correlates observed behaviors with MITRE ATT&CK:
        - Technique IDs (T1055 for Process Injection)
        - Sub-techniques where applicable
        - Tactic categories (Persistence, Defense Evasion, etc.)
        
        Args:
            detected_techniques (Dict[str, List]): Detected malicious techniques
            
        Returns:
            Dict[str, List[str]]: Mapping of behaviors to MITRE ATT&CK techniques
        """
        mitre_mapping = {
            'tactics': [],
            'techniques': [],
            'technique_details': {}
        }
        
        technique_to_tactic = {
            'T1547.001': 'Persistence',      # Registry Run Keys
            'T1543.003': 'Persistence',      # Windows Service
            'T1053.005': 'Persistence',      # Scheduled Task
            'T1055.001': 'Defense Evasion', # DLL Injection
            'T1055.012': 'Defense Evasion', # Process Hollowing
            'T1055.004': 'Defense Evasion', # APC Injection
            'T1486': 'Impact',               # Data Encrypted for Impact
            'T1490': 'Impact',               # Inhibit System Recovery
            'T1622': 'Defense Evasion',     # Debugger Evasion
            'T1497.001': 'Defense Evasion', # System Checks
            'T1497.003': 'Defense Evasion', # Time Based Evasion
            'T1041': 'Exfiltration',         # Exfiltration Over C2 Channel
            'T1057': 'Discovery'             # Process Discovery
        }
        
        # Extract MITRE techniques from detected behaviors
        all_techniques = set()
        
        for category, techniques in detected_techniques.items():
            if isinstance(techniques, list):
                for technique in techniques:
                    if isinstance(technique, dict):
                        mitre_technique = technique.get('mitre_technique')
                        if mitre_technique:
                            all_techniques.add(mitre_technique)
                            mitre_mapping['technique_details'][mitre_technique] = {
                                'category': category,
                                'description': technique.get('technique', ''),
                                'severity': technique.get('severity', 'unknown'),
                                'tactic': technique_to_tactic.get(mitre_technique, 'Unknown')
                            }
            
            elif isinstance(techniques, dict) and category == 'ransomware_behavior':
                # Special handling for ransomware behavior
                indicators = techniques.get('indicators', [])
                for indicator in indicators:
                    if isinstance(indicator, dict):
                        mitre_technique = indicator.get('mitre_technique')
                        if mitre_technique:
                            all_techniques.add(mitre_technique)
                            mitre_mapping['technique_details'][mitre_technique] = {
                                'category': category,
                                'description': indicator.get('description', ''),
                                'severity': indicator.get('severity', 'unknown'),
                                'tactic': technique_to_tactic.get(mitre_technique, 'Unknown')
                            }
        
        mitre_mapping['techniques'] = sorted(list(all_techniques))
        mitre_mapping['tactics'] = sorted(list(set(
            technique_to_tactic.get(t, 'Unknown') for t in all_techniques
        )))
        
        logger.info(f"Mapped to {len(all_techniques)} MITRE ATT&CK techniques across {len(mitre_mapping['tactics'])} tactics")
        return mitre_mapping
    
    # Helper methods
    def _extract_target_process(self, api_calls: List[Dict], api_name: str) -> Optional[str]:
        """Extract target process ID from API call parameters"""
        for call in api_calls:
            if call.get('api_name') == api_name:
                parameters = call.get('parameters', {})
                # Look for process handle or PID in parameters
                for param_name, param_value in parameters.items():
                    if 'process' in param_name.lower() or 'pid' in param_name.lower():
                        return str(param_value)
        return None
    
    def _classify_ransomware(self, confidence_score: float) -> str:
        """Classify ransomware based on confidence score"""
        if confidence_score >= 80:
            return "Highly Likely Ransomware"
        elif confidence_score >= 60:
            return "Likely Ransomware"
        elif confidence_score >= 40:
            return "Possible Ransomware"
        elif confidence_score >= 20:
            return "Ransomware Indicators Present"
        else:
            return "Low Ransomware Likelihood"
    
    def _classify_threat(self, threat_score: float, detected_techniques: Dict[str, List]) -> str:
        """Classify overall threat based on score and techniques"""
        ransomware_data = detected_techniques.get('ransomware_behavior', {})
        has_ransomware = isinstance(ransomware_data, dict) and ransomware_data.get('confidence_score', 0) > 40
        
        if threat_score >= 80 or has_ransomware:
            return "Critical Threat"
        elif threat_score >= 60:
            return "High Threat"
        elif threat_score >= 40:
            return "Medium Threat"
        elif threat_score >= 20:
            return "Low Threat"
        else:
            return "Minimal Threat"
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime object"""
        if not timestamp_str:
            return None
            
        # Try common timestamp formats
        formats = [
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%m/%d/%Y %H:%M:%S',
            '%d/%m/%Y %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        return None
    
    def _is_ip_address(self, address: str) -> bool:
        """Check if string is a valid IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def _generate_event_description(self, event: Dict) -> str:
        """Generate human-readable description for timeline event"""
        event_type = event.get('event_type', '')
        process_name = event.get('process_name', 'Unknown')
        
        if event_type == 'process_create':
            command_line = event.get('command_line', '')
            return f"Process created: {process_name} {command_line[:50]}{'...' if len(command_line) > 50 else ''}"
        
        elif event_type == 'registry_setvalue':
            key_path = event.get('key_path', '')
            value_name = event.get('value_name', '')
            return f"Registry modified: {key_path}\\{value_name}"
        
        elif event_type == 'file_create':
            file_path = event.get('file_path', '')
            return f"File created: {os.path.basename(file_path)}"
        
        elif event_type == 'file_delete':
            file_path = event.get('file_path', '')
            return f"File deleted: {os.path.basename(file_path)}"
        
        elif event_type == 'network_connection':
            dest_ip = event.get('destination_ip', '')
            dest_port = event.get('destination_port', '')
            return f"Network connection: {dest_ip}:{dest_port}"
        
        else:
            return f"{event_type.replace('_', ' ').title()}"
    
    def _summarize_window_events(self, events: List[Dict]) -> str:
        """Summarize events in a time window"""
        if not events:
            return "No significant activity"
        
        event_types = Counter(event.get('event_type', '') for event in events)
        processes = set(event.get('process_name', '') for event in events)
        processes.discard('')
        
        summary_parts = []
        
        if event_types.get('process_create', 0) > 0:
            summary_parts.append(f"{event_types['process_create']} process(es) created")
        
        if event_types.get('registry_setvalue', 0) > 0:
            summary_parts.append(f"{event_types['registry_setvalue']} registry modification(s)")
        
        if event_types.get('file_create', 0) + event_types.get('file_delete', 0) > 0:
            file_ops = event_types.get('file_create', 0) + event_types.get('file_delete', 0)
            summary_parts.append(f"{file_ops} file operation(s)")
        
        if event_types.get('network_connection', 0) > 0:
            summary_parts.append(f"{event_types['network_connection']} network connection(s)")
        
        if len(processes) > 0:
            summary_parts.append(f"Processes: {', '.join(list(processes)[:3])}")
        
        return "; ".join(summary_parts) if summary_parts else "Mixed activity"