# shikra/reporting/modules/reporting/timeline_analyzer.py
# Purpose: Analyzes temporal patterns in malware behavior and creates interactive timelines

import json
import logging
import os
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
from typing import Dict, List, Tuple, Optional, Any
import re

logger = logging.getLogger(__name__)

class TimelineAnalyzer:
    """
    Advanced timeline analysis for malware behavior correlation and pattern detection.
    Creates interactive timelines showing the sequence of malicious activities.
    """
    
    def __init__(self, config_settings: dict = None):
        self.config = config_settings or {}
        self.events = []
        self.timeline_data = {
            "metadata": {
                "analysis_start": None,
                "analysis_end": None,
                "total_events": 0,
                "event_categories": {},
                "critical_periods": []
            },
            "timeline": [],
            "patterns": {
                "burst_activities": [],
                "periodic_behaviors": [],
                "attack_phases": []
            },
            "correlations": {
                "process_chains": [],
                "file_network_correlation": [],
                "registry_file_correlation": []
            }
        }
        self.attack_phases = {
            "initial_access": {"keywords": ["createfile", "process", "load"], "weight": 1.0},
            "execution": {"keywords": ["createprocess", "thread", "execute"], "weight": 1.2},
            "persistence": {"keywords": ["registry", "run", "startup", "service"], "weight": 1.5},
            "privilege_escalation": {"keywords": ["token", "privilege", "admin"], "weight": 1.3},
            "defense_evasion": {"keywords": ["delete", "hide", "modify", "disable"], "weight": 1.4},
            "credential_access": {"keywords": ["lsass", "sam", "password", "credential"], "weight": 1.6},
            "discovery": {"keywords": ["enum", "query", "list", "find"], "weight": 1.1},
            "lateral_movement": {"keywords": ["network", "share", "remote", "wmi"], "weight": 1.3},
            "collection": {"keywords": ["copy", "compress", "archive", "collect"], "weight": 1.2},
            "command_control": {"keywords": ["http", "dns", "tcp", "connect"], "weight": 1.7},
            "exfiltration": {"keywords": ["upload", "send", "transmit", "ftp"], "weight": 1.8},
            "impact": {"keywords": ["encrypt", "delete", "destroy", "ransom"], "weight": 2.0}
        }

    def load_behavioral_data(self, behavioral_json_path: str) -> bool:
        """Load behavioral analysis results and extract temporal events."""
        try:
            with open(behavioral_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract events from behavioral analysis
            self._extract_process_events(data.get('process_operations', {}))
            self._extract_file_events(data.get('file_operations', {}))
            self._extract_registry_events(data.get('registry_operations', {}))
            self._extract_network_events(data.get('network_operations', {}))
            
            logger.info(f"Loaded {len(self.events)} behavioral events for timeline analysis")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load behavioral data: {e}")
            return False

    def load_network_data(self, network_json_path: str) -> bool:
        """Load network analysis results and extract temporal events."""
        try:
            with open(network_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract network events
            self._extract_dns_events(data.get('dns_queries', []))
            self._extract_http_events(data.get('http_requests', []))
            self._extract_tls_events(data.get('tls_connections', []))
            
            logger.info(f"Added network events to timeline (total: {len(self.events)})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load network data: {e}")
            return False

    def _extract_process_events(self, process_ops: dict):
        """Extract process-related events with timestamps."""
        processes = process_ops.get('processes_created', [])
        for proc in processes:
            event = {
                'timestamp': self._parse_timestamp(proc.get('timestamp', '')),
                'category': 'process',
                'subcategory': 'creation',
                'severity': self._calculate_process_severity(proc),
                'description': f"Process created: {proc.get('command', 'Unknown')}",
                'details': {
                    'parent_process': proc.get('parent_process', ''),
                    'child_process': proc.get('child_process_name', ''),
                    'command_line': proc.get('command', ''),
                    'pid': proc.get('child_pid', ''),
                    'ppid': proc.get('parent_pid', '')
                },
                'phase': self._classify_attack_phase(proc.get('command', ''))
            }
            self.events.append(event)

    def _extract_file_events(self, file_ops: dict):
        """Extract file operation events with timestamps."""
        for op_type, operations in file_ops.items():
            if not isinstance(operations, list):
                continue
                
            for op in operations:
                event = {
                    'timestamp': self._parse_timestamp(op.get('timestamp', '')),
                    'category': 'file',
                    'subcategory': op_type.lower(),
                    'severity': self._calculate_file_severity(op, op_type),
                    'description': f"File {op_type}: {op.get('path', 'Unknown')}",
                    'details': {
                        'operation': op_type,
                        'path': op.get('path', ''),
                        'process': op.get('process', ''),
                        'pid': op.get('pid', '')
                    },
                    'phase': self._classify_attack_phase(op.get('path', ''))
                }
                self.events.append(event)

    def _extract_registry_events(self, registry_ops: dict):
        """Extract registry operation events with timestamps."""
        for op_type, operations in registry_ops.items():
            if not isinstance(operations, list):
                continue
                
            for op in operations:
                event = {
                    'timestamp': self._parse_timestamp(op.get('timestamp', '')),
                    'category': 'registry',
                    'subcategory': op_type.lower(),
                    'severity': self._calculate_registry_severity(op),
                    'description': f"Registry {op_type}: {op.get('key', 'Unknown')}",
                    'details': {
                        'operation': op_type,
                        'key': op.get('key', ''),
                        'value': op.get('value', ''),
                        'process': op.get('process', ''),
                        'pid': op.get('pid', '')
                    },
                    'phase': self._classify_attack_phase(op.get('key', ''))
                }
                self.events.append(event)

    def _extract_network_events(self, network_ops: dict):
        """Extract network operation events from behavioral data."""
        for protocol, connections in network_ops.items():
            if not isinstance(connections, list):
                continue
                
            for conn in connections:
                event = {
                    'timestamp': self._parse_timestamp(conn.get('timestamp', '')),
                    'category': 'network',
                    'subcategory': protocol.lower(),
                    'severity': self._calculate_network_severity(conn),
                    'description': f"{protocol} connection to {conn.get('destination', 'Unknown')}",
                    'details': {
                        'protocol': protocol,
                        'destination': conn.get('destination', ''),
                        'process': conn.get('process', ''),
                        'pid': conn.get('pid', '')
                    },
                    'phase': 'command_control'  # Most network activity is C2
                }
                self.events.append(event)

    def _extract_dns_events(self, dns_queries: list):
        """Extract DNS query events from network data."""
        for query in dns_queries:
            event = {
                'timestamp': self._parse_timestamp_epoch(query.get('timestamp_epoch')),
                'category': 'network',
                'subcategory': 'dns',
                'severity': self._calculate_dns_severity(query),
                'description': f"DNS query: {query.get('query_name', 'Unknown')}",
                'details': {
                    'query_name': query.get('query_name', ''),
                    'query_type': query.get('query_type_str', ''),
                    'source_ip': query.get('source_ip', ''),
                    'dest_ip': query.get('dest_ip', ''),
                    'responses': query.get('responses', [])
                },
                'phase': 'command_control'
            }
            self.events.append(event)

    def _extract_http_events(self, http_requests: list):
        """Extract HTTP request events from network data."""
        for req in http_requests:
            event = {
                'timestamp': self._parse_timestamp_epoch(req.get('timestamp_epoch')),
                'category': 'network',
                'subcategory': 'http',
                'severity': self._calculate_http_severity(req),
                'description': f"HTTP {req.get('http_method', 'GET')} to {req.get('http_host', 'Unknown')}",
                'details': {
                    'method': req.get('http_method', ''),
                    'host': req.get('http_host', ''),
                    'uri': req.get('http_uri', ''),
                    'user_agent': req.get('http_user_agent', ''),
                    'source_ip': req.get('source_ip', ''),
                    'dest_ip': req.get('dest_ip', '')
                },
                'phase': self._classify_http_phase(req)
            }
            self.events.append(event)

    def _extract_tls_events(self, tls_connections: list):
        """Extract TLS connection events from network data."""
        for conn in tls_connections:
            event = {
                'timestamp': self._parse_timestamp_epoch(conn.get('timestamp_epoch')),
                'category': 'network',
                'subcategory': 'tls',
                'severity': self._calculate_tls_severity(conn),
                'description': f"TLS connection to {conn.get('tls_sni', conn.get('dest_ip', 'Unknown'))}",
                'details': {
                    'sni': conn.get('tls_sni', ''),
                    'dest_ip': conn.get('dest_ip', ''),
                    'source_ip': conn.get('source_ip', ''),
                    'dest_port': conn.get('dest_port', '')
                },
                'phase': 'command_control'
            }
            self.events.append(event)

    def analyze_timeline(self) -> dict:
        """Perform comprehensive timeline analysis."""
        if not self.events:
            logger.warning("No events to analyze")
            return self.timeline_data
        
        # Sort events by timestamp
        self.events.sort(key=lambda x: x['timestamp'] or datetime.min)
        
        # Update metadata
        valid_timestamps = [e['timestamp'] for e in self.events if e['timestamp']]
        if valid_timestamps:
            self.timeline_data['metadata']['analysis_start'] = min(valid_timestamps).isoformat()
            self.timeline_data['metadata']['analysis_end'] = max(valid_timestamps).isoformat()
        
        self.timeline_data['metadata']['total_events'] = len(self.events)
        
        # Count events by category
        category_counts = defaultdict(int)
        for event in self.events:
            category_counts[event['category']] += 1
        self.timeline_data['metadata']['event_categories'] = dict(category_counts)
        
        # Detect patterns
        self._detect_burst_activities()
        self._detect_periodic_behaviors()
        self._identify_attack_phases()
        self._detect_critical_periods()
        
        # Find correlations
        self._correlate_process_chains()
        self._correlate_file_network_activities()
        self._correlate_registry_file_operations()
        
        # Create timeline entries
        self._create_timeline_entries()
        
        logger.info(f"Timeline analysis completed for {len(self.events)} events")
        return self.timeline_data

    def _detect_burst_activities(self):
        """Detect periods of high activity (potential attack phases)."""
        time_windows = defaultdict(int)
        window_size = timedelta(minutes=5)  # 5-minute windows
        
        for event in self.events:
            if not event['timestamp']:
                continue
            # Round timestamp to nearest window
            window_start = event['timestamp'].replace(second=0, microsecond=0)
            window_start = window_start.replace(minute=(window_start.minute // 5) * 5)
            time_windows[window_start] += 1
        
        # Find windows with high activity
        if time_windows:
            avg_activity = sum(time_windows.values()) / len(time_windows)
            threshold = avg_activity * 2  # 2x average activity
            
            for window_start, count in time_windows.items():
                if count >= threshold:
                    self.timeline_data['patterns']['burst_activities'].append({
                        'start_time': window_start.isoformat(),
                        'end_time': (window_start + window_size).isoformat(),
                        'event_count': count,
                        'intensity': count / avg_activity
                    })

    def _detect_periodic_behaviors(self):
        """Detect repeating patterns (potential beaconing or scheduled tasks)."""
        # Group events by similar descriptions
        pattern_groups = defaultdict(list)
        for event in self.events:
            if not event['timestamp']:
                continue
            # Create pattern key from event type and target
            pattern_key = f"{event['category']}_{event['subcategory']}"
            if event['category'] == 'network':
                pattern_key += f"_{event['details'].get('destination', '')}"
            elif event['category'] == 'file':
                # Use directory instead of full path for pattern matching
                path = event['details'].get('path', '')
                pattern_key += f"_{os.path.dirname(path)}"
            
            pattern_groups[pattern_key].append(event['timestamp'])
        
        # Analyze intervals for each pattern
        for pattern, timestamps in pattern_groups.items():
            if len(timestamps) < 3:  # Need at least 3 occurrences
                continue
            
            timestamps.sort()
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                # Check for consistency (standard deviation < 30% of mean)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                
                if std_dev < (avg_interval * 0.3) and avg_interval > 10:  # At least 10 seconds
                    self.timeline_data['patterns']['periodic_behaviors'].append({
                        'pattern': pattern,
                        'occurrences': len(timestamps),
                        'average_interval': avg_interval,
                        'consistency': 1 - (std_dev / avg_interval),
                        'first_seen': timestamps[0].isoformat(),
                        'last_seen': timestamps[-1].isoformat()
                    })

    def _identify_attack_phases(self):
        """Identify and timeline attack phases using MITRE ATT&CK framework.""" 
        phase_events = defaultdict(list)
        
        for event in self.events:
            phase = event.get('phase', 'unknown')
            if phase != 'unknown':
                phase_events[phase].append(event)
        
        for phase, events in phase_events.items():
            if not events:
                continue
            
            events.sort(key=lambda x: x['timestamp'] or datetime.min)
            valid_events = [e for e in events if e['timestamp']]
            
            if valid_events:
                self.timeline_data['patterns']['attack_phases'].append({
                    'phase': phase,
                    'event_count': len(events),
                    'first_activity': valid_events[0]['timestamp'].isoformat(),
                    'last_activity': valid_events[-1]['timestamp'].isoformat(),
                    'duration': (valid_events[-1]['timestamp'] - valid_events[0]['timestamp']).total_seconds(),
                    'severity_score': sum(e['severity'] for e in events) / len(events)
                })

    def _detect_critical_periods(self):
        """Identify time periods with the highest-severity events."""
        high_severity_events = [e for e in self.events if e['severity'] >= 0.7 and e['timestamp']]
        
        if not high_severity_events:
            return
        
        # Group high-severity events by time proximity (within 10 minutes)
        critical_periods = []
        current_period = []
        
        high_severity_events.sort(key=lambda x: x['timestamp'])
        
        for event in high_severity_events:
            if not current_period:
                current_period = [event]
            else:
                # Check if event is within 10 minutes of the last event in current period
                time_diff = (event['timestamp'] - current_period[-1]['timestamp']).total_seconds()
                if time_diff <= 600:  # 10 minutes
                    current_period.append(event)
                else:
                    # Save current period and start new one
                    if len(current_period) >= 2:  # At least 2 high-severity events
                        critical_periods.append(current_period)
                    current_period = [event]
        
        # Don't forget the last period
        if len(current_period) >= 2:
            critical_periods.append(current_period)
        
        # Convert to timeline format
        for period in critical_periods:
            self.timeline_data['metadata']['critical_periods'].append({
                'start_time': period[0]['timestamp'].isoformat(),
                'end_time': period[-1]['timestamp'].isoformat(),
                'event_count': len(period),
                'average_severity': sum(e['severity'] for e in period) / len(period),
                'primary_categories': list(set(e['category'] for e in period)),
                'description': f"Critical activity period with {len(period)} high-severity events"
            })

    def _correlate_process_chains(self):
        """Find process creation chains and execution flows."""
        process_events = [e for e in self.events if e['category'] == 'process']
        
        # Build parent-child relationships
        processes = {}
        chains = []
        
        for event in process_events:
            pid = event['details'].get('pid')
            ppid = event['details'].get('ppid')
            
            if pid:
                processes[pid] = {
                    'event': event,
                    'children': [],
                    'parent': ppid
                }
        
        # Build chains
        for pid, proc_info in processes.items():
            if proc_info['parent'] in processes:
                processes[proc_info['parent']]['children'].append(pid)
        
        # Find chain roots and build sequences
        for pid, proc_info in processes.items():
            if proc_info['parent'] not in processes:  # Root process
                chain = self._build_process_chain(pid, processes)
                if len(chain) > 1:  # Only interested in chains, not single processes
                    chains.append(chain)
        
        self.timeline_data['correlations']['process_chains'] = chains

    def _build_process_chain(self, pid: str, processes: dict) -> list:
        """Recursively build a process execution chain."""
        chain = []
        if pid in processes:
            proc_info = processes[pid]
            chain.append({
                'pid': pid,
                'command': proc_info['event']['details'].get('command_line', ''),
                'timestamp': proc_info['event']['timestamp'].isoformat() if proc_info['event']['timestamp'] else None,
                'severity': proc_info['event']['severity']
            })
            
            # Add children
            for child_pid in proc_info['children']:
                chain.extend(self._build_process_chain(child_pid, processes))
        
        return chain

    def _correlate_file_network_activities(self):
        """Correlate file operations with network activities."""
        file_events = [e for e in self.events if e['category'] == 'file']
        network_events = [e for e in self.events if e['category'] == 'network']
        
        correlations = []
        
        for file_event in file_events:
            file_timestamp = file_event['timestamp']
            if not file_timestamp:
                continue
            
            # Look for network events within 30 seconds
            for net_event in network_events:
                net_timestamp = net_event['timestamp']
                if not net_timestamp:
                    continue
                
                time_diff = abs((net_timestamp - file_timestamp).total_seconds())
                if time_diff <= 30:  # Within 30 seconds
                    correlations.append({
                        'file_event': {
                            'timestamp': file_event['timestamp'].isoformat(),
                            'path': file_event['details'].get('path', ''),
                            'operation': file_event['subcategory']
                        },
                        'network_event': {
                            'timestamp': net_event['timestamp'].isoformat(),
                            'destination': net_event['details'].get('destination', ''),
                            'protocol': net_event['subcategory']
                        },
                        'time_difference': time_diff,
                        'correlation_strength': max(0, 1 - (time_diff / 30))
                    })
        
        # Sort by correlation strength
        correlations.sort(key=lambda x: x['correlation_strength'], reverse=True)
        self.timeline_data['correlations']['file_network_correlation'] = correlations[:20]  # Top 20

    def _correlate_registry_file_operations(self):
        """Correlate registry modifications with file operations."""
        registry_events = [e for e in self.events if e['category'] == 'registry']
        file_events = [e for e in self.events if e['category'] == 'file']
        
        correlations = []
        
        for reg_event in registry_events:
            reg_timestamp = reg_event['timestamp']
            if not reg_timestamp:
                continue
            
            # Look for file events within 60 seconds
            for file_event in file_events:
                file_timestamp = file_event['timestamp']
                if not file_timestamp:
                    continue
                
                time_diff = abs((file_timestamp - reg_timestamp).total_seconds())
                if time_diff <= 60:  # Within 60 seconds
                    correlations.append({
                        'registry_event': {
                            'timestamp': reg_event['timestamp'].isoformat(),
                            'key': reg_event['details'].get('key', ''),
                            'value': reg_event['details'].get('value', ''),
                            'operation': reg_event['subcategory']
                        },
                        'file_event': {
                            'timestamp': file_event['timestamp'].isoformat(),
                            'path': file_event['details'].get('path', ''),
                            'operation': file_event['subcategory']
                        },
                        'time_difference': time_diff,
                        'correlation_strength': max(0, 1 - (time_diff / 60))
                    })
        
        # Sort by correlation strength
        correlations.sort(key=lambda x: x['correlation_strength'], reverse=True)
        self.timeline_data['correlations']['registry_file_correlation'] = correlations[:20]  # Top 20

    def _create_timeline_entries(self):
        """Create the main timeline entries for visualization."""
        for event in self.events:
            if not event['timestamp']:
                continue
            
            timeline_entry = {
                'timestamp': event['timestamp'].isoformat(),
                'category': event['category'],
                'subcategory': event['subcategory'],
                'severity': event['severity'],
                'description': event['description'],
                'phase': event.get('phase', 'unknown'),
                'details': event['details'],
                'color': self._get_event_color(event),
                'icon': self._get_event_icon(event)
            }
            
            self.timeline_data['timeline'].append(timeline_entry)

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats."""
        if not timestamp_str:
            return None
        
        # Common timestamp formats
        formats = [
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%m/%d/%Y %H:%M:%S.%f',
            '%m/%d/%Y %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        logger.debug(f"Unable to parse timestamp: {timestamp_str}")
        return None

    def _parse_timestamp_epoch(self, epoch_time: float) -> Optional[datetime]:
        """Parse epoch timestamp."""
        if not epoch_time:
            return None
        try:
            return datetime.fromtimestamp(float(epoch_time))
        except (ValueError, TypeError):
            return None

    def _calculate_process_severity(self, proc: dict) -> float:
        """Calculate severity score for process events."""
        severity = 0.3  # Base severity
        
        command = proc.get('command', '').lower()
        suspicious_commands = [
            'powershell', 'cmd', 'wscript', 'cscript', 'regsvr32', 'rundll32',
            'mshta', 'bitsadmin', 'certutil', 'wmic', 'schtasks'
        ]
        
        for sus_cmd in suspicious_commands:
            if sus_cmd in command:
                severity += 0.2
                
        # Check for suspicious arguments
        suspicious_args = ['-enc', '-hidden', '-windowstyle', '/c', 'delete', 'shadows']
        for arg in suspicious_args:
            if arg in command:
                severity += 0.1
        
        return min(1.0, severity)

    def _calculate_file_severity(self, file_op: dict, op_type: str) -> float:
        """Calculate severity score for file operations."""
        severity = 0.2  # Base severity
        
        path = file_op.get('path', '').lower()
        
        # High-risk locations
        high_risk_paths = [
            'system32', 'windows', 'program files', 'startup', 'temp',
            'appdata\\roaming', 'documents'
        ]
        
        for risk_path in high_risk_paths:
            if risk_path in path:
                severity += 0.2
                break
        
        # High-risk operations
        if op_type.lower() in ['deletefile', 'setendoffileinformationfile']:
            severity += 0.3
        elif op_type.lower() in ['createfile', 'writefile']:
            severity += 0.1
        
        # Suspicious file extensions
        suspicious_extensions = ['.exe', '.dll', '.scr', '.bat', '.vbs', '.ps1']
        for ext in suspicious_extensions:
            if path.endswith(ext):
                severity += 0.2
                break
        
        return min(1.0, severity)

    def _calculate_registry_severity(self, reg_op: dict) -> float:
        """Calculate severity score for registry operations."""
        severity = 0.4  # Base severity (registry changes are inherently more suspicious)
        
        key = reg_op.get('key', '').lower()
        
        # High-risk registry locations
        high_risk_keys = [
            'currentversion\\run', 'currentversion\\runonce', 'winlogon',
            'userinit', 'shell', 'load', 'services', 'policies'
        ]
        
        for risk_key in high_risk_keys:
            if risk_key in key:
                severity += 0.4
                break
        
        return min(1.0, severity)

    def _calculate_network_severity(self, net_op: dict) -> float:
        """Calculate severity score for network operations."""
        severity = 0.3  # Base severity
        
        destination = net_op.get('destination', '').lower()
        
        # Suspicious domains/IPs
        if any(keyword in destination for keyword in ['.onion', 'pastebin', 'temp', 'bit']):
            severity += 0.4
        
        # External IPs (not local)
        if not any(destination.startswith(local) for local in ['192.168.', '10.', '172.16.', '127.']):
            severity += 0.2
        
        return min(1.0, severity)

    def _calculate_dns_severity(self, query: dict) -> float:
        """Calculate severity score for DNS queries."""
        severity = 0.2  # Base severity
        
        query_name = query.get('query_name', '').lower()
        
        # Suspicious domains
        suspicious_indicators = [
            '.onion', '.bit', 'temp', 'pastebin', 'duckdns', 'no-ip',
            'dynamicdns', 'hopto'
        ]
        
        for indicator in suspicious_indicators:
            if indicator in query_name:
                severity += 0.3
                break
        
        # DGA-like domains (very long, random-looking)
        if len(query_name) > 20 and query_name.count('.') <= 2:
            # Simple entropy check
            unique_chars = len(set(query_name.replace('.', '')))
            if unique_chars > 8:  # High character diversity
                severity += 0.4
        
        return min(1.0, severity)

    def _calculate_http_severity(self, request: dict) -> float:
        """Calculate severity score for HTTP requests."""
        severity = 0.3  # Base severity
        
        host = request.get('http_host', '').lower()
        uri = request.get('http_uri', '').lower()
        
        # Suspicious hosts
        suspicious_hosts = ['.onion', 'pastebin', 'temp', 'bit', 'no-ip']
        for sus_host in suspicious_hosts:
            if sus_host in host:
                severity += 0.3
                break
        
        # Suspicious URIs
        suspicious_uris = ['/gate.php', '/panel/', '/check.php', '/stats.php']
        for sus_uri in suspicious_uris:
            if sus_uri in uri:
                severity += 0.3
                break
        
        return min(1.0, severity)

    def _calculate_tls_severity(self, connection: dict) -> float:
        """Calculate severity score for TLS connections."""
        severity = 0.25  # Base severity
        
        sni = connection.get('tls_sni', '').lower()
        
        if sni:
            # Suspicious SNI
            if any(keyword in sni for keyword in ['.onion', 'temp', 'bit']):
                severity += 0.4
        else:
            # No SNI could indicate evasion
            severity += 0.2
        
        return min(1.0, severity)

    def _classify_attack_phase(self, context: str) -> str:
        """Classify an event into MITRE ATT&CK phase based on context."""
        context_lower = context.lower()
        
        for phase, config in self.attack_phases.items():
            for keyword in config['keywords']:
                if keyword in context_lower:
                    return phase
        
        return 'unknown'

    def _classify_http_phase(self, request: dict) -> str:
        """Classify HTTP request into attack phase."""
        method = request.get('http_method', '').upper()
        uri = request.get('http_uri', '').lower()
        
        if method == 'POST':
            if any(keyword in uri for keyword in ['upload', 'send', 'submit']):
                return 'exfiltration'
            else:
                return 'command_control'
        elif method == 'GET':
            if any(keyword in uri for keyword in ['download', 'get', 'fetch']):
                return 'collection'
            else:
                return 'command_control'
        
        return 'command_control'

    def _get_event_color(self, event: dict) -> str:
        """Get color for timeline visualization based on event properties."""
        severity = event['severity']
        category = event['category']
        
        # Base colors by category
        category_colors = {
            'process': '#FF6B6B',    # Red family
            'file': '#4ECDC4',       # Teal family  
            'registry': '#45B7D1',   # Blue family
            'network': '#96CEB4'     # Green family
        }
        
        base_color = category_colors.get(category, '#95A5A6')
        
        # Adjust intensity based on severity
        if severity >= 0.8:
            return base_color  # Full intensity
        elif severity >= 0.6:
            return base_color + 'CC'  # 80% opacity
        elif severity >= 0.4:
            return base_color + '99'  # 60% opacity
        else:
            return base_color + '66'  # 40% opacity

    def _get_event_icon(self, event: dict) -> str:
        """Get icon name for timeline visualization."""
        category = event['category']
        subcategory = event['subcategory']
        
        icon_map = {
            'process': {
                'creation': 'fas fa-cogs',
                'default': 'fas fa-microchip'
            },
            'file': {
                'createfile': 'fas fa-file-plus',
                'writefile': 'fas fa-file-edit',
                'deletefile': 'fas fa-file-minus',
                'default': 'fas fa-file'
            },
            'registry': {
                'regsetvalue': 'fas fa-edit',
                'regdeletevalue': 'fas fa-trash',
                'default': 'fas fa-database'
            },
            'network': {
                'dns': 'fas fa-search',
                'http': 'fas fa-globe',
                'tls': 'fas fa-lock',
                'tcp': 'fas fa-network-wired',
                'default': 'fas fa-wifi'
            }
        }
        
        return icon_map.get(category, {}).get(subcategory, 
                icon_map.get(category, {}).get('default', 'fas fa-question'))

    def export_timeline_data(self, output_path: str) -> bool:
        """Export timeline analysis results to JSON file."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.timeline_data, f, indent=2, default=str)
            logger.info(f"Timeline data exported to: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export timeline data: {e}")
            return False

    def generate_timeline_summary(self) -> dict:
        """Generate a summary of timeline analysis for reports."""
        summary = {
            'total_events': len(self.events),
            'analysis_duration': None,
            'event_distribution': {},
            'severity_distribution': {'high': 0, 'medium': 0, 'low': 0},
            'attack_phases_detected': [],
            'critical_periods_count': len(self.timeline_data['metadata']['critical_periods']),
            'correlations_found': {
                'process_chains': len(self.timeline_data['correlations']['process_chains']),
                'file_network': len(self.timeline_data['correlations']['file_network_correlation']),
                'registry_file': len(self.timeline_data['correlations']['registry_file_correlation'])
            },
            'patterns_detected': {
                'burst_activities': len(self.timeline_data['patterns']['burst_activities']),
                'periodic_behaviors': len(self.timeline_data['patterns']['periodic_behaviors'])
            }
        }
        
        # Calculate analysis duration
        if (self.timeline_data['metadata']['analysis_start'] and 
            self.timeline_data['metadata']['analysis_end']):
            start = datetime.fromisoformat(self.timeline_data['metadata']['analysis_start'])
            end = datetime.fromisoformat(self.timeline_data['metadata']['analysis_end'])
            summary['analysis_duration'] = (end - start).total_seconds()
        
        # Event distribution by category
        summary['event_distribution'] = self.timeline_data['metadata']['event_categories']
        
        # Severity distribution
        for event in self.events:
            severity = event['severity']
            if severity >= 0.7:
                summary['severity_distribution']['high'] += 1
            elif severity >= 0.4:
                summary['severity_distribution']['medium'] += 1
            else:
                summary['severity_distribution']['low'] += 1
        
        # Attack phases detected
        summary['attack_phases_detected'] = [
            phase['phase'] for phase in self.timeline_data['patterns']['attack_phases']
        ]
        
        return summary


# Main function for module integration
def analyze_timeline_from_files(behavioral_json_path: str, network_json_path: str = None, 
                               output_path: str = None) -> dict:
    """
    Analyze timeline from analysis result files.
    
    Args:
        behavioral_json_path (str): Path to behavioral analysis JSON
        network_json_path (str, optional): Path to network analysis JSON  
        output_path (str, optional): Path to save timeline analysis results
        
    Returns:
        dict: Timeline analysis results
    """
    analyzer = TimelineAnalyzer()
    
    # Load data
    if not analyzer.load_behavioral_data(behavioral_json_path):
        logger.error("Failed to load behavioral data")
        return {}
    
    if network_json_path and os.path.exists(network_json_path):
        analyzer.load_network_data(network_json_path)
    
    # Perform analysis
    results = analyzer.analyze_timeline()
    
    # Export if path provided
    if output_path:
        analyzer.export_timeline_data(output_path)
    
    return results


if __name__ == '__main__':
    import argparse
    
    logging.basicConfig(level=logging.INFO, 
                       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    parser = argparse.ArgumentParser(description='Shikra Timeline Analyzer')
    parser.add_argument('--behavioral-json', required=True, 
                       help='Path to behavioral analysis JSON file')
    parser.add_argument('--network-json', 
                       help='Path to network analysis JSON file')
    parser.add_argument('--output', 
                       help='Path to save timeline analysis results')
    
    args = parser.parse_args()
    
    # Create dummy data if files don't exist (for testing)
    if not os.path.exists(args.behavioral_json):
        dummy_behavioral = {
            'process_operations': {
                'processes_created': [
                    {
                        'timestamp': '2024-01-01 10:00:00',
                        'parent_process': 'explorer.exe',
                        'child_process_name': 'cmd.exe',
                        'command': 'cmd.exe /c whoami',
                        'child_pid': '1234',
                        'parent_pid': '5678'
                    }
                ]
            },
            'file_operations': {
                'CreateFile': [
                    {
                        'timestamp': '2024-01-01 10:00:30',
                        'process': 'cmd.exe',
                        'path': 'C:\\Windows\\Temp\\malware.exe',
                        'pid': '1234'
                    }
                ]
            },
            'registry_operations': {
                'RegSetValue': [
                    {
                        'timestamp': '2024-01-01 10:01:00',
                        'process': 'malware.exe',
                        'key': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil',
                        'value': 'C:\\Windows\\Temp\\malware.exe',
                        'pid': '9999'
                    }
                ]
            },
            'network_operations': {
                'TCP': [
                    {
                        'timestamp': '2024-01-01 10:02:00',
                        'process': 'malware.exe',
                        'destination': '192.168.1.100:4444',
                        'pid': '9999'
                    }
                ]
            }
        }
        
        os.makedirs(os.path.dirname(args.behavioral_json), exist_ok=True)
        with open(args.behavioral_json, 'w') as f:
            json.dump(dummy_behavioral, f, indent=2)
        logger.info(f"Created dummy behavioral data at {args.behavioral_json}")
    
    # Run analysis
    results = analyze_timeline_from_files(
        behavioral_json_path=args.behavioral_json,
        network_json_path=args.network_json,
        output_path=args.output
    )
    
    if results:
        logger.info("Timeline analysis completed successfully")
        summary = TimelineAnalyzer().generate_timeline_summary() if hasattr(TimelineAnalyzer(), 'events') else {}
        print(f"Analysis Summary: {json.dumps(summary, indent=2)}")
    else:
        logger.error("Timeline analysis failed")