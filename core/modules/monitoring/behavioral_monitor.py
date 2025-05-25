# # shikra/core/modules/monitoring/behavioral_monitor.py
# # Purpose: Real-time behavioral monitoring and threat detection during malware execution
# #          Provides live analysis capabilities beyond static log processing

# import json
# import logging
# import threading
# import time
# import queue
# from collections import defaultdict, deque
# from datetime import datetime, timedelta
# from typing import Dict, List, Optional, Callable, Any
# import os
# import re

# logger = logging.getLogger(__name__)

# class RealTimeAnalyzer:
#     """
#     Real-time analysis engine for processing behavioral events as they occur.
    
#     Features:
#     - Live event processing and correlation
#     - Immediate threat detection and alerting
#     - Behavioral pattern recognition in real-time
#     - Memory-efficient sliding window analysis
#     """
    
#     def __init__(self, config_settings: dict = None):
#         """
#         Initialize the real-time analyzer.
        
#         Args:
#             config_settings: Configuration dictionary
#         """
#         self.config = config_settings or {}
#         self.event_queue = queue.Queue(maxsize=10000)
#         self.analysis_thread = None
#         self.running = False
        
#         # Sliding window for temporal analysis
#         self.time_window_seconds = self.config.get("time_window_seconds", 300)
#         self.event_history = deque(maxlen=1000)
        
#         # Real-time detection patterns
#         self.detection_patterns = self._load_detection_patterns()
        
#         # Alert callbacks
#         self.alert_callbacks = []
        
#         # Statistics tracking
#         self.stats = {
#             "events_processed": 0,
#             "alerts_triggered": 0,
#             "patterns_matched": 0,
#             "analysis_start_time": None
#         }
        
#     def _load_detection_patterns(self) -> Dict[str, Dict]:
#         """Load real-time detection patterns from configuration."""
        
#         patterns = {
#             "mass_file_encryption": {
#                 "type": "file_operations",
#                 "threshold": 20,
#                 "time_window": 120,
#                 "severity": "critical",
#                 "description": "Mass file modification indicating encryption"
#             },
#             "shadow_copy_deletion": {
#                 "type": "command_execution",
#                 "patterns": [
#                     r"vssadmin.*delete.*shadows",
#                     r"wmic.*shadowcopy.*delete",
#                     r"bcdedit.*set.*bootstatuspolicy"
#                 ],
#                 "threshold": 1,
#                 "time_window": 60,
#                 "severity": "high",
#                 "description": "Shadow copy deletion attempt"
#             },
#             "persistence_creation": {
#                 "type": "registry_operations",
#                 "patterns": [
#                     r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
#                     r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#                 ],
#                 "threshold": 1,
#                 "time_window": 300,
#                 "severity": "medium",
#                 "description": "Persistence mechanism creation"
#             },
#             "service_manipulation": {
#                 "type": "command_execution",
#                 "patterns": [
#                     r"net\s+stop\s+(vss|swprv|sqlvss)",
#                     r"sc\s+stop\s+(vss|swprv|sqlvss)",
#                     r"taskkill.*\/f.*\/im.*(sql|mysql|oracle)"
#                 ],
#                 "threshold": 3,
#                 "time_window": 180,
#                 "severity": "high",
#                 "description": "Critical service manipulation"
#             },
#             "network_beaconing": {
#                 "type": "network_operations",
#                 "threshold": 10,
#                 "time_window": 300,
#                 "regularity_check": True,
#                 "severity": "medium",
#                 "description": "Regular network communication pattern"
#             }
#         }
        
#         # Load additional patterns from config if available
#         config_patterns = self.config.get("realtime_patterns", {})
#         patterns.update(config_patterns)
        
#         return patterns
    
#     def add_alert_callback(self, callback: Callable[[Dict], None]):
#         """
#         Add a callback function to be called when alerts are triggered.
        
#         Args:
#             callback: Function to call with alert information
#         """
#         self.alert_callbacks.append(callback)
    
#     def start(self):
#         """Start real-time analysis."""
#         if self.running:
#             logger.warning("Real-time analyzer is already running")
#             return
        
#         self.running = True
#         self.stats["analysis_start_time"] = datetime.now()
#         self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
#         self.analysis_thread.start()
        
#         logger.info("Real-time behavioral analyzer started")
    
#     def stop(self):
#         """Stop real-time analysis."""
#         self.running = False
#         if self.analysis_thread:
#             self.analysis_thread.join(timeout=5)
        
#         logger.info("Real-time behavioral analyzer stopped")
    
#     def process_event(self, event: Dict[str, Any]):
#         """
#         Process a single behavioral event.
        
#         Args:
#             event: Event dictionary with operation details
#         """
#         try:
#             # Add timestamp if not present
#             if "timestamp" not in event:
#                 event["timestamp"] = datetime.now().isoformat()
            
#             # Queue event for processing
#             if not self.event_queue.full():
#                 self.event_queue.put(event, block=False)
#             else:
#                 logger.warning("Event queue is full, dropping event")
                
#         except Exception as e:
#             logger.error(f"Error processing event: {e}")
    
#     def _analysis_loop(self):
#         """Main analysis loop running in separate thread."""
#         logger.info("Starting real-time analysis loop")
        
#         while self.running:
#             try:
#                 # Get event from queue (blocking with timeout)
#                 event = self.event_queue.get(timeout=1.0)
                
#                 # Process the event
#                 self._analyze_event(event)
#                 self.stats["events_processed"] += 1
                
#                 # Mark task as done
#                 self.event_queue.task_done()
                
#             except queue.Empty:
#                 continue
#             except Exception as e:
#                 logger.error(f"Error in analysis loop: {e}")
#                 continue
    
#     def _analyze_event(self, event: Dict[str, Any]):
#         """
#         Analyze a single event for suspicious patterns.
        
#         Args:
#             event: Event to analyze
#         """
#         # Add event to history
#         self.event_history.append(event)
        
#         # Clean old events outside time window
#         self._cleanup_old_events()
        
#         # Check each detection pattern
#         for pattern_name, pattern_config in self.detection_patterns.items():
#             if self._check_pattern(event, pattern_config):
#                 self._trigger_alert(pattern_name, pattern_config, event)
    
#     def _check_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
#         """
#         Check if an event matches a detection pattern.
        
#         Args:
#             event: Event to check
#             pattern_config: Pattern configuration
            
#         Returns:
#             bool: True if pattern matches
#         """
#         pattern_type = pattern_config.get("type")
        
#         if pattern_type == "file_operations":
#             return self._check_file_pattern(event, pattern_config)
#         elif pattern_type == "command_execution":
#             return self._check_command_pattern(event, pattern_config)
#         elif pattern_type == "registry_operations":
#             return self._check_registry_pattern(event, pattern_config)
#         elif pattern_type == "network_operations":
#             return self._check_network_pattern(event, pattern_config)
        
#         return False
    
#     def _check_file_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
#         """Check file operation patterns."""
#         if event.get("operation") not in ["WriteFile", "SetInformation", "CreateFile"]:
#             return False
        
#         # Count file modifications in time window
#         threshold = pattern_config.get("threshold", 10)
#         time_window = pattern_config.get("time_window", 300)
        
#         recent_file_ops = [
#             e for e in self.event_history
#             if (e.get("operation") in ["WriteFile", "SetInformation", "CreateFile"] and
#                 self._is_within_time_window(e, time_window))
#         ]
        
#         return len(recent_file_ops) >= threshold
    
#     def _check_command_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
#         """Check command execution patterns."""
#         command_line = event.get("command_line", "") or event.get("args", "")
#         if not command_line:
#             return False
        
#         patterns = pattern_config.get("patterns", [])
        
#         for pattern in patterns:
#             if re.search(pattern, command_line, re.IGNORECASE):
#                 return True
        
#         return False
    
#     def _check_registry_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
#         """Check registry operation patterns."""
#         if event.get("operation") not in ["RegSetValue", "RegCreateKey"]:
#             return False
        
#         registry_path = event.get("path", "")
#         patterns = pattern_config.get("patterns", [])
        
#         for pattern in patterns:
#             if re.search(pattern, registry_path, re.IGNORECASE):
#                 return True
        
#         return False
    
#     def _check_network_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
#         """Check network operation patterns."""
#         if event.get("operation") not in ["TCP Connect", "UDP Send"]:
#             return False
        
#         threshold = pattern_config.get("threshold", 5)
#         time_window = pattern_config.get("time_window", 300)
        
#         # Count network operations in time window
#         recent_network_ops = [
#             e for e in self.event_history
#             if (e.get("operation") in ["TCP Connect", "UDP Send"] and
#                 self._is_within_time_window(e, time_window))
#         ]
        
#         if len(recent_network_ops) >= threshold:
#             # Check for regularity if required
#             if pattern_config.get("regularity_check"):
#                 return self._check_network_regularity(recent_network_ops)
#             return True
        
#         return False
    
#     def _check_network_regularity(self, network_events: List[Dict]) -> bool:
#         """Check if network events show regular beaconing pattern."""
#         if len(network_events) < 3:
#             return False
        
#         # Extract timestamps and calculate intervals
#         timestamps = []
#         for event in network_events:
#             try:
#                 timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
#                 timestamps.append(timestamp)
#             except:
#                 continue
        
#         if len(timestamps) < 3:
#             return False
        
#         timestamps.sort()
#         intervals = []
#         for i in range(1, len(timestamps)):
#             interval = (timestamps[i] - timestamps[i-1]).total_seconds()
#             intervals.append(interval)
        
#         # Check if intervals are relatively consistent (beaconing)
#         if len(intervals) < 2:
#             return False
        
#         avg_interval = sum(intervals) / len(intervals)
#         variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
#         std_dev = variance ** 0.5
        
#         # If standard deviation is less than 30% of average, consider it regular
#         coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else float('inf')
#         return coefficient_of_variation < 0.3
    
#     def _is_within_time_window(self, event: Dict[str, Any], window_seconds: int) -> bool:
#         """Check if event is within specified time window."""
#         try:
#             event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
#             current_time = datetime.now()
            
#             # Handle timezone-aware/naive datetime comparison
#             if event_time.tzinfo is None:
#                 event_time = event_time.replace(tzinfo=current_time.tzinfo)
#             elif current_time.tzinfo is None:
#                 current_time = current_time.replace(tzinfo=event_time.tzinfo)
            
#             time_diff = (current_time - event_time).total_seconds()
#             return time_diff <= window_seconds
            
#         except Exception as e:
#             logger.debug(f"Error parsing timestamp: {e}")
#             return True  # Include event if timestamp parsing fails
    
#     def _cleanup_old_events(self):
#         """Remove events older than the maximum time window."""
#         max_window = max(
#             pattern.get("time_window", 300) 
#             for pattern in self.detection_patterns.values()
#         )
        
#         current_time = datetime.now()
#         cleaned_history = deque()
        
#         for event in self.event_history:
#             if self._is_within_time_window(event, max_window):
#                 cleaned_history.append(event)
        
#         self.event_history = cleaned_history
    
#     def _trigger_alert(self, pattern_name: str, pattern_config: Dict, triggering_event: Dict):
#         """
#         Trigger an alert for a detected pattern.
        
#         Args:
#             pattern_name: Name of the detected pattern
#             pattern_config: Pattern configuration
#             triggering_event: Event that triggered the pattern
#         """
#         alert = {
#             "timestamp": datetime.now().isoformat(),
#             "pattern_name": pattern_name,
#             "severity": pattern_config.get("severity", "medium"),
#             "description": pattern_config.get("description", "Suspicious behavior detected"),
#             "triggering_event": triggering_event,
#             "pattern_config": pattern_config,
#             "alert_id": f"{pattern_name}_{int(time.time())}"
#         }
        
#         self.stats["alerts_triggered"] += 1
#         self.stats["patterns_matched"] += 1
        
#         logger.warning(f"BEHAVIORAL ALERT: {alert['description']} (Severity: {alert['severity']})")
        
#         # Call all registered alert callbacks
#         for callback in self.alert_callbacks:
#             try:
#                 callback(alert)
#             except Exception as e:
#                 logger.error(f"Error in alert callback: {e}")
    
#     def get_statistics(self) -> Dict[str, Any]:
#         """Get current analysis statistics."""
#         stats = self.stats.copy()
#         if stats["analysis_start_time"]:
#             stats["runtime_seconds"] = (datetime.now() - stats["analysis_start_time"]).total_seconds()
        
#         stats["event_queue_size"] = self.event_queue.qsize()
#         stats["event_history_size"] = len(self.event_history)
#         stats["active_patterns"] = len(self.detection_patterns)
        
#         return stats


# class BehavioralMonitor:
#     """
#     Main behavioral monitoring system that orchestrates real-time analysis.
    
#     Integrates with ProcMon handler and other monitoring components to provide
#     comprehensive behavioral analysis during malware execution.
#     """
    
#     def __init__(self, config_settings: dict = None):
#         """
#         Initialize behavioral monitor.
        
#         Args:
#             config_settings: Configuration dictionary
#         """
#         self.config = config_settings or {}
#         self.analyzer = RealTimeAnalyzer(config_settings)
#         self.monitoring_sessions = {}
#         self.alert_history = []
        
#         # Setup default alert handler
#         self.analyzer.add_alert_callback(self._default_alert_handler)
        
#     def _default_alert_handler(self, alert: Dict[str, Any]):
#         """Default alert handler that logs and stores alerts."""
#         self.alert_history.append(alert)
        
#         # Log alert with appropriate level
#         severity = alert.get("severity", "medium").lower()
#         message = f"BEHAVIORAL ALERT [{severity.upper()}]: {alert.get('description')}"
        
#         if severity == "critical":
#             logger.critical(message)
#         elif severity == "high":
#             logger.error(message)
#         elif severity == "medium":
#             logger.warning(message)
#         else:
#             logger.info(message)
    
#     def start_monitoring_session(self, session_id: str, vm_identifier: str = None) -> bool:
#         """
#         Start a new behavioral monitoring session.
        
#         Args:
#             session_id: Unique session identifier
#             vm_identifier: Optional VM identifier for context
            
#         Returns:
#             bool: True if session started successfully
#         """
#         if session_id in self.monitoring_sessions:
#             logger.warning(f"Monitoring session {session_id} already exists")
#             return False
        
#         try:
#             # Start the real-time analyzer
#             self.analyzer.start()
            
#             # Track the session
#             self.monitoring_sessions[session_id] = {
#                 "start_time": datetime.now(),
#                 "vm_identifier": vm_identifier,
#                 "status": "active",
#                 "events_processed": 0,
#                 "alerts_generated": 0
#             }
            
#             logger.info(f"Started behavioral monitoring session: {session_id}")
#             return True
            
#         except Exception as e:
#             logger.error(f"Failed to start monitoring session {session_id}: {e}")
#             return False
    
#     def stop_monitoring_session(self, session_id: str) -> Dict[str, Any]:
#         """
#         Stop a behavioral monitoring session and return results.
        
#         Args:
#             session_id: Session identifier to stop
            
#         Returns:
#             dict: Session results and statistics
#         """
#         if session_id not in self.monitoring_sessions:
#             logger.error(f"Monitoring session {session_id} not found")
#             return {}
        
#         try:
#             session = self.monitoring_sessions[session_id]
#             session["status"] = "completed"
#             session["end_time"] = datetime.now()
#             session["duration_seconds"] = (session["end_time"] - session["start_time"]).total_seconds()
            
#             # Get analyzer statistics
#             analyzer_stats = self.analyzer.get_statistics()
#             session.update(analyzer_stats)
            
#             # Stop the analyzer
#             self.analyzer.stop()
            
#             # Get alerts for this session
#             session_alerts = [
#                 alert for alert in self.alert_history
#                 if alert["timestamp"] >= session["start_time"].isoformat()
#             ]
#             session["alerts"] = session_alerts
#             session["alerts_generated"] = len(session_alerts)
            
#             logger.info(f"Stopped monitoring session {session_id}. "
#                        f"Processed {session.get('events_processed', 0)} events, "
#                        f"Generated {session['alerts_generated']} alerts")
            
#             return session
            
#         except Exception as e:
#             logger.error(f"Error stopping monitoring session {session_id}: {e}")
#             return {}
    
#     def process_event(self, event: Dict[str, Any], session_id: str = None):
#         """
#         Process a behavioral event through the monitoring system.
        
#         Args:
#             event: Event dictionary
#             session_id: Optional session identifier for tracking
#         """
#         # Update session statistics if provided
#         if session_id and session_id in self.monitoring_sessions:
#             self.monitoring_sessions[session_id]["events_processed"] += 1
        
#         # Send event to real-time analyzer
#         self.analyzer.process_event(event)
    
#     def get_session_status(self, session_id: str) -> Dict[str, Any]:
#         """
#         Get current status of a monitoring session.
        
#         Args:
#             session_id: Session identifier
            
#         Returns:
#             dict: Session status information
#         """
#         if session_id not in self.monitoring_sessions:
#             return {"error": "Session not found"}
        
#         session = self.monitoring_sessions[session_id].copy()
        
#         # Add current analyzer statistics if session is active
#         if session.get("status") == "active":
#             analyzer_stats = self.analyzer.get_statistics()
#             session.update(analyzer_stats)
        
#         return session
    
#     def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
#         """
#         Get most recent alerts.
        
#         Args:
#             limit: Maximum number of alerts to return
            
#         Returns:
#             list: Recent alerts
#         """
#         return self.alert_history[-limit:] if self.alert_history else []
    
#     def export_session_results(self, session_id: str, output_path: str) -> bool:
#         """
#         Export session results to JSON file.
        
#         Args:
#             session_id: Session identifier
#             output_path: Output file path
            
#         Returns:
#             bool: True if export successful
#         """
#         if session_id not in self.monitoring_sessions:
#             logger.error(f"Session {session_id} not found for export")
#             return False
        
#         try:
#             session_data = self.get_session_status(session_id)
            
#             os.makedirs(os.path.dirname(output_path), exist_ok=True)
#             with open(output_path, 'w', encoding='utf-8') as f:
#                 json.dump(session_data, f, indent=2, default=str)
            
#             logger.info(f"Exported session {session_id} results to {output_path}")
#             return True
            
#         except Exception as e:
#             logger.error(f"Failed to export session {session_id}: {e}")
#             return False


# # Convenience function for integration
# def create_behavioral_monitor(config_settings: dict = None) -> BehavioralMonitor:
#     """
#     Create and configure a behavioral monitor instance.
    
#     Args:
#         config_settings: Optional configuration settings
        
#     Returns:
#         BehavioralMonitor: Configured monitor instance
#     """
#     return BehavioralMonitor(config_settings)


# if __name__ == "__main__":
#     # Example usage and testing
#     import sys
    
#     logging.basicConfig(
#         level=logging.INFO,
#         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
#     )
    
#     # Create and test behavioral monitor
#     monitor = BehavioralMonitor()
    
#     # Start monitoring session
#     session_id = "test_session_001"
#     if monitor.start_monitoring_session(session_id):
#         print(f"Started monitoring session: {session_id}")
        
#         # Simulate some events
#         test_events = [
#             {
#                 "operation": "WriteFile",
#                 "path": "C:\\Users\\Test\\Documents\\file1.txt.encrypted",
#                 "process": "malware.exe"
#             },
#             {
#                 "operation": "RegSetValue", 
#                 "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
#                 "process": "malware.exe"
#             },
#             {
#                 "operation": "WriteFile",
#                 "path": "C:\\Users\\Test\\Documents\\file2.docx.encrypted", 
#                 "process": "malware.exe"
#             }
#         ]
        
#         # Process test events
#         for event in test_events:
#             monitor.process_event(event, session_id)
#             time.sleep(1)  # Simulate real-time processing
        
#         # Wait a bit for processing
#         time.sleep(2)
        
#         # Stop session and get results
#         results = monitor.stop_monitoring_session(session_id)
#         print(f"Session results: {json.dumps(results, indent=2, default=str)}")
        
#         # Show recent alerts
#         alerts = monitor.get_recent_alerts()
#         print(f"Recent alerts: {len(alerts)}")
#         for alert in alerts:
#             print(f"  - {alert['severity'].upper()}: {alert['description']}")
    
#     else:
#         print("Failed to start monitoring session")
#         sys.exit(1)

# shikra/core/modules/monitoring/behavioral_monitor.py
# Purpose: Real-time behavioral monitoring and analysis engine

import os
import time
import threading
import logging
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path
import queue

from .procmon_handler import ProcMonHandler
from .procmon_processor import ProcMonProcessor
from .filter_engine import FilterEngine

logger = logging.getLogger(__name__)

class BehavioralMonitor:
    """
    Real-time behavioral monitoring system that combines ProcMon data collection
    with live analysis and alerting capabilities.
    """
    
    def __init__(self, sample_id: str = None, config: Dict = None):
        """
        Initialize the behavioral monitor.
        
        Args:
            sample_id: Unique identifier for the monitoring session
            config: Configuration dictionary
        """
        self.sample_id = sample_id or f"behavioral_monitor_{int(time.time())}"
        self.config = config or {}
        
        # Initialize components
        self.procmon_handler = ProcMonHandler(self.config.get('procmon', {}))
        self.processor = ProcMonProcessor(self.sample_id, self.config.get('processor', {}))
        self.filter_engine = FilterEngine(self.config.get('filter', {}))
        
        # Monitoring state
        self.is_monitoring = False
        self.start_time = None
        self.monitor_thread = None
        self.analysis_thread = None
        
        # Real-time data structures
        self.event_queue = queue.Queue(maxsize=10000)
        self.recent_events = deque(maxlen=1000)  # Keep last 1000 events
        self.live_stats = {
            "events_processed": 0,
            "events_filtered": 0,
            "behavioral_indicators": 0,
            "suspicious_activities": 0,
            "last_update": None
        }
        
        # Alert system
        self.alert_callbacks = []
        self.alert_thresholds = self.config.get('alert_thresholds', {})
        self.alert_history = []
        
        # Performance tracking
        self.performance_metrics = {
            "processing_rate": deque(maxlen=60),  # Events per second over last minute
            "memory_usage": deque(maxlen=60),
            "cpu_usage": deque(maxlen=60)
        }
        
        # Load behavioral patterns for real-time detection
        self._load_realtime_patterns()
        
        logger.info(f"Behavioral monitor initialized for sample: {self.sample_id}")
    
    def _load_realtime_patterns(self):
        """Load patterns for real-time behavioral detection."""
        patterns_file = self.config.get('realtime_patterns_file', 'config/procmon/realtime_patterns.json')
        
        try:
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    self.realtime_patterns = json.load(f)
            else:
                self.realtime_patterns = self._get_default_realtime_patterns()
                logger.warning("Using default real-time patterns")
        except Exception as e:
            logger.error(f"Failed to load real-time patterns: {e}")
            self.realtime_patterns = self._get_default_realtime_patterns()
    
    def _get_default_realtime_patterns(self) -> Dict:
        """Default patterns for real-time detection and alerting."""
        return {
            "critical_alerts": {
                "mass_file_encryption": {
                    "description": "Mass file encryption detected",
                    "conditions": [
                        {"type": "file_operations", "operation": "WriteFile", "count": 50, "timeframe": 60},
                        {"type": "file_extensions", "extensions": [".encrypted", ".locked", ".crypted"], "count": 10, "timeframe": 60}
                    ]
                },
                "shadow_copy_deletion": {
                    "description": "Shadow copy deletion attempt",
                    "conditions": [
                        {"type": "process_command", "process": "vssadmin.exe", "args_contains": "delete shadows"}
                    ]
                },
                "boot_modification": {
                    "description": "Boot configuration modification",
                    "conditions": [
                        {"type": "process_command", "process": "bcdedit.exe", "args_contains": "recoveryenabled no"}
                    ]
                }
            },
            
            "high_alerts": {
                "persistence_registry": {
                    "description": "Registry persistence mechanism",
                    "conditions": [
                        {"type": "registry_write", "key_contains": "\\CurrentVersion\\Run", "count": 1, "timeframe": 300}
                    ]
                },
                "suspicious_network": {
                    "description": "Suspicious network activity",
                    "conditions": [
                        {"type": "network_connections", "domains": [".onion", "pastebin.com"], "count": 1, "timeframe": 300}
                    ]
                },
                "process_injection": {
                    "description": "Potential process injection",
                    "conditions": [
                        {"type": "memory_operations", "operation": "WriteProcessMemory", "count": 10, "timeframe": 60}
                    ]
                }
            },
            
            "medium_alerts": {
                "suspicious_file_location": {
                    "description": "File operations in suspicious locations",
                    "conditions": [
                        {"type": "file_operations", "path_contains": ["\\AppData\\Local\\Temp\\", "\\Users\\Public\\"], "count": 20, "timeframe": 120}
                    ]
                },
                "system_tool_usage": {
                    "description": "Suspicious system tool usage",
                    "conditions": [
                        {"type": "process_creation", "processes": ["wmic.exe", "powershell.exe", "cmd.exe"], "count": 5, "timeframe": 180}
                    ]
                }
            }
        }
    
    def add_alert_callback(self, callback: Callable[[Dict], None]):
        """
        Add callback function for real-time alerts.
        
        Args:
            callback: Function to call when alert is triggered
        """
        self.alert_callbacks.append(callback)
        logger.info(f"Added alert callback: {callback.__name__}")
    
    def start_monitoring(self, duration: int = None) -> bool:
        """
        Start real-time behavioral monitoring.
        
        Args:
            duration: Monitoring duration in seconds (None for indefinite)
            
        Returns:
            True if monitoring started successfully
        """
        if self.is_monitoring:
            logger.warning("Monitoring is already active")
            return True
        
        try:
            # Start ProcMon
            output_dir = self.config.get('output_dir', 'logs/monitoring')
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"realtime_{self.sample_id}.csv")
            
            if not self.procmon_handler.start_monitoring(output_file, duration):
                logger.error("Failed to start ProcMon")
                return False
            
            # Initialize monitoring state
            self.is_monitoring = True
            self.start_time = datetime.now()
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                name=f"MonitorThread-{self.sample_id}",
                daemon=True
            )
            self.monitor_thread.start()
            
            # Start analysis thread
            self.analysis_thread = threading.Thread(
                target=self._analysis_loop,
                name=f"AnalysisThread-{self.sample_id}",
                daemon=True
            )
            self.analysis_thread.start()
            
            logger.info(f"Started real-time monitoring for {duration or 'indefinite'} seconds")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self.is_monitoring = False
            return False
    
    def stop_monitoring(self) -> Dict:
        """
        Stop monitoring and return analysis results.
        
        Returns:
            Dictionary containing analysis results
        """
        if not self.is_monitoring:
            logger.warning("Monitoring is not active")
            return {}
        
        try:
            # Stop monitoring
            self.is_monitoring = False
            
            # Stop ProcMon and get output file
            success, csv_file = self.procmon_handler.stop_monitoring()
            if not success:
                logger.error("Failed to stop ProcMon properly")
            
            # Wait for threads to finish
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=10)
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.analysis_thread.join(timeout=10)
            
            # Process collected data
            if csv_file and os.path.exists(csv_file):
                results = self.processor.process_csv_log(csv_file)
            else:
                results = {"error": "No output file available for processing"}
            
            # Add real-time statistics
            results["realtime_stats"] = self.get_live_statistics()
            results["alert_history"] = self.alert_history.copy()
            results["monitoring_duration"] = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            
            logger.info("Monitoring stopped successfully")
            return results
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
            return {"error": str(e)}
    
    def _monitoring_loop(self):
        """Main monitoring loop - reads ProcMon output and queues events."""
        csv_file_path = self.procmon_handler.output_file
        if not csv_file_path:
            logger.error("No output file available for monitoring")
            return
        
        # Wait for file to be created
        wait_time = 0
        while not os.path.exists(csv_file_path) and wait_time < 30:
            time.sleep(1)
            wait_time += 1
        
        if not os.path.exists(csv_file_path):
            logger.error(f"Output file not created: {csv_file_path}")
            return
        
        # Monitor file for new events
        last_position = 0
        last_event_time = time.time()
        
        logger.info(f"Starting monitoring loop for file: {csv_file_path}")
        
        while self.is_monitoring:
            try:
                # Check if file has grown
                if os.path.exists(csv_file_path):
                    current_size = os.path.getsize(csv_file_path)
                    
                    if current_size > last_position:
                        # Read new data
                        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(last_position)
                            new_data = f.read()
                            last_position = f.tell()
                        
                        # Process new lines
                        if new_data.strip():
                            self._process_new_data(new_data)
                            last_event_time = time.time()
                
                # Check for stale monitoring (no new events for too long)
                if time.time() - last_event_time > 300:  # 5 minutes
                    logger.warning("No new events detected for 5 minutes")
                    last_event_time = time.time()  # Reset to avoid spam
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Wait longer on error
    
    def _process_new_data(self, data: str):
        """Process new data from ProcMon output."""
        lines = data.strip().split('\n')
        
        for line in lines:
            if not line.strip() or line.startswith('#'):
                continue
            
            try:
                # Parse CSV line (simplified parsing)
                parts = line.split(',')
                if len(parts) < 6:
                    continue
                
                event = {
                    "timestamp": parts[0].strip('"'),
                    "process_name": parts[1].strip('"'),
                    "pid": parts[2].strip('"'),
                    "operation": parts[3].strip('"'),
                    "path": parts[4].strip('"'),
                    "result": parts[5].strip('"'),
                    "detail": parts[6].strip('"') if len(parts) > 6 else ""
                }
                
                # Apply filtering
                if self.filter_engine.should_process_event(event):
                    # Add to queue for analysis
                    try:
                        self.event_queue.put_nowait(event)
                        self.recent_events.append(event)
                        self.live_stats["events_processed"] += 1
                    except queue.Full:
                        logger.warning("Event queue is full, dropping events")
                else:
                    self.live_stats["events_filtered"] += 1
                
            except Exception as e:
                logger.debug(f"Error parsing line: {line[:100]}... - {e}")
                continue
    
    def _analysis_loop(self):
        """Analysis loop - processes queued events and checks for alerts."""
        logger.info("Starting analysis loop")
        
        # Tracking for pattern detection
        pattern_counters = defaultdict(lambda: defaultdict(int))
        time_windows = defaultdict(lambda: defaultdict(list))
        
        while self.is_monitoring or not self.event_queue.empty():
            try:
                # Get event from queue
                try:
                    event = self.event_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Update performance metrics
                current_time = time.time()
                self.performance_metrics["processing_rate"].append(1)  # One event processed
                
                # Check real-time patterns
                self._check_realtime_patterns(event, pattern_counters, time_windows, current_time)
                
                # Update live statistics
                self.live_stats["last_update"] = datetime.now().isoformat()
                
                # Task done
                self.event_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
                time.sleep(1)
    
    def _check_realtime_patterns(self, event: Dict, pattern_counters: Dict, time_windows: Dict, current_time: float):
        """Check event against real-time patterns and trigger alerts."""
        
        for severity in ["critical_alerts", "high_alerts", "medium_alerts"]:
            for pattern_name, pattern_config in self.realtime_patterns.get(severity, {}).items():
                
                # Check each condition
                pattern_matched = False
                
                for condition in pattern_config.get("conditions", []):
                    if self._check_pattern_condition(event, condition, pattern_counters, time_windows, current_time):
                        pattern_matched = True
                        break
                
                if pattern_matched:
                    self._trigger_alert(severity, pattern_name, pattern_config, event)
    
    def _check_pattern_condition(self, event: Dict, condition: Dict, pattern_counters: Dict, time_windows: Dict, current_time: float) -> bool:
        """Check if an event matches a specific pattern condition."""
        
        condition_type = condition.get("type")
        timeframe = condition.get("timeframe", 300)  # Default 5 minutes
        required_count = condition.get("count", 1)
        
        # Clean old entries from time windows
        cutoff_time = current_time - timeframe
        
        if condition_type == "file_operations":
            operation = condition.get("operation")
            if event.get("operation") == operation:
                # Add to time window
                key = f"file_ops_{operation}"
                time_windows[key] = [t for t in time_windows[key] if t > cutoff_time]
                time_windows[key].append(current_time)
                
                return len(time_windows[key]) >= required_count
        
        elif condition_type == "file_extensions":
            extensions = condition.get("extensions", [])
            path = event.get("path", "").lower()
            
            for ext in extensions:
                if path.endswith(ext.lower()):
                    key = f"file_ext_{ext}"
                    time_windows[key] = [t for t in time_windows[key] if t > cutoff_time]
                    time_windows[key].append(current_time)
                    
                    return len(time_windows[key]) >= required_count
        
        elif condition_type == "process_command":
            process = condition.get("process", "").lower()
            args_contains = condition.get("args_contains", "")
            
            if (process in event.get("process_name", "").lower() and 
                args_contains.lower() in event.get("detail", "").lower()):
                return True
        
        elif condition_type == "registry_write":
            key_contains = condition.get("key_contains", "")
            if (event.get("operation", "").startswith("Reg") and 
                key_contains.lower() in event.get("path", "").lower()):
                
                key = f"reg_write_{key_contains}"
                time_windows[key] = [t for t in time_windows[key] if t > cutoff_time]
                time_windows[key].append(current_time)
                
                return len(time_windows[key]) >= required_count
        
        elif condition_type == "process_creation":
            processes = condition.get("processes", [])
            process_name = event.get("process_name", "").lower()
            
            if any(proc.lower() in process_name for proc in processes):
                key = "process_creation"
                time_windows[key] = [t for t in time_windows[key] if t > cutoff_time]
                time_windows[key].append(current_time)
                
                return len(time_windows[key]) >= required_count
        
        return False
    
    def _trigger_alert(self, severity: str, pattern_name: str, pattern_config: Dict, event: Dict):
        """Trigger an alert for a matched pattern."""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity.replace("_alerts", ""),
            "pattern_name": pattern_name,
            "description": pattern_config.get("description", "Unknown alert"),
            "event": event,
            "sample_id": self.sample_id
        }
        
        # Add to alert history
        self.alert_history.append(alert)
        
        # Update live stats
        if severity == "critical_alerts":
            self.live_stats["suspicious_activities"] += 1
        self.live_stats["behavioral_indicators"] += 1
        
        # Call alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
        
        logger.warning(f"ALERT [{alert['severity'].upper()}]: {alert['description']} - Process: {event.get('process_name')} - Path: {event.get('path')}")
    
    def get_live_statistics(self) -> Dict:
        """Get current live monitoring statistics."""
        stats = self.live_stats.copy()
        
        # Add additional metrics
        if self.start_time:
            stats["monitoring_duration"] = (datetime.now() - self.start_time).total_seconds()
        
        stats["queue_size"] = self.event_queue.qsize()
        stats["recent_events_count"] = len(self.recent_events)
        stats["alert_count"] = len(self.alert_history)
        
        # Performance metrics
        if self.performance_metrics["processing_rate"]:
            stats["events_per_second"] = len(self.performance_metrics["processing_rate"])
        
        return stats
    
    def get_recent_events(self, count: int = 100) -> List[Dict]:
        """Get recent events for real-time display."""
        recent = list(self.recent_events)
        return recent[-count:] if count else recent
    
    def get_alerts(self, severity: str = None, count: int = None) -> List[Dict]:
        """Get alert history, optionally filtered by severity."""
        alerts = self.alert_history
        
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        
        if count:
            alerts = alerts[-count:]
        
        return alerts
    
    def export_realtime_data(self, output_file: str = None) -> str:
        """Export real-time monitoring data to JSON file."""
        if not output_file:
            output_file = f"realtime_monitoring_{self.sample_id}_{int(time.time())}.json"
        
        data = {
            "sample_id": self.sample_id,
            "monitoring_session": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": datetime.now().isoformat(),
                "duration": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            },
            "statistics": self.get_live_statistics(),
            "alerts": self.alert_history,
            "recent_events": self.get_recent_events(500),  # Last 500 events
            "filter_stats": self.filter_engine.get_statistics()
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Real-time monitoring data exported to: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to export real-time data: {e}")
            return ""
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.is_monitoring:
            self.stop_monitoring()
        self.procmon_handler.cleanup()

# Utility functions
def create_realtime_monitor(sample_id: str, config_file: str = None) -> BehavioralMonitor:
    """
    Create a behavioral monitor with configuration from file.
    
    Args:
        sample_id: Unique identifier for monitoring session
        config_file: Path to configuration file
        
    Returns:
        Configured BehavioralMonitor instance
    """
    config = {}
    if config_file and os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
    
    return BehavioralMonitor(sample_id, config)

def monitor_with_alerts(sample_id: str, duration: int = 300, alert_callback: Callable = None) -> Dict:
    """
    Convenience function for monitoring with alert notifications.
    
    Args:
        sample_id: Unique identifier
        duration: Monitoring duration in seconds
        alert_callback: Function to call for alerts
        
    Returns:
        Monitoring results dictionary
    """
    with BehavioralMonitor(sample_id) as monitor:
        if alert_callback:
            monitor.add_alert_callback(alert_callback)
        
        if monitor.start_monitoring(duration):
            # Wait for monitoring to complete
            time.sleep(duration + 5)
            return monitor.stop_monitoring()
        else:
            return {"error": "Failed to start monitoring"}

if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def sample_alert_callback(alert):
        """Sample alert callback function."""
        print(f"🚨 ALERT: [{alert['severity'].upper()}] {alert['description']}")
        print(f"   Process: {alert['event'].get('process_name')}")
        print(f"   Path: {alert['event'].get('path')}")
        print(f"   Time: {alert['timestamp']}")
        print()
    
    parser = argparse.ArgumentParser(description='Behavioral Monitor Test')
    parser.add_argument('--sample-id', default=f"test_monitor_{int(time.time())}", help='Sample ID')
    parser.add_argument('--duration', type=int, default=60, help='Monitoring duration in seconds')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--export', help='Export file path for results')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    print(f"Starting behavioral monitoring for sample: {args.sample_id}")
    print(f"Duration: {args.duration} seconds")
    print("Press Ctrl+C to stop monitoring early\n")
    
    try:
        with BehavioralMonitor(args.sample_id, config) as monitor:
            # Add alert callback
            monitor.add_alert_callback(sample_alert_callback)
            
            # Start monitoring
            if not monitor.start_monitoring(args.duration):
                print("Failed to start monitoring")
                exit(1)
            
            print("Monitoring started successfully...")
            print("Watching for behavioral patterns...\n")
            
            # Monitor progress
            start_time = time.time()
            try:
                while monitor.is_monitoring and (time.time() - start_time) < args.duration:
                    time.sleep(5)
                    
                    # Print live statistics
                    stats = monitor.get_live_statistics()
                    print(f"\r📊 Events: {stats['events_processed']} | "
                          f"Filtered: {stats['events_filtered']} | "
                          f"Alerts: {stats.get('alert_count', 0)} | "
                          f"Queue: {stats.get('queue_size', 0)}", end="")
                    
            except KeyboardInterrupt:
                print("\n\n⏹️  Monitoring interrupted by user")
            
            # Stop monitoring and get results
            print("\n\n🔄 Stopping monitoring and processing results...")
            results = monitor.stop_monitoring()
            
            if "error" in results:
                print(f"❌ Error: {results['error']}")
            else:
                print("✅ Monitoring completed successfully!")
                
                # Print summary
                stats = results.get("realtime_stats", {})
                print(f"\n📈 Final Statistics:")
                print(f"   Events Processed: {stats.get('events_processed', 0)}")
                print(f"   Events Filtered: {stats.get('events_filtered', 0)}")
                print(f"   Behavioral Indicators: {stats.get('behavioral_indicators', 0)}")
                print(f"   Suspicious Activities: {stats.get('suspicious_activities', 0)}")
                print(f"   Monitoring Duration: {stats.get('monitoring_duration', 0):.1f} seconds")
                
                # Print alerts summary
                alerts = results.get("alert_history", [])
                if alerts:
                    print(f"\n🚨 Alerts Generated ({len(alerts)} total):")
                    alert_counts = {}
                    for alert in alerts:
                        severity = alert.get("severity", "unknown")
                        alert_counts[severity] = alert_counts.get(severity, 0) + 1
                    
                    for severity, count in alert_counts.items():
                        print(f"   {severity.upper()}: {count}")
                
                # Export results if requested
                if args.export:
                    export_path = monitor.export_realtime_data(args.export)
                    if export_path:
                        print(f"\n💾 Results exported to: {export_path}")
                    else:
                        print("\n❌ Failed to export results")
                
                print(f"\n🎯 Behavioral monitoring session complete!")
                
    except Exception as e:
        print(f"❌ Error during monitoring: {e}")
        exit(1)
