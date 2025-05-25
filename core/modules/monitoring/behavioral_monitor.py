# shikra/core/modules/monitoring/behavioral_monitor.py
# Purpose: Real-time behavioral monitoring and threat detection during malware execution
#          Provides live analysis capabilities beyond static log processing

import json
import logging
import threading
import time
import queue
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
import os
import re

logger = logging.getLogger(__name__)

class RealTimeAnalyzer:
    """
    Real-time analysis engine for processing behavioral events as they occur.
    
    Features:
    - Live event processing and correlation
    - Immediate threat detection and alerting
    - Behavioral pattern recognition in real-time
    - Memory-efficient sliding window analysis
    """
    
    def __init__(self, config_settings: dict = None):
        """
        Initialize the real-time analyzer.
        
        Args:
            config_settings: Configuration dictionary
        """
        self.config = config_settings or {}
        self.event_queue = queue.Queue(maxsize=10000)
        self.analysis_thread = None
        self.running = False
        
        # Sliding window for temporal analysis
        self.time_window_seconds = self.config.get("time_window_seconds", 300)
        self.event_history = deque(maxlen=1000)
        
        # Real-time detection patterns
        self.detection_patterns = self._load_detection_patterns()
        
        # Alert callbacks
        self.alert_callbacks = []
        
        # Statistics tracking
        self.stats = {
            "events_processed": 0,
            "alerts_triggered": 0,
            "patterns_matched": 0,
            "analysis_start_time": None
        }
        
    def _load_detection_patterns(self) -> Dict[str, Dict]:
        """Load real-time detection patterns from configuration."""
        
        patterns = {
            "mass_file_encryption": {
                "type": "file_operations",
                "threshold": 20,
                "time_window": 120,
                "severity": "critical",
                "description": "Mass file modification indicating encryption"
            },
            "shadow_copy_deletion": {
                "type": "command_execution",
                "patterns": [
                    r"vssadmin.*delete.*shadows",
                    r"wmic.*shadowcopy.*delete",
                    r"bcdedit.*set.*bootstatuspolicy"
                ],
                "threshold": 1,
                "time_window": 60,
                "severity": "high",
                "description": "Shadow copy deletion attempt"
            },
            "persistence_creation": {
                "type": "registry_operations",
                "patterns": [
                    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                ],
                "threshold": 1,
                "time_window": 300,
                "severity": "medium",
                "description": "Persistence mechanism creation"
            },
            "service_manipulation": {
                "type": "command_execution",
                "patterns": [
                    r"net\s+stop\s+(vss|swprv|sqlvss)",
                    r"sc\s+stop\s+(vss|swprv|sqlvss)",
                    r"taskkill.*\/f.*\/im.*(sql|mysql|oracle)"
                ],
                "threshold": 3,
                "time_window": 180,
                "severity": "high",
                "description": "Critical service manipulation"
            },
            "network_beaconing": {
                "type": "network_operations",
                "threshold": 10,
                "time_window": 300,
                "regularity_check": True,
                "severity": "medium",
                "description": "Regular network communication pattern"
            }
        }
        
        # Load additional patterns from config if available
        config_patterns = self.config.get("realtime_patterns", {})
        patterns.update(config_patterns)
        
        return patterns
    
    def add_alert_callback(self, callback: Callable[[Dict], None]):
        """
        Add a callback function to be called when alerts are triggered.
        
        Args:
            callback: Function to call with alert information
        """
        self.alert_callbacks.append(callback)
    
    def start(self):
        """Start real-time analysis."""
        if self.running:
            logger.warning("Real-time analyzer is already running")
            return
        
        self.running = True
        self.stats["analysis_start_time"] = datetime.now()
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()
        
        logger.info("Real-time behavioral analyzer started")
    
    def stop(self):
        """Stop real-time analysis."""
        self.running = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        
        logger.info("Real-time behavioral analyzer stopped")
    
    def process_event(self, event: Dict[str, Any]):
        """
        Process a single behavioral event.
        
        Args:
            event: Event dictionary with operation details
        """
        try:
            # Add timestamp if not present
            if "timestamp" not in event:
                event["timestamp"] = datetime.now().isoformat()
            
            # Queue event for processing
            if not self.event_queue.full():
                self.event_queue.put(event, block=False)
            else:
                logger.warning("Event queue is full, dropping event")
                
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    def _analysis_loop(self):
        """Main analysis loop running in separate thread."""
        logger.info("Starting real-time analysis loop")
        
        while self.running:
            try:
                # Get event from queue (blocking with timeout)
                event = self.event_queue.get(timeout=1.0)
                
                # Process the event
                self._analyze_event(event)
                self.stats["events_processed"] += 1
                
                # Mark task as done
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
                continue
    
    def _analyze_event(self, event: Dict[str, Any]):
        """
        Analyze a single event for suspicious patterns.
        
        Args:
            event: Event to analyze
        """
        # Add event to history
        self.event_history.append(event)
        
        # Clean old events outside time window
        self._cleanup_old_events()
        
        # Check each detection pattern
        for pattern_name, pattern_config in self.detection_patterns.items():
            if self._check_pattern(event, pattern_config):
                self._trigger_alert(pattern_name, pattern_config, event)
    
    def _check_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
        """
        Check if an event matches a detection pattern.
        
        Args:
            event: Event to check
            pattern_config: Pattern configuration
            
        Returns:
            bool: True if pattern matches
        """
        pattern_type = pattern_config.get("type")
        
        if pattern_type == "file_operations":
            return self._check_file_pattern(event, pattern_config)
        elif pattern_type == "command_execution":
            return self._check_command_pattern(event, pattern_config)
        elif pattern_type == "registry_operations":
            return self._check_registry_pattern(event, pattern_config)
        elif pattern_type == "network_operations":
            return self._check_network_pattern(event, pattern_config)
        
        return False
    
    def _check_file_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
        """Check file operation patterns."""
        if event.get("operation") not in ["WriteFile", "SetInformation", "CreateFile"]:
            return False
        
        # Count file modifications in time window
        threshold = pattern_config.get("threshold", 10)
        time_window = pattern_config.get("time_window", 300)
        
        recent_file_ops = [
            e for e in self.event_history
            if (e.get("operation") in ["WriteFile", "SetInformation", "CreateFile"] and
                self._is_within_time_window(e, time_window))
        ]
        
        return len(recent_file_ops) >= threshold
    
    def _check_command_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
        """Check command execution patterns."""
        command_line = event.get("command_line", "") or event.get("args", "")
        if not command_line:
            return False
        
        patterns = pattern_config.get("patterns", [])
        
        for pattern in patterns:
            if re.search(pattern, command_line, re.IGNORECASE):
                return True
        
        return False
    
    def _check_registry_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
        """Check registry operation patterns."""
        if event.get("operation") not in ["RegSetValue", "RegCreateKey"]:
            return False
        
        registry_path = event.get("path", "")
        patterns = pattern_config.get("patterns", [])
        
        for pattern in patterns:
            if re.search(pattern, registry_path, re.IGNORECASE):
                return True
        
        return False
    
    def _check_network_pattern(self, event: Dict[str, Any], pattern_config: Dict) -> bool:
        """Check network operation patterns."""
        if event.get("operation") not in ["TCP Connect", "UDP Send"]:
            return False
        
        threshold = pattern_config.get("threshold", 5)
        time_window = pattern_config.get("time_window", 300)
        
        # Count network operations in time window
        recent_network_ops = [
            e for e in self.event_history
            if (e.get("operation") in ["TCP Connect", "UDP Send"] and
                self._is_within_time_window(e, time_window))
        ]
        
        if len(recent_network_ops) >= threshold:
            # Check for regularity if required
            if pattern_config.get("regularity_check"):
                return self._check_network_regularity(recent_network_ops)
            return True
        
        return False
    
    def _check_network_regularity(self, network_events: List[Dict]) -> bool:
        """Check if network events show regular beaconing pattern."""
        if len(network_events) < 3:
            return False
        
        # Extract timestamps and calculate intervals
        timestamps = []
        for event in network_events:
            try:
                timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                timestamps.append(timestamp)
            except:
                continue
        
        if len(timestamps) < 3:
            return False
        
        timestamps.sort()
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        # Check if intervals are relatively consistent (beaconing)
        if len(intervals) < 2:
            return False
        
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # If standard deviation is less than 30% of average, consider it regular
        coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else float('inf')
        return coefficient_of_variation < 0.3
    
    def _is_within_time_window(self, event: Dict[str, Any], window_seconds: int) -> bool:
        """Check if event is within specified time window."""
        try:
            event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            current_time = datetime.now()
            
            # Handle timezone-aware/naive datetime comparison
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=current_time.tzinfo)
            elif current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=event_time.tzinfo)
            
            time_diff = (current_time - event_time).total_seconds()
            return time_diff <= window_seconds
            
        except Exception as e:
            logger.debug(f"Error parsing timestamp: {e}")
            return True  # Include event if timestamp parsing fails
    
    def _cleanup_old_events(self):
        """Remove events older than the maximum time window."""
        max_window = max(
            pattern.get("time_window", 300) 
            for pattern in self.detection_patterns.values()
        )
        
        current_time = datetime.now()
        cleaned_history = deque()
        
        for event in self.event_history:
            if self._is_within_time_window(event, max_window):
                cleaned_history.append(event)
        
        self.event_history = cleaned_history
    
    def _trigger_alert(self, pattern_name: str, pattern_config: Dict, triggering_event: Dict):
        """
        Trigger an alert for a detected pattern.
        
        Args:
            pattern_name: Name of the detected pattern
            pattern_config: Pattern configuration
            triggering_event: Event that triggered the pattern
        """
        alert = {
            "timestamp": datetime.now().isoformat(),
            "pattern_name": pattern_name,
            "severity": pattern_config.get("severity", "medium"),
            "description": pattern_config.get("description", "Suspicious behavior detected"),
            "triggering_event": triggering_event,
            "pattern_config": pattern_config,
            "alert_id": f"{pattern_name}_{int(time.time())}"
        }
        
        self.stats["alerts_triggered"] += 1
        self.stats["patterns_matched"] += 1
        
        logger.warning(f"BEHAVIORAL ALERT: {alert['description']} (Severity: {alert['severity']})")
        
        # Call all registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current analysis statistics."""
        stats = self.stats.copy()
        if stats["analysis_start_time"]:
            stats["runtime_seconds"] = (datetime.now() - stats["analysis_start_time"]).total_seconds()
        
        stats["event_queue_size"] = self.event_queue.qsize()
        stats["event_history_size"] = len(self.event_history)
        stats["active_patterns"] = len(self.detection_patterns)
        
        return stats


class BehavioralMonitor:
    """
    Main behavioral monitoring system that orchestrates real-time analysis.
    
    Integrates with ProcMon handler and other monitoring components to provide
    comprehensive behavioral analysis during malware execution.
    """
    
    def __init__(self, config_settings: dict = None):
        """
        Initialize behavioral monitor.
        
        Args:
            config_settings: Configuration dictionary
        """
        self.config = config_settings or {}
        self.analyzer = RealTimeAnalyzer(config_settings)
        self.monitoring_sessions = {}
        self.alert_history = []
        
        # Setup default alert handler
        self.analyzer.add_alert_callback(self._default_alert_handler)
        
    def _default_alert_handler(self, alert: Dict[str, Any]):
        """Default alert handler that logs and stores alerts."""
        self.alert_history.append(alert)
        
        # Log alert with appropriate level
        severity = alert.get("severity", "medium").lower()
        message = f"BEHAVIORAL ALERT [{severity.upper()}]: {alert.get('description')}"
        
        if severity == "critical":
            logger.critical(message)
        elif severity == "high":
            logger.error(message)
        elif severity == "medium":
            logger.warning(message)
        else:
            logger.info(message)
    
    def start_monitoring_session(self, session_id: str, vm_identifier: str = None) -> bool:
        """
        Start a new behavioral monitoring session.
        
        Args:
            session_id: Unique session identifier
            vm_identifier: Optional VM identifier for context
            
        Returns:
            bool: True if session started successfully
        """
        if session_id in self.monitoring_sessions:
            logger.warning(f"Monitoring session {session_id} already exists")
            return False
        
        try:
            # Start the real-time analyzer
            self.analyzer.start()
            
            # Track the session
            self.monitoring_sessions[session_id] = {
                "start_time": datetime.now(),
                "vm_identifier": vm_identifier,
                "status": "active",
                "events_processed": 0,
                "alerts_generated": 0
            }
            
            logger.info(f"Started behavioral monitoring session: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start monitoring session {session_id}: {e}")
            return False
    
    def stop_monitoring_session(self, session_id: str) -> Dict[str, Any]:
        """
        Stop a behavioral monitoring session and return results.
        
        Args:
            session_id: Session identifier to stop
            
        Returns:
            dict: Session results and statistics
        """
        if session_id not in self.monitoring_sessions:
            logger.error(f"Monitoring session {session_id} not found")
            return {}
        
        try:
            session = self.monitoring_sessions[session_id]
            session["status"] = "completed"
            session["end_time"] = datetime.now()
            session["duration_seconds"] = (session["end_time"] - session["start_time"]).total_seconds()
            
            # Get analyzer statistics
            analyzer_stats = self.analyzer.get_statistics()
            session.update(analyzer_stats)
            
            # Stop the analyzer
            self.analyzer.stop()
            
            # Get alerts for this session
            session_alerts = [
                alert for alert in self.alert_history
                if alert["timestamp"] >= session["start_time"].isoformat()
            ]
            session["alerts"] = session_alerts
            session["alerts_generated"] = len(session_alerts)
            
            logger.info(f"Stopped monitoring session {session_id}. "
                       f"Processed {session.get('events_processed', 0)} events, "
                       f"Generated {session['alerts_generated']} alerts")
            
            return session
            
        except Exception as e:
            logger.error(f"Error stopping monitoring session {session_id}: {e}")
            return {}
    
    def process_event(self, event: Dict[str, Any], session_id: str = None):
        """
        Process a behavioral event through the monitoring system.
        
        Args:
            event: Event dictionary
            session_id: Optional session identifier for tracking
        """
        # Update session statistics if provided
        if session_id and session_id in self.monitoring_sessions:
            self.monitoring_sessions[session_id]["events_processed"] += 1
        
        # Send event to real-time analyzer
        self.analyzer.process_event(event)
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """
        Get current status of a monitoring session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            dict: Session status information
        """
        if session_id not in self.monitoring_sessions:
            return {"error": "Session not found"}
        
        session = self.monitoring_sessions[session_id].copy()
        
        # Add current analyzer statistics if session is active
        if session.get("status") == "active":
            analyzer_stats = self.analyzer.get_statistics()
            session.update(analyzer_stats)
        
        return session
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most recent alerts.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            list: Recent alerts
        """
        return self.alert_history[-limit:] if self.alert_history else []
    
    def export_session_results(self, session_id: str, output_path: str) -> bool:
        """
        Export session results to JSON file.
        
        Args:
            session_id: Session identifier
            output_path: Output file path
            
        Returns:
            bool: True if export successful
        """
        if session_id not in self.monitoring_sessions:
            logger.error(f"Session {session_id} not found for export")
            return False
        
        try:
            session_data = self.get_session_status(session_id)
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, default=str)
            
            logger.info(f"Exported session {session_id} results to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export session {session_id}: {e}")
            return False


# Convenience function for integration
def create_behavioral_monitor(config_settings: dict = None) -> BehavioralMonitor:
    """
    Create and configure a behavioral monitor instance.
    
    Args:
        config_settings: Optional configuration settings
        
    Returns:
        BehavioralMonitor: Configured monitor instance
    """
    return BehavioralMonitor(config_settings)


if __name__ == "__main__":
    # Example usage and testing
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and test behavioral monitor
    monitor = BehavioralMonitor()
    
    # Start monitoring session
    session_id = "test_session_001"
    if monitor.start_monitoring_session(session_id):
        print(f"Started monitoring session: {session_id}")
        
        # Simulate some events
        test_events = [
            {
                "operation": "WriteFile",
                "path": "C:\\Users\\Test\\Documents\\file1.txt.encrypted",
                "process": "malware.exe"
            },
            {
                "operation": "RegSetValue", 
                "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
                "process": "malware.exe"
            },
            {
                "operation": "WriteFile",
                "path": "C:\\Users\\Test\\Documents\\file2.docx.encrypted", 
                "process": "malware.exe"
            }
        ]
        
        # Process test events
        for event in test_events:
            monitor.process_event(event, session_id)
            time.sleep(1)  # Simulate real-time processing
        
        # Wait a bit for processing
        time.sleep(2)
        
        # Stop session and get results
        results = monitor.stop_monitoring_session(session_id)
        print(f"Session results: {json.dumps(results, indent=2, default=str)}")
        
        # Show recent alerts
        alerts = monitor.get_recent_alerts()
        print(f"Recent alerts: {len(alerts)}")
        for alert in alerts:
            print(f"  - {alert['severity'].upper()}: {alert['description']}")
    
    else:
        print("Failed to start monitoring session")
        sys.exit(1)