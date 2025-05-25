# shikra/modules/reporting/report_generator.py
# Purpose: Generates comprehensive malware analysis reports in multiple formats
# Complete implementation based on existing Shikra codebase patterns

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import os
import base64
from collections import defaultdict, Counter
from html import escape
import hashlib
import re

# Optional dependencies for report generation
try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    jinja2 = None

try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    weasyprint = None

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Configure logging for this module
logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates comprehensive malware analysis reports in multiple formats
    by consolidating and formatting results from all analysis modules.
    
    This class serves as the primary report generation engine in Shikra,
    creating professional reports suitable for technical analysis teams
    and executive briefings.
    """
    
    def __init__(self, template_directory: Optional[Path] = None, output_directory: Optional[Path] = None):
        """
        Initialize the report generator with template and output directories.
        
        Args:
            template_directory (Optional[Path]): Path to report templates directory
            output_directory (Optional[Path]): Default output directory for generated reports
        """
        self.template_directory = template_directory or Path(__file__).parent / "templates"
        self.output_directory = output_directory or Path("./reports")
        self.supported_formats = ['pdf', 'html', 'json']
        self.report_metadata = {
            "generator": "Shikra Analysis Framework",
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat() + "Z"
        }
        
        # Ensure directories exist
        self.template_directory.mkdir(parents=True, exist_ok=True)
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment if available
        self.jinja_env = None
        if JINJA2_AVAILABLE:
            try:
                self.jinja_env = jinja2.Environment(
                    loader=jinja2.FileSystemLoader(str(self.template_directory)),
                    autoescape=jinja2.select_autoescape(['html', 'xml'])
                )
                self.jinja_env.filters['datetime_format'] = self._datetime_format_filter
                self.jinja_env.filters['severity_color'] = self._severity_color_filter
            except Exception as e:
                logger.warning(f"Failed to initialize Jinja2 environment: {e}")
                JINJA2_AVAILABLE = False
        
        # MITRE ATT&CK technique mappings
        self.mitre_mappings = self._initialize_mitre_mappings()
        
        logger.info("ReportGenerator initialized")
    
    def _datetime_format_filter(self, timestamp, fmt='%Y-%m-%d %H:%M:%S UTC'):
        """Jinja2 filter for datetime formatting."""
        if not timestamp:
            return "N/A"
        try:
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif isinstance(timestamp, (int, float)):
                dt = datetime.fromtimestamp(timestamp)
            else:
                dt = timestamp
            return dt.strftime(fmt)
        except (ValueError, TypeError):
            return str(timestamp)
    
    def _severity_color_filter(self, severity):
        """Jinja2 filter for severity color mapping."""
        color_map = {
            'critical': '#dc3545',
            'high': '#fd7e14', 
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        return color_map.get(str(severity).lower(), '#6c757d')
    
    def _initialize_mitre_mappings(self) -> Dict[str, Dict[str, str]]:
        """Initialize MITRE ATT&CK technique mappings."""
        return {
            # Persistence techniques
            'registry_run_key': {
                'technique_id': 'T1547.001',
                'technique_name': 'Registry Run Keys / Startup Folder',
                'tactic': 'Persistence'
            },
            'scheduled_task': {
                'technique_id': 'T1053.005',
                'technique_name': 'Scheduled Task',
                'tactic': 'Persistence'
            },
            'service_creation': {
                'technique_id': 'T1543.003',
                'technique_name': 'Windows Service',
                'tactic': 'Persistence'
            },
            
            # Defense Evasion
            'process_injection': {
                'technique_id': 'T1055',
                'technique_name': 'Process Injection',
                'tactic': 'Defense Evasion'
            },
            'masquerading': {
                'technique_id': 'T1036',
                'technique_name': 'Masquerading',
                'tactic': 'Defense Evasion'
            },
            'shadow_copy_deletion': {
                'technique_id': 'T1490',
                'technique_name': 'Inhibit System Recovery',
                'tactic': 'Impact'
            },
            
            # Discovery
            'system_info_discovery': {
                'technique_id': 'T1082',
                'technique_name': 'System Information Discovery',
                'tactic': 'Discovery'
            },
            'process_discovery': {
                'technique_id': 'T1057',
                'technique_name': 'Process Discovery',
                'tactic': 'Discovery'
            },
            
            # Collection
            'data_from_local_system': {
                'technique_id': 'T1005',
                'technique_name': 'Data from Local System',
                'tactic': 'Collection'
            },
            
            # Command and Control
            'application_layer_protocol': {
                'technique_id': 'T1071',
                'technique_name': 'Application Layer Protocol',
                'tactic': 'Command and Control'
            },
            'encrypted_channel': {
                'technique_id': 'T1573',
                'technique_name': 'Encrypted Channel',
                'tactic': 'Command and Control'
            },
            
            # Impact
            'data_encrypted_for_impact': {
                'technique_id': 'T1486',
                'technique_name': 'Data Encrypted for Impact',
                'tactic': 'Impact'
            }
        }
    
    def generate_comprehensive_report(self, analysis_results: Dict[str, Any], 
                                    sample_info: Dict[str, Any],
                                    output_path: Path,
                                    report_format: str = 'html') -> Path:
        """
        Generate a comprehensive analysis report combining all analysis module results.
        """
        logger.info(f"Generating comprehensive report in {report_format} format")
        
        if report_format not in self.supported_formats:
            raise ValueError(f"Unsupported format: {report_format}. Supported: {self.supported_formats}")
        
        # Compile all report data
        report_data = {
            "metadata": self.report_metadata.copy(),
            "sample_info": sample_info,
            "executive_summary": self.create_executive_summary(analysis_results),
            "technical_findings": self.compile_technical_findings(analysis_results),
            "iocs": self.extract_and_categorize_iocs(analysis_results),
            "mitre_attack": self.map_mitre_attack_techniques(analysis_results.get('behavioral', {})),
            "timeline": self.generate_timeline_analysis(analysis_results),
            "threat_assessment": self.calculate_threat_score(analysis_results),
            "analysis_results": analysis_results
        }
        
        # Add sample hash to metadata
        if sample_info.get('file_path'):
            report_data["metadata"]["sample_hash"] = self._calculate_file_hash(sample_info['file_path'])
        
        # Validate report completeness
        validation_warnings = self.validate_report_completeness(report_data)
        if validation_warnings:
            logger.warning(f"Report validation warnings: {validation_warnings}")
            report_data["validation_warnings"] = validation_warnings
        
        # Generate report based on format
        if report_format == 'json':
            return self.generate_json_report(report_data, output_path)
        elif report_format == 'html':
            return self.generate_html_report(report_data, output_path)
        elif report_format == 'pdf':
            return self.generate_pdf_report(report_data, output_path)
        
        return output_path
    
    def create_executive_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create an executive summary section for non-technical stakeholders.
        """
        logger.info("Creating executive summary")
        
        # Determine overall threat level
        behavioral_score = analysis_results.get('behavioral', {}).get('score', 0)
        network_score = analysis_results.get('network', {}).get('score', 0)
        memory_score = analysis_results.get('memory', {}).get('score', 0)
        
        max_score = max(behavioral_score, network_score, memory_score)
        
        if max_score >= 80:
            threat_level = "CRITICAL"
            risk_description = "Immediate action required. High confidence malicious software detected."
        elif max_score >= 60:
            threat_level = "HIGH"
            risk_description = "Significant threat detected. Recommend immediate investigation and containment."
        elif max_score >= 40:
            threat_level = "MEDIUM"
            risk_description = "Suspicious activity detected. Further analysis and monitoring recommended."
        elif max_score >= 20:
            threat_level = "LOW"
            risk_description = "Low-level suspicious indicators. Monitoring recommended."
        else:
            threat_level = "MINIMAL"
            risk_description = "No significant threats detected in current analysis."
        
        # Identify key capabilities
        capabilities = []
        
        # Check for ransomware indicators
        behavioral_data = analysis_results.get('behavioral', {})
        if any(sig.get('type') == 'data_encrypted_for_impact' for sig in behavioral_data.get('signatures', [])):
            capabilities.append("File Encryption (Ransomware)")
        
        # Check for persistence
        if any(sig.get('type') in ['registry_run_key', 'scheduled_task'] for sig in behavioral_data.get('signatures', [])):
            capabilities.append("System Persistence")
        
        # Check for network communication
        network_data = analysis_results.get('network', {})
        if network_data.get('summary', {}).get('c2_communication_detected'):
            capabilities.append("Command & Control Communication")
        
        # Check for evasion techniques
        if behavioral_data.get('evasion_techniques') or any(sig.get('type') == 'process_injection' for sig in behavioral_data.get('signatures', [])):
            capabilities.append("Anti-Analysis/Evasion")
        
        # Primary targets
        targets = []
        extension_targeting = behavioral_data.get('extension_targeting', {})
        if extension_targeting:
            common_extensions = ['.docx', '.pdf', '.xlsx', '.jpg', '.png']
            if any(ext in extension_targeting for ext in common_extensions):
                targets.append("User Documents and Media Files")
        
        if any('System' in str(item) for item in behavioral_data.get('system_modifications', [])):
            targets.append("System Configuration and Security")
        
        # Recommended actions
        actions = []
        if threat_level in ['CRITICAL', 'HIGH']:
            actions.extend([
                "Immediately isolate affected systems from network",
                "Initiate incident response procedures",
                "Preserve forensic evidence",
                "Check for lateral movement indicators"
            ])
        elif threat_level == 'MEDIUM':
            actions.extend([
                "Enhanced monitoring of affected systems",
                "Deploy additional security controls",
                "Update threat detection signatures"
            ])
        else:
            actions.append("Continue normal security monitoring")
        
        return {
            "threat_level": threat_level,
            "overall_score": max_score,
            "risk_description": risk_description,
            "key_capabilities": capabilities,
            "primary_targets": targets,
            "recommended_actions": actions,
            "analysis_confidence": "High" if max_score > 60 else "Medium" if max_score > 30 else "Low"
        }
    
    def compile_technical_findings(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile detailed technical findings from all analysis modules.
        """
        logger.info("Compiling technical findings")
        
        findings = {
            "behavioral_analysis": self._process_behavioral_findings(analysis_results.get('behavioral', {})),
            "network_analysis": self._process_network_findings(analysis_results.get('network', {})),
            "memory_analysis": self._process_memory_findings(analysis_results.get('memory', {})),
            "cross_correlations": self._identify_cross_correlations(analysis_results)
        }
        
        return findings
    
    def _process_behavioral_findings(self, behavioral_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process behavioral analysis findings."""
        if not behavioral_data:
            return {"status": "No behavioral analysis data available"}
        
        return {
            "classification": behavioral_data.get('classification', 'Unknown'),
            "score": behavioral_data.get('score', 0),
            "file_operations": {
                "summary": behavioral_data.get('file_operations', {}).get('summary', {}),
                "targeted_extensions": behavioral_data.get('extension_targeting', {}),
                "suspicious_patterns": [
                    sig for sig in behavioral_data.get('signatures', [])
                    if sig.get('type') in ['mass_file_modification', 'ransomware_extension', 'ransom_note']
                ]
            },
            "process_activity": {
                "created_processes": behavioral_data.get('process_operations', {}).get('processes_created', []),
                "suspicious_commands": [
                    sig for sig in behavioral_data.get('signatures', [])
                    if sig.get('type') == 'suspicious_command'
                ]
            },
            "persistence_mechanisms": behavioral_data.get('persistence_mechanisms', []),
            "evasion_techniques": behavioral_data.get('evasion_techniques', []),
            "system_modifications": behavioral_data.get('system_modifications', [])
        }
    
    def _process_network_findings(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process network analysis findings."""
        if not network_data:
            return {"status": "No network analysis data available"}
        
        return {
            "classification": network_data.get('classification', 'Unknown'),
            "score": network_data.get('score', 0),
            "dns_activity": {
                "total_queries": len(network_data.get('dns_queries', [])),
                "suspicious_domains": [
                    finding for finding in network_data.get('suspicious_findings', [])
                    if finding.get('type') in ['Suspicious DNS Query', 'DGA Domain Query']
                ],
                "c2_domains": [
                    finding for finding in network_data.get('suspicious_findings', [])
                    if finding.get('type') == 'Known C2 Communication'
                ]
            },
            "http_activity": {
                "total_requests": len(network_data.get('http_requests', [])),
                "suspicious_requests": [
                    finding for finding in network_data.get('suspicious_findings', [])
                    if finding.get('type') in ['Suspicious Host Communication', 'Suspicious URI Pattern']
                ]
            },
            "communication_patterns": {
                "beaconing_detected": network_data.get('summary', {}).get('beaconing_detected_count', 0) > 0,
                "tor_usage": network_data.get('summary', {}).get('tor_traffic_detected', False),
                "data_exfiltration": network_data.get('summary', {}).get('data_exfiltration_suspected', False)
            }
        }
    
    def _process_memory_findings(self, memory_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process memory analysis findings."""
        if not memory_data:
            return {"status": "No memory analysis data available"}
        
        return {
            "classification": memory_data.get('classification', 'Unknown'),
            "score": memory_data.get('score', 0),
            "process_analysis": {
                "suspicious_processes": memory_data.get('suspicious_processes', []),
                "hidden_processes": memory_data.get('hidden_processes', []),
                "code_injection": memory_data.get('injected_code_regions', [])
            },
            "network_artifacts": {
                "active_connections": memory_data.get('network_connections_mem', []),
                "suspicious_connections": [
                    sig for sig in memory_data.get('signatures', [])
                    if sig.get('type') == 'Suspicious Network Connection (Mem)'
                ]
            },
            "encryption_indicators": memory_data.get('encryption_keywords_in_memory', []),
            "command_lines": memory_data.get('command_line_args', [])
        }
    
    def _identify_cross_correlations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify correlations between different analysis modules."""
        correlations = []
        
        behavioral_data = analysis_results.get('behavioral', {})
        network_data = analysis_results.get('network', {})
        memory_data = analysis_results.get('memory', {})
        
        # Check for process names appearing in multiple modules
        behavioral_processes = set()
        if behavioral_data.get('process_operations', {}).get('processes_created'):
            behavioral_processes = {
                proc.get('child_process_name', '') 
                for proc in behavioral_data['process_operations']['processes_created']
            }
        
        memory_processes = set()
        if memory_data.get('suspicious_processes'):
            memory_processes = {proc.get('name', '') for proc in memory_data['suspicious_processes']}
        
        common_processes = behavioral_processes.intersection(memory_processes)
        if common_processes:
            correlations.append({
                "type": "Cross-Module Process Correlation",
                "description": f"Processes observed in both behavioral and memory analysis: {', '.join(common_processes)}",
                "confidence": "High"
            })
        
        # Check for network indicators in behavioral vs network modules
        behavioral_network_indicators = set()
        for sig in behavioral_data.get('signatures', []):
            if 'network' in str(sig.get('description', '')).lower():
                behavioral_network_indicators.add(sig.get('description', ''))
        
        if behavioral_network_indicators and network_data.get('suspicious_findings'):
            correlations.append({
                "type": "Network Activity Correlation",
                "description": "Network-related behaviors observed in both behavioral analysis and network traffic",
                "confidence": "Medium"
            })
        
        return correlations
    
    def extract_and_categorize_iocs(self, analysis_results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract and categorize Indicators of Compromise from all analysis modules.
        """
        logger.info("Extracting and categorizing IOCs")
        
        iocs = {
            "file_hashes": [],
            "file_paths": [],
            "registry_keys": [],
            "network_indicators": [],
            "process_names": [],
            "mutexes": [],
            "behavioral_indicators": []
        }
        
        # Extract from behavioral analysis
        behavioral_data = analysis_results.get('behavioral', {})
        if behavioral_data:
            # File paths from file operations
            for file_op_type, operations in behavioral_data.get('file_operations', {}).items():
                if isinstance(operations, list):
                    for op in operations:
                        if isinstance(op, dict) and op.get('path'):
                            iocs["file_paths"].append({
                                "indicator": op['path'],
                                "context": f"File operation: {file_op_type}",
                                "source": "behavioral_analysis"
                            })
            
            # Registry keys
            for reg_op_type, operations in behavioral_data.get('registry_operations', {}).items():
                if isinstance(operations, list):
                    for op in operations:
                        if isinstance(op, dict) and op.get('key'):
                            iocs["registry_keys"].append({
                                "indicator": op['key'],
                                "value": op.get('value', ''),
                                "context": f"Registry operation: {reg_op_type}",
                                "source": "behavioral_analysis"
                            })
            
            # Process names
            for proc in behavioral_data.get('process_operations', {}).get('processes_created', []):
                if proc.get('child_process_name'):
                    iocs["process_names"].append({
                        "indicator": proc['child_process_name'],
                        "command_line": proc.get('command', ''),
                        "context": "Process creation",
                        "source": "behavioral_analysis"
                    })
        
        # Extract from network analysis
        network_data = analysis_results.get('network', {})
        if network_data:
            # DNS queries
            for query in network_data.get('dns_queries', []):
                if query.get('query_name'):
                    iocs["network_indicators"].append({
                        "type": "domain",
                        "indicator": query['query_name'],
                        "context": "DNS query",
                        "source": "network_analysis"
                    })
            
            # HTTP requests
            for request in network_data.get('http_requests', []):
                if request.get('http_host'):
                    iocs["network_indicators"].append({
                        "type": "domain",
                        "indicator": request['http_host'],
                        "context": "HTTP request",
                        "source": "network_analysis"
                    })
                if request.get('dest_ip'):
                    iocs["network_indicators"].append({
                        "type": "ip",
                        "indicator": request['dest_ip'],
                        "context": "HTTP connection",
                        "source": "network_analysis"
                    })
            
            # TLS connections
            for conn in network_data.get('tls_connections', []):
                if conn.get('tls_sni'):
                    iocs["network_indicators"].append({
                        "type": "domain",
                        "indicator": conn['tls_sni'],
                        "context": "TLS SNI",
                        "source": "network_analysis"
                    })
        
        # Extract from memory analysis
        memory_data = analysis_results.get('memory', {})
        if memory_data:
            # Mutexes
            for mutex in memory_data.get('mutexes', []):
                if mutex.get('name'):
                    iocs["mutexes"].append({
                        "indicator": mutex['name'],
                        "context": "Memory mutex",
                        "source": "memory_analysis"
                    })
            
            # Suspicious processes
            for proc in memory_data.get('suspicious_processes', []):
                if proc.get('name'):
                    iocs["process_names"].append({
                        "indicator": proc['name'],
                        "pid": proc.get('pid', ''),
                        "context": "Suspicious memory process",
                        "source": "memory_analysis"
                    })
        
        # Deduplicate IOCs
        for category in iocs:
            seen = set()
            unique_iocs = []
            for ioc in iocs[category]:
                indicator = ioc.get('indicator', '')
                if indicator and indicator not in seen:
                    seen.add(indicator)
                    unique_iocs.append(ioc)
            iocs[category] = unique_iocs
        
        return iocs
    
    def map_mitre_attack_techniques(self, behavioral_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Map observed behaviors to MITRE ATT&CK framework techniques.
        """
        logger.info("Mapping MITRE ATT&CK techniques")
        
        mapped_techniques = []
        
        if not behavioral_results:
            return mapped_techniques
        
        # Check signatures for technique indicators
        for signature in behavioral_results.get('signatures', []):
            sig_type = signature.get('type', '')
            evidence = signature.get('description', '')
            
            # Map signature types to MITRE techniques
            technique_mapping = None
            
            if 'registry_run_key' in sig_type.lower() or 'persistence' in sig_type.lower():
                technique_mapping = self.mitre_mappings.get('registry_run_key')
            elif 'shadow_copy' in sig_type.lower():
                technique_mapping = self.mitre_mappings.get('shadow_copy_deletion')
            elif 'injection' in sig_type.lower():
                technique_mapping = self.mitre_mappings.get('process_injection')
            elif 'scheduled_task' in sig_type.lower():
                technique_mapping = self.mitre_mappings.get('scheduled_task')
            elif 'service' in sig_type.lower():
                technique_mapping = self.mitre_mappings.get('service_creation')
            elif 'encryption' in sig_type.lower() or 'ransomware' in sig_type.lower():
                technique_mapping = self.mitre_mappings.get('data_encrypted_for_impact')
            
            if technique_mapping:
                mapped_techniques.append({
                    "technique_id": technique_mapping['technique_id'],
                    "technique_name": technique_mapping['technique_name'],
                    "tactic": technique_mapping['tactic'],
                    "evidence": evidence,
                    "confidence": signature.get('severity', 'medium'),
                    "source": "behavioral_signatures"
                })
        
        # Check persistence mechanisms
        for persistence in behavioral_results.get('persistence_mechanisms', []):
            if persistence.get('type') == 'registry':
                mapped_techniques.append({
                    "technique_id": "T1547.001",
                    "technique_name": "Registry Run Keys / Startup Folder",
                    "tactic": "Persistence",
                    "evidence": f"Registry key: {persistence.get('key', '')}",
                    "confidence": "high",
                    "source": "persistence_mechanisms"
                })
        
        # Check system modifications
        for modification in behavioral_results.get('system_modifications', []):
            if 'shadow_copy' in str(modification).lower():
                mapped_techniques.append({
                    "technique_id": "T1490",
                    "technique_name": "Inhibit System Recovery",
                    "tactic": "Impact",
                    "evidence": str(modification),
                    "confidence": "high",
                    "source": "system_modifications"
                })
        
        # Remove duplicates
        unique_techniques = []
        seen_techniques = set()
        for technique in mapped_techniques:
            key = (technique['technique_id'], technique['evidence'])
            if key not in seen_techniques:
                seen_techniques.add(key)
                unique_techniques.append(technique)
        
        return unique_techniques
    
    def generate_timeline_analysis(self, all_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate a comprehensive timeline of malware execution events.
        """
        logger.info("Generating timeline analysis")
        
        timeline_events = []
        
        # Extract events from behavioral analysis
        behavioral_data = all_results.get('behavioral', {})
        if behavioral_data.get('timeline'):
            for event in behavioral_data['timeline']:
                timeline_events.append({
                    "timestamp": event.get('time_display', 'Unknown'),
                    "source": "behavioral",
                    "event_type": event.get('event_type', 'Unknown'),
                    "description": event.get('description', ''),
                    "details": event.get('details_summary', ''),
                    "severity": self._extract_severity_from_event(event)
                })
        
        # Extract events from network analysis
        network_data = all_results.get('network', {})
        if network_data.get('dns_queries'):
            # Add first DNS query as timeline event
            first_dns = network_data['dns_queries'][0] if network_data['dns_queries'] else None
            if first_dns:
                timeline_events.append({
                    "timestamp": self._format_timestamp(first_dns.get('timestamp_epoch')),
                    "source": "network",
                    "event_type": "First DNS Query",
                    "description": f"First DNS query to {first_dns.get('query_name', 'unknown domain')}",
                    "details": f"Query type: {first_dns.get('query_type_str', 'unknown')}",
                    "severity": "info"
                })
        
        if network_data.get('http_requests'):
            # Add first HTTP request as timeline event
            first_http = network_data['http_requests'][0] if network_data['http_requests'] else None
            if first_http:
                timeline_events.append({
                    "timestamp": self._format_timestamp(first_http.get('timestamp_epoch')),
                    "source": "network",
                    "event_type": "First HTTP Request",
                    "description": f"First HTTP request to {first_http.get('http_host', 'unknown host')}",
                    "details": f"URI: {first_http.get('http_uri', 'unknown')}",
                    "severity": "medium" if first_http.get('http_host') else "info"
                })
        
        # Add suspicious findings as timeline events
        for finding in network_data.get('suspicious_findings', []):
            timeline_events.append({
                "timestamp": finding.get('timestamp', 'Unknown'),
                "source": "network",
                "event_type": finding.get('type', 'Suspicious Activity'),
                "description": finding.get('description', ''),
                "details": str(finding.get('details', {})),
                "severity": finding.get('severity', 'medium')
            })
        
        # Sort timeline by timestamp (attempt to parse timestamps)
        def parse_timestamp_for_sort(event):
            timestamp = event.get('timestamp', '')
            try:
                if isinstance(timestamp, str):
                    # Try various timestamp formats
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%H:%M:%S', '%Y-%m-%dT%H:%M:%S']:
                        try:
                            return datetime.strptime(timestamp, fmt)
                        except ValueError:
                            continue
                    return datetime.min
                elif isinstance(timestamp, (int, float)):
                    return datetime.fromtimestamp(timestamp)
                else:
                    return datetime.min
            except:
                return datetime.min
        
        timeline_events.sort(key=parse_timestamp_for_sort)
        
        return timeline_events
    
    def _extract_severity_from_event(self, event: Dict[str, Any]) -> str:
        """Extract severity from behavioral timeline event."""
        event_type = event.get('event_type', '').lower()
        description = event.get('description', '').lower()
        
        if any(keyword in event_type or keyword in description 
               for keyword in ['critical', 'shadow_copy', 'ransomware', 'encryption']):
            return 'critical'
        elif any(keyword in event_type or keyword in description 
                 for keyword in ['high', 'persistence', 'injection', 'suspicious']):
            return 'high'
        elif any(keyword in event_type or keyword in description 
                 for keyword in ['medium', 'registry', 'network']):
            return 'medium'
        else:
            return 'low'
    
    def _format_timestamp(self, timestamp) -> str:
        """Format timestamp for display."""
        if not timestamp:
            return "Unknown"
        try:
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            else:
                return str(timestamp)
        except:
            return str(timestamp)
    
    def calculate_threat_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate an overall threat score and risk assessment.
        """
        logger.info("Calculating threat score and assessment")
        
        # Get individual module scores
        behavioral_score = analysis_results.get('behavioral', {}).get('score', 0)
        network_score = analysis_results.get('network', {}).get('score', 0)
        memory_score = analysis_results.get('memory', {}).get('score', 0)
        
        # Calculate weighted overall score
        weights = {'behavioral': 0.4, 'network': 0.3, 'memory': 0.3}
        overall_score = (
            behavioral_score * weights['behavioral'] +
            network_score * weights['network'] +
            memory_score * weights['memory']
        )
        
        # Determine risk level
        if overall_score >= 80:
            risk_level = "CRITICAL"
            risk_color = "#dc3545"
        elif overall_score >= 60:
            risk_level = "HIGH"
            risk_color = "#fd7e14"
        elif overall_score >= 40:
            risk_level = "MEDIUM"
            risk_color = "#ffc107"
        elif overall_score >= 20:
            risk_level = "LOW"
            risk_color = "#28a745"
        else:
            risk_level = "MINIMAL"
            risk_color = "#6c757d"
        
        # Calculate confidence based on number of analysis modules with results
        modules_with_data = sum(1 for module in ['behavioral', 'network', 'memory'] 
                               if analysis_results.get(module, {}).get('score', 0) > 0)
        
        if modules_with_data >= 3:
            confidence = "High"
        elif modules_with_data >= 2:
            confidence = "Medium"
        else:
            confidence = "Low"
        
        # Identify primary threat factors
        threat_factors = []
        
        behavioral_data = analysis_results.get('behavioral', {})
        if behavioral_data.get('score', 0) > 60:
            threat_factors.append("Malicious behavioral patterns detected")
        
        network_data = analysis_results.get('network', {})
        if network_data.get('summary', {}).get('c2_communication_detected'):
            threat_factors.append("Command & Control communication identified")
        
        memory_data = analysis_results.get('memory', {})
        if memory_data.get('summary', {}).get('code_injection_found', 0) > 0:
            threat_factors.append("Code injection techniques observed")
        
        if any('encryption' in str(sig).lower() 
               for sig in behavioral_data.get('signatures', [])):
            threat_factors.append("File encryption capabilities detected")
        
        return {
            "overall_score": round(overall_score, 1),
            "risk_level": risk_level,
            "risk_color": risk_color,
            "confidence": confidence,
            "module_scores": {
                "behavioral": behavioral_score,
                "network": network_score,
                "memory": memory_score
            },
            "threat_factors": threat_factors,
            "score_breakdown": {
                "behavioral_weighted": round(behavioral_score * weights['behavioral'], 1),
                "network_weighted": round(network_score * weights['network'], 1),
                "memory_weighted": round(memory_score * weights['memory'], 1)
            }
        }
    
    def _calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes for the analyzed sample."""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hashes: {e}")
        return hashes
    
    def generate_pdf_report(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """
        Generate a PDF format report using HTML to PDF conversion.
        """
        logger.info(f"Generating PDF report: {output_path}")
        
        if WEASYPRINT_AVAILABLE:
            # Generate HTML first, then convert to PDF
            html_path = output_path.with_suffix('.html')
            self.generate_html_report(report_data, html_path)
            
            try:
                weasyprint.HTML(filename=str(html_path)).write_pdf(str(output_path))
                logger.info(f"PDF report generated successfully: {output_path}")
                return output_path
            except Exception as e:
                logger.error(f"Error generating PDF with WeasyPrint: {e}")
        
        elif REPORTLAB_AVAILABLE:
            # Use ReportLab for PDF generation
            try:
                doc = SimpleDocTemplate(str(output_path), pagesize=letter)
                styles = getSampleStyleSheet()
                story = []
                
                # Title
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=18,
                    spaceAfter=30,
                    textColor=colors.darkblue
                )
                story.append(Paragraph("Shikra Malware Analysis Report", title_style))
                story.append(Spacer(1, 12))
                
                # Executive Summary
                story.append(Paragraph("Executive Summary", styles['Heading2']))
                exec_summary = report_data.get('executive_summary', {})
                story.append(Paragraph(f"Threat Level: {exec_summary.get('threat_level', 'Unknown')}", styles['Normal']))
                story.append(Paragraph(f"Overall Score: {exec_summary.get('overall_score', 0)}/100", styles['Normal']))
                story.append(Spacer(1, 12))
                
                # Key Findings
                if exec_summary.get('key_capabilities'):
                    story.append(Paragraph("Key Capabilities:", styles['Heading3']))
                    for capability in exec_summary['key_capabilities']:
                        story.append(Paragraph(f"• {capability}", styles['Normal']))
                    story.append(Spacer(1, 12))
                
                # IOCs Table
                iocs = report_data.get('iocs', {})
                if any(iocs.values()):
                    story.append(Paragraph("Indicators of Compromise", styles['Heading2']))
                    
                    # Create IOC table data
                    ioc_data = [['Type', 'Indicator', 'Context']]
                    for ioc_type, ioc_list in iocs.items():
                        for ioc in ioc_list[:5]:  # Limit to first 5 per type
                            ioc_data.append([
                                ioc_type.replace('_', ' ').title(),
                                str(ioc.get('indicator', '')),
                                str(ioc.get('context', ''))
                            ])
                    
                    if len(ioc_data) > 1:
                        ioc_table = Table(ioc_data)
                        ioc_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, 0), 12),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        story.append(ioc_table)
                
                doc.build(story)
                logger.info(f"PDF report generated with ReportLab: {output_path}")
                return output_path
                
            except Exception as e:
                logger.error(f"Error generating PDF with ReportLab: {e}")
        
        else:
            logger.error("No PDF generation library available (WeasyPrint or ReportLab)")
            # Fallback: generate HTML instead
            html_path = output_path.with_suffix('.html')
            return self.generate_html_report(report_data, html_path)
        
        return output_path
    
    def generate_html_report(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """
        Generate an HTML format report with interactive elements.
        """
        logger.info(f"Generating HTML report: {output_path}")
        
        if JINJA2_AVAILABLE and self.jinja_env:
            try:
                template = self.jinja_env.get_template('comprehensive_report.html')
                html_content = template.render(report=report_data)
            except Exception as e:
                logger.warning(f"Jinja2 template rendering failed: {e}. Using basic HTML generation.")
                html_content = self._generate_basic_html_report(report_data)
        else:
            html_content = self._generate_basic_html_report(report_data)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report generated successfully: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error writing HTML report: {e}")
            raise
    
    def _generate_basic_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate basic HTML report without Jinja2."""
        sample_info = report_data.get('sample_info', {})
        exec_summary = report_data.get('executive_summary', {})
        threat_assessment = report_data.get('threat_assessment', {})
        iocs = report_data.get('iocs', {})
        mitre_attack = report_data.get('mitre_attack', [])
        timeline = report_data.get('timeline', [])
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Shikra Malware Analysis Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ text-align: center; border-bottom: 3px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }}
                .header h1 {{ color: #007bff; margin: 0; font-size: 2.5em; }}
                .header p {{ color: #6c757d; margin: 10px 0 0 0; }}
                
                .executive-summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 8px; margin-bottom: 30px; }}
                .threat-level {{ font-size: 2em; font-weight: bold; text-align: center; margin-bottom: 15px; }}
                .threat-level.CRITICAL {{ color: #ff6b6b; }}
                .threat-level.HIGH {{ color: #ffa726; }}
                .threat-level.MEDIUM {{ color: #ffeb3b; }}
                .threat-level.LOW {{ color: #4caf50; }}
                
                .section {{ margin-bottom: 30px; }}
                .section h2 {{ color: #343a40; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }}
                .section h3 {{ color: #495057; margin-top: 25px; }}
                
                .score-container {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .score-item {{ text-align: center; padding: 15px; background-color: #f8f9fa; border-radius: 8px; }}
                .score-value {{ font-size: 2em; font-weight: bold; color: #007bff; }}
                
                .ioc-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
                .ioc-category {{ background-color: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #007bff; }}
                .ioc-category h4 {{ margin-top: 0; color: #495057; }}
                .ioc-item {{ background-color: white; padding: 8px; margin: 5px 0; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
                
                .mitre-techniques {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px; }}
                .mitre-technique {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; }}
                .mitre-technique .technique-id {{ font-weight: bold; color: #856404; }}
                .mitre-technique .tactic {{ background-color: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
                
                .timeline {{ background-color: #f8f9fa; padding: 20px; border-radius: 8px; }}
                .timeline-item {{ background-color: white; margin: 10px 0; padding: 15px; border-left: 4px solid #007bff; border-radius: 4px; }}
                .timeline-item .timestamp {{ font-weight: bold; color: #6c757d; }}
                .timeline-item .severity {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.8em; }}
                .severity.critical {{ background-color: #dc3545; }}
                .severity.high {{ background-color: #fd7e14; }}
                .severity.medium {{ background-color: #ffc107; color: #212529; }}
                .severity.low {{ background-color: #28a745; }}
                
                .capabilities {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 15px 0; }}
                .capability {{ background-color: #e3f2fd; color: #1565c0; padding: 8px 16px; border-radius: 20px; font-size: 0.9em; }}
                
                .recommendations {{ background-color: #d1ecf1; border: 1px solid #bee5eb; padding: 20px; border-radius: 8px; }}
                .recommendations ul {{ margin: 0; padding-left: 20px; }}
                .recommendations li {{ margin: 8px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Shikra Malware Analysis Report</h1>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p>Sample: {escape(sample_info.get('filename', 'Unknown'))}</p>
                </div>
                
                <div class="executive-summary">
                    <div class="threat-level {exec_summary.get('threat_level', 'UNKNOWN')}">
                        THREAT LEVEL: {exec_summary.get('threat_level', 'UNKNOWN')}
                    </div>
                    <div class="score-container">
                        <div class="score-item">
                            <div class="score-value">{exec_summary.get('overall_score', 0)}</div>
                            <div>Overall Score</div>
                        </div>
                        <div class="score-item">
                            <div class="score-value">{exec_summary.get('analysis_confidence', 'Unknown')}</div>
                            <div>Confidence</div>
                        </div>
                    </div>
                    <p><strong>Risk Assessment:</strong> {exec_summary.get('risk_description', 'No assessment available')}</p>
                    
                    {f'<div class="capabilities">{"".join(f"<span class=\"capability\">{escape(cap)}</span>" for cap in exec_summary.get("key_capabilities", []))}</div>' if exec_summary.get('key_capabilities') else ''}
                </div>
                
                <div class="section">
                    <h2>Threat Assessment Breakdown</h2>
                    <div class="score-container">
                        <div class="score-item">
                            <div class="score-value">{threat_assessment.get('module_scores', {}).get('behavioral', 0)}</div>
                            <div>Behavioral Score</div>
                        </div>
                        <div class="score-item">
                            <div class="score-value">{threat_assessment.get('module_scores', {}).get('network', 0)}</div>
                            <div>Network Score</div>
                        </div>
                        <div class="score-item">
                            <div class="score-value">{threat_assessment.get('module_scores', {}).get('memory', 0)}</div>
                            <div>Memory Score</div>
                        </div>
                    </div>
                    
                    {f'<h3>Primary Threat Factors</h3><ul>{"".join(f"<li>{escape(factor)}</li>" for factor in threat_assessment.get("threat_factors", []))}</ul>' if threat_assessment.get('threat_factors') else ''}
                </div>
        """
        
        # Add MITRE ATT&CK section
        if mitre_attack:
            html_content += f"""
                <div class="section">
                    <h2>MITRE ATT&CK Techniques</h2>
                    <div class="mitre-techniques">
            """
            for technique in mitre_attack:
                html_content += f"""
                        <div class="mitre-technique">
                            <div class="technique-id">{escape(technique.get('technique_id', ''))}: {escape(technique.get('technique_name', ''))}</div>
                            <div style="margin: 8px 0;">
                                <span class="tactic">{escape(technique.get('tactic', ''))}</span>
                                <span style="float: right; font-size: 0.9em; color: #6c757d;">Confidence: {escape(technique.get('confidence', ''))}</span>
                            </div>
                            <div style="font-size: 0.9em; color: #495057;">{escape(technique.get('evidence', ''))}</div>
                        </div>
                """
            html_content += """
                    </div>
                </div>
            """
        
        # Add IOCs section
        if any(iocs.values()):
            html_content += """
                <div class="section">
                    <h2>Indicators of Compromise (IOCs)</h2>
                    <div class="ioc-grid">
            """
            for ioc_type, ioc_list in iocs.items():
                if ioc_list:
                    html_content += f"""
                        <div class="ioc-category">
                            <h4>{escape(ioc_type.replace('_', ' ').title())} ({len(ioc_list)})</h4>
                    """
                    for ioc in ioc_list[:10]:  # Show first 10 per category
                        indicator = escape(str(ioc.get('indicator', '')))
                        context = escape(str(ioc.get('context', '')))
                        html_content += f"""
                            <div class="ioc-item" title="{context}">
                                {indicator}
                            </div>
                        """
                    if len(ioc_list) > 10:
                        html_content += f"<div style='text-align: center; margin-top: 10px; color: #6c757d;'>... and {len(ioc_list) - 10} more</div>"
                    html_content += "</div>"
            html_content += """
                    </div>
                </div>
            """
        
        # Add Timeline section
        if timeline:
            html_content += """
                <div class="section">
                    <h2>Execution Timeline</h2>
                    <div class="timeline">
            """
            for event in timeline[:20]:  # Show first 20 events
                html_content += f"""
                    <div class="timeline-item">
                        <div class="timestamp">{escape(event.get('timestamp', 'Unknown'))}</div>
                        <div style="margin: 5px 0;">
                            <span class="severity {event.get('severity', 'info')}">{escape(event.get('severity', 'info').upper())}</span>
                            <strong>{escape(event.get('event_type', 'Unknown Event'))}</strong>
                        </div>
                        <div>{escape(event.get('description', ''))}</div>
                        {f'<div style="font-size: 0.9em; color: #6c757d; margin-top: 5px;">{escape(event.get("details", ""))}</div>' if event.get('details') else ''}
                    </div>
                """
            html_content += """
                    </div>
                </div>
            """
        
        # Add Recommendations section
        if exec_summary.get('recommended_actions'):
            html_content += f"""
                <div class="section">
                    <h2>Recommendations</h2>
                    <div class="recommendations">
                        <h3>Immediate Actions Required</h3>
                        <ul>
                            {"".join(f"<li>{escape(action)}</li>" for action in exec_summary.get('recommended_actions', []))}
                        </ul>
                    </div>
                </div>
            """
        
        html_content += """
                <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #6c757d;">
                    <p>Report generated by Shikra Malware Analysis Framework</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def generate_json_report(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """
        Generate a JSON format report for programmatic consumption.
        """
        logger.info(f"Generating JSON report: {output_path}")
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
            logger.info(f"JSON report generated successfully: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            raise
    
    def integrate_visualizations(self, report_data: Dict[str, Any], 
                               visualization_paths: Dict[str, Path]) -> Dict[str, Any]:
        """
        Integrate charts and visualizations into report content.
        """
        logger.info("Integrating visualizations into report")
        
        integrated_visualizations = []
        
        for viz_name, viz_path in visualization_paths.items():
            if viz_path.exists():
                try:
                    # For HTML reports, we can embed images as base64
                    with open(viz_path, 'rb') as f:
                        image_data = base64.b64encode(f.read()).decode('utf-8')
                    
                    file_extension = viz_path.suffix.lower()
                    if file_extension in ['.png', '.jpg', '.jpeg']:
                        mime_type = f"image/{file_extension[1:]}"
                    elif file_extension == '.svg':
                        mime_type = "image/svg+xml"
                    else:
                        mime_type = "application/octet-stream"
                    
                    integrated_visualizations.append({
                        "name": viz_name,
                        "path": str(viz_path),
                        "data_uri": f"data:{mime_type};base64,{image_data}",
                        "description": self._get_visualization_description(viz_name)
                    })
                    
                except Exception as e:
                    logger.error(f"Error integrating visualization {viz_name}: {e}")
        
        report_data["visualizations"] = integrated_visualizations
        return report_data
    
    def _get_visualization_description(self, viz_name: str) -> str:
        """Get description for visualization based on its name."""
        descriptions = {
            "process_tree": "Process execution tree showing parent-child relationships",
            "network_timeline": "Timeline of network communications and suspicious activities",
            "file_operations": "Overview of file system operations and targeted extensions",
            "registry_activity": "Registry modifications and persistence mechanisms",
            "threat_landscape": "Overall threat assessment and risk factors"
        }
        return descriptions.get(viz_name, f"Visualization: {viz_name}")
    
    def validate_report_completeness(self, report_data: Dict[str, Any]) -> List[str]:
        """
        Validate that all required report sections are present and complete.
        """
        warnings = []
        
        # Check required sections
        required_sections = ['metadata', 'sample_info', 'executive_summary', 'threat_assessment']
        for section in required_sections:
            if section not in report_data or not report_data[section]:
                warnings.append(f"Missing or empty required section: {section}")
        
        # Check executive summary completeness
        exec_summary = report_data.get('executive_summary', {})
        if not exec_summary.get('threat_level'):
            warnings.append("Executive summary missing threat level assessment")
        if not exec_summary.get('overall_score'):
            warnings.append("Executive summary missing overall score")
        
        # Check for analysis results
        analysis_results = report_data.get('analysis_results', {})
        if not any(analysis_results.get(module) for module in ['behavioral', 'network', 'memory']):
            warnings.append("No analysis results from any module available")
        
        # Check IOCs
        iocs = report_data.get('iocs', {})
        if not any(iocs.values()):
            warnings.append("No IOCs extracted from analysis results")
        
        # Check timeline
        if not report_data.get('timeline'):
            warnings.append("No timeline events generated")
        
        # Check MITRE mapping
        if not report_data.get('mitre_attack'):
            warnings.append("No MITRE ATT&CK techniques mapped")
        
        return warnings