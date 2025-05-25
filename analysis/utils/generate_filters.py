"""
Filter Generation Utility (generate_filters.py)

Purpose:
This utility module generates and manages filter files for behavioral monitoring tools
like Noriben and Procmon. It helps reduce noise in analysis by creating whitelists
of known-good behavior and blacklists of confirmed malicious indicators.

Context in Shikra:
- Input: Clean baseline system captures and malware analysis results
- Processing: Pattern analysis, statistical filtering, manual rule creation
- Output: Whitelist/blacklist files for core/modules/monitor/ tools

Key Functionalities:
The FilterGenerator class provides utilities to:
- Generate whitelists from clean system baselines
- Create blacklists from confirmed malware indicators
- Merge and optimize filter files
- Update filters based on new intelligence
- Validate filter effectiveness against known samples

Integration Points:
- Processes clean system captures to build baseline filters
- Uses analysis results from behavioral, network, and memory modules
- Outputs filter files used by core/modules/monitor/noriben_wrapper.py
- Can be run periodically to update and refine filters
"""

import logging
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
import json
import re
import math
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

class FilterGenerator:
    """
    Generates and manages filter files for behavioral monitoring tools.
    
    This utility helps improve the signal-to-noise ratio in behavioral analysis
    by creating intelligent filters based on baseline system behavior and
    confirmed malicious indicators from previous analyses.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the filter generator with configuration.
        
        Args:
            config_path (Optional[Path]): Path to filter generation configuration file
        """
        self.config = {
            'whitelist_threshold': 0.8,
            'blacklist_threshold': 0.3,
            'min_samples': 3,
            'max_wildcards': 5,
            'entropy_threshold': 3.5,
            'path_similarity_threshold': 0.7,
        }
        self.baseline_data = []
        self.malware_data = []
        self.existing_filters = {}
        
        if config_path and config_path.exists():
            self._load_configuration(config_path)
            
        logger.info("FilterGenerator initialized")
    
    def _load_configuration(self, config_path: Path):
        """
        Load filter generation configuration from file.
        Configuration includes filter thresholds, exclusion patterns, and rule weights.
        """
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
                self.config.update(config_data)
            logger.info(f"Configuration loaded from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
    
    def generate_whitelist_from_baseline(self, baseline_results: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Generate whitelist filters from clean system baseline captures.
        
        Analyzes baseline system behavior to identify:
        - Common legitimate process executions
        - Standard file system operations
        - Normal registry modifications
        - Expected network connections
        - System service behaviors
        
        Args:
            baseline_results (List[Dict[str, Any]]): List of analysis results from clean systems
            
        Returns:
            Dict[str, List[str]]: Categorized whitelist filters
        """
        logger.info(f"Generating whitelist from {len(baseline_results)} baseline results")
        
        whitelist_filters = {
            'processes': [],
            'files': [],
            'registry': [],
            'network': [],
            'commands': []
        }
        
        all_processes = []
        all_files = []
        all_registry = []
        all_network = []
        all_commands = []
        
        for result in baseline_results:
            if 'process_operations' in result:
                processes = result['process_operations'].get('processes_created', [])
                for proc in processes:
                    all_processes.append(proc.get('command', ''))
            
            if 'file_operations' in result:
                for op_type, operations in result['file_operations'].items():
                    for op in operations:
                        all_files.append(op.get('path', ''))
            
            if 'registry_operations' in result:
                for op_type, operations in result['registry_operations'].items():
                    for op in operations:
                        all_registry.append(op.get('key', ''))
            
            if 'network_operations' in result:
                for proto, connections in result['network_operations'].items():
                    for conn in connections:
                        all_network.append(conn.get('destination', ''))
            
            if 'command_line_args' in result:
                for cmd in result['command_line_args']:
                    all_commands.append(cmd.get('args', ''))
        
        whitelist_filters['processes'] = self._generate_whitelist_patterns(all_processes)
        whitelist_filters['files'] = self._generate_whitelist_patterns(all_files)
        whitelist_filters['registry'] = self._generate_whitelist_patterns(all_registry)
        whitelist_filters['network'] = self._generate_whitelist_patterns(all_network)
        whitelist_filters['commands'] = self._generate_whitelist_patterns(all_commands)
        
        logger.info(f"Generated whitelist with {sum(len(v) for v in whitelist_filters.values())} total patterns")
        return whitelist_filters

    def generate_blacklist_from_malware(self, malware_results: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Generate blacklist filters from confirmed malware analysis results.
        
        Identifies recurring malicious patterns:
        - Common malware file paths
        - Suspicious registry modifications
        - Malicious network indicators
        - Known bad process behaviors
        - Cryptographic indicators
        
        Args:
            malware_results (List[Dict[str, Any]]): List of analysis results from malware samples
            
        Returns:
            Dict[str, List[str]]: Categorized blacklist filters for threat detection
        """
        logger.info(f"Generating blacklist from {len(malware_results)} malware results")
        
        blacklist_filters = {
            'processes': [],
            'files': [],
            'registry': [],
            'network': [],
            'commands': [],
            'crypto_indicators': [],
            'persistence': []
        }
        
        malicious_processes = []
        malicious_files = []
        malicious_registry = []
        malicious_network = []
        malicious_commands = []
        crypto_indicators = []
        persistence_indicators = []
        
        for result in malware_results:
            if 'signatures' in result:
                for sig in result['signatures']:
                    sig_type = sig.get('type', '')
                    details = sig.get('details', {})
                    
                    if 'process' in sig_type.lower():
                        if 'command' in details:
                            malicious_processes.append(details['command'])
                    
                    elif 'file' in sig_type.lower():
                        if 'path' in details:
                            malicious_files.append(details['path'])
                    
                    elif 'registry' in sig_type.lower():
                        if 'key' in details:
                            malicious_registry.append(details['key'])
                    
                    elif 'network' in sig_type.lower() or 'dns' in sig_type.lower():
                        if 'destination' in details:
                            malicious_network.append(details['destination'])
                    
                    elif 'crypto' in sig_type.lower() or 'encrypt' in sig_type.lower():
                        crypto_indicators.append(sig.get('description', ''))
                    
                    elif 'persistence' in sig_type.lower():
                        persistence_indicators.append(details.get('key', details.get('command', '')))
            
            if 'encryption_indicators' in result:
                for indicator in result['encryption_indicators']:
                    crypto_indicators.append(indicator.get('file', indicator.get('type', '')))
            
            if 'persistence_mechanisms' in result:
                for mech in result['persistence_mechanisms']:
                    persistence_indicators.append(mech.get('key', mech.get('value', '')))
        
        blacklist_filters['processes'] = self._generate_blacklist_patterns(malicious_processes)
        blacklist_filters['files'] = self._generate_blacklist_patterns(malicious_files)
        blacklist_filters['registry'] = self._generate_blacklist_patterns(malicious_registry)
        blacklist_filters['network'] = self._generate_blacklist_patterns(malicious_network)
        blacklist_filters['commands'] = self._generate_blacklist_patterns(malicious_commands)
        blacklist_filters['crypto_indicators'] = self._generate_blacklist_patterns(crypto_indicators)
        blacklist_filters['persistence'] = self._generate_blacklist_patterns(persistence_indicators)
        
        logger.info(f"Generated blacklist with {sum(len(v) for v in blacklist_filters.values())} total patterns")
        return blacklist_filters

    def analyze_process_patterns(self, behavioral_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze process execution patterns to generate process-related filters.
        
        Examines process behaviors including:
        - Process creation chains
        - Command line patterns
        - Parent-child relationships
        - Process persistence mechanisms
        - Unusual process locations
        
        Args:
            behavioral_data (List[Dict[str, Any]]): Behavioral analysis results
            
        Returns:
            Dict[str, Any]: Process pattern analysis for filter generation
        """
        logger.info("Analyzing process patterns")
        
        process_patterns = {
            'common_processes': Counter(),
            'command_patterns': Counter(),
            'process_chains': [],
            'unusual_locations': [],
            'persistence_processes': []
        }
        
        for data in behavioral_data:
            if 'process_operations' in data:
                processes = data['process_operations'].get('processes_created', [])
                
                for proc in processes:
                    proc_name = proc.get('child_process_name', '')
                    if proc_name:
                        process_patterns['common_processes'][proc_name] += 1
                    
                    command = proc.get('command', '')
                    if command:
                        cmd_pattern = self._extract_command_pattern(command)
                        process_patterns['command_patterns'][cmd_pattern] += 1
                        
                        if self._is_unusual_location(command):
                            process_patterns['unusual_locations'].append(command)
                    
                    parent = proc.get('parent_process', '')
                    child = proc.get('child_process_name', '')
                    if parent and child:
                        process_patterns['process_chains'].append(f"{parent} -> {child}")
            
            if 'persistence_mechanisms' in data:
                for mech in data['persistence_mechanisms']:
                    if mech.get('type') == 'registry':
                        process_patterns['persistence_processes'].append(mech.get('value', ''))
        
        return process_patterns

    def analyze_file_patterns(self, behavioral_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze file system activity patterns to generate file-related filters.
        
        Examines file operations including:
        - File creation and modification patterns
        - Temporary file usage
        - System directory access
        - File extension patterns
        - Hidden file operations
        
        Args:
            behavioral_data (List[Dict[str, Any]]): Behavioral analysis results
            
        Returns:
            Dict[str, Any]: File pattern analysis for filter generation
        """
        logger.info("Analyzing file patterns")
        
        file_patterns = {
            'common_paths': Counter(),
            'file_extensions': Counter(),
            'temp_files': [],
            'system_access': [],
            'hidden_files': [],
            'creation_patterns': Counter(),
            'modification_patterns': Counter()
        }
        
        temp_dirs = ['temp', 'tmp', 'appdata\\local\\temp', 'windows\\temp']
        system_dirs = ['windows\\system32', 'program files', 'programdata']
        
        for data in behavioral_data:
            if 'file_operations' in data:
                for op_type, operations in data['file_operations'].items():
                    for op in operations:
                        path = op.get('path', '').lower()
                        if not path:
                            continue
                        
                        dir_path = str(Path(path).parent)
                        file_patterns['common_paths'][dir_path] += 1
                        
                        ext = Path(path).suffix.lower()
                        if ext:
                            file_patterns['file_extensions'][ext] += 1
                        
                        if any(temp_dir in path for temp_dir in temp_dirs):
                            file_patterns['temp_files'].append(path)
                        
                        if any(sys_dir in path for sys_dir in system_dirs):
                            file_patterns['system_access'].append(path)
                        
                        if Path(path).name.startswith('.') or '\\.' in path:
                            file_patterns['hidden_files'].append(path)
                        
                        if 'create' in op_type.lower():
                            file_patterns['creation_patterns'][dir_path] += 1
                        elif 'write' in op_type.lower() or 'modify' in op_type.lower():
                            file_patterns['modification_patterns'][dir_path] += 1
        
        return file_patterns

    def analyze_registry_patterns(self, behavioral_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze registry activity patterns to generate registry-related filters.
        
        Examines registry operations including:
        - Common system registry modifications
        - Application-specific registry usage
        - Persistence-related registry keys
        - Configuration storage patterns
        - Registry-based communication
        
        Args:
            behavioral_data (List[Dict[str, Any]]): Behavioral analysis results
            
        Returns:
            Dict[str, Any]: Registry pattern analysis for filter generation
        """
        logger.info("Analyzing registry patterns")
        
        registry_patterns = {
            'common_keys': Counter(),
            'persistence_keys': [],
            'run_keys': [],
            'service_keys': [],
            'policy_keys': [],
            'value_patterns': Counter()
        }
        
        persistence_key_patterns = [
            'currentversion\\run',
            'currentversion\\runonce',
            'winlogon',
            'userinit',
            'shell'
        ]
        
        for data in behavioral_data:
            if 'registry_operations' in data:
                for op_type, operations in data['registry_operations'].items():
                    for op in operations:
                        key = op.get('key', '').lower()
                        value = op.get('value', '')
                        
                        if not key:
                            continue
                        
                        key_root = key.split('\\')[0] if '\\' in key else key
                        registry_patterns['common_keys'][key_root] += 1
                        
                        if any(pattern in key for pattern in persistence_key_patterns):
                            registry_patterns['persistence_keys'].append(key)
                            
                            if 'run' in key:
                                registry_patterns['run_keys'].append(key)
                        
                        if 'services' in key:
                            registry_patterns['service_keys'].append(key)
                        
                        if 'policies' in key:
                            registry_patterns['policy_keys'].append(key)
                        
                        if value:
                            value_pattern = self._extract_value_pattern(value)
                            registry_patterns['value_patterns'][value_pattern] += 1
        
        return registry_patterns

    def analyze_network_patterns(self, network_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze network communication patterns to generate network-related filters.
        
        Examines network behaviors including:
        - Legitimate service communications
        - Update and telemetry patterns
        - Common protocol usage
        - Expected domain resolutions
        - Normal traffic patterns
        
        Args:
            network_data (List[Dict[str, Any]]): Network analysis results
            
        Returns:
            Dict[str, Any]: Network pattern analysis for filter generation
        """
        logger.info("Analyzing network patterns")
        
        network_patterns = {
            'common_domains': Counter(),
            'common_ips': Counter(),
            'port_usage': Counter(),
            'protocol_patterns': Counter(),
            'dns_patterns': [],
            'http_patterns': [],
            'suspicious_domains': [],
            'dga_domains': []
        }
        
        for data in network_data:
            if 'dns_queries' in data:
                for query in data['dns_queries']:
                    domain = query.get('query_name', '')
                    if domain:
                        network_patterns['common_domains'][domain] += 1
                        
                        if self._is_dga_domain(domain):
                            network_patterns['dga_domains'].append(domain)
                        
                        dns_pattern = self._extract_dns_pattern(domain)
                        network_patterns['dns_patterns'].append(dns_pattern)
            
            if 'http_requests' in data:
                for request in data['http_requests']:
                    host = request.get('http_host', '')
                    if host:
                        network_patterns['common_domains'][host] += 1
                    
                    uri = request.get('http_uri', '')
                    if uri:
                        uri_pattern = self._extract_uri_pattern(uri)
                        network_patterns['http_patterns'].append(uri_pattern)
            
            if 'ip_communications' in data:
                for ip, details in data['ip_communications'].items():
                    network_patterns['common_ips'][ip] += details.get('count', 1)
                    
                    ports = details.get('ports', {})
                    for port, count in ports.items():
                        network_patterns['port_usage'][port] += count
                    
                    protocols = details.get('protocols', {})
                    for protocol, count in protocols.items():
                        network_patterns['protocol_patterns'][protocol] += count
            
            if 'suspicious_findings' in data:
                for finding in data['suspicious_findings']:
                    if 'domain' in finding.get('type', '').lower():
                        domain = finding.get('details', {}).get('destination', '')
                        if domain:
                            network_patterns['suspicious_domains'].append(domain)
        
        return network_patterns

    def optimize_filters(self, raw_filters: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """
        Optimize filter lists by removing redundancy and improving efficiency.
        
        Optimization includes:
        - Removing duplicate entries
        - Consolidating similar patterns with wildcards
        - Removing overly broad filters
        - Sorting by effectiveness
        - Balancing precision vs. recall
        
        Args:
            raw_filters (Dict[str, List[str]]): Raw generated filters
            
        Returns:
            Dict[str, List[str]]: Optimized filter lists
        """
        logger.info("Optimizing filter lists")
        
        optimized_filters = {}
        
        for filter_type, patterns in raw_filters.items():
            if not patterns:
                optimized_filters[filter_type] = []
                continue
            
            unique_patterns = list(set(p for p in patterns if p.strip()))
            consolidated = self._consolidate_patterns(unique_patterns)
            filtered = self._remove_broad_patterns(consolidated)
            sorted_patterns = self._sort_by_specificity(filtered)
            optimized_filters[filter_type] = sorted_patterns
        
        total_before = sum(len(v) for v in raw_filters.values())
        total_after = sum(len(v) for v in optimized_filters.values())
        
        logger.info(f"Filter optimization: {total_before} -> {total_after} patterns")
        return optimized_filters

    def merge_filter_sets(self, filter_sets: List[Dict[str, List[str]]]) -> Dict[str, List[str]]:
        """
        Merge multiple filter sets into a unified set.
        
        Merging process includes:
        - Combining filters from multiple sources
        - Resolving conflicts between filter sets
        - Maintaining filter provenance
        - Applying precedence rules
        - Validating merged results
        
        Args:
            filter_sets (List[Dict[str, List[str]]]): Multiple filter sets to merge
            
        Returns:
            Dict[str, List[str]]: Unified filter set
        """
        logger.info(f"Merging {len(filter_sets)} filter sets")
        
        merged_filters = defaultdict(list)
        
        for filter_set in filter_sets:
            for filter_type, patterns in filter_set.items():
                merged_filters[filter_type].extend(patterns)
        
        optimized_merged = {}
        for filter_type, patterns in merged_filters.items():
            seen = set()
            unique_patterns = []
            for pattern in patterns:
                if pattern not in seen:
                    seen.add(pattern)
                    unique_patterns.append(pattern)
            
            optimized_merged[filter_type] = unique_patterns
        
        final_filters = self.optimize_filters(optimized_merged)
        
        logger.info(f"Merged filters: {sum(len(v) for v in final_filters.values())} total patterns")
        return final_filters

    def validate_filters(self, filters: Dict[str, List[str]], test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate filter effectiveness against known test data.
        
        Validation includes:
        - False positive rate analysis
        - False negative rate analysis
        - Filter coverage assessment  
        - Performance impact measurement
        - Effectiveness scoring
        
        Args:
            filters (Dict[str, List[str]]): Filters to validate
            test_data (List[Dict[str, Any]]): Test data with known classifications
            
        Returns:
            Dict[str, Any]: Validation results and effectiveness metrics
        """
        logger.info(f"Validating filters against {len(test_data)} test samples")
        
        validation_results = {
            'total_samples': len(test_data),
            'filter_coverage': {},
            'false_positives': 0,
            'false_negatives': 0,
            'true_positives': 0,
            'true_negatives': 0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0,
            'filter_effectiveness': {}
        }
        
        for filter_type, patterns in filters.items():
            matches = 0
            for sample in test_data:
                if self._check_filter_match(sample, filter_type, patterns):
                    matches += 1
            
            coverage = matches / len(test_data) if test_data else 0
            validation_results['filter_coverage'][filter_type] = coverage
        
        for filter_type, patterns in filters.items():
            tp = tn = fp = fn = 0
            
            for sample in test_data:
                is_malicious = sample.get('classification', '').lower() in ['malicious', 'ransomware']
                filter_match = self._check_filter_match(sample, filter_type, patterns)
                
                if filter_type in ['processes', 'files', 'registry', 'network']: # Assuming these are blacklist type filters
                    if is_malicious and filter_match:
                        tp += 1
                    elif is_malicious and not filter_match:
                        fn += 1
                    elif not is_malicious and filter_match:
                        fp += 1
                    else: # not is_malicious and not filter_match
                        tn += 1
            
            total = tp + tn + fp + fn
            if total > 0:
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                
                validation_results['filter_effectiveness'][filter_type] = {
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1,
                    'true_positives': tp,
                    'false_positives': fp,
                    'false_negatives': fn,
                    'true_negatives': tn
                }
        
        total_tp = sum(metrics.get('true_positives', 0) for metrics in validation_results['filter_effectiveness'].values())
        total_fp = sum(metrics.get('false_positives', 0) for metrics in validation_results['filter_effectiveness'].values())
        total_fn = sum(metrics.get('false_negatives', 0) for metrics in validation_results['filter_effectiveness'].values())
        
        validation_results['true_positives'] = total_tp
        validation_results['false_positives'] = total_fp
        validation_results['false_negatives'] = total_fn
        
        if (total_tp + total_fp) > 0:
            validation_results['precision'] = total_tp / (total_tp + total_fp)
        if (total_tp + total_fn) > 0:
            validation_results['recall'] = total_tp / (total_tp + total_fn)
        
        prec = validation_results['precision']
        rec = validation_results['recall']
        if (prec + rec) > 0:
            validation_results['f1_score'] = 2 * (prec * rec) / (prec + rec)
        
        logger.info(f"Validation complete: Precision={prec:.3f}, Recall={rec:.3f}, F1={validation_results['f1_score']:.3f}")
        return validation_results

    def export_noriben_filters(self, filters: Dict[str, List[str]], output_dir: Path) -> Dict[str, Path]:
        """
        Export filters in Noriben-compatible format.
        
        Creates filter files for:
        - Process whitelist/blacklist
        - File operation filters
        - Registry key filters
        - Network connection filters
        - Custom rule formats
        
        Args:
            filters (Dict[str, List[str]]): Generated filters
            output_dir (Path): Directory to save filter files
            
        Returns:
            Dict[str, Path]: Mapping of filter types to file paths
        """
        logger.info(f"Exporting Noriben filters to {output_dir}")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        filter_files = {}
        
        if 'processes' in filters:
            process_file = output_dir / 'noriben_process_filters.txt'
            with open(process_file, 'w') as f:
                f.write("# Noriben Process Filters\n")
                f.write("# Generated on: " + datetime.now().isoformat() + "\n\n")
                for pattern in filters['processes']:
                    f.write(f"{pattern}\n")
            filter_files['processes'] = process_file
        
        if 'files' in filters:
            file_filter = output_dir / 'noriben_file_filters.txt'
            with open(file_filter, 'w') as f:
                f.write("# Noriben File Filters\n")
                f.write("# Generated on: " + datetime.now().isoformat() + "\n\n")
                for pattern in filters['files']:
                    f.write(f"{pattern}\n")
            filter_files['files'] = file_filter
        
        if 'registry' in filters:
            registry_file = output_dir / 'noriben_registry_filters.txt'
            with open(registry_file, 'w') as f:
                f.write("# Noriben Registry Filters\n")
                f.write("# Generated on: " + datetime.now().isoformat() + "\n\n")
                for pattern in filters['registry']:
                    f.write(f"{pattern}\n")
            filter_files['registry'] = registry_file
        
        if 'network' in filters:
            network_file = output_dir / 'noriben_network_filters.txt'
            with open(network_file, 'w') as f:
                f.write("# Noriben Network Filters\n")
                f.write("# Generated on: " + datetime.now().isoformat() + "\n\n")
                for pattern in filters['network']:
                    f.write(f"{pattern}\n")
            filter_files['network'] = network_file
        
        combined_file = output_dir / 'noriben_combined_filters.json'
        with open(combined_file, 'w') as f:
            json.dump(filters, f, indent=2)
        filter_files['combined'] = combined_file
        
        logger.info(f"Exported {len(filter_files)} Noriben filter files")
        return filter_files

    def export_procmon_filters(self, filters: Dict[str, List[str]], output_dir: Path) -> Path:
        """
        Export filters in Procmon-compatible XML format.
        
        Creates Procmon filter configuration including:
        - Process and image filters
        - File system filters
        - Registry filters  
        - Network filters
        - Advanced filtering rules
        
        Args:
            filters (Dict[str, List[str]]): Generated filters
            output_dir (Path): Directory to save filter files
            
        Returns:
            Path: Path to the generated Procmon XML filter file.
        """
        logger.info(f"Exporting Procmon filters to {output_dir}")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        root = ET.Element("ProcessMonitor")
        config = ET.SubElement(root, "FilterRules")
        
        rule_id = 1
        
        if 'processes' in filters:
            for pattern in filters['processes']:
                rule = ET.SubElement(config, "FilterRule")
                rule.set("Column", "Process Name")
                rule.set("Relation", "contains") # Procmon uses "is", "contains", "begins with", "ends with", "excludes"
                rule.set("Value", pattern)
                rule.set("Action", "Include") # "Include" or "Exclude"
                rule.set("ID", str(rule_id))
                rule_id += 1
        
        if 'files' in filters:
            for pattern in filters['files']:
                rule = ET.SubElement(config, "FilterRule")
                rule.set("Column", "Path")
                rule.set("Relation", "contains")
                rule.set("Value", pattern)
                rule.set("Action", "Include")
                rule.set("ID", str(rule_id))
                rule_id += 1
        
        if 'registry' in filters:
            for pattern in filters['registry']:
                rule = ET.SubElement(config, "FilterRule")
                rule.set("Column", "Path") # Registry paths are also under "Path" in Procmon
                rule.set("Relation", "contains")
                rule.set("Value", pattern)
                rule.set("Action", "Include")
                rule.set("ID", str(rule_id))
                rule_id += 1
        
        # Note: Procmon has specific network filtering capabilities (e.g., TCP/UDP events)
        # This generic export might need refinement for specific network filter types if 'network' filters are complex.
        # For now, assuming 'network' patterns are simple strings that could be matched against e.g. "Path" (for URLs) or "Detail" columns.
        # A more robust Procmon network filter would set "Column" to "Operation" (e.g., "TCP Connect")
        # and then filter on "Path" (e.g., "1.2.3.4:80") or "Detail".

        procmon_file = output_dir / 'procmon_filters.xml'
        tree = ET.ElementTree(root)
        tree.write(procmon_file, encoding='utf-8', xml_declaration=True)
        
        logger.info(f"Exported Procmon filter file: {procmon_file}")
        return procmon_file

    def generate_statistical_report(self, filter_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate statistical report on filter generation process.
        
        Report includes:
        - Filter generation statistics
        - Pattern frequency analysis
        - Coverage and effectiveness metrics
        - Recommendations for improvement
        - Filter maintenance suggestions
        
        Args:
            filter_analysis (Dict[str, Any]): Complete filter analysis results
            
        Returns:
            Dict[str, Any]: Statistical report on filter generation
        """
        logger.info("Generating statistical report")
        
        report = {
            'generation_timestamp': datetime.now().isoformat(),
            'filter_statistics': {},
            'pattern_analysis': {},
            'effectiveness_metrics': {},
            'recommendations': [],
            'maintenance_suggestions': []
        }
        
        for filter_type, patterns in filter_analysis.get('filters', {}).items():
            report['filter_statistics'][filter_type] = {
                'total_patterns': len(patterns),
                'unique_patterns': len(set(patterns)),
                'average_length': sum(len(p) for p in patterns) / len(patterns) if patterns else 0,
                'complexity_score': self._calculate_pattern_complexity(patterns)
            }
        
        for analysis_type, pattern_data in filter_analysis.get('pattern_analysis', {}).items():
            if isinstance(pattern_data, dict) and 'common_' in analysis_type: # Assuming pattern_data is a Counter or dict
                # Convert Counter to dict for JSON serialization if it's a Counter
                if isinstance(pattern_data, Counter):
                    top_patterns = dict(pattern_data.most_common(10))
                else: # If it's already a dict, sort and take top 10
                    top_patterns = dict(sorted(pattern_data.items(), key=lambda item: item[1], reverse=True)[:10])
                report['pattern_analysis'][analysis_type] = top_patterns
        
        if 'validation_results' in filter_analysis:
            validation = filter_analysis['validation_results']
            report['effectiveness_metrics'] = {
                'overall_precision': validation.get('precision', 0),
                'overall_recall': validation.get('recall', 0),
                'overall_f1_score': validation.get('f1_score', 0),
                'filter_coverage': validation.get('filter_coverage', {}),
                'false_positive_rate': validation.get('false_positives', 0) / validation.get('total_samples', 1) if validation.get('total_samples', 1) > 0 else 0
            }
        
        report['recommendations'] = self._generate_recommendations(filter_analysis)
        report['maintenance_suggestions'] = self._generate_maintenance_suggestions(filter_analysis)
        
        logger.info("Statistical report generated")
        return report

    def update_filters_from_feedback(self, current_filters: Dict[str, List[str]], 
                                     feedback_data: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Update existing filters based on analyst feedback and new data.
        
        Updates include:
        - Adding new confirmed indicators
        - Removing false positive filters
        - Adjusting filter sensitivity
        - Incorporating threat intelligence
        - Learning from missed detections
        
        Args:
            current_filters (Dict[str, List[str]]): Current filter set
            feedback_data (List[Dict[str, Any]]): Analyst feedback and new intelligence
            
        Returns:
            Dict[str, List[str]]: Updated filter set
        """
        logger.info(f"Updating filters based on {len(feedback_data)} feedback items")
        
        updated_filters = {k: v.copy() for k, v in current_filters.items()}
        
        for feedback in feedback_data:
            feedback_type = feedback.get('type', '')
            filter_category = feedback.get('filter_category', '')
            pattern = feedback.get('pattern', '')
            action = feedback.get('action', '') 
            
            if not filter_category or not pattern:
                continue
            
            if filter_category not in updated_filters:
                updated_filters[filter_category] = []
            
            if action == 'add':
                if pattern not in updated_filters[filter_category]:
                    updated_filters[filter_category].append(pattern)
                    logger.info(f"Added pattern to {filter_category}: {pattern}")
            
            elif action == 'remove':
                if pattern in updated_filters[filter_category]:
                    updated_filters[filter_category].remove(pattern)
                    logger.info(f"Removed pattern from {filter_category}: {pattern}")
            
            elif action == 'modify':
                old_pattern = feedback.get('old_pattern', '')
                if old_pattern in updated_filters[filter_category]:
                    try:
                        idx = updated_filters[filter_category].index(old_pattern)
                        updated_filters[filter_category][idx] = pattern
                        logger.info(f"Modified pattern in {filter_category}: {old_pattern} -> {pattern}")
                    except ValueError:
                         logger.warning(f"Old pattern {old_pattern} not found for modification in {filter_category}")


        optimized_filters = self.optimize_filters(updated_filters)
        
        logger.info("Filter updates completed")
        return optimized_filters

    def _generate_whitelist_patterns(self, data_list: List[str]) -> List[str]:
        if not data_list:
            return []
        
        item_counts = Counter(data_list)
        total_items = len(data_list)
        threshold = self.config['whitelist_threshold']
        patterns = []
        
        for item, count in item_counts.items():
            if count / total_items >= threshold and count >= self.config['min_samples']:
                patterns.append(item)
        
        return patterns

    def _generate_blacklist_patterns(self, data_list: List[str]) -> List[str]:
        if not data_list:
            return []
        
        item_counts = Counter(data_list)
        total_items = len(data_list)
        threshold = self.config['blacklist_threshold']
        patterns = []
        
        for item, count in item_counts.items():
            if count / total_items >= threshold and count >= self.config['min_samples']:
                patterns.append(item)
        
        return patterns

    def _extract_command_pattern(self, command: str) -> str:
        pattern = re.sub(r'[A-Z]:\\[^\\]*\\', '*\\', command, flags=re.IGNORECASE)
        pattern = re.sub(r'\b\d+\b', '*', pattern)
        return pattern

    def _extract_value_pattern(self, value: str) -> str:
        pattern = re.sub(r'[A-Z]:\\[^\\]*\\', '*\\', value, flags=re.IGNORECASE)
        pattern = re.sub(r'\b[0-9a-fA-F]{8,}\b', '*', pattern)
        return pattern

    def _extract_dns_pattern(self, domain: str) -> str:
        parts = domain.split('.')
        if len(parts) > 2:
            return f"*.{'.'.join(parts[-2:])}"
        return domain

    def _extract_uri_pattern(self, uri: str) -> str:
        """Extract pattern from URI"""
        pattern = re.sub(r'\?.*', '', uri) 
        pattern = re.sub(r'/\d+/', '/*/', pattern)
        pattern = re.sub(r'=[^&]*', '=*', pattern)
        return pattern

    def _is_unusual_location(self, path: str) -> bool:
        unusual_dirs = ['temp', 'tmp', 'appdata', 'public', 'users\\public']
        path_lower = path.lower()
        return any(unusual_dir in path_lower for unusual_dir in unusual_dirs)

    def _is_dga_domain(self, domain: str) -> bool:
        if not domain or len(domain.split('.')) < 2:
            return False
        
        base_domain = domain.split('.')[0]
        if len(base_domain) < 8:
            return False
        
        entropy = self._calculate_entropy(base_domain)
        consonants = sum(1 for c in base_domain if c.lower() in 'bcdfghjklmnpqrstvwxyz')
        consonant_ratio = consonants / len(base_domain) if len(base_domain) > 0 else 0
        numeric_count = sum(1 for c in base_domain if c.isdigit())
        numeric_ratio = numeric_count / len(base_domain) if len(base_domain) > 0 else 0
        
        return (entropy > self.config['entropy_threshold'] and 
                consonant_ratio > 0.6 and 
                numeric_ratio < 0.3)

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        
        counts = Counter(s)
        probs = [count / len(s) for count in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def _consolidate_patterns(self, patterns: List[str]) -> List[str]:
        if len(patterns) < 2:
            return patterns
        
        consolidated = []
        used_patterns = set()
        
        # Sort patterns to make consolidation more consistent, e.g., by length
        sorted_patterns = sorted(patterns, key=len)

        for i, pattern1 in enumerate(sorted_patterns):
            if pattern1 in used_patterns:
                continue
            
            similar_group = [pattern1]
            
            for j in range(i + 1, len(sorted_patterns)):
                pattern2 = sorted_patterns[j]
                if pattern2 in used_patterns:
                    continue
                
                if self._are_similar_patterns(pattern1, pattern2):
                    similar_group.append(pattern2)
                    used_patterns.add(pattern2)
            
            if len(similar_group) > 1:
                consolidated_pattern = self._create_wildcard_pattern(similar_group)
                consolidated.append(consolidated_pattern)
            else:
                consolidated.append(pattern1)
            
            used_patterns.add(pattern1)
        
        return consolidated

    def _are_similar_patterns(self, pattern1: str, pattern2: str) -> bool:
        if len(pattern1) == 0 or len(pattern2) == 0:
            return False
        
        common_chars = 0
        # Using a basic longest common subsequence idea might be too complex here.
        # Sticking to simpler heuristic for now.
        # Compare parts of paths if they are paths
        parts1 = pattern1.split('\\')
        parts2 = pattern2.split('\\')
        
        if len(parts1) != len(parts2) and '*' not in pattern1 and '*' not in pattern2 : # Only try to consolidate if similar structure
             if abs(len(parts1) - len(parts2)) > 1 : # if differs by more than one part, less likely similar for consolidation
                return False

        # A simple length and character similarity
        len_diff_ratio = abs(len(pattern1) - len(pattern2)) / max(len(pattern1), len(pattern2))
        if len_diff_ratio > (1.0 - self.config['path_similarity_threshold']): # if lengths are too different
            return False

        # Count common characters at the beginning and end
        prefix_len = 0
        while prefix_len < min(len(pattern1), len(pattern2)) and pattern1[prefix_len] == pattern2[prefix_len]:
            prefix_len +=1
        
        suffix_len = 0
        while suffix_len < min(len(pattern1), len(pattern2)) and pattern1[-(suffix_len+1)] == pattern2[-(suffix_len+1)]:
            suffix_len +=1

        common_chars = prefix_len + suffix_len
        max_len = max(len(pattern1), len(pattern2))
        similarity = common_chars / max_len if max_len > 0 else 0
        
        return similarity >= self.config['path_similarity_threshold']

    def _create_wildcard_pattern(self, patterns: List[str]) -> str:
        if not patterns:
            return ""
        if len(patterns) == 1:
            return patterns[0]
        
        # Ensure all patterns are strings
        patterns = [str(p) for p in patterns]

        common_prefix = ""
        min_len = min(len(p) for p in patterns)
        
        for i in range(min_len):
            char_to_check = patterns[0][i]
            if all(p[i] == char_to_check for p in patterns):
                common_prefix += char_to_check
            else:
                break
        
        common_suffix = ""
        for i in range(min_len):
            char_to_check = patterns[0][len(patterns[0]) - 1 - i]
            if all(p[len(p) - 1 - i] == char_to_check for p in patterns):
                common_suffix = char_to_check + common_suffix
            else:
                break
        
        # Ensure prefix and suffix do not overlap incorrectly for short strings
        if len(common_prefix) + len(common_suffix) > min_len:
             # This case can happen if patterns are identical or one is substring of another
             # If they are identical, common_prefix will be the whole string, suffix empty (or vice versa)
             if common_prefix == patterns[0] : return patterns[0] # all patterns are same as first
             # Heuristic: if overlap is significant, choose the shortest pattern or common prefix + *
             # This part needs careful handling to avoid overly generic or incorrect wildcards.
             # For now, a simple strategy:
             if len(common_prefix) > len(common_suffix):
                 return common_prefix + "*" if len(common_prefix) > 0 else "*" # Default to one of the patterns or a generic one
             else:
                 return "*" + common_suffix if len(common_suffix) > 0 else "*"


        if common_prefix and common_suffix:
            # Check if the middle part is short or variable enough for a single wildcard
            middle_parts = [p[len(common_prefix):len(p)-len(common_suffix)] for p in patterns]
            if all(len(m) < 10 for m in middle_parts) or len(set(middle_parts)) > 1: # Arbitrary length 10
                 return f"{common_prefix}*{common_suffix}"
        if common_prefix and len(common_prefix) > min_len * 0.5 : # If prefix is substantial
            return f"{common_prefix}*"
        if common_suffix and len(common_suffix) > min_len * 0.5: # If suffix is substantial
            return f"*{common_suffix}"
        
        # Fallback: return the shortest pattern if no good consolidation found
        return min(patterns, key=len)


    def _remove_broad_patterns(self, patterns: List[str]) -> List[str]:
        filtered = []
        
        for pattern in patterns:
            if len(pattern) < 3 and pattern != "*": # Allow "*" if it's the only thing, but generally too broad
                continue
            
            wildcard_count = pattern.count('*') + pattern.count('?')
            # Effective length (non-wildcard characters)
            effective_length = len(pattern) - wildcard_count
            
            if wildcard_count > self.config['max_wildcards'] or effective_length < 2 : # Ensure some literal chars
                continue
            
            if pattern in ['*', '*.exe', '*.dll', 'C:\\*', '*\\*', '*.*'] or pattern.startswith("*\\") and pattern.endswith("\\*"):
                continue
            
            filtered.append(pattern)
        
        return filtered

    def _sort_by_specificity(self, patterns: List[str]) -> List[str]:
        def specificity_score(pattern):
            score = len(pattern) 
            score -= pattern.count('*') * 5 
            score -= pattern.count('?') * 3 
            return score
        
        return sorted(patterns, key=specificity_score, reverse=True)

    def _check_filter_match(self, sample: Dict[str, Any], filter_type: str, patterns: List[str]) -> bool:
        sample_data = []
        
        if filter_type == 'processes':
            if 'process_operations' in sample:
                processes = sample['process_operations'].get('processes_created', [])
                sample_data = [p.get('command', '') for p in processes if p.get('command')]
        elif filter_type == 'files':
            if 'file_operations' in sample:
                for ops in sample['file_operations'].values():
                    sample_data.extend([op.get('path', '') for op in ops if op.get('path')])
        elif filter_type == 'registry':
            if 'registry_operations' in sample:
                for ops in sample['registry_operations'].values():
                    sample_data.extend([op.get('key', '') for op in ops if op.get('key')])
        elif filter_type == 'network':
            if 'network_operations' in sample: # This needs to be more specific based on how network data is structured
                # Example: DNS queries
                if 'dns_queries' in sample.get('network_operations', {}):
                     sample_data.extend([q.get('query_name','') for q in sample['network_operations']['dns_queries'] if q.get('query_name')])
                # Example: HTTP hosts
                if 'http_requests' in sample.get('network_operations', {}):
                     sample_data.extend([r.get('http_host','') for r in sample['network_operations']['http_requests'] if r.get('http_host')])
                # Example: IP destinations
                if 'ip_communications' in sample.get('network_operations', {}):
                    sample_data.extend(list(sample['network_operations']['ip_communications'].keys()))


        for data_item in sample_data:
            if not isinstance(data_item, str): # Ensure data_item is a string
                continue
            for pattern in patterns:
                if self._pattern_matches(pattern, data_item):
                    return True
        
        return False

    def _pattern_matches(self, pattern: str, text: str) -> bool:
        if not isinstance(text, str) or not isinstance(pattern, str):
            return False # Should not happen if data is clean
        
        try:
            # Convert glob-like wildcards to regex: '*' -> '.*', '?' -> '.'
            # Escape other regex special characters in the pattern
            regex_pattern_parts = []
            for part in pattern.split('*'):
                sub_parts = []
                for sub_part in part.split('?'):
                    sub_parts.append(re.escape(sub_part))
                regex_pattern_parts.append('.'.join(sub_parts)) # '?' becomes '.'
            final_regex_pattern = '.*'.join(regex_pattern_parts) # '*' becomes '.*'
            
            return bool(re.search(f"^{final_regex_pattern}$", text, re.IGNORECASE)) # Anchored match
        except re.error:
            logger.warning(f"Regex error for pattern '{pattern}'. Falling back to simple substring match.")
            return pattern.lower() in text.lower()

    def _calculate_pattern_complexity(self, patterns: List[str]) -> float:
        if not patterns:
            return 0.0
        
        total_complexity = 0
        for pattern in patterns:
            complexity = len(pattern) / 100.0 
            complexity += pattern.count('*') * 0.1
            complexity += pattern.count('?') * 0.05
            complexity += pattern.count('\\') * 0.02 
            total_complexity += complexity
        
        return total_complexity / len(patterns) if patterns else 0.0

    def _generate_recommendations(self, filter_analysis: Dict[str, Any]) -> List[str]:
        recommendations = []
        validation = filter_analysis.get('validation_results', {})
        
        if validation.get('precision', 0) < 0.8 and validation.get('precision', 0) > 0: # Avoid if 0
            recommendations.append("Low Precision: Consider increasing filter specificity or reviewing patterns causing false positives.")
        
        if validation.get('recall', 0) < 0.7 and validation.get('recall', 0) > 0: # Avoid if 0
            recommendations.append("Low Recall: Consider adding more patterns for known indicators or broadening existing ones carefully to improve detection coverage.")
        
        filter_stats = filter_analysis.get('filter_statistics', {})
        for filter_type, stats in filter_stats.items():
            if stats.get('total_patterns', 0) > 1000:
                recommendations.append(f"High Pattern Count for '{filter_type}' ({stats['total_patterns']}): Consider optimizing or consolidating these filters to improve performance.")
            
            if stats.get('complexity_score', 0) > 0.5: # Adjusted threshold for complexity
                recommendations.append(f"High Complexity for '{filter_type}' patterns: Review for potential simplification without losing effectiveness.")
        
        if not recommendations:
            recommendations.append("Filter analysis shows good metrics. Continue regular monitoring and updates.")
            
        return recommendations

    def _generate_maintenance_suggestions(self, filter_analysis: Dict[str, Any]) -> List[str]:
        suggestions = [
            "Regularly review and update filters (e.g., monthly) based on new threat intelligence and observed system changes.",
            "Validate filter effectiveness against new malware samples and clean baseline captures quarterly or after major updates.",
            "Monitor false positive and false negative rates continuously. Adjust filter thresholds and patterns as needed.",
            "Maintain a version history or backup of filter configurations before applying significant changes.",
            "Document all filter modifications, including the rationale, for audit and future reference.",
            "Consider a feedback loop where analysts can report FPs/FNs directly to refine specific filters."
        ]
        return suggestions

