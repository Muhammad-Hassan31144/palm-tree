"""
Memory Analysis Module (memory_analysis.py)

Purpose:
This module analyzes memory dumps captured during malware execution using the
Volatility framework to extract volatile artifacts, identify hidden processes,
detect rootkits, and uncover evidence of advanced malware techniques.

Context in Shikra:
- Input: Memory dump files (.raw, .mem, .vmem) from VM snapshots
- Processing: Volatility-based analysis, artifact extraction, pattern detection
- Output: Memory artifacts, hidden processes, injected code, and kernel-level IOCs

Key Functionalities:
The MemoryAnalyzer class uses Volatility to perform:
- Process and DLL analysis (hidden processes, injected code)
- Network connection reconstruction
- Registry hive extraction and analysis
- Kernel rootkit detection
- Code injection and hooking detection
- Cryptographic key and password extraction

Integration Points:
- Processes memory dumps collected by core/scripts/memory_dump.sh
- Uses Volatility 2.x/3.x framework for analysis
- Correlates findings with behavioral and network analysis results
- Outputs memory artifacts to reporting/modules/reporting/report_generator.py
"""

import logging
import os
import re
import json
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
import hashlib

# Configure logging for this module
logger = logging.getLogger(__name__)

class MemoryAnalyzer:
    """
    Analyzes memory dumps using Volatility framework to extract volatile artifacts
    and identify advanced malware techniques that may not be visible through
    behavioral monitoring alone.
    
    This class serves as the primary memory forensics engine in Shikra,
    leveraging Volatility plugins to perform deep memory analysis and
    extract evidence of sophisticated malware techniques.
    """
    
    def __init__(self, volatility_path: Optional[Path] = None, symbol_cache: Optional[Path] = None):
        """
        Initialize the memory analyzer with Volatility configuration.
        
        Args:
            volatility_path (Optional[Path]): Path to Volatility executable
            symbol_cache (Optional[Path]): Path to Volatility symbol cache directory
        """
        self.volatility_path = volatility_path or self._find_volatility()
        self.symbol_cache = symbol_cache
        self.analysis_results = {}
        self.supported_profiles = []
        self.volatility_version = None
        self.temp_dir = None
        
        # Volatility plugin mappings (v2 vs v3)
        self.plugin_map = {
            'v2': {
                'imageinfo': 'imageinfo',
                'pslist': 'pslist',
                'psscan': 'psscan',
                'psxview': 'psxview',
                'cmdline': 'cmdline',
                'netscan': 'netscan',
                'netstat': 'netstat',
                'malfind': 'malfind',
                'hollowfind': 'hollowfind',
                'dlllist': 'dlllist',
                'handles': 'handles',
                'mutantscan': 'mutantscan',
                'filescan': 'filescan',
                'registry': 'hivelist',
                'hashdump': 'hashdump',
                'lsadump': 'lsadump',
                'ssdt': 'ssdt',
                'idt': 'idt',
                'modules': 'modules',
                'modscan': 'modscan',
                'driverscan': 'driverscan'
            },
            'v3': {
                'imageinfo': 'banners.Banners',
                'pslist': 'windows.pslist.PsList',
                'psscan': 'windows.psscan.PsScan',
                'psxview': 'windows.pslist.PsList',  # v3 doesn't have psxview
                'cmdline': 'windows.cmdline.CmdLine',
                'netscan': 'windows.netscan.NetScan',
                'netstat': 'windows.netstat.NetStat',
                'malfind': 'windows.malfind.Malfind',
                'hollowfind': 'windows.hollowfind.HollowFind',
                'dlllist': 'windows.dlllist.DllList',
                'handles': 'windows.handles.Handles',
                'mutantscan': 'windows.mutantscan.MutantScan',
                'filescan': 'windows.filescan.FileScan',
                'registry': 'windows.registry.hivelist.HiveList',
                'hashdump': 'windows.hashdump.Hashdump',
                'lsadump': 'windows.lsadump.Lsadump',
                'ssdt': 'windows.ssdt.SSDT',
                'modules': 'windows.modules.Modules',
                'driverscan': 'windows.driverscan.DriverScan'
            }
        }
        
        # Known malicious patterns
        self.malicious_patterns = {
            'process_names': [
                'svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
                'explorer.exe', 'rundll32.exe', 'regsvr32.exe'
            ],
            'suspicious_paths': [
                r'\\temp\\', r'\\tmp\\', r'\\appdata\\local\\temp\\',
                r'\\users\\public\\', r'\\programdata\\', r'\\windows\\temp\\'
            ],
            'injection_indicators': [
                'PAGE_EXECUTE_READWRITE', 'PAGE_EXECUTE_WRITECOPY',
                'MZ', 'PE', 'This program cannot be run in DOS mode'
            ],
            'network_indicators': [
                'irc', 'bot', 'c&c', 'command', 'control',
                '.onion', 'tor', 'proxy', 'tunnel'
            ]
        }
        
        if self.volatility_path:
            self._verify_volatility_installation()
            
        logger.info(f"MemoryAnalyzer initialized with Volatility at: {self.volatility_path}")
    
    def _find_volatility(self) -> Optional[Path]:
        """
        Attempt to locate Volatility installation automatically.
        Checks common installation paths and system PATH.
        """
        # Common Volatility executable names
        vol_names = ['vol.py', 'volatility', 'volatility.py', 'vol', 'python vol.py']
        
        # Check system PATH first
        for vol_name in vol_names:
            if shutil.which(vol_name.split()[0]):  # Check first part of command
                logger.info(f"Found Volatility in PATH: {vol_name}")
                return Path(vol_name)
        
        # Check common installation paths
        common_paths = [
            Path('/usr/bin/volatility'),
            Path('/usr/local/bin/volatility'),
            Path('/opt/volatility/vol.py'),
            Path('C:\\Program Files\\Volatility\\vol.py'),
            Path('C:\\Tools\\Volatility\\vol.py'),
            Path('./volatility/vol.py'),
            Path('./vol.py')
        ]
        
        for path in common_paths:
            if path.exists():
                logger.info(f"Found Volatility at: {path}")
                return path
        
        logger.warning("Volatility not found. Please specify volatility_path parameter.")
        return None
    
    def _verify_volatility_installation(self):
        """
        Verify Volatility installation and load supported profiles.
        Tests Volatility functionality and caches available profiles.
        """
        if not self.volatility_path:
            raise RuntimeError("Volatility path not configured")
        
        try:
            # Test Volatility and determine version
            cmd = [str(self.volatility_path), '--info']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'volatility 3' in output or '--help' not in output:
                    self.volatility_version = 'v3'
                else:
                    self.volatility_version = 'v2'
                
                logger.info(f"Detected {self.volatility_version} installation")
                
                # Extract supported profiles for v2
                if self.volatility_version == 'v2':
                    profiles_match = re.findall(r'(\w+x\d+)', result.stdout)
                    self.supported_profiles = list(set(profiles_match))
                    logger.info(f"Found {len(self.supported_profiles)} supported profiles")
                
            else:
                raise RuntimeError(f"Volatility test failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Volatility test timed out")
        except Exception as e:
            raise RuntimeError(f"Volatility verification failed: {e}")
    
    def analyze_memory_dump(self, dump_path: Path, profile: Optional[str] = None) -> Dict[str, Any]:
        """
        Main analysis function that processes a memory dump and returns comprehensive results.
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (Optional[str]): Volatility profile to use (auto-detected if None)
            
        Returns:
            Dict[str, Any]: Complete memory analysis results including processes,
                          network connections, artifacts, and detected threats
        """
        logger.info(f"Starting memory analysis of: {dump_path}")
        
        if not dump_path.exists():
            raise FileNotFoundError(f"Memory dump not found: {dump_path}")
        
        # Create temporary directory for analysis outputs
        self.temp_dir = Path(tempfile.mkdtemp(prefix='shikra_memory_'))
        
        try:
            # Auto-detect profile if not provided
            if not profile and self.volatility_version == 'v2':
                profile = self.detect_profile(dump_path)
                logger.info(f"Auto-detected profile: {profile}")
            
            # Initialize results structure
            analysis_results = {
                'dump_info': {
                    'file_path': str(dump_path),
                    'file_size': dump_path.stat().st_size,
                    'profile': profile,
                    'volatility_version': self.volatility_version,
                    'analysis_timestamp': datetime.now().isoformat()
                },
                'processes': [],
                'hidden_processes': [],
                'network_connections': [],
                'injected_code': [],
                'loaded_dlls': [],
                'registry_artifacts': {},
                'credentials': [],
                'rootkit_indicators': [],
                'suspicious_handles': [],
                'memory_strings': {},
                'timeline_correlation': [],
                'threat_indicators': [],
                'summary': {}
            }
            
            # Perform individual analysis components
            logger.info("Analyzing processes...")
            analysis_results['processes'] = self.analyze_processes(dump_path, profile)
            
            logger.info("Detecting process injection...")
            analysis_results['injected_code'] = self.detect_process_injection(dump_path, profile)
            
            logger.info("Analyzing network connections...")
            analysis_results['network_connections'] = self.analyze_network_connections(dump_path, profile)
            
            logger.info("Detecting rootkits...")
            analysis_results['rootkit_indicators'] = self.detect_rootkits(dump_path, profile)
            
            logger.info("Extracting registry data...")
            analysis_results['registry_artifacts'] = self.extract_registry_data(dump_path, profile)
            
            logger.info("Extracting credentials...")
            analysis_results['credentials'] = self.extract_credentials(dump_path, profile)
            
            logger.info("Analyzing DLL injections...")
            analysis_results['loaded_dlls'] = self.analyze_dll_injections(dump_path, profile)
            
            logger.info("Extracting strings and artifacts...")
            analysis_results['memory_strings'] = self.extract_strings_and_artifacts(dump_path)
            
            # Identify hidden processes
            analysis_results['hidden_processes'] = self._identify_hidden_processes(
                analysis_results['processes']
            )
            
            # Generate summary and threat indicators
            analysis_results['summary'] = self._generate_analysis_summary(analysis_results)
            analysis_results['threat_indicators'] = self._identify_threat_indicators(analysis_results)
            
            self.analysis_results = analysis_results
            logger.info("Memory analysis completed successfully")
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Memory analysis failed: {e}")
            raise
        finally:
            # Cleanup temporary files
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def detect_profile(self, dump_path: Path) -> str:
        """
        Automatically detect the appropriate Volatility profile for the memory dump.
        
        Uses Volatility's imageinfo plugin to identify:
        - Operating system version
        - Architecture (x86/x64)
        - Service pack level
        - Kernel version
        
        Args:
            dump_path (Path): Path to the memory dump file
            
        Returns:
            str: Detected Volatility profile name
        """
        if self.volatility_version == 'v3':
            # Volatility 3 doesn't require profiles
            return 'auto'
        
        try:
            cmd = [
                str(self.volatility_path),
                '-f', str(dump_path),
                'imageinfo'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Parse suggested profiles from output
                output = result.stdout
                profile_match = re.search(r'Suggested Profile\(s\) : ([^\n]+)', output)
                
                if profile_match:
                    profiles = profile_match.group(1).split(',')
                    # Return the first suggested profile
                    suggested_profile = profiles[0].strip()
                    logger.info(f"Detected profile: {suggested_profile}")
                    return suggested_profile
            
            # Fallback to common profiles if detection fails
            logger.warning("Profile auto-detection failed, trying common profiles")
            for profile in ['Win7SP1x64', 'Win10x64', 'WinXPSP2x86', 'Win7SP0x86']:
                if profile in self.supported_profiles:
                    logger.info(f"Using fallback profile: {profile}")
                    return profile
            
            raise RuntimeError("Could not detect suitable profile")
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Profile detection timed out")
        except Exception as e:
            raise RuntimeError(f"Profile detection failed: {e}")
    
    def analyze_processes(self, dump_path: Path, profile: str) -> List[Dict[str, Any]]:
        """
        Extract and analyze process information from memory.
        
        Uses Volatility plugins to identify:
        - Running processes (pslist, psscan)
        - Hidden processes (psxview)
        - Process trees and relationships
        - Command line arguments
        - Process creation times
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            
        Returns:
            List[Dict[str, Any]]: Process information with analysis results
        """
        processes = []
        
        try:
            # Get process list
            pslist_output = self._run_volatility_plugin(dump_path, profile, 'pslist')
            processes.extend(self._parse_process_output(pslist_output, 'pslist'))
            
            # Get process scan (finds hidden processes)
            psscan_output = self._run_volatility_plugin(dump_path, profile, 'psscan')
            scan_processes = self._parse_process_output(psscan_output, 'psscan')
            
            # Merge and deduplicate processes
            process_dict = {p['pid']: p for p in processes}
            for proc in scan_processes:
                if proc['pid'] not in process_dict:
                    proc['hidden'] = True
                    processes.append(proc)
                else:
                    process_dict[proc['pid']]['scan_found'] = True
            
            # Get command line arguments
            try:
                cmdline_output = self._run_volatility_plugin(dump_path, profile, 'cmdline')
                cmdline_data = self._parse_cmdline_output(cmdline_output)
                
                # Merge command line data with processes
                for proc in processes:
                    pid = proc['pid']
                    if pid in cmdline_data:
                        proc['command_line'] = cmdline_data[pid]
            except Exception as e:
                logger.warning(f"Could not extract command lines: {e}")
            
            # Analyze each process for suspicious characteristics
            for proc in processes:
                proc['suspicious_indicators'] = self._analyze_process_suspicion(proc)
                proc['process_analysis'] = {
                    'is_system_process': self._is_system_process(proc['name']),
                    'unusual_location': self._check_unusual_location(proc.get('path', '')),
                    'suspicious_name': self._check_suspicious_name(proc['name']),
                    'parent_child_relationship': self._analyze_parent_child(proc, processes)
                }
            
            logger.info(f"Analyzed {len(processes)} processes")
            return processes
            
        except Exception as e:
            logger.error(f"Process analysis failed: {e}")
            return []
    
    def detect_process_injection(self, dump_path: Path, profile: str) -> List[Dict[str, Any]]:
        """
        Detect process injection and code injection techniques.
        
        Uses Volatility plugins to find:
        - Malfind (injected code detection)
        - Hollowfind (process hollowing)
        - Modified process memory sections
        - Executable memory in unexpected locations
        - Cross-process memory modifications
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            
        Returns:
            List[Dict[str, Any]]: Detected injection techniques with memory locations
        """
        injection_findings = []
        
        try:
            # Run malfind to detect injected code
            malfind_output = self._run_volatility_plugin(dump_path, profile, 'malfind')
            malfind_results = self._parse_malfind_output(malfind_output)
            
            for result in malfind_results:
                injection_findings.append({
                    'type': 'code_injection',
                    'technique': 'Injected Code (Malfind)',
                    'pid': result['pid'],
                    'process_name': result['process_name'],
                    'virtual_address': result['virtual_address'],
                    'protection': result['protection'],
                    'hexdump': result.get('hexdump', ''),
                    'disassembly': result.get('disassembly', ''),
                    'severity': 'high'
                })
            
            # Try to run hollowfind if available
            try:
                hollow_output = self._run_volatility_plugin(dump_path, profile, 'hollowfind')
                hollow_results = self._parse_hollow_output(hollow_output)
                
                for result in hollow_results:
                    injection_findings.append({
                        'type': 'process_hollowing',
                        'technique': 'Process Hollowing',
                        'pid': result['pid'],
                        'process_name': result['process_name'],
                        'details': result,
                        'severity': 'critical'
                    })
            except Exception as e:
                logger.debug(f"Hollowfind not available or failed: {e}")
            
            logger.info(f"Detected {len(injection_findings)} injection indicators")
            return injection_findings
            
        except Exception as e:
            logger.error(f"Injection detection failed: {e}")
            return []
    
    def analyze_network_connections(self, dump_path: Path, profile: str) -> List[Dict[str, Any]]:
        """
        Extract network connection information from memory.
        
        Uses Volatility plugins to identify:
        - Active network connections (netscan, netstat)
        - Listening sockets
        - Process-to-connection mapping
        - Network artifacts and buffers
        - Historical connection data
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            
        Returns:
            List[Dict[str, Any]]: Network connections with associated processes
        """
        connections = []
        
        try:
            # Try netscan first (preferred for newer Windows versions)
            try:
                netscan_output = self._run_volatility_plugin(dump_path, profile, 'netscan')
                connections.extend(self._parse_network_output(netscan_output, 'netscan'))
            except Exception as e:
                logger.debug(f"Netscan failed, trying netstat: {e}")
                
                # Fallback to netstat
                netstat_output = self._run_volatility_plugin(dump_path, profile, 'netstat')
                connections.extend(self._parse_network_output(netstat_output, 'netstat'))
            
            # Analyze connections for suspicious indicators
            for conn in connections:
                conn['suspicious_indicators'] = self._analyze_connection_suspicion(conn)
                conn['threat_assessment'] = {
                    'is_local_connection': self._is_local_connection(conn),
                    'unusual_port': self._check_unusual_port(conn.get('foreign_port')),
                    'suspicious_process': self._check_suspicious_process(conn.get('pid')),
                    'external_connection': self._is_external_connection(conn)
                }
            
            logger.info(f"Analyzed {len(connections)} network connections")
            return connections
            
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            return []
    
    def detect_rootkits(self, dump_path: Path, profile: str) -> List[Dict[str, Any]]:
        """
        Detect kernel-level rootkits and system modifications.
        
        Uses Volatility plugins to find:
        - SSDT hooks (system service descriptor table)
        - IDT modifications (interrupt descriptor table)
        - Driver hiding techniques
        - Kernel code modifications
        - DKOM (Direct Kernel Object Manipulation)
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            
        Returns:
            List[Dict[str, Any]]: Detected rootkit techniques and kernel modifications
        """
        rootkit_indicators = []
        
        try:
            # Check SSDT hooks
            try:
                ssdt_output = self._run_volatility_plugin(dump_path, profile, 'ssdt')
                ssdt_hooks = self._parse_ssdt_output(ssdt_output)
                
                for hook in ssdt_hooks:
                    if hook.get('hooked', False):
                        rootkit_indicators.append({
                            'type': 'ssdt_hook',
                            'technique': 'SSDT Hook',
                            'entry': hook['entry'],
                            'address': hook['address'],
                            'module': hook.get('module', 'Unknown'),
                            'severity': 'high'
                        })
            except Exception as e:
                logger.debug(f"SSDT analysis failed: {e}")
            
            # Check loaded modules for suspicious drivers
            try:
                modules_output = self._run_volatility_plugin(dump_path, profile, 'modules')
                modules = self._parse_modules_output(modules_output)
                
                for module in modules:
                    if self._is_suspicious_driver(module):
                        rootkit_indicators.append({
                            'type': 'suspicious_driver',
                            'technique': 'Malicious Driver',
                            'name': module['name'],
                            'base_address': module['base'],
                            'size': module['size'],
                            'path': module.get('path', ''),
                            'severity': 'medium'
                        })
            except Exception as e:
                logger.debug(f"Module analysis failed: {e}")
            
            # Check for driver scanning discrepancies
            try:
                driverscan_output = self._run_volatility_plugin(dump_path, profile, 'driverscan')
                scan_modules = self._parse_modules_output(driverscan_output)
                
                # Compare modules vs driverscan for hidden drivers
                module_names = {m['name'] for m in modules}
                scan_names = {m['name'] for m in scan_modules}
                
                hidden_drivers = scan_names - module_names
                for driver_name in hidden_drivers:
                    rootkit_indicators.append({
                        'type': 'hidden_driver',
                        'technique': 'Driver Hiding',
                        'name': driver_name,
                        'severity': 'high'
                    })
                    
            except Exception as e:
                logger.debug(f"Driver scan comparison failed: {e}")
            
            logger.info(f"Detected {len(rootkit_indicators)} potential rootkit indicators")
            return rootkit_indicators
            
        except Exception as e:
            logger.error(f"Rootkit detection failed: {e}")
            return []
    
    def extract_registry_data(self, dump_path: Path, profile: str) -> Dict[str, Any]:
        """
        Extract registry information from memory hives.
        
        Uses Volatility plugins to access:
        - Registry hives in memory
        - Recently accessed registry keys
        - Registry modification tracking
        - Hidden or deleted registry data
        - Registry-based persistence mechanisms
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            
        Returns:
            Dict[str, Any]: Registry data and analysis results
        """
        registry_data = {
            'hives': [],
            'persistence_keys': [],
            'suspicious_entries': [],
            'analysis_summary': {}
        }
        
        try:
            # Get registry hive list
            hivelist_output = self._run_volatility_plugin(dump_path, profile, 'registry')
            hives = self._parse_hivelist_output(hivelist_output)
            registry_data['hives'] = hives
            
            # Look for common persistence registry keys
            persistence_keys = [
                'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                'SYSTEM\\CurrentControlSet\\Services'
            ]
            
            # This would require additional registry parsing plugins
            # For now, we'll note the hives found
            registry_data['analysis_summary'] = {
                'total_hives': len(hives),
                'system_hive_found': any('SYSTEM' in h.get('name', '') for h in hives),
                'software_hive_found': any('SOFTWARE' in h.get('name', '') for h in hives),
                'user_hives_count': len([h for h in hives if 'NTUSER' in h.get('name', '')])
            }
            
            logger.info(f"Found {len(hives)} registry hives")
            return registry_data
            
        except Exception as e:
            logger.error(f"Registry analysis failed: {e}")
            return registry_data
    
    def extract_credentials(self, dump_path: Path, profile: str) -> List[Dict[str, Any]]:
        """
        Extract passwords and cryptographic keys from memory.
        
        Uses Volatility plugins to find:
        - Cached passwords (hashdump, cachedump)
        - LSA secrets
        - Kerberos tickets
        - SSL/TLS private keys
        - Application-specific credentials
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            
        Returns:
            List[Dict[str, Any]]: Extracted credentials and cryptographic material
        """
        credentials = []
        
        try:
            # Extract password hashes
            try:
                hashdump_output = self._run_volatility_plugin(dump_path, profile, 'hashdump')
                hashes = self._parse_hashdump_output(hashdump_output)
                
                for hash_entry in hashes:
                    credentials.append({
                        'type': 'password_hash',
                        'username': hash_entry['username'],
                        'hash': hash_entry['hash'],
                        'hash_type': 'NTLM',
                        'source': 'SAM'
                    })
            except Exception as e:
                logger.debug(f"Hash extraction failed: {e}")
            
            # Extract LSA secrets
            try:
                lsadump_output = self._run_volatility_plugin(dump_path, profile, 'lsadump')
                lsa_secrets = self._parse_lsadump_output(lsadump_output)
                
                for secret in lsa_secrets:
                    credentials.append({
                        'type': 'lsa_secret',
                        'name': secret['name'],
                        'data': secret['data'],
                        'source': 'LSA'
                    })
            except Exception as e:
                logger.debug(f"LSA extraction failed: {e}")
            
            logger.info(f"Extracted {len(credentials)} credential artifacts")
            return credentials
            
        except Exception as e:
            logger.error(f"Credential extraction failed: {e}")
            return []
    
    def analyze_dll_injections(self, dump_path: Path, profile: str) -> List[Dict[str, Any]]:
        """
        Detect DLL injection and library manipulation techniques.
        
        Uses Volatility plugins to identify:
        - Loaded DLLs per process (dlllist)
        - Injected DLLs and libraries
        - DLL search order hijacking
        - Library-based persistence
        - Malicious library modifications
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            
        Returns:
            List[Dict[str, Any]]: DLL analysis results with injection indicators
        """
        dll_analysis = []
        
        try:
            dlllist_output = self._run_volatility_plugin(dump_path, profile, 'dlllist')
            dll_data = self._parse_dlllist_output(dlllist_output)
            
            # Analyze DLLs for each process
            for process_data in dll_data:
                pid = process_data['pid']
                process_name = process_data['process_name']
                dlls = process_data['dlls']
                
                suspicious_dlls = []
                for dll in dlls:
                    if self._is_suspicious_dll(dll):
                        suspicious_dlls.append(dll)
                
                if suspicious_dlls:
                    dll_analysis.append({
                        'pid': pid,
                        'process_name': process_name,
                        'suspicious_dlls': suspicious_dlls,
                        'total_dlls': len(dlls),
                        'analysis': {
                            'unusual_locations': [d for d in suspicious_dlls if self._check_unusual_location(d.get('path', ''))],
                            'unsigned_dlls': [d for d in suspicious_dlls if not d.get('signed', True)],
                            'packed_dlls': [d for d in suspicious_dlls if d.get('packed', False)]
                        }
                    })
            
            logger.info(f"Analyzed DLLs for processes, found {len(dll_analysis)} with suspicious libraries")
            return dll_analysis
            
        except Exception as e:
            logger.error(f"DLL analysis failed: {e}")
            return []
    
    def extract_strings_and_artifacts(self, dump_path: Path) -> Dict[str, List[str]]:
        """
        Extract strings and artifacts from memory dump.
        
        Searches memory for:
        - URLs and network indicators
        - File paths and registry keys
        - Cryptographic constants
        - Configuration data
        - Debug strings and error messages
        
        Args:
            dump_path (Path): Path to the memory dump file
            
        Returns:
            Dict[str, List[str]]: Categorized strings and artifacts
        """
        artifacts = {
            'urls': [],
            'ip_addresses': [],
            'file_paths': [],
            'registry_keys': [],
            'domains': [],
            'email_addresses': [],
            'crypto_artifacts': [],
            'debug_strings': [],
            'error_messages': []
        }
        
        try:
            # Use strings command to extract readable strings
            strings_output = self._extract_memory_strings(dump_path)
            
            # Define regex patterns for different artifact types
            patterns = {
                'urls': re.compile(r'https?://[^\s<>"]+', re.IGNORECASE),
                'ip_addresses': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
                'file_paths': re.compile(r'[A-Za-z]:\\[^<>:"|?*\s]+\.[a-zA-Z]{2,4}'),
                'registry_keys': re.compile(r'HKEY_[A-Z_]+\\[^<>:"|?*\s]+', re.IGNORECASE),
                'domains': re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'),
                'email_addresses': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            }
            
            # Search for patterns in strings
            for line in strings_output.split('\n'):
                line = line.strip()
                if len(line) < 4:  # Skip very short strings
                    continue
                
                for artifact_type, pattern in patterns.items():
                    matches = pattern.findall(line)
                    if matches:
                        artifacts[artifact_type].extend(matches)
                
                # Look for crypto artifacts
                if any(crypto_term in line.lower() for crypto_term in ['bitcoin', 'wallet', 'private key', 'aes', 'rsa', 'decrypt']):
                    artifacts['crypto_artifacts'].append(line)
                
                # Look for debug strings
                if any(debug_term in line.lower() for debug_term in ['debug', 'error', 'exception', 'failed', 'warning']):
                    if len(line) < 200:  # Avoid very long strings
                        artifacts['debug_strings'].append(line)
            
            # Remove duplicates and filter results
            for key in artifacts:
                artifacts[key] = list(set(artifacts[key]))
                # Filter out common/benign entries
                artifacts[key] = [item for item in artifacts[key] if self._is_interesting_artifact(item, key)]
            
            logger.info(f"Extracted strings: {sum(len(v) for v in artifacts.values())} total artifacts")
            return artifacts
            
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return artifacts
    
    def correlate_timeline_events(self, memory_artifacts: Dict, other_analysis: Dict) -> List[Dict[str, Any]]:
        """
        Correlate memory analysis results with timeline from other analyses.
        
        Links memory findings with:
        - Process creation events from behavioral analysis
        - Network connections from traffic analysis
        - File system activity timeline
        - Registry modification timeline
        
        Args:
            memory_artifacts (Dict): Memory analysis results
            other_analysis (Dict): Results from behavioral and network analysis
            
        Returns:
            List[Dict[str, Any]]: Correlated timeline events with memory context
        """
        correlated_events = []
        
        try:
            # Get behavioral timeline if available
            behavioral_timeline = other_analysis.get('behavioral_analysis', {}).get('timeline', [])
            network_timeline = other_analysis.get('network_analysis', {}).get('connections', [])
            
            # Correlate process creation events
            memory_processes = memory_artifacts.get('processes', [])
            for proc in memory_processes:
                # Find matching behavioral events
                matching_behavioral = [
                    event for event in behavioral_timeline
                    if event.get('process_name') == proc.get('name') or 
                       event.get('pid') == proc.get('pid')
                ]
                
                if matching_behavioral or proc.get('suspicious_indicators'):
                    correlated_events.append({
                        'type': 'process_correlation',
                        'memory_artifact': {
                            'pid': proc.get('pid'),
                            'name': proc.get('name'),
                            'path': proc.get('path'),
                            'suspicious': bool(proc.get('suspicious_indicators'))
                        },
                        'behavioral_events': matching_behavioral,
                        'correlation_strength': len(matching_behavioral)
                    })
            
            # Correlate network connections
            memory_connections = memory_artifacts.get('network_connections', [])
            for conn in memory_connections:
                # Find matching network analysis
                matching_network = [
                    net_event for net_event in network_timeline
                    if (net_event.get('destination_ip') == conn.get('foreign_addr') or
                        net_event.get('source_port') == conn.get('local_port'))
                ]
                
                if matching_network or conn.get('suspicious_indicators'):
                    correlated_events.append({
                        'type': 'network_correlation',
                        'memory_artifact': {
                            'local_addr': conn.get('local_addr'),
                            'foreign_addr': conn.get('foreign_addr'),
                            'pid': conn.get('pid'),
                            'state': conn.get('state')
                        },
                        'network_events': matching_network,
                        'correlation_strength': len(matching_network)
                    })
            
            # Correlate injected code with process activities
            injected_code = memory_artifacts.get('injected_code', [])
            for injection in injected_code:
                pid = injection.get('pid')
                # Find related behavioral events for this PID
                related_events = [
                    event for event in behavioral_timeline
                    if event.get('pid') == pid
                ]
                
                if related_events:
                    correlated_events.append({
                        'type': 'injection_correlation',
                        'memory_artifact': injection,
                        'behavioral_events': related_events,
                        'correlation_strength': len(related_events)
                    })
            
            logger.info(f"Generated {len(correlated_events)} timeline correlations")
            return correlated_events
            
        except Exception as e:
            logger.error(f"Timeline correlation failed: {e}")
            return []
    
    def dump_suspicious_processes(self, dump_path: Path, profile: str, process_list: List[int]) -> Dict[int, Path]:
        """
        Dump specific processes from memory for further analysis.
        
        Extracts process memory for:
        - Suspicious or injected processes
        - Processes with unusual characteristics
        - Parent processes of malware
        - Processes with network activity
        
        Args:
            dump_path (Path): Path to the memory dump file
            profile (str): Volatility profile to use
            process_list (List[int]): List of PIDs to dump
            
        Returns:
            Dict[int, Path]: Mapping of PIDs to dumped process files
        """
        dumped_processes = {}
        
        if not self.temp_dir:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='shikra_memory_'))
        
        try:
            for pid in process_list:
                try:
                    # Use procdump plugin to extract process
                    output_file = self.temp_dir / f"process_{pid}.dmp"
                    
                    cmd = self._build_volatility_command(dump_path, profile, 'procdump')
                    cmd.extend(['-p', str(pid), '-D', str(self.temp_dir)])
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    
                    if result.returncode == 0 and output_file.exists():
                        dumped_processes[pid] = output_file
                        logger.info(f"Dumped process {pid} to {output_file}")
                    else:
                        logger.warning(f"Failed to dump process {pid}: {result.stderr}")
                        
                except Exception as e:
                    logger.error(f"Error dumping process {pid}: {e}")
                    continue
            
            return dumped_processes
            
        except Exception as e:
            logger.error(f"Process dumping failed: {e}")
            return {}
    
    def generate_memory_report(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive memory analysis report.
        
        Compiles all memory analysis findings into:
        - Executive summary of key findings
        - Process analysis results
        - Network artifacts from memory
        - Detected threats and techniques
        - Extracted IOCs and artifacts
        
        Args:
            analysis_results (Dict[str, Any]): Complete memory analysis results
            
        Returns:
            Dict[str, Any]: Formatted memory analysis report
        """
        report = {
            'executive_summary': {},
            'key_findings': [],
            'threat_assessment': {},
            'technical_details': {},
            'iocs': {},
            'recommendations': []
        }
        
        try:
            # Generate executive summary
            total_processes = len(analysis_results.get('processes', []))
            hidden_processes = len(analysis_results.get('hidden_processes', []))
            injected_code = len(analysis_results.get('injected_code', []))
            network_connections = len(analysis_results.get('network_connections', []))
            rootkit_indicators = len(analysis_results.get('rootkit_indicators', []))
            
            report['executive_summary'] = {
                'analysis_timestamp': analysis_results['dump_info']['analysis_timestamp'],
                'dump_file': analysis_results['dump_info']['file_path'],
                'dump_size': f"{analysis_results['dump_info']['file_size'] / (1024*1024):.1f} MB",
                'total_processes_found': total_processes,
                'hidden_processes_detected': hidden_processes,
                'code_injection_instances': injected_code,
                'network_connections': network_connections,
                'rootkit_indicators': rootkit_indicators,
                'overall_threat_level': self._calculate_threat_level(analysis_results)
            }
            
            # Identify key findings
            if hidden_processes > 0:
                report['key_findings'].append(f"Detected {hidden_processes} hidden process(es)")
            
            if injected_code > 0:
                report['key_findings'].append(f"Found {injected_code} code injection instance(s)")
            
            if rootkit_indicators > 0:
                report['key_findings'].append(f"Identified {rootkit_indicators} potential rootkit indicator(s)")
            
            # Extract IOCs from memory analysis
            report['iocs'] = self._extract_memory_iocs(analysis_results)
            
            # Generate threat assessment
            report['threat_assessment'] = {
                'persistence_mechanisms': self._count_persistence_indicators(analysis_results),
                'evasion_techniques': hidden_processes + rootkit_indicators,
                'network_activity': len([c for c in analysis_results.get('network_connections', []) 
                                       if c.get('suspicious_indicators')]),
                'credential_theft': len(analysis_results.get('credentials', [])),
                'overall_score': self._calculate_memory_threat_score(analysis_results)
            }
            
            # Add technical details
            report['technical_details'] = {
                'volatility_version': analysis_results['dump_info']['volatility_version'],
                'profile_used': analysis_results['dump_info']['profile'],
                'analysis_plugins_used': self._get_plugins_used(),
                'errors_encountered': analysis_results.get('errors', [])
            }
            
            # Generate recommendations
            report['recommendations'] = self._generate_recommendations(analysis_results)
            
            logger.info("Generated comprehensive memory analysis report")
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return report
    
    # Helper methods for Volatility operations
    def _run_volatility_plugin(self, dump_path: Path, profile: str, plugin: str) -> str:
        """Run a Volatility plugin and return output"""
        try:
            cmd = self._build_volatility_command(dump_path, profile, plugin)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                return result.stdout
            else:
                raise RuntimeError(f"Plugin {plugin} failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Plugin {plugin} timed out")
    
    def _build_volatility_command(self, dump_path: Path, profile: str, plugin: str) -> List[str]:
        """Build Volatility command based on version"""
        # Get the correct plugin name for the version
        plugin_name = self.plugin_map[self.volatility_version].get(plugin, plugin)
        
        if self.volatility_version == 'v3':
            cmd = [str(self.volatility_path), '-f', str(dump_path), plugin_name]
        else:
            cmd = [str(self.volatility_path), '-f', str(dump_path), '--profile', profile, plugin_name]
        
        return cmd
    
    def _extract_memory_strings(self, dump_path: Path) -> str:
        """Extract strings from memory dump using strings command"""
        try:
            # Try to use strings command
            cmd = ['strings', '-a', '-n', '6', str(dump_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return result.stdout
            else:
                # Fallback to reading file directly and extracting printable strings
                return self._extract_printable_strings(dump_path)
                
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # strings command not available, use Python implementation
            return self._extract_printable_strings(dump_path)
    
    def _extract_printable_strings(self, dump_path: Path, min_length: int = 6) -> str:
        """Extract printable strings from binary file"""
        printable_chars = set(string.printable)
        strings_found = []
        
        try:
            with open(dump_path, 'rb') as f:
                current_string = ""
                while True:
                    chunk = f.read(8192)  # Read in chunks
                    if not chunk:
                        break
                    
                    for byte in chunk:
                        char = chr(byte) if byte < 128 else None
                        if char and char in printable_chars and char not in '\r\n\t':
                            current_string += char
                        else:
                            if len(current_string) >= min_length:
                                strings_found.append(current_string)
                            current_string = ""
            
            return '\n'.join(strings_found)
            
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return ""
    
    # Parsing methods for Volatility output
    def _parse_process_output(self, output: str, source: str) -> List[Dict[str, Any]]:
        """Parse process list output"""
        processes = []
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip header lines
            if not line.strip():
                continue
            
            # Parse process information (format varies by plugin)
            parts = line.split()
            if len(parts) >= 4:
                try:
                    process = {
                        'name': parts[0] if source == 'pslist' else parts[1],
                        'pid': int(parts[1]) if source == 'pslist' else int(parts[0]),
                        'ppid': int(parts[2]) if len(parts) > 2 else 0,
                        'threads': int(parts[3]) if len(parts) > 3 else 0,
                        'source': source,
                        'hidden': False,
                        'scan_found': source == 'psscan'
                    }
                    
                    if len(parts) > 5:
                        process['create_time'] = ' '.join(parts[5:7]) if len(parts) > 6 else parts[5]
                    
                    processes.append(process)
                    
                except (ValueError, IndexError):
                    continue
        
        return processes
    
    def _parse_cmdline_output(self, output: str) -> Dict[int, str]:
        """Parse command line output"""
        cmdlines = {}
        lines = output.strip().split('\n')
        
        current_pid = None
        current_cmdline = ""
        
        for line in lines:
            # Look for PID pattern
            pid_match = re.search(r'(\d+)\s+(.+?):', line)
            if pid_match:
                if current_pid is not None:
                    cmdlines[current_pid] = current_cmdline.strip()
                
                current_pid = int(pid_match.group(1))
                current_cmdline = line[pid_match.end():].strip()
            elif current_pid is not None:
                current_cmdline += " " + line.strip()
        
        # Add the last command line
        if current_pid is not None:
            cmdlines[current_pid] = current_cmdline.strip()
        
        return cmdlines
    
    def _parse_malfind_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse malfind output for code injection detection"""
        findings = []
        lines = output.strip().split('\n')
        
        current_finding = {}
        in_hexdump = False
        hexdump_lines = []
        
        for line in lines:
            if 'Process:' in line:
                if current_finding:
                    current_finding['hexdump'] = '\n'.join(hexdump_lines)
                    findings.append(current_finding)
                
                # Start new finding
                parts = line.split()
                current_finding = {
                    'process_name': parts[1] if len(parts) > 1 else 'Unknown',
                    'pid': int(parts[3]) if len(parts) > 3 else 0
                }
                hexdump_lines = []
                in_hexdump = False
                
            elif 'Address:' in line:
                addr_match = re.search(r'Address: (0x[0-9a-fA-F]+)', line)
                if addr_match:
                    current_finding['virtual_address'] = addr_match.group(1)
                    
            elif 'Protection:' in line:
                prot_match = re.search(r'Protection: (\w+)', line)
                if prot_match:
                    current_finding['protection'] = prot_match.group(1)
                    
            elif re.match(r'^[0-9a-fA-F]{8}:', line):
                in_hexdump = True
                hexdump_lines.append(line)
                
            elif in_hexdump and line.strip():
                hexdump_lines.append(line)
        
        # Add the last finding
        if current_finding:
            current_finding['hexdump'] = '\n'.join(hexdump_lines)
            findings.append(current_finding)
        
        return findings
    
    def _parse_hollow_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse hollowfind output"""
        # Implementation would depend on hollowfind output format
        return []
    
    def _parse_network_output(self, output: str, source: str) -> List[Dict[str, Any]]:
        """Parse network connection output"""
        connections = []
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip headers
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 5:
                try:
                    connection = {
                        'protocol': parts[0] if source == 'netscan' else 'TCP',
                        'local_addr': parts[1] if source == 'netscan' else parts[0],
                        'foreign_addr': parts[2] if source == 'netscan' else parts[1],
                        'state': parts[3] if len(parts) > 3 else 'UNKNOWN',
                        'pid': int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                        'process_name': parts[5] if len(parts) > 5 else 'Unknown',
                        'source': source
                    }
                    
                    # Parse address:port format
                    if ':' in connection['local_addr']:
                        addr_parts = connection['local_addr'].rsplit(':', 1)
                        connection['local_ip'] = addr_parts[0]
                        connection['local_port'] = int(addr_parts[1]) if addr_parts[1].isdigit() else 0
                    
                    if ':' in connection['foreign_addr']:
                        addr_parts = connection['foreign_addr'].rsplit(':', 1)
                        connection['foreign_ip'] = addr_parts[0]
                        connection['foreign_port'] = int(addr_parts[1]) if addr_parts[1].isdigit() else 0
                    
                    connections.append(connection)
                    
                except (ValueError, IndexError):
                    continue
        
        return connections
    
    def _parse_ssdt_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse SSDT output for hooks"""
        hooks = []
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip headers
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 3:
                hook = {
                    'entry': parts[0],
                    'address': parts[1],
                    'module': parts[2] if len(parts) > 2 else 'Unknown',
                    'hooked': 'HOOKED' in line.upper() or not parts[2].startswith('nt')
                }
                hooks.append(hook)
        
        return hooks
    
    def _parse_modules_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse loaded modules output"""
        modules = []
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip headers
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 3:
                module = {
                    'base': parts[0],
                    'size': parts[1],
                    'name': parts[2],
                    'path': ' '.join(parts[3:]) if len(parts) > 3 else ''
                }
                modules.append(module)
        
        return modules
    
    def _parse_hivelist_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse registry hive list output"""
        hives = []
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip headers
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                hive = {
                    'virtual_address': parts[0],
                    'name': ' '.join(parts[1:])
                }
                hives.append(hive)
        
        return hives
    
    def _parse_hashdump_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse password hash output"""
        hashes = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if ':' in line and len(line) > 20:
                parts = line.split(':')
                if len(parts) >= 4:
                    hash_entry = {
                        'username': parts[0],
                        'uid': parts[1],
                        'lm_hash': parts[2],
                        'ntlm_hash': parts[3],
                        'hash': parts[3]  # Use NTLM hash as primary
                    }
                    hashes.append(hash_entry)
        
        return hashes
    
    def _parse_lsadump_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse LSA secrets output"""
        secrets = []
        lines = output.strip().split('\n')
        
        current_secret = {}
        for line in lines:
            if line.startswith('Secret:'):
                if current_secret:
                    secrets.append(current_secret)
                current_secret = {'name': line.replace('Secret:', '').strip()}
            elif line.startswith('Data:') and current_secret:
                current_secret['data'] = line.replace('Data:', '').strip()
        
        if current_secret:
            secrets.append(current_secret)
        
        return secrets
    
    def _parse_dlllist_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse DLL list output"""
        processes = []
        lines = output.strip().split('\n')
        
        current_process = None
        for line in lines:
            if line.startswith('Process:'):
                if current_process:
                    processes.append(current_process)
                
                # Extract process info
                process_match = re.search(r'Process: (\S+) Pid: (\d+)', line)
                if process_match:
                    current_process = {
                        'process_name': process_match.group(1),
                        'pid': int(process_match.group(2)),
                        'dlls': []
                    }
            elif current_process and line.strip() and not line.startswith('Command line'):
                # Parse DLL entry
                parts = line.split()
                if len(parts) >= 3:
                    dll = {
                        'base_address': parts[0],
                        'size': parts[1],
                        'path': ' '.join(parts[2:])
                    }
                    current_process['dlls'].append(dll)
        
        if current_process:
            processes.append(current_process)
        
        return processes
    
    # Analysis helper methods
    def _identify_hidden_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify hidden processes from process analysis"""
        hidden = []
        
        # Find processes that were found by psscan but not pslist
        pslist_pids = {p['pid'] for p in processes if p.get('source') == 'pslist'}
        
        for proc in processes:
            if proc.get('source') == 'psscan' and proc['pid'] not in pslist_pids:
                proc['hiding_technique'] = 'DKOM (Direct Kernel Object Manipulation)'
                hidden.append(proc)
            elif proc.get('hidden', False):
                hidden.append(proc)
        
        return hidden
    
    def _analyze_process_suspicion(self, process: Dict[str, Any]) -> List[str]:
        """Analyze process for suspicious characteristics"""
        indicators = []
        
        process_name = process.get('name', '').lower()
        process_path = process.get('path', '').lower()
        
        # Check for process masquerading
        if process_name in [p.lower() for p in self.malicious_patterns['process_names']]:
            if not self._is_legitimate_system_process_path(process_path, process_name):
                indicators.append('process_masquerading')
        
        # Check for unusual locations
        if any(pattern in process_path for pattern in self.malicious_patterns['suspicious_paths']):
            indicators.append('suspicious_location')
        
        # Check for no parent process (orphaned)
        if process.get('ppid', 0) == 0 and process_name not in ['system', 'idle']:
            indicators.append('orphaned_process')
        
        # Check for hidden status
        if process.get('hidden', False):
            indicators.append('hidden_process')
        
        return indicators
    
    def _analyze_connection_suspicion(self, connection: Dict[str, Any]) -> List[str]:
        """Analyze network connection for suspicious characteristics"""
        indicators = []
        
        foreign_ip = connection.get('foreign_ip', '')
        foreign_port = connection.get('foreign_port', 0)
        
        # Check for external connections
        if foreign_ip and not self._is_local_ip(foreign_ip):
            indicators.append('external_connection')
        
        # Check for suspicious ports
        if foreign_port in [6667, 8080, 4444, 31337]:  # Common malware ports
            indicators.append('suspicious_port')
        
        # Check for high-numbered ports (potentially malicious)
        if foreign_port > 49152:
            indicators.append('high_port_number')
        
        return indicators
    
    def _is_suspicious_dll(self, dll: Dict[str, Any]) -> bool:
        """Check if DLL is suspicious"""
        dll_path = dll.get('path', '').lower()
        
        # Check for DLLs in suspicious locations
        suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\'
        ]
        
        for path in suspicious_paths:
            if path in dll_path:
                return True
        
        # Check for unsigned DLLs in system directories
        if ('\\system32\\' in dll_path or '\\syswow64\\' in dll_path):
            if not dll.get('signed', True):
                return True
        
        # Check for DLLs with suspicious names
        suspicious_names = ['inject', 'hook', 'keylog', 'rootkit', 'trojan']
        dll_name = os.path.basename(dll_path)
        
        for name in suspicious_names:
            if name in dll_name:
                return True
        
        return False
    
    def _is_suspicious_driver(self, module: Dict[str, Any]) -> bool:
        """Check if driver/module is suspicious"""
        module_name = module.get('name', '').lower()
        module_path = module.get('path', '').lower()
        
        # Check for drivers in unusual locations
        if module_path and not any(legit in module_path for legit in [
            '\\system32\\drivers\\', '\\syswow64\\drivers\\', '\\windows\\system32\\'
        ]):
            return True
        
        # Check for suspicious driver names
        suspicious_names = ['rootkit', 'keylog', 'inject', 'hook', 'bypass']
        for name in suspicious_names:
            if name in module_name:
                return True
        
        return False
    
    def _is_system_process(self, process_name: str) -> bool:
        """Check if process is a legitimate system process"""
        system_processes = [
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'spoolsv.exe'
        ]
        return process_name.lower() in system_processes
    
    def _check_unusual_location(self, path: str) -> bool:
        """Check if file path is in an unusual location"""
        if not path:
            return False
        
        path_lower = path.lower()
        unusual_locations = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\', '\\windows\\temp\\'
        ]
        
        return any(loc in path_lower for loc in unusual_locations)
    
    def _check_suspicious_name(self, process_name: str) -> bool:
        """Check if process name is suspicious"""
        suspicious_indicators = [
            'svchost', 'lsass', 'winlogon', 'csrss', 'explorer'
        ]
        
        name_lower = process_name.lower()
        
        # Check for typosquatting of system processes
        for legit_name in suspicious_indicators:
            if legit_name in name_lower and legit_name != name_lower:
                return True
        
        return False
    
    def _analyze_parent_child(self, process: Dict[str, Any], all_processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze parent-child relationships"""
        pid = process.get('pid')
        ppid = process.get('ppid', 0)
        
        # Find parent process
        parent = next((p for p in all_processes if p.get('pid') == ppid), None)
        
        # Find child processes
        children = [p for p in all_processes if p.get('ppid') == pid]
        
        analysis = {
            'has_parent': parent is not None,
            'parent_name': parent.get('name') if parent else None,
            'child_count': len(children),
            'child_names': [c.get('name') for c in children],
            'suspicious_relationships': []
        }
        
        # Check for suspicious parent-child relationships
        if parent:
            parent_name = parent.get('name', '').lower()
            process_name = process.get('name', '').lower()
            
            # Check for unusual parent processes
            if parent_name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']:
                if process_name in ['svchost.exe', 'lsass.exe', 'winlogon.exe']:
                    analysis['suspicious_relationships'].append('system_process_spawned_by_script')
        
        return analysis
    
    def _is_local_connection(self, connection: Dict[str, Any]) -> bool:
        """Check if connection is local"""
        foreign_ip = connection.get('foreign_ip', '')
        return self._is_local_ip(foreign_ip)
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP address is local"""
        if not ip or ip == '0.0.0.0':
            return True
        
        local_ranges = ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.']
        return any(ip.startswith(range_start) for range_start in local_ranges)
    
    def _check_unusual_port(self, port: int) -> bool:
        """Check if port number is unusual"""
        if not port:
            return False
        
        # Common malware ports
        suspicious_ports = [4444, 6667, 8080, 31337, 1337, 6666, 9999]
        return port in suspicious_ports
    
    def _check_suspicious_process(self, pid: int) -> bool:
        """Check if process ID corresponds to suspicious process"""
        # This would need to be enhanced with actual process analysis results
        return False
    
    def _is_external_connection(self, connection: Dict[str, Any]) -> bool:
        """Check if connection is to external host"""
        return not self._is_local_connection(connection)
    
    def _is_legitimate_system_process_path(self, path: str, process_name: str) -> bool:
        """Check if system process is in legitimate location"""
        if not path:
            return False
        
        path_lower = path.lower()
        name_lower = process_name.lower()
        
        # Expected locations for system processes
        system_locations = {
            'svchost.exe': ['\\system32\\', '\\syswow64\\'],
            'lsass.exe': ['\\system32\\'],
            'winlogon.exe': ['\\system32\\'],
            'csrss.exe': ['\\system32\\'],
            'explorer.exe': ['\\windows\\']
        }
        
        if name_lower in system_locations:
            expected_paths = system_locations[name_lower]
            return any(exp_path in path_lower for exp_path in expected_paths)
        
        return True  # Unknown process, assume legitimate
    
    def _is_interesting_artifact(self, artifact: str, artifact_type: str) -> bool:
        """Filter out common/benign artifacts"""
        if not artifact or len(artifact) < 3:
            return False
        
        # Common filters by type
        if artifact_type == 'urls':
            boring_domains = ['microsoft.com', 'windows.com', 'adobe.com', 'google.com']
            return not any(domain in artifact.lower() for domain in boring_domains)
        
        elif artifact_type == 'ip_addresses':
            # Filter out local IPs and common public DNS
            if self._is_local_ip(artifact) or artifact in ['8.8.8.8', '8.8.4.4', '1.1.1.1']:
                return False
        
        elif artifact_type == 'file_paths':
            # Filter out very common Windows paths
            common_paths = ['\\windows\\system32\\', '\\program files\\', '\\users\\']
            if any(common in artifact.lower() for common in common_paths):
                return len(artifact) > 50  # Only keep if unusually long
        
        return True
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics"""
        return {
            'total_processes': len(results.get('processes', [])),
            'hidden_processes': len(results.get('hidden_processes', [])),
            'suspicious_processes': len([p for p in results.get('processes', []) 
                                       if p.get('suspicious_indicators')]),
            'network_connections': len(results.get('network_connections', [])),
            'external_connections': len([c for c in results.get('network_connections', []) 
                                       if self._is_external_connection(c)]),
            'injected_code_instances': len(results.get('injected_code', [])),
            'loaded_dlls_analyzed': sum(len(p.get('dlls', [])) for p in results.get('loaded_dlls', [])),
            'suspicious_dlls': sum(len(p.get('suspicious_dlls', [])) for p in results.get('loaded_dlls', [])),
            'rootkit_indicators': len(results.get('rootkit_indicators', [])),
            'credentials_extracted': len(results.get('credentials', [])),
            'registry_hives_found': len(results.get('registry_artifacts', {}).get('hives', [])),
            'memory_strings_extracted': sum(len(v) for v in results.get('memory_strings', {}).values())
        }
    
    def _identify_threat_indicators(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify high-level threat indicators"""
        indicators = []
        
        # Hidden processes
        if results.get('hidden_processes'):
            indicators.append({
                'type': 'process_hiding',
                'severity': 'high',
                'description': f"Detected {len(results['hidden_processes'])} hidden process(es)",
                'count': len(results['hidden_processes'])
            })
        
        # Code injection
        if results.get('injected_code'):
            indicators.append({
                'type': 'code_injection',
                'severity': 'high',
                'description': f"Found {len(results['injected_code'])} code injection instance(s)",
                'count': len(results['injected_code'])
            })
        
        # Rootkit indicators
        if results.get('rootkit_indicators'):
            indicators.append({
                'type': 'rootkit_activity',
                'severity': 'critical',
                'description': f"Identified {len(results['rootkit_indicators'])} rootkit indicator(s)",
                'count': len(results['rootkit_indicators'])
            })
        
        # Suspicious network activity
        suspicious_connections = [c for c in results.get('network_connections', []) 
                                if c.get('suspicious_indicators')]
        if suspicious_connections:
            indicators.append({
                'type': 'suspicious_network',
                'severity': 'medium',
                'description': f"Found {len(suspicious_connections)} suspicious network connection(s)",
                'count': len(suspicious_connections)
            })
        
        # Credential extraction
        if results.get('credentials'):
            indicators.append({
                'type': 'credential_theft',
                'severity': 'high',
                'description': f"Extracted {len(results['credentials'])} credential artifact(s)",
                'count': len(results['credentials'])
            })
        
        return indicators
    
    def _calculate_threat_level(self, results: Dict[str, Any]) -> str:
        """Calculate overall threat level"""
        score = 0
        
        # Weight different types of findings
        score += len(results.get('hidden_processes', [])) * 3
        score += len(results.get('injected_code', [])) * 3
        score += len(results.get('rootkit_indicators', [])) * 4
        score += len(results.get('credentials', [])) * 2
        
        suspicious_connections = [c for c in results.get('network_connections', []) 
                                if c.get('suspicious_indicators')]
        score += len(suspicious_connections) * 1
        
        if score >= 10:
            return 'Critical'
        elif score >= 6:
            return 'High'
        elif score >= 3:
            return 'Medium'
        elif score >= 1:
            return 'Low'
        else:
            return 'Minimal'
    
    def _count_persistence_indicators(self, results: Dict[str, Any]) -> int:
        """Count persistence mechanism indicators"""
        count = 0
        
        # Check for suspicious services
        count += len([p for p in results.get('processes', []) 
                     if 'service' in p.get('name', '').lower()])
        
        # Check for suspicious DLLs in system processes
        for dll_analysis in results.get('loaded_dlls', []):
            if dll_analysis.get('suspicious_dlls'):
                count += 1
        
        return count
    
    def _calculate_memory_threat_score(self, results: Dict[str, Any]) -> int:
        """Calculate numeric threat score (0-100)"""
        score = 0
        
        # Hidden processes (20 points each, max 60)
        score += min(len(results.get('hidden_processes', [])) * 20, 60)
        
        # Code injection (15 points each, max 45)
        score += min(len(results.get('injected_code', [])) * 15, 45)
        
        # Rootkit indicators (25 points each, max 50)
        score += min(len(results.get('rootkit_indicators', [])) * 25, 50)
        
        # Credential theft (10 points each, max 30)
        score += min(len(results.get('credentials', [])) * 10, 30)
        
        # Suspicious network (5 points each, max 20)
        suspicious_connections = [c for c in results.get('network_connections', []) 
                                if c.get('suspicious_indicators')]
        score += min(len(suspicious_connections) * 5, 20)
        
        return min(score, 100)
    
    def _get_plugins_used(self) -> List[str]:
        """Get list of Volatility plugins used in analysis"""
        plugins = ['pslist', 'psscan', 'cmdline', 'netscan', 'malfind', 'dlllist']
        
        if self.volatility_version == 'v2':
            plugins.extend(['psxview', 'netstat', 'ssdt', 'modules', 'hashdump'])
        
        return plugins
    
    def _extract_memory_iocs(self, results: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from memory analysis results"""
        iocs = {
            'processes': [],
            'files': [],
            'network': [],
            'registry': [],
            'hashes': []
        }
        
        # Extract process IOCs
        for proc in results.get('processes', []):
            if proc.get('suspicious_indicators'):
                iocs['processes'].append(proc.get('name', ''))
                if proc.get('path'):
                    iocs['files'].append(proc.get('path'))
        
        # Extract network IOCs
        for conn in results.get('network_connections', []):
            if conn.get('suspicious_indicators'):
                if conn.get('foreign_ip'):
                    iocs['network'].append(conn.get('foreign_ip'))
        
        # Extract file IOCs from strings
        strings_data = results.get('memory_strings', {})
        if strings_data.get('file_paths'):
            iocs['files'].extend(strings_data['file_paths'][:20])  # Limit to top 20
        
        if strings_data.get('urls'):
            iocs['network'].extend(strings_data['urls'][:20])
        
        # Remove duplicates
        for key in iocs:
            iocs[key] = list(set(filter(None, iocs[key])))
        
        return iocs
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if results.get('hidden_processes'):
            recommendations.append("Investigate hidden processes for potential rootkit activity")
            recommendations.append("Run additional rootkit scanners to confirm findings")
        
        if results.get('injected_code'):
            recommendations.append("Analyze injected code segments for malicious payloads")
            recommendations.append("Check for process hollowing and DLL injection techniques")
        
        if results.get('rootkit_indicators'):
            recommendations.append("Perform kernel-level analysis to identify rootkit components")
            recommendations.append("Check system integrity and restore from known good backup")
        
        suspicious_connections = [c for c in results.get('network_connections', []) 
                                if c.get('suspicious_indicators')]
        if suspicious_connections:
            recommendations.append("Block suspicious network connections at firewall level")
            recommendations.append("Monitor network traffic for command and control activity")
        
        if results.get('credentials'):
            recommendations.append("Reset all compromised passwords and credentials")
            recommendations.append("Implement additional authentication factors")
        
        if not recommendations:
            recommendations.append("Continue monitoring for suspicious activity")
            recommendations.append("Regular memory analysis for ongoing threats")
        
        return recommendations

# Additional imports needed
import string