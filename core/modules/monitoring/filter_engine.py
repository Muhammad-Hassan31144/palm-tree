# shikra/core/modules/monitoring/filter_engine.py
# Purpose: Advanced filtering engine for noise reduction and intelligent event filtering

import re
import json
import logging
from typing import Dict, List, Set, Optional, Union
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

class FilterEngine:
    """
    Advanced filtering engine for ProcMon events.
    Provides intelligent noise filtering and pattern-based event selection.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the filter engine.
        
        Args:
            config: Configuration dictionary containing filter rules
        """
        self.config = config or {}
        self.stats = {
            "total_events": 0,
            "filtered_out": 0,
            "filtered_in": 0,
            "filter_matches": defaultdict(int)
        }
        
        # Load filter rules
        self._load_filter_rules()
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
    def _load_filter_rules(self):
        """Load filtering rules from configuration or defaults."""
        # Try to load from files first
        noise_filters_file = self.config.get('noise_filters_file', 'config/procmon/noise_filters.json')
        behavioral_filters_file = self.config.get('behavioral_filters_file', 'config/procmon/behavioral_filters.json')
        
        self.noise_filters = self._load_filter_file(noise_filters_file, self._get_default_noise_filters())
        self.behavioral_filters = self._load_filter_file(behavioral_filters_file, self._get_default_behavioral_filters())
        
        # Merge with any config-provided filters
        if 'noise_filters' in self.config:
            self.noise_filters.update(self.config['noise_filters'])
        if 'behavioral_filters' in self.config:
            self.behavioral_filters.update(self.config['behavioral_filters'])
            
        logger.info(f"Loaded {len(self.noise_filters.get('process_exclusions', []))} process exclusions")
        logger.info(f"Loaded {len(self.behavioral_filters.get('high_value_operations', []))} high-value operations")
    
    def _load_filter_file(self, file_path: str, default_data: Dict) -> Dict:
        """Load filter rules from JSON file with fallback to defaults."""
        try:
            if Path(file_path).exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                logger.info(f"Loaded filter rules from {file_path}")
                return data
        except Exception as e:
            logger.warning(f"Failed to load filter file {file_path}: {e}")
        
        logger.info("Using default filter rules")
        return default_data
    
    def _get_default_noise_filters(self) -> Dict:
        """Default noise filtering rules."""
        return {
            "process_exclusions": [
                # System processes that generate excessive noise
                "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe", "lsm.exe", "winlogon.exe",
                "dwm.exe", "taskhost.exe", "taskhostw.exe", "WmiPrvSE.exe",
                "svchost.exe", "spoolsv.exe", "SearchIndexer.exe",
                "audiodg.exe", "conhost.exe", "RuntimeBroker.exe",
                
                # Windows Update and Defender
                "MsMpEng.exe", "NisSrv.exe", "TrustedInstaller.exe",
                "wuauclt.exe", "Windows10UpgraderApp.exe",
                
                # Common applications that aren't typically malicious
                "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe",
                "notepad.exe", "calc.exe", "mspaint.exe", "winword.exe",
                "excel.exe", "powerpnt.exe", "outlook.exe"
            ],
            
            "path_exclusions": [
                # Windows system directories (legitimate activity)
                "C:\\Windows\\System32\\",
                "C:\\Windows\\SysWOW64\\",
                "C:\\Windows\\WinSxS\\",
                "C:\\Windows\\servicing\\",
                "C:\\Windows\\Microsoft.NET\\",
                "C:\\Windows\\assembly\\",
                "C:\\Program Files\\Windows Defender\\",
                "C:\\Program Files (x86)\\Windows Defender\\",
                
                # Temporary files that are usually noise
                "\\Local Settings\\Temp\\",
                "\\AppData\\Local\\Temp\\Temp",
                "\\Windows\\Temp\\~",
                "pagefile.sys", "hiberfil.sys", "swapfile.sys",
                
                # Log files and caches
                "\\.log", "\\.tmp", "\\.cache", "\\.etl"
            ],
            
            "operation_exclusions": [
                # Operations that are typically noise
                "Process and Thread Activity",
                "Image/DLL",
                "Profiling",
                "QueryNameInformationFile",
                "QueryBasicInformationFile",
                "QueryStandardInformationFile",
                "QueryAttributeTagFile",
                "IRP_MJ_CREATE",  # Too verbose
                "IRP_MJ_CLOSE"    # Too verbose
            ],
            
            "result_exclusions": [
                # Failed operations that are usually noise
                "NAME NOT FOUND",
                "PATH NOT FOUND", 
                "ACCESS DENIED",
                "BUFFER OVERFLOW",
                "NO MORE FILES",
                "INVALID PARAMETER"
            ],
            
            "file_extension_exclusions": [
                # File types that rarely contain malware
                ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
                ".mp3", ".mp4", ".avi", ".wav", ".wma", ".wmv",
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".txt", ".rtf", ".log", ".xml", ".json", ".csv"
            ]
        }
    
    def _get_default_behavioral_filters(self) -> Dict:
        """Default behavioral filtering rules for important events."""
        return {
            "high_value_operations": [
                # File operations of interest
                "CreateFile", "WriteFile", "SetDispositionInformationFile",
                "SetRenameInformationFile", "DeleteFile",
                
                # Registry operations
                "RegCreateKey", "RegSetValue", "RegDeleteKey", "RegDeleteValue",
                
                # Process operations
                "Process Create", "Thread Create", "Process Terminate",
                
                # Network operations  
                "TCP Send", "TCP Receive", "UDP Send", "UDP Receive"
            ],
            
            "high_value_paths": [
                # Startup locations
                "\\CurrentVersion\\Run",
                "\\CurrentVersion\\RunOnce", 
                "\\Winlogon\\",
                "\\Services\\",
                
                # System modification locations
                "\\System32\\drivers\\",
                "\\System32\\config\\",
                "\\Boot\\",
                
                # User data locations
                "\\Desktop\\",
                "\\Documents\\",
                "\\Downloads\\",
                "\\Pictures\\",