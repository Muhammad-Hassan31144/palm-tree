"""
Analysis Package Initializer (__init__.py)

Purpose:
This file marks the 'analysis' directory as a Python package and serves as the main
entry point for post-execution analysis modules. It provides a unified interface
for analyzing behavioral data, network traffic, and memory dumps collected during
malware execution.

Context in Shikra:
The analysis package is the third major component in the Shikra workflow:
1. Core modules (vm_controller, monitor, network) - Handle execution and data collection
2. Analysis modules (THIS PACKAGE) - Process and analyze collected data
3. Reporting modules - Generate human-readable reports from analysis results

Key Components Exposed:
- BehavioralAnalyzer: Analyzes process, file, and registry activity
- NetworkAnalyzer: Analyzes network traffic captures (pcap files)
- MemoryAnalyzer: Analyzes memory dumps using Volatility framework

Usage:
This package is typically invoked after malware execution is complete and all
artifacts (logs, pcaps, memory dumps) have been collected. It transforms raw
data into structured analysis results for reporting.
"""

from .behavioral import BehavioralAnalyzer
from .network_analysis import NetworkAnalyzer  
from .memory_analysis import MemoryAnalyzer

__all__ = [
    'BehavioralAnalyzer',
    'NetworkAnalyzer', 
    'MemoryAnalyzer'
]

# Package version and metadata
__version__ = "0.1.0"
__author__ = "Shikra Development Team"
__description__ = "Post-execution analysis modules for malware behavior analysis"
