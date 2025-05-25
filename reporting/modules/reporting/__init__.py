"""
Reporting Package Initializer (__init__.py)

Purpose:
This file marks the 'reporting' directory as a Python package and serves as the main
entry point for report generation and visualization modules. It provides a unified
interface for transforming analysis results into human-readable reports and visualizations.

Context in Shikra:
The reporting package is the final component in the Shikra workflow:
1. Core modules (vm_controller, monitor, network) - Handle execution and data collection
2. Analysis modules - Process and analyze collected data 
3. Reporting modules (THIS PACKAGE) - Generate reports and provide web interface

Key Components Exposed:
- ReportGenerator: Creates comprehensive analysis reports in multiple formats (PDF, HTML, JSON)
- DataVisualizer: Generates charts, graphs, and visual representations of analysis data
- WebInterface: Flask-based web application for browsing and managing analysis results

Usage:
This package is typically invoked after all analysis modules have completed processing.
It takes structured analysis results and transforms them into final deliverables for
analysts, including detailed reports and an interactive web interface.
"""

from .report_generator import ReportGenerator
from .visualizer import DataVisualizer

__all__ = [
    'ReportGenerator',
    'DataVisualizer'
]

# Package version and metadata
__version__ = "0.1.0"
__author__ = "Shikra Development Team"
__description__ = "Report generation and visualization modules for malware analysis results"
