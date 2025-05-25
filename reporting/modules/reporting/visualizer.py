# shikra/modules/reporting/visualizer.py
# Purpose: Creates visual representations of malware analysis data including charts,
# graphs, network diagrams, and interactive visualizations.

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import json
import base64
import math
from collections import Counter, defaultdict
import os

# Visualization libraries
try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import Rectangle
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None

try:
    import seaborn as sns
    SEABORN_AVAILABLE = True
    if MATPLOTLIB_AVAILABLE:
        sns.set_theme(style="whitegrid")
except ImportError:
    SEABORN_AVAILABLE = False
    sns = None

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.offline as pyo
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    go = px = make_subplots = pyo = None

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None

# Configure logging for this module
logger = logging.getLogger(__name__)

class DataVisualizer:
    """
    Creates visual representations of malware analysis data including charts,
    network diagrams, timelines, and interactive visualizations.
    
    This class serves as the primary visualization engine in Shikra,
    transforming complex analysis data into clear, informative visual
    representations for analysts and stakeholders.
    """
    
    def __init__(self, output_directory: Optional[Path] = None, style_theme: str = 'default'):
        """
        Initialize the data visualizer with output directory and style settings.
        
        Args:
            output_directory (Optional[Path]): Directory for saving generated visualizations
            style_theme (str): Visual style theme ('default', 'dark', 'presentation')
        """
        self.output_directory = output_directory or Path("./visualizations")
        self.style_theme = style_theme
        self.supported_formats = ['png', 'svg', 'html', 'pdf']
        self.color_schemes = {}
        
        # Ensure output directory exists
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
        self._setup_visualization_styles()
        logger.info(f"DataVisualizer initialized with theme: {style_theme}")
    
    def _setup_visualization_styles(self):
        """
        Configure visualization styles and color schemes based on selected theme.
        Sets up consistent styling across all generated visualizations.
        """
        # Define color schemes for different themes
        if self.style_theme == 'dark':
            self.color_schemes = {
                'background': '#2E2E2E',
                'text': '#FFFFFF',
                'primary': '#00D4AA',
                'secondary': '#FF6B6B',
                'accent': '#4ECDC4',
                'warning': '#FFE66D',
                'danger': '#FF6B6B',
                'success': '#4ECDC4',
                'info': '#A8E6CF'
            }
        elif self.style_theme == 'presentation':
            self.color_schemes = {
                'background': '#FFFFFF',
                'text': '#333333',
                'primary': '#1f77b4',
                'secondary': '#ff7f0e',
                'accent': '#2ca02c',
                'warning': '#d62728',
                'danger': '#9467bd',
                'success': '#8c564b',
                'info': '#e377c2'
            }
        else:  # default
            self.color_schemes = {
                'background': '#FFFFFF',
                'text': '#000000',
                'primary': '#007bff',
                'secondary': '#6c757d',
                'accent': '#28a745',
                'warning': '#ffc107',
                'danger': '#dc3545',
                'success': '#28a745',
                'info': '#17a2b8'
            }
        
        # Configure matplotlib style if available
        if MATPLOTLIB_AVAILABLE:
            plt.style.use('default')
            if self.style_theme == 'dark':
                plt.rcParams.update({
                    'figure.facecolor': self.color_schemes['background'],
                    'axes.facecolor': self.color_schemes['background'],
                    'text.color': self.color_schemes['text'],
                    'axes.labelcolor': self.color_schemes['text'],
                    'xtick.color': self.color_schemes['text'],
                    'ytick.color': self.color_schemes['text']
                })
        
        # Configure seaborn palette if available
        if SEABORN_AVAILABLE:
            colors = [self.color_schemes[key] for key in ['primary', 'secondary', 'accent', 'warning', 'danger', 'success']]
            sns.set_palette(colors)
    
    def create_network_diagram(self, network_data: Dict[str, Any], 
                             output_path: Path,
                             layout_type: str = 'force') -> Path:
        """
        Create a network communication diagram showing malware network activity.
        """
        logger.info(f"Creating network diagram: {output_path}")
        
        if not NETWORKX_AVAILABLE or not MATPLOTLIB_AVAILABLE:
            logger.error("NetworkX and Matplotlib required for network diagrams")
            return output_path
        
        try:
            # Create networkx graph
            G = nx.Graph()
            
            # Extract network communications
            dns_queries = network_data.get('dns_queries', [])
            http_requests = network_data.get('http_requests', [])
            tls_connections = network_data.get('tls_connections', [])
            ip_communications = network_data.get('ip_communications', {})
            
            # Add nodes and edges from network data
            node_colors = []
            node_sizes = []
            edge_colors = []
            
            # Add central node for the analyzed system
            G.add_node('Analyzed_System', type='system')
            
            # Process DNS queries
            for query in dns_queries[:20]:  # Limit to prevent overcrowding
                domain = query.get('query_name', '')
                if domain:
                    G.add_node(domain, type='domain')
                    G.add_edge('Analyzed_System', domain, type='dns')
            
            # Process HTTP/TLS connections
            for request in (http_requests + tls_connections)[:30]:
                host = request.get('http_host') or request.get('tls_sni') or request.get('dest_ip', '')
                if host and host not in G.nodes():
                    G.add_node(host, type='host')
                    G.add_edge('Analyzed_System', host, type='http/tls')
            
            # Process IP communications
            for ip, comm_data in list(ip_communications.items())[:15]:
                if ip not in G.nodes():
                    G.add_node(ip, type='ip')
                    G.add_edge('Analyzed_System', ip, type='tcp/udp')
            
            if not G.nodes():
                logger.warning("No network data to visualize")
                return output_path
            
            # Set up the plot
            plt.figure(figsize=(16, 12))
            
            # Choose layout
            if layout_type == 'circular':
                pos = nx.circular_layout(G)
            elif layout_type == 'hierarchical':
                pos = nx.spring_layout(G, k=1, iterations=50)
            else:  # force/spring layout
                pos = nx.spring_layout(G, k=0.5, iterations=50)
            
            # Color nodes by type
            for node in G.nodes():
                node_type = G.nodes[node].get('type', 'unknown')
                if node_type == 'system':
                    node_colors.append(self.color_schemes['danger'])
                    node_sizes.append(1000)
                elif node_type == 'domain':
                    node_colors.append(self.color_schemes['primary'])
                    node_sizes.append(600)
                elif node_type == 'host':
                    node_colors.append(self.color_schemes['warning'])
                    node_sizes.append(400)
                elif node_type == 'ip':
                    node_colors.append(self.color_schemes['info'])
                    node_sizes.append(300)
                else:
                    node_colors.append(self.color_schemes['secondary'])
                    node_sizes.append(200)
            
            # Draw the network
            nx.draw(G, pos, 
                   node_color=node_colors, 
                   node_size=node_sizes,
                   with_labels=True, 
                   font_size=8, 
                   font_weight='bold',
                   edge_color=self.color_schemes['secondary'],
                   alpha=0.7)
            
            plt.title('Network Communication Diagram', fontsize=16, fontweight='bold')
            plt.tight_layout()
            
            # Save the plot
            plt.savefig(output_path, dpi=300, bbox_inches='tight', 
                       facecolor=self.color_schemes['background'])
            plt.close()
            
            logger.info(f"Network diagram saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating network diagram: {e}")
            return output_path
    
    def create_process_tree(self, behavioral_data: Dict[str, Any], 
                          output_path: Path,
                          include_timeline: bool = True) -> Path:
        """
        Create a process execution tree showing malware behavioral hierarchy.
        """
        logger.info(f"Creating process tree: {output_path}")
        
        if not NETWORKX_AVAILABLE or not MATPLOTLIB_AVAILABLE:
            logger.error("NetworkX and Matplotlib required for process trees")
            return output_path
        
        try:
            # Extract process data
            processes_created = behavioral_data.get('process_operations', {}).get('processes_created', [])
            if not processes_created:
                processes_created = behavioral_data.get('processes', {}).get('pslist', [])
            
            if not processes_created:
                logger.warning("No process data available for tree visualization")
                return output_path
            
            # Create directed graph for process tree
            G = nx.DiGraph()
            node_labels = {}
            node_colors = []
            
            # Add processes as nodes
            for proc in processes_created:
                child_pid = proc.get('child_pid') or proc.get('pid')
                parent_pid = proc.get('parent_pid') or proc.get('ppid')
                process_name = proc.get('child_process_name') or proc.get('name', f'PID_{child_pid}')
                
                if child_pid:
                    G.add_node(child_pid)
                    node_labels[child_pid] = f"{process_name}\n(PID: {child_pid})"
                    
                    # Add edge from parent to child
                    if parent_pid and parent_pid != child_pid:
                        if parent_pid not in G:
                            G.add_node(parent_pid)
                            # Try to find parent name
                            parent_name = next((p.get('child_process_name', p.get('name', f'PID_{parent_pid}')) 
                                              for p in processes_created 
                                              if p.get('child_pid') == parent_pid or p.get('pid') == parent_pid), 
                                             f'PID_{parent_pid}')
                            node_labels[parent_pid] = f"{parent_name}\n(PID: {parent_pid})"
                        
                        G.add_edge(parent_pid, child_pid)
            
            if not G.nodes():
                logger.warning("No process tree data to visualize")
                return output_path
            
            # Set up the plot
            plt.figure(figsize=(14, 10))
            
            # Use hierarchical layout for process tree
            try:
                pos = nx.nx_agraph.graphviz_layout(G, prog='dot')
            except:
                # Fallback to spring layout
                pos = nx.spring_layout(G, k=1, iterations=50)
            
            # Color nodes based on suspicious indicators
            suspicious_processes = behavioral_data.get('suspicious_processes', [])
            suspicious_pids = {proc.get('pid') for proc in suspicious_processes}
            
            for node in G.nodes():
                if node in suspicious_pids:
                    node_colors.append(self.color_schemes['danger'])
                else:
                    node_colors.append(self.color_schemes['primary'])
            
            # Draw the process tree
            nx.draw(G, pos,
                   labels=node_labels,
                   node_color=node_colors,
                   node_size=2000,
                   font_size=8,
                   font_weight='bold',
                   arrows=True,
                   arrowsize=20,
                   edge_color=self.color_schemes['secondary'],
                   with_labels=True)
            
            plt.title('Process Execution Tree', fontsize=16, fontweight='bold')
            plt.tight_layout()
            
            # Save the plot
            plt.savefig(output_path, dpi=300, bbox_inches='tight',
                       facecolor=self.color_schemes['background'])
            plt.close()
            
            logger.info(f"Process tree saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating process tree: {e}")
            return output_path
    
    def create_timeline_chart(self, timeline_data: List[Dict[str, Any]], 
                            output_path: Path,
                            chart_type: str = 'gantt') -> Path:
        """
        Create a timeline visualization of malware execution events.
        """
        logger.info(f"Creating timeline chart: {output_path}")
        
        if not PLOTLY_AVAILABLE:
            logger.error("Plotly required for timeline charts")
            return output_path
        
        try:
            if not timeline_data:
                logger.warning("No timeline data available")
                return output_path
            
            # Process timeline data
            events_by_type = defaultdict(list)
            for event in timeline_data:
                event_type = event.get('event_type', 'Unknown')
                events_by_type[event_type].append(event)
            
            if chart_type == 'gantt':
                # Create Gantt chart
                fig = go.Figure()
                
                y_pos = 0
                colors = [self.color_schemes['primary'], self.color_schemes['secondary'], 
                         self.color_schemes['accent'], self.color_schemes['warning']]
                
                for i, (event_type, events) in enumerate(events_by_type.items()):
                    color = colors[i % len(colors)]
                    
                    for event in events:
                        timestamp = event.get('timestamp', '')
                        description = event.get('description', '')
                        
                        # Try to parse timestamp
                        try:
                            if isinstance(timestamp, str) and timestamp not in ['Unknown', 'N/A']:
                                start_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            else:
                                start_time = datetime.now()
                        except:
                            start_time = datetime.now()
                        
                        end_time = start_time + timedelta(seconds=30)  # Default duration
                        
                        fig.add_trace(go.Scatter(
                            x=[start_time, end_time],
                            y=[y_pos, y_pos],
                            mode='lines+markers',
                            name=f"{event_type}: {description[:50]}",
                            line=dict(color=color, width=8),
                            hovertemplate=f"<b>{event_type}</b><br>{description}<br>Time: {timestamp}<extra></extra>"
                        ))
                    
                    y_pos += 1
                
                fig.update_layout(
                    title='Malware Execution Timeline',
                    xaxis_title='Time',
                    yaxis_title='Event Types',
                    showlegend=False,
                    height=max(400, len(events_by_type) * 60)
                )
                
            else:  # scatter or bar chart
                # Create scatter plot timeline
                x_data = []
                y_data = []
                colors_data = []
                text_data = []
                
                for event in timeline_data:
                    timestamp = event.get('timestamp', '')
                    event_type = event.get('event_type', 'Unknown')
                    severity = event.get('severity', 'low')
                    
                    try:
                        if isinstance(timestamp, str) and timestamp not in ['Unknown', 'N/A']:
                            time_val = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        else:
                            time_val = datetime.now()
                    except:
                        time_val = datetime.now()
                    
                    x_data.append(time_val)
                    y_data.append(event_type)
                    
                    # Color by severity
                    if severity == 'critical':
                        colors_data.append(self.color_schemes['danger'])
                    elif severity == 'high':
                        colors_data.append(self.color_schemes['warning'])
                    elif severity == 'medium':
                        colors_data.append(self.color_schemes['info'])
                    else:
                        colors_data.append(self.color_schemes['success'])
                    
                    text_data.append(event.get('description', ''))
                
                fig = go.Figure(data=go.Scatter(
                    x=x_data,
                    y=y_data,
                    mode='markers',
                    marker=dict(
                        color=colors_data,
                        size=10
                    ),
                    text=text_data,
                    hovertemplate='<b>%{y}</b><br>%{text}<br>Time: %{x}<extra></extra>'
                ))
                
                fig.update_layout(
                    title='Event Timeline Scatter Plot',
                    xaxis_title='Time',
                    yaxis_title='Event Type'
                )
            
            # Save as HTML
            pyo.plot(fig, filename=str(output_path), auto_open=False)
            
            logger.info(f"Timeline chart saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating timeline chart: {e}")
            return output_path
    
    def create_threat_dashboard(self, analysis_results: Dict[str, Any], 
                              output_path: Path) -> Path:
        """
        Create an interactive dashboard summarizing all threat analysis results.
        """
        logger.info(f"Creating threat dashboard: {output_path}")
        
        if not PLOTLY_AVAILABLE:
            logger.error("Plotly required for interactive dashboards")
            return output_path
        
        try:
            # Extract data from analysis results
            behavioral_data = analysis_results.get('behavioral', {})
            network_data = analysis_results.get('network', {})
            memory_data = analysis_results.get('memory', {})
            
            # Get scores
            behavioral_score = behavioral_data.get('score', 0)
            network_score = network_data.get('score', 0)
            memory_score = memory_data.get('score', 0)
            
            # Create subplot layout
            fig = make_subplots(
                rows=3, cols=2,
                subplot_titles=('Threat Score Breakdown', 'Signature Distribution',
                               'IOC Categories', 'Timeline Overview',
                               'Network Activity', 'Process Analysis'),
                specs=[[{"type": "bar"}, {"type": "pie"}],
                       [{"type": "bar"}, {"type": "scatter"}],
                       [{"type": "bar"}, {"type": "bar"}]]
            )
            
            # 1. Threat Score Breakdown
            fig.add_trace(go.Bar(
                x=['Behavioral', 'Network', 'Memory'],
                y=[behavioral_score, network_score, memory_score],
                name='Module Scores',
                marker_color=[self.color_schemes['danger'], self.color_schemes['warning'], self.color_schemes['info']]
            ), row=1, col=1)
            
            # 2. Signature Distribution
            all_signatures = []
            for module_data in [behavioral_data, network_data, memory_data]:
                signatures = module_data.get('signatures', [])
                for sig in signatures:
                    all_signatures.append(sig.get('severity', 'unknown'))
            
            severity_counts = Counter(all_signatures)
            if severity_counts:
                fig.add_trace(go.Pie(
                    labels=list(severity_counts.keys()),
                    values=list(severity_counts.values()),
                    name='Signatures'
                ), row=1, col=2)
            
            # 3. IOC Categories (example data)
            ioc_categories = ['File Hashes', 'Network IPs', 'Domains', 'Registry Keys', 'Process Names']
            ioc_counts = [
                len(behavioral_data.get('file_operations', {}).get('summary', {}).get('files_created', [])),
                len(network_data.get('ip_communications', {})),
                len(network_data.get('dns_queries', [])),
                len(behavioral_data.get('registry_operations', {}).get('RegSetValue', [])),
                len(behavioral_data.get('process_operations', {}).get('processes_created', []))
            ]
            
            fig.add_trace(go.Bar(
                x=ioc_categories,
                y=ioc_counts,
                name='IOCs',
                marker_color=self.color_schemes['accent']
            ), row=2, col=1)
            
            # 4. Timeline Overview (simplified)
            timeline_data = behavioral_data.get('timeline', [])
            if timeline_data:
                event_times = []
                event_types = []
                for event in timeline_data[:20]:
                    event_times.append(len(event_times))  # Simple x-axis
                    event_types.append(event.get('event_type', 'Unknown'))
                
                fig.add_trace(go.Scatter(
                    x=event_times,
                    y=event_types,
                    mode='markers',
                    name='Timeline',
                    marker=dict(color=self.color_schemes['primary'])
                ), row=2, col=2)
            
            # 5. Network Activity
            if network_data.get('summary'):
                net_summary = network_data['summary']
                net_metrics = ['DNS Queries', 'HTTP Requests', 'Suspicious Connections']
                net_values = [
                    net_summary.get('dns_queries_found', 0),
                    net_summary.get('http_requests_found', 0),
                    net_summary.get('suspicious_network_conn_mem', 0)
                ]
                
                fig.add_trace(go.Bar(
                    x=net_metrics,
                    y=net_values,
                    name='Network',
                    marker_color=self.color_schemes['info']
                ), row=3, col=1)
            
            # 6. Process Analysis
            if memory_data.get('summary'):
                mem_summary = memory_data['summary']
                proc_metrics = ['Suspicious Processes', 'Hidden Processes', 'Code Injection']
                proc_values = [
                    mem_summary.get('suspicious_processes_found', 0),
                    mem_summary.get('hidden_processes_found', 0),
                    mem_summary.get('code_injection_found', 0)
                ]
                
                fig.add_trace(go.Bar(
                    x=proc_metrics,
                    y=proc_values,
                    name='Processes',
                    marker_color=self.color_schemes['secondary']
                ), row=3, col=2)
            
            # Update layout
            fig.update_layout(
                title_text="Shikra Threat Analysis Dashboard",
                showlegend=False,
                height=1000
            )
            
            # Save as HTML
            pyo.plot(fig, filename=str(output_path), auto_open=False)
            
            logger.info(f"Threat dashboard saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating threat dashboard: {e}")
            return output_path
    
    def create_behavioral_heatmap(self, behavioral_data: Dict[str, Any], 
                                output_path: Path,
                                activity_type: str = 'file') -> Path:
        """
        Create a heatmap visualization of behavioral activity patterns.
        """
        logger.info(f"Creating behavioral heatmap: {output_path}")
        
        if not MATPLOTLIB_AVAILABLE or not SEABORN_AVAILABLE:
            logger.error("Matplotlib and Seaborn required for heatmaps")
            return output_path
        
        try:
            if activity_type == 'file':
                # File operations heatmap
                file_ops = behavioral_data.get('file_operations', {})
                
                # Create matrix data
                operations = ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile']
                extensions = ['.exe', '.dll', '.txt', '.doc', '.pdf', '.jpg']
                
                # Generate sample data (in real implementation, extract from actual data)
                matrix_data = []
                for ext in extensions:
                    row = []
                    for op in operations:
                        # Count operations for this extension
                        op_list = file_ops.get(op, [])
                        count = sum(1 for item in op_list if str(item.get('path', '')).endswith(ext))
                        row.append(count)
                    matrix_data.append(row)
                
                # Create heatmap
                plt.figure(figsize=(10, 6))
                sns.heatmap(matrix_data, 
                           xticklabels=operations,
                           yticklabels=extensions,
                           annot=True, 
                           cmap='YlOrRd',
                           cbar_kws={'label': 'Operation Count'})
                
                plt.title('File Operations Heatmap by Extension')
                plt.xlabel('Operation Type')
                plt.ylabel('File Extension')
                
            elif activity_type == 'registry':
                # Registry operations heatmap
                reg_ops = behavioral_data.get('registry_operations', {})
                
                # Registry hives and operations
                hives = ['HKLM', 'HKCU', 'HKCR', 'HKU']
                operations = ['RegSetValue', 'RegCreateKey', 'RegDeleteKey', 'RegQueryValue']
                
                matrix_data = []
                for hive in hives:
                    row = []
                    for op in operations:
                        op_list = reg_ops.get(op, [])
                        count = sum(1 for item in op_list if str(item.get('key', '')).startswith(hive))
                        row.append(count)
                    matrix_data.append(row)
                
                plt.figure(figsize=(10, 6))
                sns.heatmap(matrix_data,
                           xticklabels=operations,
                           yticklabels=hives,
                           annot=True,
                           cmap='Blues',
                           cbar_kws={'label': 'Operation Count'})
                
                plt.title('Registry Operations Heatmap by Hive')
                plt.xlabel('Operation Type')
                plt.ylabel('Registry Hive')
                
            else:  # network
                # Network activity heatmap
                plt.figure(figsize=(12, 8))
                
                # Create time-based activity matrix (simplified)
                hours = list(range(24))
                protocols = ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP']
                
                # Generate sample network activity data
                matrix_data = []
                for protocol in protocols:
                    row = [max(0, int(10 * math.sin(h/24 * 2 * math.pi) + 5 + protocol.__hash__() % 3)) for h in hours]
                    matrix_data.append(row)
                
                sns.heatmap(matrix_data,
                           xticklabels=[f"{h:02d}:00" for h in hours],
                           yticklabels=protocols,
                           cmap='Reds',
                           cbar_kws={'label': 'Activity Level'})
                
                plt.title('Network Activity Heatmap by Hour')
                plt.xlabel('Hour of Day')
                plt.ylabel('Protocol')
            
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight',
                       facecolor=self.color_schemes['background'])
            plt.close()
            
            logger.info(f"Behavioral heatmap saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating behavioral heatmap: {e}")
            return output_path
    
    def create_ioc_distribution_chart(self, ioc_data: Dict[str, List[str]], 
                                    output_path: Path) -> Path:
        """
        Create charts showing distribution and categorization of IOCs.
        """
        logger.info(f"Creating IOC distribution chart: {output_path}")
        
        if not PLOTLY_AVAILABLE:
            logger.error("Plotly required for IOC distribution charts")
            return output_path
        
        try:
            # Count IOCs by category
            ioc_counts = {}
            for category, iocs in ioc_data.items():
                if isinstance(iocs, list):
                    ioc_counts[category.replace('_', ' ').title()] = len(iocs)
                else:
                    ioc_counts[category.replace('_', ' ').title()] = 0
            
            if not ioc_counts or sum(ioc_counts.values()) == 0:
                logger.warning("No IOC data to visualize")
                return output_path
            
            # Create subplots for different views
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=('IOC Distribution (Pie)', 'IOC Counts (Bar)',
                               'Top IOCs by Frequency', 'IOC Sources'),
                specs=[[{"type": "pie"}, {"type": "bar"}],
                       [{"type": "bar"}, {"type": "bar"}]]
            )
            
            # 1. Pie chart of IOC distribution
            fig.add_trace(go.Pie(
                labels=list(ioc_counts.keys()),
                values=list(ioc_counts.values()),
                name="IOC Distribution"
            ), row=1, col=1)
            
            # 2. Bar chart of IOC counts
            fig.add_trace(go.Bar(
                x=list(ioc_counts.keys()),
                y=list(ioc_counts.values()),
                name="IOC Counts",
                marker_color=self.color_schemes['primary']
            ), row=1, col=2)
            
            # 3. Top individual IOCs (flatten all IOCs and count)
            all_iocs = []
            for category, iocs in ioc_data.items():
                if isinstance(iocs, list):
                    for ioc in iocs:
                        if isinstance(ioc, dict):
                            indicator = ioc.get('indicator', '')
                        else:
                            indicator = str(ioc)
                        if indicator:
                            all_iocs.append(indicator)
            
            if all_iocs:
                ioc_frequency = Counter(all_iocs).most_common(10)
                if ioc_frequency:
                    fig.add_trace(go.Bar(
                        x=[item[0][:30] + '...' if len(item[0]) > 30 else item[0] for item in ioc_frequency],
                        y=[item[1] for item in ioc_frequency],
                        name="Top IOCs",
                        marker_color=self.color_schemes['accent']
                    ), row=2, col=1)
            
            # 4. IOC sources (if available in data)
            sources = defaultdict(int)
            for category, iocs in ioc_data.items():
                if isinstance(iocs, list):
                    for ioc in iocs:
                        if isinstance(ioc, dict):
                            source = ioc.get('source', 'unknown')
                            sources[source] += 1
            
            if sources:
                fig.add_trace(go.Bar(
                    x=list(sources.keys()),
                    y=list(sources.values()),
                    name="IOC Sources",
                    marker_color=self.color_schemes['info']
                ), row=2, col=2)
            
            # Update layout
            fig.update_layout(
                title_text="IOC Distribution Analysis",
                showlegend=False,
                height=800
            )
            
            # Save as HTML
            pyo.plot(fig, filename=str(output_path), auto_open=False)
            
            logger.info(f"IOC distribution chart saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating IOC distribution chart: {e}")
            return output_path
    
    def create_mitre_attack_matrix(self, technique_data: Dict[str, List[str]], 
                                 output_path: Path) -> Path:
        """
        Create a visual representation of MITRE ATT&CK techniques used.
        """
        logger.info(f"Creating MITRE ATT&CK matrix: {output_path}")
        
        if not PLOTLY_AVAILABLE:
            logger.error("Plotly required for MITRE ATT&CK matrix")
            return output_path
        
        try:
            # MITRE ATT&CK tactics in order
            tactics = [
                'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
                'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                'Collection', 'Command and Control', 'Exfiltration', 'Impact'
            ]
            
            # Process technique data
            techniques_by_tactic = defaultdict(list)
            
            # If technique_data is a list of technique objects
            if isinstance(technique_data, list):
                for technique in technique_data:
                    if isinstance(technique, dict):
                        tactic = technique.get('tactic', 'Unknown')
                        technique_id = technique.get('technique_id', '')
                        technique_name = technique.get('technique_name', '')
                        confidence = technique.get('confidence', 'medium')
                        
                        techniques_by_tactic[tactic].append({
                            'id': technique_id,
                            'name': technique_name,
                            'confidence': confidence
                        })
            elif isinstance(technique_data, dict):
                # If it's a dict mapping tactics to techniques
                for tactic, techniques in technique_data.items():
                    if isinstance(techniques, list):
                        for tech in techniques:
                            techniques_by_tactic[tactic].append({
                                'id': tech if isinstance(tech, str) else str(tech),
                                'name': tech if isinstance(tech, str) else str(tech),
                                'confidence': 'medium'
                            })
            
            if not techniques_by_tactic:
                logger.warning("No MITRE ATT&CK technique data to visualize")
                return output_path
            
            # Create matrix visualization
            fig = go.Figure()
            
            # Create heatmap-style matrix
            matrix_data = []
            matrix_text = []
            matrix_hover = []
            y_labels = []
            
            max_techniques = max(len(techniques) for techniques in techniques_by_tactic.values()) if techniques_by_tactic else 0
            
            for tactic in tactics:
                if tactic in techniques_by_tactic:
                    techniques = techniques_by_tactic[tactic]
                    row_data = []
                    row_text = []
                    row_hover = []
                    
                    for i in range(max_techniques):
                        if i < len(techniques):
                            technique = techniques[i]
                            confidence = technique.get('confidence', 'medium')
                            
                            # Map confidence to numeric value for coloring
                            confidence_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                            conf_value = confidence_map.get(confidence.lower(), 2)
                            
                            row_data.append(conf_value)
                            row_text.append(technique['id'])
                            row_hover.append(f"{technique['name']}<br>ID: {technique['id']}<br>Confidence: {confidence}")
                        else:
                            row_data.append(0)
                            row_text.append('')
                            row_hover.append('')
                    
                    matrix_data.append(row_data)
                    matrix_text.append(row_text)
                    matrix_hover.append(row_hover)
                    y_labels.append(tactic)
            
            # Create heatmap
            fig.add_trace(go.Heatmap(
                z=matrix_data,
                text=matrix_text,
                hovertext=matrix_hover,
                hovertemplate='%{hovertext}<extra></extra>',
                texttemplate='%{text}',
                y=y_labels,
                x=[f'Technique {i+1}' for i in range(max_techniques)],
                colorscale=[[0, 'white'], [0.25, 'lightblue'], [0.5, 'blue'], [0.75, 'darkblue'], [1, 'red']],
                showscale=True,
                colorbar=dict(
                    title="Confidence Level",
                    tickvals=[0, 1, 2, 3, 4],
                    ticktext=['None', 'Low', 'Medium', 'High', 'Critical']
                )
            ))
            
            fig.update_layout(
                title='MITRE ATT&CK Techniques Matrix',
                xaxis_title='Technique Position',
                yaxis_title='Tactic',
                height=600,
                width=1000
            )
            
            # Save as HTML
            pyo.plot(fig, filename=str(output_path), auto_open=False)
            
            logger.info(f"MITRE ATT&CK matrix saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating MITRE ATT&CK matrix: {e}")
            return output_path
    
    def create_statistical_charts(self, analysis_data: Dict[str, Any], 
                                output_path: Path,
                                chart_types: List[str] = None) -> Dict[str, Path]:
        """
        Create various statistical charts and graphs from analysis data.
        """
        logger.info(f"Creating statistical charts: {output_path}")
        
        if not MATPLOTLIB_AVAILABLE or not SEABORN_AVAILABLE:
            logger.error("Matplotlib and Seaborn required for statistical charts")
            return {}
        
        if chart_types is None:
            chart_types = ['histogram', 'correlation', 'boxplot', 'distribution']
        
        generated_charts = {}
        
        try:
            # Extract numerical data for statistics
            behavioral_data = analysis_data.get('behavioral', {})
            network_data = analysis_data.get('network', {})
            memory_data = analysis_data.get('memory', {})
            
            # Collect scores and metrics
            scores = {
                'Behavioral Score': behavioral_data.get('score', 0),
                'Network Score': network_data.get('score', 0),
                'Memory Score': memory_data.get('score', 0)
            }
            
            # File operation counts
            file_ops = behavioral_data.get('file_operations', {})
            file_counts = {}
            for op_type, operations in file_ops.items():
                if isinstance(operations, list):
                    file_counts[op_type] = len(operations)
            
            # Network metrics
            network_metrics = {
                'DNS Queries': len(network_data.get('dns_queries', [])),
                'HTTP Requests': len(network_data.get('http_requests', [])),
                'TLS Connections': len(network_data.get('tls_connections', []))
            }
            
            # 1. Histogram of scores
            if 'histogram' in chart_types:
                plt.figure(figsize=(10, 6))
                score_values = list(scores.values())
                plt.hist(score_values, bins=10, alpha=0.7, color=self.color_schemes['primary'])
                plt.title('Distribution of Analysis Scores')
                plt.xlabel('Score')
                plt.ylabel('Frequency')
                
                hist_path = output_path.parent / f"{output_path.stem}_histogram.png"
                plt.savefig(hist_path, dpi=300, bbox_inches='tight')
                plt.close()
                generated_charts['histogram'] = hist_path
            
            # 2. Correlation matrix
            if 'correlation' in chart_types and PANDAS_AVAILABLE:
                # Create correlation data
                correlation_data = {**scores, **network_metrics}
                if len(correlation_data) > 1:
                    df = pd.DataFrame([correlation_data])
                    correlation_matrix = df.corr()
                    
                    plt.figure(figsize=(10, 8))
                    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0)
                    plt.title('Correlation Matrix of Analysis Metrics')
                    
                    corr_path = output_path.parent / f"{output_path.stem}_correlation.png"
                    plt.savefig(corr_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    generated_charts['correlation'] = corr_path
            
            # 3. Box plot of different metrics
            if 'boxplot' in chart_types:
                all_metrics = {**scores, **file_counts, **network_metrics}
                if all_metrics:
                    plt.figure(figsize=(12, 6))
                    
                    # Prepare data for box plot
                    categories = list(all_metrics.keys())
                    values = list(all_metrics.values())
                    
                    # Create multiple box plots
                    plt.boxplot([values], labels=['All Metrics'])
                    plt.title('Distribution of Analysis Metrics')
                    plt.ylabel('Value')
                    plt.xticks(rotation=45, ha='right')
                    
                    box_path = output_path.parent / f"{output_path.stem}_boxplot.png"
                    plt.savefig(box_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    generated_charts['boxplot'] = box_path
            
            # 4. Distribution plots
            if 'distribution' in chart_types:
                fig, axes = plt.subplots(2, 2, figsize=(15, 10))
                fig.suptitle('Analysis Data Distributions')
                
                # Score distribution
                if scores:
                    axes[0, 0].bar(scores.keys(), scores.values(), color=self.color_schemes['primary'])
                    axes[0, 0].set_title('Analysis Scores')
                    axes[0, 0].tick_params(axis='x', rotation=45)
                
                # File operations distribution
                if file_counts:
                    axes[0, 1].bar(file_counts.keys(), file_counts.values(), color=self.color_schemes['accent'])
                    axes[0, 1].set_title('File Operations')
                    axes[0, 1].tick_params(axis='x', rotation=45)
                
                # Network metrics distribution
                if network_metrics:
                    axes[1, 0].bar(network_metrics.keys(), network_metrics.values(), color=self.color_schemes['info'])
                    axes[1, 0].set_title('Network Metrics')
                    axes[1, 0].tick_params(axis='x', rotation=45)
                
                # Severity distribution (from signatures)
                all_signatures = []
                for module_data in [behavioral_data, network_data, memory_data]:
                    signatures = module_data.get('signatures', [])
                    for sig in signatures:
                        all_signatures.append(sig.get('severity', 'unknown'))
                
                if all_signatures:
                    severity_counts = Counter(all_signatures)
                    axes[1, 1].bar(severity_counts.keys(), severity_counts.values(), color=self.color_schemes['warning'])
                    axes[1, 1].set_title('Signature Severity Distribution')
                
                plt.tight_layout()
                dist_path = output_path.parent / f"{output_path.stem}_distributions.png"
                plt.savefig(dist_path, dpi=300, bbox_inches='tight')
                plt.close()
                generated_charts['distribution'] = dist_path
            
            logger.info(f"Generated {len(generated_charts)} statistical charts")
            return generated_charts
            
        except Exception as e:
            logger.error(f"Error creating statistical charts: {e}")
            return generated_charts
    
    def create_interactive_report_widgets(self, report_data: Dict[str, Any], 
                                        output_directory: Path) -> Dict[str, Path]:
        """
        Create interactive widgets for web-based report consumption.
        """
        logger.info(f"Creating interactive report widgets: {output_directory}")
        
        if not PLOTLY_AVAILABLE:
            logger.error("Plotly required for interactive widgets")
            return {}
        
        try:
            output_directory.mkdir(parents=True, exist_ok=True)
            generated_widgets = {}
            
            # 1. Interactive IOC Table
            iocs = report_data.get('iocs', {})
            if iocs:
                # Flatten IOCs for table
                table_data = []
                for category, ioc_list in iocs.items():
                    if isinstance(ioc_list, list):
                        for ioc in ioc_list:
                            if isinstance(ioc, dict):
                                table_data.append({
                                    'Category': category.replace('_', ' ').title(),
                                    'Indicator': ioc.get('indicator', ''),
                                    'Context': ioc.get('context', ''),
                                    'Source': ioc.get('source', 'unknown')
                                })
                
                if table_data:
                    fig = go.Figure(data=[go.Table(
                        header=dict(values=list(table_data[0].keys()),
                                   fill_color='paleturquoise',
                                   align='left'),
                        cells=dict(values=[[row[col] for row in table_data] for col in table_data[0].keys()],
                                  fill_color='lavender',
                                  align='left'))
                    ])
                    
                    fig.update_layout(title="Interactive IOC Table")
                    
                    ioc_table_path = output_directory / "ioc_table.html"
                    pyo.plot(fig, filename=str(ioc_table_path), auto_open=False)
                    generated_widgets['ioc_table'] = ioc_table_path
            
            # 2. Interactive Timeline
            timeline = report_data.get('timeline', [])
            if timeline:
                fig = go.Figure()
                
                for i, event in enumerate(timeline):
                    fig.add_trace(go.Scatter(
                        x=[i],
                        y=[event.get('event_type', 'Unknown')],
                        mode='markers',
                        marker=dict(
                            size=15,
                            color=event.get('severity', 'low'),
                            colorscale='Viridis'
                        ),
                        text=event.get('description', ''),
                        hovertemplate='<b>%{y}</b><br>%{text}<br>Time: %{customdata}<extra></extra>',
                        customdata=[event.get('timestamp', 'Unknown')],
                        name=f"Event {i+1}"
                    ))
                
                fig.update_layout(
                    title="Interactive Timeline",
                    xaxis_title="Event Sequence",
                    yaxis_title="Event Type",
                    showlegend=False
                )
                
                timeline_path = output_directory / "interactive_timeline.html"
                pyo.plot(fig, filename=str(timeline_path), auto_open=False)
                generated_widgets['timeline'] = timeline_path
            
            # 3. Interactive Threat Score Gauge
            threat_assessment = report_data.get('threat_assessment', {})
            overall_score = threat_assessment.get('overall_score', 0)
            
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=overall_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Threat Score"},
                delta={'reference': 50},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 25], 'color': "lightgray"},
                        {'range': [25, 50], 'color': "yellow"},
                        {'range': [50, 75], 'color': "orange"},
                        {'range': [75, 100], 'color': "red"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            
            gauge_path = output_directory / "threat_gauge.html"
            pyo.plot(fig, filename=str(gauge_path), auto_open=False)
            generated_widgets['threat_gauge'] = gauge_path
            
            logger.info(f"Generated {len(generated_widgets)} interactive widgets")
            return generated_widgets
            
        except Exception as e:
            logger.error(f"Error creating interactive widgets: {e}")
            return {}
    
    def create_comparison_visualizations(self, comparison_data: List[Dict[str, Any]], 
                                       output_path: Path) -> Path:
        """
        Create visualizations comparing multiple samples or analysis runs.
        """
        logger.info(f"Creating comparison visualizations: {output_path}")
        
        if not PLOTLY_AVAILABLE:
            logger.error("Plotly required for comparison visualizations")
            return output_path
        
        try:
            if len(comparison_data) < 2:
                logger.warning("Need at least 2 samples for comparison")
                return output_path
            
            # Extract comparison metrics
            sample_names = []
            behavioral_scores = []
            network_scores = []
            memory_scores = []
            
            for i, sample in enumerate(comparison_data):
                sample_names.append(sample.get('sample_id', f'Sample {i+1}'))
                behavioral_scores.append(sample.get('behavioral', {}).get('score', 0))
                network_scores.append(sample.get('network', {}).get('score', 0))
                memory_scores.append(sample.get('memory', {}).get('score', 0))
            
            # Create comparison chart
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                name='Behavioral',
                x=sample_names,
                y=behavioral_scores,
                marker_color=self.color_schemes['primary']
            ))
            
            fig.add_trace(go.Bar(
                name='Network',
                x=sample_names,
                y=network_scores,
                marker_color=self.color_schemes['secondary']
            ))
            
            fig.add_trace(go.Bar(
                name='Memory',
                x=sample_names,
                y=memory_scores,
                marker_color=self.color_schemes['accent']
            ))
            
            fig.update_layout(
                title='Sample Comparison - Analysis Scores',
                xaxis_title='Samples',
                yaxis_title='Score',
                barmode='group'
            )
            
            # Save as HTML
            pyo.plot(fig, filename=str(output_path), auto_open=False)
            
            logger.info(f"Comparison visualization saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error creating comparison visualization: {e}")
            return output_path
    
    def export_visualization_data(self, visualization_data: Dict[str, Any], 
                                output_path: Path,
                                export_format: str = 'json') -> Path:
        """
        Export visualization data in machine-readable formats.
        """
        logger.info(f"Exporting visualization data: {output_path}")
        
        try:
            if export_format.lower() == 'json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(visualization_data, f, indent=2, default=str, ensure_ascii=False)
            
            elif export_format.lower() == 'csv' and PANDAS_AVAILABLE:
                # Flatten data for CSV export
                flattened_data = self._flatten_dict(visualization_data)
                df = pd.DataFrame([flattened_data])
                df.to_csv(output_path, index=False)
            
            elif export_format.lower() == 'xml':
                # Simple XML export
                xml_content = self._dict_to_xml(visualization_data, 'visualization_data')
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                    f.write(xml_content)
            
            else:
                logger.error(f"Unsupported export format: {export_format}")
                return output_path
            
            logger.info(f"Visualization data exported: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting visualization data: {e}")
            return output_path
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
        """Flatten nested dictionary for CSV export."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _dict_to_xml(self, d: Dict[str, Any], root_name: str = 'root') -> str:
        """Convert dictionary to XML string."""
        def _to_xml(obj, name):
            if isinstance(obj, dict):
                xml = f"<{name}>"
                for k, v in obj.items():
                    xml += _to_xml(v, k)
                xml += f"</{name}>"
                return xml
            elif isinstance(obj, list):
                xml = f"<{name}>"
                for item in obj:
                    xml += _to_xml(item, 'item')
                xml += f"</{name}>"
                return xml
            else:
                return f"<{name}>{str(obj)}</{name}>"
        
        return _to_xml(d, root_name)
    
    def generate_all_visualizations(self, analysis_results: Dict[str, Any], 
                                   base_filename: str = "analysis") -> Dict[str, Path]:
        """
        Generate all available visualizations for the analysis results.
        
        Args:
            analysis_results: Complete analysis results from all modules
            base_filename: Base filename for generated visualizations
            
        Returns:
            Dict mapping visualization types to generated file paths
        """
        logger.info("Generating all visualizations")
        
        generated_files = {}
        
        try:
            # 1. Network diagram
            if analysis_results.get('network'):
                network_path = self.output_directory / f"{base_filename}_network_diagram.png"
                if self.create_network_diagram(analysis_results['network'], network_path):
                    generated_files['network_diagram'] = network_path
            
            # 2. Process tree
            if analysis_results.get('behavioral'):
                process_path = self.output_directory / f"{base_filename}_process_tree.png"
                if self.create_process_tree(analysis_results['behavioral'], process_path):
                    generated_files['process_tree'] = process_path
            
            # 3. Timeline chart
            timeline_data = []
            for module_name, module_data in analysis_results.items():
                if isinstance(module_data, dict) and module_data.get('timeline'):
                    timeline_data.extend(module_data['timeline'])
            
            if timeline_data:
                timeline_path = self.output_directory / f"{base_filename}_timeline.html"
                if self.create_timeline_chart(timeline_data, timeline_path):
                    generated_files['timeline'] = timeline_path
            
            # 4. Threat dashboard
            dashboard_path = self.output_directory / f"{base_filename}_dashboard.html"
            if self.create_threat_dashboard(analysis_results, dashboard_path):
                generated_files['dashboard'] = dashboard_path
            
            # 5. Behavioral heatmaps
            if analysis_results.get('behavioral'):
                for activity_type in ['file', 'registry', 'network']:
                    heatmap_path = self.output_directory / f"{base_filename}_heatmap_{activity_type}.png"
                    if self.create_behavioral_heatmap(analysis_results['behavioral'], heatmap_path, activity_type):
                        generated_files[f'heatmap_{activity_type}'] = heatmap_path
            
            # 6. Statistical charts
            stats_base_path = self.output_directory / f"{base_filename}_statistics"
            stats_charts = self.create_statistical_charts(analysis_results, stats_base_path)
            generated_files.update(stats_charts)
            
            logger.info(f"Generated {len(generated_files)} visualizations")
            return generated_files
            
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")
            return generated_files