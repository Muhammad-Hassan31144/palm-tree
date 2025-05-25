# 📋 Usage Guide

This comprehensive guide covers common usage patterns, workflows, and advanced features of the Shikra malware analysis platform.

## 🚀 Basic Workflow

### 1. Sample Preparation
```bash
# Navigate to project root
cd /path/to/shikra

# Activate Python virtual environment
source venv/bin/activate

# Place malware sample in samples directory
cp /path/to/suspicious_file.exe data/samples/malware_sample.exe

# Verify sample integrity
sha256sum data/samples/malware_sample.exe
```

### 2. Environment Setup
```bash
# Navigate to core scripts
cd core/scripts

# Configure network for analysis (choose isolation level)
./network_setup.sh --mode isolated --interface virbr1

# Alternative: Use INetSim for service simulation
./network_setup.sh --mode inetsim --interface virbr1
```

### 3. Execute Analysis
```bash
# Basic analysis with default settings
./run_analysis.sh \
    --sample ../../data/samples/malware_sample.exe \
    --vm win10_analysis \
    --timeout 300

# Advanced analysis with custom profile
./run_analysis.sh \
    --sample ../../data/samples/malware_sample.exe \
    --vm win10_analysis \
    --profile evasive_malware \
    --timeout 600 \
    --memory-dump
```

### 4. Review Results
```bash
# Check analysis results directory
ls -la ../../data/results/

# Start web interface for report viewing
cd ../../reporting/web
python app.py

# Access reports at http://localhost:5000
```

## 🔧 Advanced Usage Patterns

### Custom VM Profiles

Create specialized VM configurations for different malware families:

```bash
# Edit VM profile
nano config/vm_profiles/custom_profile.json
```json
{
  "name": "ransomware_analysis",
  "description": "Optimized for ransomware analysis",
  "os": "windows_10",
  "hardware": {
    "memory_mb": 8192,
    "cpu_cores": 4,
    "disk_gb": 100
  },
  "stealth": {
    "enabled": true,
    "hide_vm_artifacts": true,
    "randomize_hardware": true,
    "fake_user_activity": true
  },
  "monitoring": {
    "procmon": true,
    "noriben": true,
    "memory_dump": true,
    "screenshot_interval": 30
  },
  "network": {
    "simulation": "inetsim",
    "capture_traffic": true,
    "dns_redirection": true
  },
  "analysis": {
    "timeout_seconds": 900,
    "file_monitoring": true,
    "registry_monitoring": true,
    "api_hooking": true
  }
}
```

### Batch Analysis

Process multiple samples automatically:

```bash
#!/bin/bash
# batch_analysis.sh

SAMPLES_DIR="../../data/samples"
VM_NAME="win10_analysis"
TIMEOUT=300

for sample in "$SAMPLES_DIR"/*.exe "$SAMPLES_DIR"/*.dll; do
    if [[ -f "$sample" ]]; then
        echo "Analyzing: $(basename "$sample")"
        
        ./run_analysis.sh \
            --sample "$sample" \
            --vm "$VM_NAME" \
            --timeout "$TIMEOUT"
        
        # Wait between analyses to prevent resource conflicts
        sleep 60
    fi
done

echo "Batch analysis completed"
```

### Advanced Network Configuration

#### INetSim Configuration
```bash
# Configure INetSim for comprehensive service simulation
nano config/inetsim/inetsim.conf
```ini
# INetSim Configuration for Malware Analysis
service_bind_address    10.0.2.1
service_max_childs      50
service_timeout         120

# DNS Service
dns_default_ip          10.0.2.1
dns_bind_port           53

# HTTP Service  
http_bind_port          80
http_version            1.1
http_default_page       index.html

# HTTPS Service
https_bind_port         443
https_version           1.1

# FTP Service
ftp_bind_port           21
ftp_version             2.3.4

# SMTP Service
smtp_bind_port          25
smtp_banner             220 mail.company.com ESMTP
```

#### Custom Network Isolation
```bash
# Create dedicated analysis network
./network_setup.sh \
    --mode custom \
    --subnet 192.168.100.0/24 \
    --gateway 192.168.100.1 \
    --dns 192.168.100.1 \
    --firewall-rules analysis_rules.conf
```

### Memory Analysis Integration

#### Automated Memory Dumps
```bash
# Configure automatic memory dump collection
./run_analysis.sh \
    --sample ../../data/samples/advanced_threat.exe \
    --vm win10_analysis \
    --memory-dump \
    --dump-interval 60 \
    --timeout 600
```

#### Manual Memory Analysis
```python
# Use memory analysis module directly
from analysis.modules.analysis.memory_analysis import MemoryAnalyzer # Assuming path

analyzer = MemoryAnalyzer(volatility_path="/usr/local/bin/vol.py")
results = analyzer.analyze_dump(
    dump_path="data/results/sample_123/memory_dump.raw",
    profile="Win10x64_19041"
)

print("Detected processes:", results.get('processes'))
print("Network connections:", results.get('network'))
print("Injected code:", results.get('malfind'))
```

## 🔍 Analysis Customization

### Behavioral Monitoring

#### Custom Noriben Configuration
```bash
# Edit Noriben whitelist to reduce noise
nano config/noriben/whitelist.txt
```text
# Process whitelist - ignore benign system processes
svchost.exe
dwm.exe
explorer.exe
winlogon.exe
csrss.exe

# File path whitelist - ignore system file operations
C:\\Windows\\System32\\
C:\\Windows\\Prefetch\\
C:\\Users\\*\\AppData\\Local\\Temp\\

# Registry whitelist - ignore benign registry operations
HKLM\\SYSTEM\\CurrentControlSet\\Services\\
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\
```

#### Custom Behavioral Rules
```python
# Create custom behavioral detection rules
# analysis/custom_rules/ransomware_detection.py

def detect_ransomware_behavior(events):
    """
    Custom ransomware detection based on behavioral patterns.
    
    Looks for:
    - Mass file encryption patterns
    - Shadow copy deletion
    - Ransom note creation
    """
    indicators = []
    
    # Check for rapid file modifications with extension changes
    file_changes = [e for e in events if e.get('type') == 'file_write']
    encrypted_files = 0
    
    for event in file_changes:
        if event.get('path', '').endswith(('.locked', '.encrypted', '.crypt')):
            encrypted_files += 1
    
    if encrypted_files >= 10:
        indicators.append({
            'type': 'mass_encryption',
            'confidence': 0.9,
            'description': f'Detected {encrypted_files} files with encryption extensions'
        })
    
    return indicators
```

### Network Analysis

#### Custom C2 Detection
```python
# Custom command and control detection
from analysis.modules.analysis.network_analysis import NetworkAnalyzer # Assuming path

def detect_custom_c2(pcap_file):
    """
    Custom C2 detection for specific malware families.
    """
    analyzer = NetworkAnalyzer()
    results = analyzer.analyze_pcap(pcap_file)
    
    # Look for specific patterns
    c2_indicators = []
    
    # Check for beaconing behavior
    connections = results.get('connections', [])
    for conn in connections:
        if conn.get('packet_count', 0) > 10:
            # Analyze timing patterns
            # Implementation specific to malware family
            pass
    
    return c2_indicators
```

## 📊 Reporting and Visualization

### Custom Report Templates

Create custom report templates for specific use cases:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Custom Malware Analysis Report</title>
    <style>
        .threat-high { color: red; font-weight: bold; }
        .threat-medium { color: orange; }
        .threat-low { color: green; }
    </style>
</head>
<body>
    <h1>Analysis Report: {{ data.sample_info.file_name }}</h1>
    
    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <p class="threat-{{ 'high' if data.threat_score > 70 else 'medium' if data.threat_score > 40 else 'low' }}">
            Threat Score: {{ data.threat_score }}/100
        </p>
        <p>{{ data.executive_summary }}</p>
    </div>
    
    <div class="behavioral-findings">
        <h2>Key Behavioral Indicators</h2>
        <ul>
        {% for finding in data.behavioral_results.findings_summary %}
            <li>{{ finding }}</li>
        {% endfor %}
        </ul>
    </div>
    
    <div class="network-analysis">
        <h2>Network Activity</h2>
        <h3>Contacted Domains</h3>
        <ul>
        {% for domain in data.network_results.network_iocs.domains %}
            <li>{{ domain }}</li>
        {% endfor %}
        </ul>
    </div>
</body>
</html>
```

### Generate Custom Visualizations

```python
# Custom visualization script
from reporting.modules.reporting.visualizer import DataVisualizer # Assuming path
from pathlib import Path # Make sure Path is imported

def create_custom_dashboard(analysis_data):
    """
    Create a custom dashboard with specific visualizations.
    """
    visualizer = DataVisualizer()
    
    # Create network communication graph
    network_data = analysis_data.get('network_results', {}).get('graph_data', {})
    visualizer.create_network_graph(
        network_data, 
        Path("custom_reports/network_graph.png"), # Use Path object
        layout_type="kamada_kawai"
    )
    
    # Create process tree
    process_events = analysis_data.get('behavioral_results', {}).get('process_activity', [])
    visualizer.create_process_tree(
        process_events,
        Path("custom_reports/process_tree.png") # Use Path object
    )
    
    # Create timeline
    all_events = combine_all_events(analysis_data)
    visualizer.create_timeline_chart(
        all_events,
        Path("custom_reports/timeline.png") # Use Path object
    )

def combine_all_events(data):
    """Combine events from all analysis modules into chronological order."""
    events = []
    
    # Add behavioral events
    for event in data.get('behavioral_results', {}).get('behavior_timeline', []):
        events.append(event)
    
    # Add network events  
    for event in data.get('network_results', {}).get('dns_queries', []):
        events.append({
            'timestamp': event.get('timestamp', ''),
            'type': 'DNS Query',
            'details': f"Query: {event.get('query', '')}"
        })
    
    return sorted(events, key=lambda x: x.get('timestamp', ''))
```

## 🔧 Command Reference

### Core Analysis Commands

#### VM Management
```bash
# Create new analysis VM
./create_vm.sh --name <vm_name> --profile <profile> [options]

# Available options:
#   --os-iso <path>         Path to OS installation ISO
#   --memory <mb>           Memory allocation in MB
#   --disk <gb>             Disk size in GB
#   --stealth               Enable stealth features
#   --snapshot <name>       Create named snapshot after setup

# List available VMs
virsh list --all

# Manage VM snapshots
virsh snapshot-list <vm_name>
virsh snapshot-revert <vm_name> <snapshot_name>
```

#### Network Configuration
```bash
# Setup isolated network
./network_setup.sh --mode isolated [options]

# Setup with INetSim
./network_setup.sh --mode inetsim --interface <interface>

# Custom network configuration
./network_setup.sh --mode custom --subnet <cidr> --gateway <ip>
```

#### Analysis Execution
```bash
# Basic analysis
./run_analysis.sh --sample <path> --vm <vm_name> [options]

# Available options:
#   --timeout <seconds>     Analysis timeout (default: 300)
#   --profile <profile>     Analysis profile to use
#   --memory-dump           Collect memory dump
#   --screenshots           Take periodic screenshots
#   --network-capture       Capture network traffic
#   --output-dir <path>     Custom output directory
```

### Analysis Module Commands

#### Behavioral Analysis
```python
# Standalone behavioral analysis
from analysis.modules.analysis.behavioral import BehavioralAnalyzer # Assuming path

analyzer = BehavioralAnalyzer(rules_path="config/behavioral_rules/")
results = analyzer.analyze_noriben_report_data(parsed_data)
```

#### Network Analysis
```python
# Standalone network analysis
from analysis.modules.analysis.network_analysis import NetworkAnalyzer # Assuming path

analyzer = NetworkAnalyzer()
results = analyzer.analyze_pcap(Path("data/results/sample_123/traffic.pcap")) # Use Path
```

#### Memory Analysis
```python
# Standalone memory analysis
from analysis.modules.analysis.memory_analysis import MemoryAnalyzer # Assuming path

analyzer = MemoryAnalyzer(volatility_path="/usr/local/bin/vol.py")
results = analyzer.analyze_dump(
    Path("data/results/sample_123/memory.raw"), # Use Path
    profile="Win10x64_19041"
)
```

## 🚨 Best Practices

### Security Guidelines

1. **Network Isolation**
   - Always verify network isolation before analysis
   - Use dedicated network interfaces for analysis traffic
   - Monitor for any signs of network escape
   - Regularly audit firewall rules and network configuration

2. **Sample Handling**
   - Store samples in encrypted containers when possible
   - Use unique identifiers (hashes) for sample tracking
   - Maintain chain of custody documentation
   - Implement access controls for sample repositories

3. **VM Security**
   - Regularly update base VM images with security patches
   - Use random MAC addresses and hardware identifiers
   - Implement VM escape detection mechanisms
   - Rotate VM snapshots to prevent analysis artifacts

### Performance Optimization

1. **Resource Management**
   ```bash
   # Monitor system resources during analysis
   htop -p $(pgrep -f "run_analysis")
   
   # Adjust VM resource allocation based on sample requirements
   virsh setmem <vm_name> 8388608  # 8GB in KB
   virsh setvcpus <vm_name> 4 --live
   ```

2. **Storage Optimization**
   ```bash
   # Use SSD storage for VM images and analysis data
   # Implement regular cleanup of old analysis results
   find data/results/ -type d -mtime +30 -exec rm -rf {} \;
   
   # Compress archived results
   tar -czf archived_results_$(date +%Y%m).tar.gz data/results/
   ```

3. **Concurrent Analysis**
   ```bash
   # Run multiple analyses in parallel (monitor resource usage)
   ./run_analysis.sh --sample sample1.exe --vm vm1 &
   ./run_analysis.sh --sample sample2.exe --vm vm2 &
   wait  # Wait for all background jobs to complete
   ```

### Quality Assurance

1. **Result Validation**
   - Cross-reference findings with multiple analysis tools
   - Validate IOCs against threat intelligence feeds
   - Review automated classifications manually
   - Document false positives and adjust rules accordingly

2. **Regular Maintenance**
   ```bash
   # Update analysis tools monthly
   cd setup/utils
   ./update_noriben.sh
   pip install --upgrade volatility3 yara-python
   
   # Update VM base images quarterly
   # Update signature databases weekly
   ```

3. **Documentation**
   - Document custom configurations and modifications
   - Maintain analysis playbooks for different malware families
   - Keep logs of all analysis activities
   - Create incident response procedures

## 🔍 Troubleshooting Guide

### Common Issues and Solutions

#### Analysis Failures
```bash
# Check VM status
virsh domstate <vm_name>

# Review analysis logs
tail -f data/results/<analysis_id>/analysis.log

# Verify sample accessibility
file data/samples/<sample_name>
sha256sum data/samples/<sample_name>
```

#### Network Issues
```bash
# Test network connectivity
ping -c 1 <vm_ip>

# Check network configuration
ip addr show <bridge_interface>
iptables -L -n

# Restart networking services
sudo systemctl restart libvirtd
```

#### Performance Issues
```bash
# Monitor system resources
iotop -a  # Disk I/O
htop      # CPU/Memory
df -h     # Disk space

# Check VM resource usage
virsh domstats <vm_name>
```

This comprehensive usage guide provides the foundation for effective malware analysis using the Shikra platform. Adapt the examples and configurations to your specific analysis requirements and environment.
