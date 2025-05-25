# 🏗️ Architecture Overview

Shikra follows a modular, pipeline-based architecture designed for scalability, maintainability, and security in malware analysis workflows.

## 🎯 Design Principles

### Security First
- **Network Isolation**: All analysis occurs in isolated virtual networks
- **VM Sandboxing**: Malware executes in disposable virtual machines
- **Host Protection**: Analysis environment is separated from host system
- **Data Integrity**: Cryptographic hashing ensures sample integrity

### Modularity
- **Pluggable Components**: Easy to add new analysis modules
- **Tool Integration**: Wraps existing tools (Volatility, Noriben, etc.)
- **API-Driven**: Components communicate via well-defined interfaces
- **Configuration-Based**: Behavior controlled through JSON configs

### Automation
- **Minimal User Input**: Fully automated analysis pipeline
- **Reproducible Results**: Consistent analysis across samples
- **Batch Processing**: Handle multiple samples efficiently
- **Error Recovery**: Graceful handling of failures

## 📦 Core Components

### 1. Setup Module (`setup/`)
**Purpose**: One-time environment preparation and maintenance

**Components**:
- `setup_environment.sh` - Main system configuration script
- `install_dependencies.sh` - Analysis tool installation
- `update_noriben.sh` - Monitoring tool updates

**Responsibilities**:
- Install virtualization software (QEMU/KVM)
- Configure network isolation infrastructure
- Set up Python virtual environment
- Install analysis tools (Volatility, YARA, etc.)
- Create necessary directories and permissions

**Usage Pattern**: Run once during initial installation, occasionally for updates

### 2. Core Module (`core/`)
**Purpose**: Main analysis workflow execution and VM management

**Components**:
- `scripts/` - Shell scripts for workflow orchestration
  - `create_vm.sh` - VM provisioning and configuration
  - `network_setup.sh` - Network environment preparation
  - `run_analysis.sh` - Main analysis coordinator
  - `memory_dump.sh` - Memory acquisition
  - `cleanup.sh` - Environment reset
- `modules/` - Python modules for VM and monitoring control
  - `vm_controller/` - VM lifecycle management
  - `monitor/` - Behavioral monitoring integration
  - `network/` - Traffic capture and simulation

**Responsibilities**:
- Create and manage analysis VMs
- Configure network isolation and simulation
- Orchestrate malware execution and monitoring
- Collect artifacts (memory dumps, network captures)
- Coordinate between different analysis phases

**Usage Pattern**: Used for every malware analysis run

### 3. Analysis Module (`analysis/`)
**Purpose**: Post-execution data processing and intelligence extraction

**Components**:
- `behavioral.py` - Process/file/registry activity analysis
- `network_analysis.py` - Traffic pattern and C2 detection
- `memory_analysis.py` - Memory forensics using Volatility
- `generate_filters.py` - Whitelist/blacklist management

**Responsibilities**:
- Parse monitoring tool outputs (Noriben, Procmon)
- Identify malicious patterns and techniques
- Extract IOCs (IPs, domains, hashes, etc.)
- Correlate behavioral and network activities
- Generate threat scores and classifications

**Data Flow**: Processes artifacts collected by Core module

### 4. Reporting Module (`reporting/`)
**Purpose**: Result presentation and user interface

**Components**:
- `report_generator.py` - Multi-format report creation
- `visualizer.py` - Charts, graphs, and network diagrams
- `web/app.py` - Flask-based web interface

**Responsibilities**:
- Compile analysis results into readable reports
- Generate visualizations (network graphs, timelines)
- Provide web interface for report browsing
- Export data in multiple formats (PDF, HTML, JSON)

**Output**: Human-readable reports and searchable web interface

## 🔄 Data Flow Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│   Sample    │───▶│      Core      │───▶│  Analysis   │───▶│  Reporting   │
│ Input/Queue │     │   Execution    │     │ Processing  │     │ Generation   │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘
        │                  │                  │                  │
        ▼                  ▼                  ▼                  ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│ data/       │     │ VM Execution │     │ Pattern     │     │ Web Interface│
│ samples/    │     │ + Monitoring │     │ Detection   │     │ + Reports    │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘
```

### Detailed Flow

1. **Sample Ingestion**
   - Malware sample placed in `data/samples/`
   - Sample metadata extracted (hashes, file type)
   - Analysis queued with specified VM profile

2. **Environment Preparation** - VM restored from clean snapshot
   - Network isolation configured
   - Monitoring tools initialized

3. **Execution Phase**
   - Sample transferred to VM
   - Behavioral monitoring started (Noriben/Procmon)
   - Network capture initiated (tcpdump)
   - Sample executed with timeout
   - Memory dump collected (optional)

4. **Data Collection**
   - Monitoring logs retrieved from VM
   - Network capture files saved
   - Screenshots captured
   - VM artifacts collected

5. **Analysis Phase**
   - Behavioral data parsed and analyzed
   - Network traffic examined for C2 patterns
   - Memory dump processed (if available)
   - IOCs extracted and correlated

6. **Report Generation**
   - Analysis results compiled
   - Visualizations generated
   - Multi-format reports created
   - Results stored in `data/results/`

## 🔗 Component Interactions

### VM Controller Interface
```python
class VMController:
    def create_vm(self, name, profile)       # VM provisioning
    def restore_snapshot(self, vm, snapshot)  # Clean state reset
    def execute_sample(self, vm, sample_path) # Malware execution
    def collect_artifacts(self, vm, dest_dir) # Data retrieval
```

### Monitor Integration
```python
class MonitorWrapper:
    def start_monitoring(self, vm, config)    # Begin data collection
    def stop_monitoring(self, vm)             # End collection
    def parse_results(self, log_path)         # Extract structured data
```

### Analysis Pipeline
```python
class AnalysisPipeline:
    def analyze_behavioral(self, noriben_data) # Process activity analysis
    def analyze_network(self, pcap_file)       # Traffic analysis  
    def analyze_memory(self, dump_file)        # Memory forensics
    def correlate_findings(self, all_data)     # Cross-reference results
```

## 🔐 Security Architecture

### Network Isolation
- **Analysis VLANs**: Separate network segments for malware execution
- **NAT Isolation**: Outbound traffic filtered and logged
- **DNS Sinkholing**: Malicious domains redirected to controlled servers
- **INetSim Integration**: Fake services for malware interaction

### VM Security
- **Snapshot-Based**: Clean state restoration after each analysis
- **Resource Limits**: CPU/memory quotas prevent resource exhaustion
- **Hypervisor Isolation**: VM escape prevention measures
- **Storage Isolation**: Temporary disk images for analysis

### Host Protection
- **Service Isolation**: Analysis components run with minimal privileges
- **File System Protection**: Samples stored in restricted directories
- **Process Monitoring**: Host-based detection of anomalous activity
- **Log Auditing**: Comprehensive logging of all system interactions

## 📊 Performance Considerations

### Scalability
- **Parallel Execution**: Multiple VMs for concurrent analysis
- **Resource Pooling**: Shared VM images and configurations
- **Queue Management**: Batch processing of sample backlogs
- **Distributed Architecture**: Support for multi-host deployments

### Optimization
- **VM Templates**: Pre-configured base images
- **Incremental Snapshots**: Efficient storage utilization  
- **Caching**: Reuse of analysis results for duplicate samples
- **Streaming Processing**: Real-time analysis of long-running samples

## 🔧 Configuration Management

### VM Profiles (`config/vm_profiles/`)
```json
{
  "name": "windows_10_default",
  "os": "windows_10",
  "memory_mb": 4096,
  "disk_gb": 60,
  "stealth": {
    "enabled": true,
    "hide_vm_artifacts": true,
    "randomize_hardware": true
  },
  "monitoring": {
    "procmon": true,
    "noriben": true,
    "memory_dump": false
  }
}
```

### Analysis Profiles
- Timeout settings per malware family
- Tool selection based on sample type
- Stealth configuration for evasive samples
- Network simulation parameters

This modular architecture ensures Shikra can adapt to new malware families, integrate additional analysis tools, and scale to handle varying workloads while maintaining security and reliability.
