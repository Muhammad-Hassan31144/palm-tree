# Shikra VM Controller Integration

A comprehensive VM management system for malware analysis, providing unified interfaces for snapshot management, file operations, command execution, and stealth configuration across multiple hypervisors.

## Overview

The VM Controller integration combines several modules to provide a complete solution for automated malware analysis in virtual machines:

- **Snapshot Management**: Create, restore, delete, and manage VM snapshots
- **File Operations**: Copy files and directories to/from VMs  
- **Command Execution**: Execute commands and scripts in VMs remotely
- **Stealth Configuration**: Anti-detection features for evasive malware
- **Workflow Automation**: Complete analysis pipelines with cleanup

## Architecture

```
shikra/modules/vm_controller/
├── __init__.py              # Main integration module
├── snapshot.py              # Enhanced snapshot management
├── run_in_vm.py            # Command execution (WinRM/SSH)
├── copy_to_vm.py           # File upload operations
├── copy_from_vm.py         # File download operations
├── stealth.py              # Anti-detection features
└── examples/
    └── vm_controller_example.py  # Comprehensive usage examples
```

## Features

### 🔄 Snapshot Management
- **Multi-hypervisor support**: QEMU/KVM (libvirt), VirtualBox, VMware
- **Advanced operations**: Live snapshots, memory inclusion, metadata tracking
- **Automatic pruning**: Keep recent snapshots, clean up old ones
- **Integrity validation**: Verify snapshot health and consistency
- **Workflow integration**: Automatic pre/post-analysis snapshots

### 📁 File Operations  
- **Cross-platform**: Windows (WinRM) and Linux (SSH/SFTP)
- **Flexible transfers**: Single files or entire directories
- **Automatic pathing**: OS-appropriate path handling
- **Error handling**: Robust error detection and reporting
- **Large file support**: Efficient transfer of analysis tools and samples

### ⚡ Command Execution
- **Protocol support**: WinRM for Windows, SSH for Linux
- **Script execution**: PowerShell scripts, shell commands
- **Timeout management**: Configurable execution timeouts  
- **Output capture**: Full stdout/stderr capture
- **Authentication**: Password and key-based authentication

### 🥷 Stealth Features
- **Hardware spoofing**: SMBIOS information modification
- **CPU features**: Hide hypervisor flags and features
- **MAC randomization**: Generate random network addresses
- **QEMU arguments**: Complete anti-detection argument generation
- **Profile-based**: Configurable stealth profiles per VM

### 🔧 Workflow Automation
- **Complete pipelines**: End-to-end analysis automation
- **Environment preparation**: Tool deployment and configuration
- **Artifact collection**: Automatic log and output gathering
- **Cleanup management**: Automatic snapshot and file cleanup
- **Operation tracking**: Complete audit trail of all operations

## Quick Start

### 1. Installation

```bash
# Install required dependencies
pip install paramiko winrm pywinrm requests-kerberos

# For libvirt support (optional)
pip install libvirt-python

# Clone or install Shikra
git clone <shikra-repo>
cd shikra
```

### 2. Configuration

Create a configuration file `vm_config.json`:

```json
{
  "vms": {
    "windows_analysis": {
      "name": "WindowsAnalysisVM",
      "ip": "192.168.122.100", 
      "guest_os_type": "windows",
      "user": "Analyst",
      "password": "AnalysisPass123!",
      "stealth_profile": {
        "hide_hypervisor_flag": true,
        "smbios": {
          "enable_spoofing": true,
          "system_manufacturer": "Dell Inc.",
          "system_product_name": "OptiPlex 7050",
          "system_version": "1.0.0",
          "system_serial_number": "AUTO_GENERATE",
          "bios_vendor": "Dell Inc.",
          "bios_version": "2.18.0",
          "bios_release_date": "07/14/2022"
        },
        "custom_acpi_tables": [],
        "use_localtime_rtc": true,
        "disable_hpet": false,
        "machine_type": "q35"
      }
    }
  }
}
```

### Analysis Tools Configuration

```json
{
  "analysis_tools": {
    "windows": [
      {
        "name": "Process Monitor",
        "local_path": "/opt/tools/procmon.exe",
        "remote_path": "C:\\Tools\\procmon.exe"
      },
      {
        "name": "Sysinternals Suite", 
        "local_path": "/opt/tools/sysinternals/",
        "remote_path": "C:\\Tools\\Sysinternals\\",
        "is_directory": true
      }
    ],
    "linux": [
      {
        "name": "strace",
        "local_path": "/usr/bin/strace", 
        "remote_path": "/tmp/tools/strace"
      }
    ]
  },
  "collection_paths": {
    "windows": [
      "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
      "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
      "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
      "C:\\Users\\*\\AppData\\Local\\Temp\\*",
      "C:\\Temp\\*"
    ],
    "linux": [
      "/var/log/syslog",
      "/var/log/auth.log", 
      "/tmp/*.log",
      "/var/tmp/*"
    ]
  }
}
```

## Prerequisites

### System Requirements

- **Python 3.8+** with required packages
- **Hypervisor access**: QEMU/KVM, VirtualBox, or VMware
- **Network connectivity** to VMs
- **Storage space** for snapshots and artifacts

### VM Requirements

#### Windows VMs
- **WinRM enabled** and configured:
  ```powershell
  # Run as Administrator
  Enable-PSRemoting -Force
  winrm quickconfig -q
  winrm set winrm/config/service/auth '@{Basic="true"}'
  winrm set winrm/config/service '@{AllowUnencrypted="true"}'
  ```
- **User account** with administrative privileges
- **Firewall rules** allowing WinRM (ports 5985/5986)

#### Linux VMs  
- **SSH server** running and accessible
- **User account** with sudo privileges (if needed)
- **SSH key** or password authentication configured

### Hypervisor Setup

#### QEMU/KVM with libvirt
```bash
# Install libvirt tools
sudo apt-get install qemu-kvm libvirt-daemon-system libvirt-clients
sudo usermod -aG libvirt $USER

# Install Python bindings
pip install libvirt-python

# Verify installation
virsh list --all
```

#### VirtualBox
```bash
# Install VirtualBox
sudo apt-get install virtualbox

# Verify VBoxManage access
VBoxManage list vms
```

## Error Handling

The VM Controller provides comprehensive error handling and logging:

### Common Issues

1. **Connection Failures**
   ```python
   # Check VM connectivity
   status = controller.get_vm_status()
   if status['current_state'] == 'unknown':
       print("VM connection failed - check IP/credentials")
   ```

2. **Snapshot Failures**
   ```python
   # Validate snapshot integrity
   if controller.snapshot_manager:
       validation = controller.snapshot_manager.validate_snapshot_integrity()
       if validation['overall_status'] != 'healthy':
           print(f"Snapshot issues: {validation['issues_found']}")
   ```

3. **File Transfer Failures** 
   ```python
   # Check operation history for file transfer errors
   history = controller.get_operation_history("copy_to_vm")
   failed_ops = [op for op in history if not op['success']]
   for op in failed_ops:
       print(f"Failed transfer: {op['details']}")
       print(f"Errors: {op['errors']}")
   ```

### Logging Configuration

```python
import logging

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vm_controller.log'),
        logging.StreamHandler()
    ]
)

# Module-specific logging
logging.getLogger('shikra.modules.vm_controller').setLevel(logging.INFO)
logging.getLogger('paramiko').setLevel(logging.WARNING)
```

## Performance Optimization

### Snapshot Management
- **Use external snapshots** for large VMs to improve performance
- **Prune regularly** to avoid excessive disk usage
- **Avoid deep snapshot chains** (max 5-10 levels)

### File Operations
- **Batch transfers** when possible to reduce overhead
- **Use compression** for large file transfers
- **Limit concurrent operations** to avoid resource exhaustion

### Network Optimization
- **Use persistent connections** where possible
- **Configure appropriate timeouts** based on network conditions
- **Monitor bandwidth usage** during large transfers

## Security Considerations

### Network Security
- **Use SSH keys** instead of passwords when possible
- **Restrict VM network access** to analysis networks only
- **Enable WinRM over HTTPS** in production environments

### VM Isolation
- **Isolated networks** for malware analysis VMs
- **Snapshot-based isolation** to prevent persistent infections
- **Regular baseline updates** with clean system images

### Credential Management
- **Store credentials securely** (not in plain text)
- **Use dedicated analysis accounts** with minimal privileges
- **Rotate credentials regularly**

## Integration Examples

### With Cuckoo Sandbox
```python
def integrate_with_cuckoo(sample_path, vm_id, config):
    """Integration example with Cuckoo Sandbox"""
    
    with VMController(vm_id, config) as controller:
        # Prepare VM with Cuckoo agent
        prep_commands = [
            "mkdir C:\\cuckoo",
            "copy C:\\agent.py C:\\cuckoo\\agent.py"
        ]
        
        controller.prepare_analysis_environment(setup_commands=prep_commands)
        
        # Create pre-analysis snapshot
        controller.create_snapshot("cuckoo_ready", "Ready for Cuckoo analysis")
        
        # Execute sample with Cuckoo monitoring
        analysis_results = controller.execute_malware_analysis(
            malware_sample_path=sample_path,
            analysis_duration=300,
            collect_artifacts=[
                "C:\\cuckoo\\analysis.json",
                "C:\\cuckoo\\memory.dmp"
            ]
        )
        
        return analysis_results
```

### With MISP Integration
```python
def misp_enhanced_analysis(sample_path, misp_event_id, vm_id, config):
    """Enhanced analysis with MISP context"""
    
    # Get MISP context (pseudo-code)
    misp_context = get_misp_event_context(misp_event_id)
    
    # Prepare analysis with MISP IOCs
    analysis_commands = []
    for ioc in misp_context.get('iocs', []):
        if ioc['type'] == 'domain':
            analysis_commands.append(f"echo {ioc['value']} >> C:\\analysis\\iocs.txt")
    
    with VMController(vm_id, config) as controller:
        # Enhanced preparation with MISP context
        controller.prepare_analysis_environment(
            setup_commands=analysis_commands,
            tools_to_copy=[
                {"local_path": "/tools/misp_analyzer.py", "remote_path": "C:\\Tools\\misp_analyzer.py"}
            ]
        )
        
        # Execute analysis
        results = controller.execute_malware_analysis(
            malware_sample_path=sample_path,
            analysis_duration=600,
            collect_artifacts=[
                "C:\\analysis\\iocs.txt",
                "C:\\analysis\\misp_results.json"
            ]
        )
        
        # Update MISP with results (pseudo-code)
        update_misp_event(misp_event_id, results)
        
        return results
```

## Testing

### Unit Tests
```bash
# Run unit tests
python -m pytest tests/vm_controller/

# Run with coverage
python -m pytest --cov=shikra.modules.vm_controller tests/
```

### Integration Tests
```bash
# Test with real VMs (requires configuration)
python -m pytest tests/integration/ --vm-config test_config.json
```

### Example Test Configuration
```python
# tests/conftest.py
import pytest

@pytest.fixture
def test_vm_config():
    return {
        "vms": {
            "test_vm": {
                "name": "TestVM",
                "ip": "192.168.122.200",
                "guest_os_type": "windows",
                "user": "testuser",
                "password": "testpass"
            }
        }
    }

@pytest.fixture  
def dummy_malware_sample(tmp_path):
    sample_path = tmp_path / "dummy_sample.exe"
    sample_path.write_text("Dummy malware content")
    return str(sample_path)
```

## Troubleshooting

### Common Problems and Solutions

#### 1. WinRM Connection Issues
**Problem**: Cannot connect to Windows VM via WinRM

**Solutions**:
```bash
# Check WinRM service status
sc query winrm

# Test WinRM connectivity  
winrs -r:http://VM_IP:5985 -u:username -p:password cmd

# Enable WinRM logging
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true
```

#### 2. SSH Connection Timeouts
**Problem**: SSH connections timing out or failing

**Solutions**:
```python
# Increase timeout values
controller.execute_command("long_command", timeout_sec=1800)

# Test SSH connectivity
ssh -v user@vm_ip

# Check SSH configuration
cat /etc/ssh/sshd_config | grep -E "MaxSessions|MaxStartups"
```

#### 3. Snapshot Corruption
**Problem**: Snapshots failing to create or restore

**Solutions**:
```python
# Validate snapshot integrity
validation = manager.validate_snapshot_integrity()
print(validation)

# Clean up corrupted snapshots
manager.prune_snapshots(keep_count=1)

# Check disk space
df -h /var/lib/libvirt/images/
```

#### 4. File Transfer Failures  
**Problem**: Large files failing to transfer

**Solutions**:
```python
# Increase timeout for large files
controller.copy_file_to_vm(large_file, remote_path, timeout_sec=3600)

# Split large files
split -b 100M large_file chunk_

# Verify file integrity after transfer
controller.execute_command(f"certutil -hashfile {remote_path} SHA256")
```

### Debug Mode

Enable comprehensive debugging:

```python
import logging

# Enable debug logging for all VM controller components
loggers = [
    'shikra.modules.vm_controller',
    'shikra.modules.vm_controller.snapshot', 
    'shikra.modules.vm_controller.run_in_vm',
    'shikra.modules.vm_controller.copy_to_vm',
    'shikra.modules.vm_controller.copy_from_vm'
]

for logger_name in loggers:
    logging.getLogger(logger_name).setLevel(logging.DEBUG)

# Trace all operations
with VMController(vm_id, config) as controller:
    # All operations will be logged in detail
    controller.execute_command("debug_command")
    
    # Check operation history for debugging
    history = controller.get_operation_history()
    for op in history:
        if not op['success']:
            print(f"Failed operation: {op}")
```

## Contributing

### Development Setup
```bash
# Clone repository
git clone <shikra-repo>
cd shikra

# Create development environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e .[dev]
pip install pytest pytest-cov black flake8
```

### Code Style
```bash
# Format code
black shikra/modules/vm_controller/

# Check style
flake8 shikra/modules/vm_controller/

# Type checking
mypy shikra/modules/vm_controller/
```

### Testing Guidelines
- Write unit tests for all new functionality
- Include integration tests for VM operations
- Test with multiple hypervisors when possible
- Document any test VM requirements

## License

This project is part of the Shikra malware analysis framework. Please refer to the main project license for usage terms.

## Support

For issues, questions, or contributions:

1. **Check the documentation** and examples first
2. **Search existing issues** in the project repository  
3. **Create detailed bug reports** with configuration and logs
4. **Contribute improvements** via pull requests

## Changelog

### Version 2.0.0
- Complete rewrite with enhanced integration
- Multi-hypervisor support added
- Advanced stealth features implemented
- Comprehensive workflow automation
- Improved error handling and logging

### Version 1.0.0  
- Initial release with basic VM operations
- QEMU/KVM support only
- Basic snapshot management
- Simple file operations

---

**Note**: This integration represents a significant enhancement over the original individual modules, providing a unified and more powerful interface for VM-based malware analysis workflows.
          "system_product_name": "OptiPlex 7050"
        }
      }
    },
    "linux_analysis": {
      "name": "LinuxAnalysisVM", 
      "ip": "192.168.122.101",
      "guest_os_type": "linux",
      "user": "analyst",
      "password": "linuxpass",
      "ssh_key_path": "/path/to/key.pem"
    }
  },
  "snapshot_metadata_dir": "/tmp/shikra_snapshots"
}
```

### 3. Basic Usage

```python
from shikra.modules.vm_controller import VMController

# Initialize controller
with VMController("windows_analysis", config) as controller:
    # Check VM status
    status = controller.get_vm_status()
    print(f"VM State: {status['current_state']}")
    
    # Execute command
    stdout, stderr, rc = controller.execute_command("whoami")
    
    # Copy file to VM
    controller.copy_file_to_vm("/local/file.txt", "C:\\temp\\file.txt")
    
    # Create snapshot
    controller.create_snapshot("before_analysis", "Clean state snapshot")
    
    # Run analysis...
    
    # Restore to clean state
    controller.restore_snapshot("before_analysis")
```

### 4. Complete Analysis Workflow

```python
from shikra.modules.vm_controller import execute_complete_analysis

# Run complete analysis pipeline
results = execute_complete_analysis(
    vm_identifier="windows_analysis",
    config=config,
    malware_sample_path="/samples/malware.exe",
    analysis_duration=300,
    setup_commands=[
        "mkdir C:\\Analysis",
        "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1"
    ],
    analysis_tools=[
        {"local_path": "/tools/procmon.exe", "remote_path": "C:\\Tools\\procmon.exe"}
    ],
    collect_artifacts=[
        "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
        "C:\\Analysis\\output.txt"
    ]
)

print(f"Analysis Success: {results['overall_success']}")
```

## Detailed Usage

### Snapshot Management

```python
from shikra.modules.vm_controller.snapshot import EnhancedSnapshotManager

with EnhancedSnapshotManager("vm_name", config) as manager:
    # Create snapshot with memory
    manager.create_snapshot(
        snapshot_name="analysis_ready",
        description="VM prepared for analysis", 
        include_memory=True,
        quiesce=True  # Requires guest agent
    )
    
    # List all snapshots
    snapshots = manager.list_snapshots(detailed=True)
    for snap in snapshots:
        print(f"{snap['name']}: {snap['creation_time']}")
    
    # Restore to clean state
    manager.restore_clean_state("clean|baseline")
    
    # Prune old snapshots
    manager.prune_snapshots(keep_count=5, keep_patterns=["baseline", "clean"])
    
    # Validate snapshot integrity
    validation = manager.validate_snapshot_integrity()
    print(f"Snapshot health: {validation['overall_status']}")
```

### Advanced File Operations

```python
# Copy entire directory structure
controller.copy_file_to_vm(
    "/local/tools/",
    "C:\\Analysis\\Tools\\", 
    is_directory=True
)

# Collect multiple artifacts
artifacts = [
    "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    "C:\\Windows\\System32\\winevt\\Logs\\System.evtx", 
    "C:\\Users\\Analyst\\AppData\\Local\\Temp\\*"
]

for artifact in artifacts:
    local_path = f"/analysis/artifacts/{Path(artifact).name}"
    controller.copy_file_from_vm(artifact, local_path)
```

### Stealth Configuration

```python
from shikra.modules.vm_controller.stealth import get_stealth_qemu_args

# Define stealth profile
stealth_profile = {
    "stealth_options": {
        "custom_cpu_model": "Haswell-noTSX",
        "hide_hypervisor_flag": True,
        "smbios": {
            "enable_spoofing": True,
            "system_manufacturer": "LENOVO",
            "system_product_name": "ThinkPad X1 Carbon",
            "bios_vendor": "LENOVO"
        },
        "disable_hpet": True,
        "machine_type": "q35"
    }
}

# Generate QEMU arguments  
qemu_args = get_stealth_qemu_args(stealth_profile)
print("Stealth QEMU Args:", " ".join(qemu_args))

# Use in VM controller
controller = VMController("vm_name", config)
stealth_config = controller.get_stealth_configuration()
```

### Workflow Orchestration

```python
from shikra.modules.vm_controller.snapshot import SnapshotWorkflow

workflow = SnapshotWorkflow("vm_name", config)

# Prepare complete analysis environment
prep_results = workflow.prepare_analysis_environment(
    setup_scripts=[
        "powershell Set-ExecutionPolicy Unrestricted -Force",
        "mkdir C:\\Analysis\\Logs",
        "schtasks /create /tn 'LogCleanup' /tr 'del C:\\*.log' /sc daily"
    ],
    tools_to_copy=[
        {"local_path": "/tools/sysinternals/", "remote_path": "C:\\Tools\\", "is_directory": True},
        {"local_path": "/tools/wireshark.exe", "remote_path": "C:\\Tools\\wireshark.exe"}
    ]
)

# Execute analysis cycle with automatic snapshots
cycle_results = workflow.execute_analysis_cycle(
    malware_sample_path="/samples/ransomware.exe",
    analysis_duration=600,
    collect_artifacts=[
        "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
        "C:\\Analysis\\Logs\\*"
    ]
)

# Cleanup
workflow.cleanup_analysis_artifacts(keep_recent=3)
```

## Configuration Reference

### VM Configuration

```json
{
  "vm_identifier": {
    "name": "VM display name",
    "ip": "VM IP address",
    "guest_os_type": "windows|linux", 
    "user": "username",
    "password": "password",
    "ssh_key_path": "/path/to/ssh/key",
    "stealth_profile": {
      "hide_hypervisor_flag": true,
      "custom_cpu_model": "host|Haswell|etc",
      "cpu_features": ["+feature", "-feature"],
      "smbios": {
        "enable_spoofing": true,
        "system_manufacturer": "Dell Inc.",