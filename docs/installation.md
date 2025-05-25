# 📖 Installation Guide

This guide covers the complete installation and setup of the Shikra malware analysis platform.

## 🔧 System Requirements

### Hardware Requirements
- **CPU**: 4+ cores with virtualization support (VT-x/AMD-V enabled in BIOS)
- **RAM**: 16GB minimum, 32GB recommended for multiple concurrent analyses
- **Storage**: 100GB+ free space (SSD recommended for better VM performance)
- **Network**: Isolated network interface or VLAN for analysis traffic

### Software Requirements
- **Operating System**: Ubuntu 20.04 LTS or newer (tested on 20.04, 22.04)
- **Python**: Version 3.8 or higher with pip
- **Virtualization**: QEMU/KVM (recommended) or VirtualBox
- **Git**: For cloning repositories and version control
- **Network Tools**: tcpdump, tshark, nmap

## 🚀 Installation Steps

### 1. System Preparation
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y git python3 python3-pip python3-venv curl wget

# Verify virtualization support
egrep -c '(vmx|svm)' /proc/cpuinfo
# Should return > 0 if virtualization is supported
```

### 2. Clone Repository
```bash
# Clone the Shikra repository
git clone [https://github.com/your-org/shikra.git](https://github.com/your-org/shikra.git)
cd shikra

# Verify directory structure
ls -la
```

### 3. Run Setup Script
```bash
# Navigate to setup directory
cd setup/scripts

# Make script executable and run (requires sudo)
chmod +x setup_environment.sh
sudo ./setup_environment.sh

# The script will:
# - Install QEMU/KVM or VirtualBox
# - Configure virtualization permissions
# - Create Python virtual environment
# - Set up network bridges
# - Create data directories
```

### 4. Install Dependencies
```bash
# Install additional analysis tools
./install_dependencies.sh

# This installs:
# - Volatility (memory analysis)
# - YARA (malware signatures)  
# - Network analysis tools
# - Monitoring utilities
```

### 5. Activate Virtual Environment
```bash
# Navigate to project root
cd ../../

# Activate Python virtual environment
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt

# Verify installation
python -c "import volatility3; print('Volatility OK')"
```

### 6. Create Analysis VM
```bash
# Navigate to core scripts
cd core/scripts

# Create Windows 10 analysis VM (requires Windows ISO)
./create_vm.sh \
    --name win10_analysis \
    --profile default \
    --os-iso /path/to/Windows10.iso \
    --memory 4096 \
    --disk 60G

# This process takes 30-60 minutes and will:
# - Create VM with specified resources
# - Install Windows from ISO
# - Install analysis tools (Procmon, Python, etc.)
# - Configure stealth settings
# - Create clean snapshot
```

## ✅ Post-Installation Verification

### 1. Verify VM Creation
```bash
# List created VMs
virsh list --all

# Check VM status  
virsh dominfo win10_analysis
```

### 2. Test Network Isolation
```bash
# Configure isolated network
./network_setup.sh --mode isolated --interface virbr1

# Verify isolation (should show no internet access from VM)
# Start VM and test connectivity
```

### 3. Run Test Analysis
```bash
# Create a harmless test file
echo "Test sample" > ../../data/samples/test.txt

# Run basic analysis
./run_analysis.sh \
    --sample ../../data/samples/test.txt \
    --vm win10_analysis \
    --timeout 60

# Check results
ls ../../data/results/
```

### 4. Start Web Interface
```bash
# Navigate to web interface
cd ../../reporting/web

# Start development server
python app.py

# Access interface at http://localhost:5000
```

## 🔧 Configuration

### VM Profiles
Edit VM profiles in `config/vm_profiles/`:
- `default.json` - Standard analysis VM
- `evasive_malware.json` - VM with anti-analysis evasion

### Monitoring Tools
Configure monitoring in `config/noriben/`:
- `whitelist.txt` - Processes to ignore
- `blacklist.txt` - Processes to highlight
- `Noriben.py` - Main monitoring script

### Network Settings
Configure network simulation in `config/inetsim/`:
- `inetsim.conf` - Service simulation settings

## 🐛 Troubleshooting

### Common Issues

**1. Virtualization Not Enabled**
```bash
# Check if KVM is loaded
lsmod | grep kvm

# If not loaded, enable in BIOS/UEFI settings
# Look for: Intel VT-x, AMD SVM, Virtualization Technology
```

**2. Permission Denied Errors**
```bash
# Add user to required groups
sudo usermod -aG libvirt,kvm $USER

# Log out and log back in for changes to take effect
```

**3. VM Creation Fails**
```bash
# Check available space
df -h

# Verify ISO file exists and is readable
file /path/to/Windows10.iso

# Check libvirt logs
sudo tail -f /var/log/libvirt/qemu/win10_analysis.log
```

**4. Network Issues**
```bash
# Restart networking
sudo systemctl restart libvirtd

# Check bridge configuration
ip addr show virbr0
```

### Getting Help

- Check log files in project root: `setup.log`, `analysis.log`
- Review VM logs: `/var/log/libvirt/qemu/`
- Verify system resources: `htop`, `df -h`
- Test connectivity: `ping`, `traceroute`

For additional support, please create an issue with:
- Operating system version
- Hardware specifications  
- Error messages and log excerpts
- Steps to reproduce the problem
