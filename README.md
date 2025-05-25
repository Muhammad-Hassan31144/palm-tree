# Shikra Malware Analysis Platform

Shikra is a comprehensive malware analysis platform that provides automated behavioral analysis, network monitoring, and forensic capabilities in isolated virtual environments.

## 🎯 Purpose

Shikra automates the complex process of malware analysis by:
- Executing samples in isolated VMs to observe behavior
- Monitoring system calls, file operations, and network traffic
- Analyzing memory dumps for advanced threats
- Generating comprehensive reports with actionable intelligence

## ✨ Key Features

- **🖥️ Automated VM Management**: Create, configure, and manage analysis VMs with stealth capabilities
- **👁️ Behavioral Monitoring**: Real-time process, file, and registry monitoring using Noriben/Procmon
- **🌐 Network Analysis**: Traffic capture, C2 detection, and DNS monitoring with INetSim integration
- **🧠 Memory Forensics**: Memory dump analysis using Volatility for rootkit and injection detection
- **📊 Comprehensive Reporting**: Detailed HTML/PDF reports with visualizations and IOCs
- **🌍 Web Interface**: Browser-based report viewing, search, and analysis management

## 🚀 Quick Start

1. **Initial Setup**
   ```bash
   cd setup/scripts
   sudo ./setup_environment.sh
   ```

2. **Create Analysis VM**
   ```bash
   cd core/scripts  
   ./create_vm.sh --name win10_analysis --profile default --os-iso /path/to/windows10.iso
   ```

3. **Run Analysis**
   ```bash
   ./run_analysis.sh --sample /path/to/malware.exe --vm win10_analysis --timeout 300
   ```

4. **View Results**
   ```bash
   cd ../../reporting/web
   python app.py
   # Visit http://localhost:5000
   ```

## 📁 Architecture Overview

```
shikra/
├── 🔧 setup/           # One-time environment setup and dependencies
├── ⚙️ core/            # Main analysis workflow and VM management  
├── 🔍 analysis/        # Post-execution data processing and analysis
├── 📋 reporting/        # Report generation and web interface
├── ⚙️ config/          # VM profiles, tool configs, and settings
└── 💾 data/            # Sample storage, VM images, and results
```

## 📚 Documentation

- [📖 Installation Guide](docs/installation.md) - Complete setup instructions
- [🏗️ Architecture Overview](docs/architecture.md) - Technical design and components  
- [📋 Usage Instructions](docs/usage.md) - Common workflows and examples

## 🔧 Requirements

### Hardware
- **CPU**: 4+ cores with virtualization support (VT-x/AMD-V)
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 100GB+ free space (SSD recommended)
- **Network**: Dedicated interface for analysis isolation

### Software  
- **OS**: Ubuntu 20.04 LTS or newer
- **Virtualization**: QEMU/KVM or VirtualBox
- **Python**: 3.8+
- **Tools**: Git, tcpdump, tshark, volatility

## ⚠️ Security Warning

**This tool is designed for malware analysis in controlled environments.**

- Always run in isolated networks
- Use dedicated analysis machines
- Never analyze samples on production systems
- Follow responsible disclosure for findings
- Ensure proper legal authorization

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear description
4. Follow coding standards and include tests

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: Check the docs/ directory for detailed guides
- **Community**: Join our discussions for help and tips

---

**Built for security researchers, malware analysts, and incident responders.**
