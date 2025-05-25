#!/bin/bash
# Shikra Dependencies Installation Script (Enhanced)
#
# Purpose:
# This utility script handles installation and configuration of specialized tools
# and packages required by the Shikra analysis platform. It focuses on analysis-specific
# software that requires custom installation procedures or configuration.
#
# Key Functions Implemented:
# - install_system_packages(): Install essential system packages and libraries
# - install_virtualization(): Install QEMU/KVM and related virtualization tools
# - install_analysis_tools(): Install malware analysis tools (Volatility, YARA, etc.)
# - install_monitoring_tools(): Set up behavioral monitoring utilities  
# - install_network_tools(): Install network analysis and simulation tools
# - verify_installation(): Validate that all tools are properly installed
#
# Usage:
#     sudo ./install_dependencies.sh [--category <category>]
#
# Categories:
#     all         - Install all dependencies (default)
#     system      - System packages only
#     virtualization - QEMU/KVM and virtualization tools
#     analysis    - Analysis tools only (Volatility, YARA, pefile)
#     monitoring  - Monitoring tools only (Noriben, Procmon utilities)
#     network     - Network analysis tools only (INetSim, Wireshark, etc.)
#
# Examples:
#     sudo ./install_dependencies.sh                          # Install everything
#     sudo ./install_dependencies.sh --category system        # System packages only
#     sudo ./install_dependencies.sh --category virtualization # VM tools only

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PROJECT_ROOT should be 'shikra/'
# It's two levels up from setup/utils/
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")" 
TOOLS_DIR="$PROJECT_ROOT/tools" # Assumes shikra/tools/
LOG_FILE="$PROJECT_ROOT/logs/dependency_install.log" # Assumes shikra/logs/

# Default category if none specified
INSTALL_CATEGORY="all"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   log "${RED}This script must be run as root (use sudo).${NC}" 
   exit 1
fi

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --category)
                INSTALL_CATEGORY="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [--category <category>]"
                echo "Categories: all, system, virtualization, analysis, monitoring, network"
                exit 0
                ;;
            *)
                log "${RED}Unknown parameter: $1${NC}"
                exit 1
                ;;
        esac
    done
}

activate_venv() {
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        log "Activating Python virtual environment: $PROJECT_ROOT/venv/bin/activate"
        # shellcheck source=/dev/null
        source "$PROJECT_ROOT/venv/bin/activate"
    else
        log "${RED}Virtual environment not found at $PROJECT_ROOT/venv. Please run setup_environment.sh first.${NC}"
        exit 1
    fi
}

deactivate_venv_if_sourced() {
    if command -v deactivate &> /dev/null && [[ -n "$VIRTUAL_ENV" ]]; then
        log "Deactivating virtual environment."
        deactivate
    fi
}

# Enhanced package installation with retry logic
install_package_with_retry() {
    local package="$1"
    local pkg_manager="$2"
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "Installing $package (attempt $attempt/$max_attempts)..."
        
        case "$pkg_manager" in
            "apt")
                if apt-get install -y "$package"; then
                    log "${GREEN}Successfully installed: $package${NC}"
                    return 0
                fi
                ;;
            "dnf"|"yum")
                if "$pkg_manager" install -y "$package"; then
                    log "${GREEN}Successfully installed: $package${NC}"
                    return 0
                fi
                ;;
        esac
        
        log "${YELLOW}Attempt $attempt failed for $package, retrying...${NC}"
        ((attempt++))
        sleep 2
    done
    
    log "${YELLOW}Warning: Failed to install $package after $max_attempts attempts${NC}"
    return 1
}

install_system_packages() {
    log "${BLUE}Installing system packages...${NC}"
    
    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu package installation
        local debian_packages=(
            "build-essential"      # Compilation tools
            "python3-dev"          # Python development headers
            "tcpdump"              # Network packet capture
            "tshark"               # Network protocol analyzer (CLI for Wireshark)
            "nmap"                 # Network discovery and scanning
            "binutils"             # Binary manipulation utilities
            "file"                 # File type identification
            "sqlite3"              # Lightweight database
            "unzip"                # Archive extraction
            "curl"                 # Data transfer tool
            "wget"                 # Web content retrieval
            "git"                  # Version control system
            "libpcap-dev"          # Packet capture library
            "libssl-dev"           # SSL development library
            "libffi-dev"           # Foreign function interface library
            "pkg-config"           # Helper tool for compiling
            "libjpeg-dev"          # For Pillow (JPEG support)
            "zlib1g-dev"           # For Pillow (PNG/general compression)
            "libfuzzy-dev"         # For ssdeep fuzzy hashing
            "libmagic-dev"         # For python-magic file type detection
        )
        
        apt-get update || {
            log "${RED}Error: Failed to update package lists${NC}"
            return 1
        }
        
        for package in "${debian_packages[@]}"; do
            install_package_with_retry "$package" "apt"
        done
        
        # Handle python3-pip specially - often problematic
        log "Installing python3-pip with special handling..."
        if ! command -v pip3 &>/dev/null; then
            if ! install_package_with_retry "python3-pip" "apt"; then
                log "${YELLOW}python3-pip failed via apt, trying alternative method...${NC}"
                if curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 -; then
                    log "${GREEN}pip installed via get-pip.py${NC}"
                else
                    log "${RED}Failed to install pip via alternative method${NC}"
                fi
            fi
        else
            log "pip3 already available"
        fi
            
    elif [[ -f /etc/redhat-release ]]; then
        # Red Hat/CentOS/Fedora package installation
        local pkg_manager="yum"
        if command -v dnf &> /dev/null; then
            pkg_manager="dnf"
        fi

        local redhat_packages=(
            "gcc" "gcc-c++" "make" # build-essential equivalent
            "python3-devel"
            "tcpdump"
            "wireshark-cli" # tshark equivalent
            "nmap"
            "binutils"
            "file"
            "sqlite"
            "unzip"
            "curl"
            "wget"
            "git"
            "libpcap-devel"
            "openssl-devel"
            "libffi-devel"
            "pkgconf-pkg-config" # pkg-config equivalent
            "libjpeg-turbo-devel" # libjpeg-dev equivalent
            "zlib-devel"          # zlib1g-dev equivalent
        )
        
        for package in "${redhat_packages[@]}"; do
            install_package_with_retry "$package" "$pkg_manager"
        done
        
        # Handle python3-pip for RHEL/CentOS
        log "Installing python3-pip for RHEL/CentOS..."
        if ! command -v pip3 &>/dev/null; then
            if ! install_package_with_retry "python3-pip" "$pkg_manager"; then
                log "${YELLOW}python3-pip failed via $pkg_manager, trying EPEL or alternative...${NC}"
                # Try EPEL first
                "$pkg_manager" install -y epel-release 2>/dev/null
                if ! install_package_with_retry "python3-pip" "$pkg_manager"; then
                    # Last resort: get-pip.py
                    if curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 -; then
                        log "${GREEN}pip installed via get-pip.py${NC}"
                    else
                        log "${RED}Failed to install pip via alternative method${NC}"
                    fi
                fi
            fi
        else
            log "pip3 already available"
        fi
    else
        log "${YELLOW}Unsupported distribution for automatic system package installation.${NC}"
        return 1
    fi
    
    log "${GREEN}System packages installation completed${NC}"
    return 0
}

install_virtualization() {
    log "${BLUE}Installing virtualization tools (QEMU/KVM)...${NC}"
    
    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu virtualization packages
        local virt_packages=(
            "qemu-kvm"
            "qemu-system-x86"
            "qemu-utils"
            "libvirt-daemon-system"
            "libvirt-clients"
            "bridge-utils"
            "virt-manager"
            "ovmf"  # UEFI firmware
        )
        
        # Check if virtualization is supported
        if ! grep -E "(vmx|svm)" /proc/cpuinfo > /dev/null; then
            log "${YELLOW}Warning: Hardware virtualization may not be supported on this system${NC}"
        fi
        
        for package in "${virt_packages[@]}"; do
            if [[ "$package" == "virt-manager" ]]; then
                # virt-manager often fails in headless environments
                log "Installing virt-manager (may fail in headless environments)..."
                if ! install_package_with_retry "$package" "apt"; then
                    log "${YELLOW}virt-manager failed - this is normal for headless systems${NC}"
                fi
            elif [[ "$package" == "ovmf" ]]; then
                # OVMF may not be available in older repositories
                log "Installing OVMF UEFI firmware (may not be available in older repos)..."
                if ! install_package_with_retry "$package" "apt"; then
                    log "${YELLOW}OVMF failed - older system may not have this package${NC}"
                fi
            else
                install_package_with_retry "$package" "apt"
            fi
        done
        
        # Add user to necessary groups
        if [[ -n "$SUDO_USER" ]]; then
            log "Adding user $SUDO_USER to libvirt and kvm groups..."
            usermod -a -G libvirt "$SUDO_USER" 2>/dev/null || log "${YELLOW}Failed to add to libvirt group${NC}"
            usermod -a -G kvm "$SUDO_USER" 2>/dev/null || log "${YELLOW}Failed to add to kvm group${NC}"
        fi
        
        # Start and enable libvirt service
        systemctl enable libvirtd 2>/dev/null || log "${YELLOW}Failed to enable libvirtd${NC}"
        systemctl start libvirtd 2>/dev/null || log "${YELLOW}Failed to start libvirtd${NC}"
        
    elif [[ -f /etc/redhat-release ]]; then
        local pkg_manager="yum"
        if command -v dnf &> /dev/null; then
            pkg_manager="dnf"
        fi
        
        local virt_packages=(
            "qemu-kvm"
            "qemu-img"
            "libvirt"
            "libvirt-client"
            "virt-install"
            "virt-manager"
            "bridge-utils"
        )
        
        for package in "${virt_packages[@]}"; do
            install_package_with_retry "$package" "$pkg_manager"
        done
        
        # Add user to groups and start services
        if [[ -n "$SUDO_USER" ]]; then
            usermod -a -G libvirt "$SUDO_USER" 2>/dev/null
            usermod -a -G kvm "$SUDO_USER" 2>/dev/null
        fi
        
        systemctl enable libvirtd 2>/dev/null
        systemctl start libvirtd 2>/dev/null
    fi
    
    log "${GREEN}Virtualization tools installation completed${NC}"
    return 0
}

install_wireshark() {
    log "Installing Wireshark with proper configuration..."
    
    if [[ -f /etc/debian_version ]]; then
        # Pre-configure wireshark to allow non-root capture
        echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
        
        if install_package_with_retry "wireshark" "apt"; then
            # Add user to wireshark group
            if [[ -n "$SUDO_USER" ]]; then
                usermod -a -G wireshark "$SUDO_USER" 2>/dev/null || log "${YELLOW}Failed to add user to wireshark group${NC}"
            fi
            
            # Set capabilities for non-root packet capture
            if command -v setcap &>/dev/null; then
                setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap 2>/dev/null || log "${YELLOW}Failed to set dumpcap capabilities${NC}"
            fi
            
            log "${GREEN}Wireshark installed successfully${NC}"
            return 0
        else
            log "${YELLOW}Wireshark installation failed${NC}"
            return 1
        fi
    elif [[ -f /etc/redhat-release ]]; then
        local pkg_manager="yum"
        if command -v dnf &> /dev/null; then
            pkg_manager="dnf"
        fi
        
        if install_package_with_retry "wireshark" "$pkg_manager"; then
            if [[ -n "$SUDO_USER" ]]; then
                usermod -a -G wireshark "$SUDO_USER" 2>/dev/null
            fi
            log "${GREEN}Wireshark installed successfully${NC}"
            return 0
        else
            log "${YELLOW}Wireshark installation failed${NC}"
            return 1
        fi
    fi
}

install_netcat() {
    log "Installing netcat with fallback options..."
    
    if [[ -f /etc/debian_version ]]; then
        # Try different netcat variants
        local netcat_variants=("netcat-openbsd" "netcat-traditional" "netcat")
        
        for variant in "${netcat_variants[@]}"; do
            if install_package_with_retry "$variant" "apt"; then
                log "${GREEN}Installed netcat variant: $variant${NC}"
                return 0
            fi
        done
        
        log "${YELLOW}All netcat variants failed to install${NC}"
        return 1
        
    elif [[ -f /etc/redhat-release ]]; then
        local pkg_manager="yum"
        if command -v dnf &> /dev/null; then
            pkg_manager="dnf"
        fi
        
        local netcat_variants=("nc" "nmap-ncat" "netcat")
        
        for variant in "${netcat_variants[@]}"; do
            if install_package_with_retry "$variant" "$pkg_manager"; then
                log "${GREEN}Installed netcat variant: $variant${NC}"
                return 0
            fi
        done
        
        log "${YELLOW}All netcat variants failed to install${NC}"
        return 1
    fi
}

install_analysis_tools() {
    log "${BLUE}Installing analysis tools (Python packages into venv)...${NC}"
    activate_venv # Ensure commands use the venv pip

    # Upgrade pip first to avoid installation issues
    log "Upgrading pip in virtual environment..."
    "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip setuptools wheel || log "${YELLOW}Failed to upgrade pip/setuptools/wheel${NC}"

    # Install Volatility 3 for memory analysis with enhanced error handling
    log "Installing Volatility 3..."
    if "$PROJECT_ROOT/venv/bin/pip" install volatility3; then
        log "${GREEN}Volatility 3 installed successfully into venv${NC}"
    else
        log "${YELLOW}Volatility 3 installation failed, trying alternative method...${NC}"
        # Try installing from git directly
        if "$PROJECT_ROOT/venv/bin/pip" install git+https://github.com/volatilityfoundation/volatility3.git; then
            log "${GREEN}Volatility 3 installed from git successfully${NC}"
        else
            log "${RED}Volatility 3 installation failed completely${NC}"
            # Create a manual note for user
            echo "MANUAL_INSTALL_NEEDED: Volatility 3 failed to install automatically" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
        fi
    fi
    
    # Install YARA (system package preferred for CLI, Python bindings for venv)
    log "Installing YARA system package and Python bindings..."
    if [[ -f /etc/debian_version ]]; then
        if ! dpkg -s yara >/dev/null 2>&1; then
            if ! install_package_with_retry "yara" "apt"; then
                log "${YELLOW}YARA system package failed, trying to build from source...${NC}"
                # Add instructions for manual build
                echo "MANUAL_INSTALL_NEEDED: YARA system package - consider building from source" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
            fi
        else 
            log "YARA system package already installed."
        fi
    elif [[ -f /etc/redhat-release ]]; then
        if ! rpm -q yara >/dev/null 2>&1; then
            local pkg_mgr="yum"; 
            if command -v dnf &>/dev/null; then pkg_mgr="dnf"; fi
            if ! install_package_with_retry "yara" "$pkg_mgr"; then
                log "${YELLOW}YARA system package not available in standard repos${NC}"
                echo "MANUAL_INSTALL_NEEDED: YARA system package for RHEL/CentOS" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
            fi
        else 
            log "YARA system package already installed."
        fi
    fi

    # Install Python analysis libraries into venv with better error handling
    local python_analysis_packages=(
        "pefile"             # PE file analysis
        "yara-python"        # YARA Python bindings
        "ssdeep"             # Fuzzy hashing (requires libfuzzy-dev)
        "python-magic"       # File type identification (requires libmagic1)
        "requests"           # HTTP library
        "beautifulsoup4"     # HTML/XML parsing
        "lxml"               # XML processing
        "Pillow"             # Image processing
        "matplotlib"         # Plotting and visualization
        "networkx"           # Network analysis
        "pandas"             # Data analysis
        "numpy"              # Numerical computing
        "cryptography"       # Cryptographic functions
        "pyopenssl"          # OpenSSL bindings
    )
    
    log "Installing Python analysis packages into venv..."
    for package in "${python_analysis_packages[@]}"; do
        log "Installing $package..."
        if "$PROJECT_ROOT/venv/bin/pip" install "$package"; then
            log "✓ Installed: $package"
        else
            log "${YELLOW}✗ Failed to install: $package${NC}"
            # Try with --no-cache-dir for problematic packages
            if "$PROJECT_ROOT/venv/bin/pip" install --no-cache-dir "$package"; then
                log "✓ Installed $package (with --no-cache-dir)"
            else
                log "${RED}✗ $package failed completely${NC}"
                echo "MANUAL_INSTALL_NEEDED: Python package $package" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
            fi
        fi
    done

    # Install Binwalk with enhanced handling
    log "Installing Binwalk..."
    if command -v binwalk &>/dev/null; then
        log "Binwalk already installed."
    else
        if [[ -f /etc/debian_version ]]; then
            if ! install_package_with_retry "binwalk" "apt"; then
                log "${YELLOW}Binwalk system package failed, trying pip install...${NC}"
                "$PROJECT_ROOT/venv/bin/pip" install binwalk || echo "MANUAL_INSTALL_NEEDED: Binwalk" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
            fi
        elif [[ -f /etc/redhat-release ]]; then
            log "${YELLOW}Binwalk not in standard RHEL repos, trying pip...${NC}"
            if ! "$PROJECT_ROOT/venv/bin/pip" install binwalk; then
                echo "MANUAL_INSTALL_NEEDED: Binwalk for RHEL/CentOS" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
            fi
        fi
    fi
    
    log "${GREEN}Analysis tools installation completed${NC}"
    return 0
}

install_inetsim() {
    log "Installing INetSim network simulator..."
    
    # INetSim is complex and often requires manual installation
    if command -v inetsim &>/dev/null; then
        log "INetSim already installed"
        return 0
    fi
    
    if [[ -f /etc/debian_version ]]; then
        # Try from repositories first
        if install_package_with_retry "inetsim" "apt"; then
            log "${GREEN}INetSim installed from repository${NC}"
            return 0
        fi
        
        # Try to install dependencies for manual build
        log "INetSim not in repos, preparing for manual installation..."
        local inetsim_deps=(
            "libnet-dns-perl"
            "libnet-server-perl" 
            "libio-socket-ssl-perl"
            "libdigest-sha-perl"
        )
        
        for dep in "${inetsim_deps[@]}"; do
            install_package_with_retry "$dep" "apt"
        done
        
        # Download and install INetSim manually
        cd "$TOOLS_DIR" || return 1
        if [[ ! -f "inetsim-1.3.2.tar.gz" ]]; then
            log "Downloading INetSim..."
            if wget -q http://www.inetsim.org/downloads/inetsim-1.3.2.tar.gz; then
                tar -xzf inetsim-1.3.2.tar.gz
                cd inetsim-1.3.2 || return 1
                
                # Install to /opt/inetsim
                mkdir -p /opt/inetsim
                cp -r * /opt/inetsim/
                chmod +x /opt/inetsim/inetsim
                ln -sf /opt/inetsim/inetsim /usr/local/bin/inetsim
                
                log "${GREEN}INetSim installed manually to /opt/inetsim${NC}"
                return 0
            else
                log "${YELLOW}Failed to download INetSim${NC}"
            fi
        fi
    fi
    
    echo "MANUAL_INSTALL_NEEDED: INetSim network simulator" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
    log "${YELLOW}INetSim requires manual installation - added to manual install list${NC}"
    return 1
}

install_monitoring_tools() {
    log "${BLUE}Installing monitoring tools...${NC}"
    
    # Create tools directory for downloaded utilities
    mkdir -p "$TOOLS_DIR"
    cd "$TOOLS_DIR" || {
        log "${RED}Error: Cannot create/access tools directory: $TOOLS_DIR${NC}"
        return 1
    }
    
    # Download Noriben behavioral analysis tool
    if [[ ! -d "Noriben" ]]; then
        log "Cloning Noriben repository..."
        if git clone https://github.com/Rurik/Noriben.git; then
            log "${GREEN}Noriben cloned successfully into $TOOLS_DIR/Noriben${NC}"
        else
            log "${RED}Error: Failed to clone Noriben repository${NC}"
            echo "MANUAL_INSTALL_NEEDED: Noriben - git clone https://github.com/Rurik/Noriben.git" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
        fi
    else
        log "Noriben already exists in $TOOLS_DIR, skipping download."
    fi
    
    # Download Sysinternals Suite for Windows VM deployment
    if [[ ! -f "SysinternalsSuite.zip" && ! -d "SysinternalsSuite" ]]; then
        log "Downloading Sysinternals Suite..."
        if wget -q https://download.sysinternals.com/files/SysinternalsSuite.zip -O SysinternalsSuite.zip; then
            if unzip -q SysinternalsSuite.zip -d SysinternalsSuite/; then
                log "${GREEN}Sysinternals Suite downloaded and extracted to $TOOLS_DIR/SysinternalsSuite${NC}"
            else
                log "${RED}Error: Failed to extract Sysinternals Suite${NC}"
            fi
        else
            log "${RED}Error: Failed to download Sysinternals Suite${NC}"
            echo "MANUAL_INSTALL_NEEDED: Sysinternals Suite - download from Microsoft" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
        fi
    else
        log "Sysinternals Suite already exists in $TOOLS_DIR, skipping download."
    fi
    
    # Set proper ownership for tools directory
    cd "$PROJECT_ROOT" || exit 1
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$TOOLS_DIR"
    fi
    
    log "${GREEN}Monitoring tools setup completed${NC}"
    return 0
}

install_network_tools() {
    log "${BLUE}Installing network analysis tools...${NC}"
    activate_venv
    
    # Install Wireshark first
    install_wireshark
    
    # Install netcat
    install_netcat
    
    # Try to install INetSim
    install_inetsim

    # Install Python network analysis libraries into venv
    local network_packages=(
        "scapy"              # Packet manipulation and analysis
        "pyshark"            # Python wrapper for tshark
        "netaddr"            # Network address manipulation
        "dnspython"          # DNS toolkit
        "netifaces"          # Network interface information
        "dpkt"               # Packet creation and parsing
    )
    
    log "Installing Python network packages into venv..."
    for package in "${network_packages[@]}"; do
        log "Installing $package..."
        if "$PROJECT_ROOT/venv/bin/pip" install "$package"; then
            log "✓ Installed: $package"
        else
            log "${YELLOW}✗ Failed to install: $package${NC}"
            echo "MANUAL_INSTALL_NEEDED: Python network package $package" >> "$PROJECT_ROOT/logs/manual_installs_needed.txt"
        fi
    done
    
    log "${GREEN}Network tools installation completed${NC}"
    return 0
}

verify_installation() {
    log "${BLUE}Verifying installation...${NC}"
    activate_venv

    local verification_failed=false
    
    # Test Python library imports from venv
    log "Testing Python library imports from venv..."
    "$PROJECT_ROOT/venv/bin/python" -c "
import sys
errors = []
warnings = []

# Critical packages
try:
    import pefile
    print('✓ pefile: OK')
except ImportError as e: 
    errors.append(f'✗ pefile: FAILED ({e})')

try:
    import requests
    print('✓ requests: OK')
except ImportError as e: 
    errors.append(f'✗ requests: FAILED ({e})')

try:
    import matplotlib
    print('✓ matplotlib: OK')
except ImportError as e: 
    errors.append(f'✗ matplotlib: FAILED ({e})')

# Optional but important packages
try:
    import volatility3
    print('✓ Volatility 3: OK')
except ImportError as e: 
    warnings.append(f'⚠ Volatility 3: FAILED ({e})')

try:
    import yara
    print('✓ YARA (python): OK')  
except ImportError as e: 
    warnings.append(f'⚠ YARA (python): FAILED ({e})')

try:
    from scapy.all import IP
    print('✓ Scapy: OK')
except ImportError as e: 
    warnings.append(f'⚠ Scapy: FAILED ({e})')

try:
    import ssdeep
    print('✓ ssdeep: OK')
except ImportError as e: 
    warnings.append(f'⚠ ssdeep: FAILED ({e})')

if warnings:
    print('\\nWarnings (non-critical):')
    print('\\n'.join(warnings))

if errors: 
    print('\\nCritical Errors:')
    print('\\n'.join(errors))
    sys.exit(1)
else:
    print('\\nAll critical Python packages verified successfully!')
" || verification_failed=true
    
    # Test command-line tools
    log "Testing command-line tools..."
    
    # Critical tools
    if command -v python3 &>/dev/null; then log "✓ Python 3: OK"; else log "✗ Python 3: FAILED"; verification_failed=true; fi
    if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then log "✓ pip: OK"; else log "✗ pip: FAILED"; verification_failed=true; fi
    
    # Important but not critical tools
    if command -v tshark &>/dev/null && tshark --version >/dev/null 2>&1; then 
        log "✓ TShark: OK"
    else 
        log "⚠ TShark: FAILED (install wireshark-cli or tshark package)"
    fi
    
    if command -v yara &>/dev/null && yara --version >/dev/null 2>&1; then 
        log "✓ YARA CLI: OK"
    else 
        log "⚠ YARA CLI: FAILED (consider manual installation)"
    fi
    
    if command -v tcpdump &>/dev/null && tcpdump --version >/dev/null 2>&1; then 
        log "✓ tcpdump: OK"
    else 
        log "⚠ tcpdump: FAILED"
    fi
    
    if command -v qemu-system-x86_64 &>/dev/null || command -v kvm &>/dev/null; then 
        log "✓ QEMU/KVM: OK"
    else 
        log "⚠ QEMU/KVM: FAILED (virtualization may not work)"
    fi
    
    if command -v nc &>/dev/null || command -v netcat &>/dev/null; then 
        log "✓ netcat: OK"
    else 
        log "⚠ netcat: FAILED"
    fi
    
    if command -v wireshark &>/dev/null || command -v tshark &>/dev/null; then 
        log "✓ Wireshark/tshark: OK"
    else 
        log "⚠ Wireshark: FAILED"
    fi
    
    if command -v inetsim &>/dev/null; then 
        log "✓ INetSim: OK"
    else 
        log "⚠ INetSim: FAILED (requires manual installation)"
    fi
    
    # Check if tools were downloaded
    if [[ -f "$TOOLS_DIR/Noriben/Noriben.py" ]]; then 
        log "✓ Noriben files: OK"
    else 
        log "⚠ Noriben files: NOT FOUND in $TOOLS_DIR"
    fi
    
    if [[ -f "$TOOLS_DIR/SysinternalsSuite/procexp.exe" || -f "$TOOLS_DIR/SysinternalsSuite/procexp64.exe" ]]; then 
        log "✓ Sysinternals Suite files: OK"
    else 
        log "⚠ Sysinternals Suite files: NOT FOUND in $TOOLS_DIR"
    fi
    
    # Check virtualization support
    if grep -E "(vmx|svm)" /proc/cpuinfo > /dev/null; then
        log "✓ Hardware virtualization: Supported"
    else
        log "⚠ Hardware virtualization: Not detected (VMs may not work properly)"
    fi
    
    # Check if libvirt is running
    if systemctl is-active --quiet libvirtd 2>/dev/null; then
        log "✓ libvirtd service: Running"
    else
        log "⚠ libvirtd service: Not running"
    fi
    
    # Summary of verification
    if [[ "$verification_failed" == "false" ]]; then
        log "${GREEN}Critical verification checks passed${NC}"
        log "${YELLOW}Note: Some warnings above are for optional components${NC}"
        
        # Check if manual installs are needed
        if [[ -f "$PROJECT_ROOT/logs/manual_installs_needed.txt" ]]; then
            log "${YELLOW}Manual installation required for some components:${NC}"
            cat "$PROJECT_ROOT/logs/manual_installs_needed.txt" | while read -r line; do
                log "  - $line"
            done
            log "See $PROJECT_ROOT/logs/manual_installs_needed.txt for details"
        fi
        
        return 0
    else
        log "${RED}Critical verification checks failed. Please review logs and resolve issues.${NC}"
        return 1
    fi
}

show_post_install_instructions() {
    log "${BLUE}Post-Installation Instructions:${NC}"
    
    log "1. Virtual Environment:"
    log "   - Activate: source $PROJECT_ROOT/venv/bin/activate"
    log "   - Deactivate: deactivate"
    
    log "2. User Groups (requires logout/login to take effect):"
    if [[ -n "$SUDO_USER" ]]; then
        log "   - User '$SUDO_USER' added to groups: libvirt, kvm, wireshark"
        log "   - Please log out and log back in for group changes to take effect"
    fi
    
    log "3. Services:"
    log "   - libvirtd service should be running for VM management"
    log "   - Check with: systemctl status libvirtd"
    
    log "4. Virtualization:"
    log "   - Test VM creation: virt-manager (GUI) or virsh (CLI)"
    log "   - Verify hardware virtualization: grep -E '(vmx|svm)' /proc/cpuinfo"
    
    log "5. Network Tools:"
    log "   - Wireshark: Use 'wireshark' or 'tshark' commands"
    log "   - Packet capture may require root or wireshark group membership"
    
    if [[ -f "$PROJECT_ROOT/logs/manual_installs_needed.txt" ]]; then
        log "6. Manual Installations Required:"
        log "   - Review: $PROJECT_ROOT/logs/manual_installs_needed.txt"
        log "   - Some tools require manual installation or configuration"
    fi
    
    log "7. Verification:"
    log "   - Re-run this script with --category all to verify fixes"
    log "   - Test individual tools with their --version or --help flags"
}

cleanup_failed_installs() {
    log "Cleaning up any failed package installations..."
    
    if [[ -f /etc/debian_version ]]; then
        # Clean up apt
        apt-get autoremove -y 2>/dev/null || true
        apt-get autoclean 2>/dev/null || true
        
        # Fix any broken packages
        dpkg --configure -a 2>/dev/null || true
        apt-get -f install -y 2>/dev/null || true
        
    elif [[ -f /etc/redhat-release ]]; then
        # Clean up yum/dnf
        local pkg_manager="yum"
        if command -v dnf &> /dev/null; then
            pkg_manager="dnf"
        fi
        
        "$pkg_manager" autoremove -y 2>/dev/null || true
        "$pkg_manager" clean all 2>/dev/null || true
    fi
    
    log "Cleanup completed"
}

main_install_deps() {
    log "${GREEN}Starting Shikra dependency installation (Enhanced)...${NC}"
    log "Installation category: $INSTALL_CATEGORY"
    log "Installation log: $LOG_FILE"
    log "Manual install tracking: $PROJECT_ROOT/logs/manual_installs_needed.txt"
    
    # Create manual install tracking file
    mkdir -p "$PROJECT_ROOT/logs"
    > "$PROJECT_ROOT/logs/manual_installs_needed.txt"  # Clear the file
    
    # Install based on category selection
    local success=true
    case "$INSTALL_CATEGORY" in
        "all")
            install_system_packages || success=false
            install_virtualization || success=false
            install_analysis_tools || success=false
            install_monitoring_tools || success=false
            install_network_tools || success=false
            ;;
        "system") 
            install_system_packages || success=false 
            ;;
        "virtualization") 
            install_virtualization || success=false 
            ;;
        "analysis") 
            install_analysis_tools || success=false 
            ;;
        "monitoring") 
            install_monitoring_tools || success=false 
            ;;
        "network") 
            install_network_tools || success=false 
            ;;
        *)
            log "${RED}Error: Unknown category '$INSTALL_CATEGORY'${NC}"
            log "Valid categories: all, system, virtualization, analysis, monitoring, network"
            exit 1
            ;;
    esac
    
    # Clean up any package manager issues
    cleanup_failed_installs
    
    if ! $success; then
        log "${YELLOW}One or more installation steps had issues. Continuing with verification...${NC}"
    fi

    # Verify installation
    verify_installation || success=false
    
    log "${GREEN}========================================${NC}"
    if $success; then
        log "${GREEN}Dependency installation completed successfully!${NC}"
    else
        log "${YELLOW}Dependency installation completed with some issues.${NC}"
        log "This is normal - some tools require manual installation."
    fi
    log "${GREEN}========================================${NC}"
    
    # Show detailed post-installation instructions
    show_post_install_instructions
    
    log "Installation summary for category '$INSTALL_CATEGORY':"
    log "- System packages: Essential development and analysis tools"
    log "- Virtualization: QEMU/KVM, libvirt, bridge-utils, virt-manager"
    log "- Analysis tools: Volatility, YARA, pefile, and Python libraries (in venv)"
    log "- Monitoring tools: Noriben and Sysinternals Suite (downloaded to $TOOLS_DIR)"
    log "- Network tools: Wireshark, netcat, INetSim, Python network libraries (in venv)"
    
    # Final status
    if [[ -s "$PROJECT_ROOT/logs/manual_installs_needed.txt" ]]; then
        log "${YELLOW}Some components require manual installation. Check:${NC}"
        log "$PROJECT_ROOT/logs/manual_installs_needed.txt"
    else
        log "${GREEN}All components installed successfully!${NC}"
    fi
}

# Parse command line arguments
parse_arguments "$@"

# Execute main installation process
main_install_deps

# Deactivate virtual environment if it was activated
deactivate_venv_if_sourced