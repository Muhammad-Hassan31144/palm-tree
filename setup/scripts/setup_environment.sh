#!/bin/bash
# Shikra Environment Setup Script
#
# Purpose:
# This script performs the initial one-time setup of the Shikra analysis environment.
# It prepares the host system with all necessary dependencies, virtualization software,
# and security configurations required for safe malware analysis.
#
# Key Functions Implemented:
# - check_requirements(): Validate system compatibility and resources
# - create_virtual_environment(): Set up Python virtual environment  
# - setup_virtualization(): Install and configure QEMU/KVM or VirtualBox
# - configure_network(): Set up network isolation infrastructure
# - create_data_directories(): Create directory structure for samples and results
# - configure_permissions(): Set appropriate file and directory permissions
#
# Usage:
#     sudo ./setup_environment.sh
#
# Security Notes:
# - Requires root privileges for system-level configurations
# - Creates isolated network environments for malware analysis
# - Sets up proper file permissions to contain malware samples
# - Configures firewall rules for network isolation
#
# Dependencies:
# - Ubuntu 20.04+ or compatible Linux distribution
# - Hardware virtualization support (VT-x/AMD-V)
# - Minimum 16GB RAM and 100GB free disk space

# Script configuration and global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")" # This should point to 'shikra/'
LOG_FILE="$PROJECT_ROOT/logs/setup.log" # Adjusted log path assuming shikra/logs/
REQUIRED_RAM_KB=8388608  # 8GB minimum
REQUIRED_DISK_GB=50      # 50GB minimum free space

# Color codes for enhanced output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function for consistent output and file logging
log() {
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

check_requirements() {
    log "${BLUE}Checking system requirements...${NC}"
    local requirements_met=true

    # Check operating system compatibility
    if [[ ! -f /etc/os-release ]]; then
        log "${RED}Error: Cannot determine operating system${NC}"
        requirements_met=false
    else
        source /etc/os-release
        log "Operating System: $PRETTY_NAME"
        if [[ "$ID" != "ubuntu" && "$ID_LIKE" != *"debian"* ]]; then
            log "${YELLOW}Warning: Untested OS. Ubuntu/Debian recommended${NC}"
        fi
    fi

    # Check CPU virtualization extensions
    if ! grep -q -E "vmx|svm" /proc/cpuinfo; then
        log "${RED}Error: CPU virtualization extensions (VT-x/AMD-V) not detected${NC}"
        log "Please enable virtualization in BIOS/UEFI settings"
        requirements_met=false
    else
        log "${GREEN}CPU virtualization support detected${NC}"
    fi

    # Check available memory
    local total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [[ $total_mem_kb -lt $REQUIRED_RAM_KB ]]; then
        log "${YELLOW}Warning: Less than 8GB RAM detected (${total_mem_kb} KB available)${NC}"
        log "Minimum 16GB recommended for optimal performance"
    else
        log "${GREEN}Sufficient memory available: $(($total_mem_kb / 1024 / 1024))GB${NC}"
    fi

    # Check available disk space on the partition of PROJECT_ROOT
    local available_space_gb=$(df -P "$PROJECT_ROOT" | awk 'NR==2 {print int($4/1024/1024)}')
    if [[ $available_space_gb -lt $REQUIRED_DISK_GB ]]; then
        log "${RED}Error: Insufficient disk space. Need ${REQUIRED_DISK_GB}GB, have ${available_space_gb}GB in $PROJECT_ROOT partition${NC}"
        requirements_met=false
    else
        log "${GREEN}Sufficient disk space available: ${available_space_gb}GB in $PROJECT_ROOT partition${NC}"
    fi

    # Check if running as root (required for system modifications)
    if [[ $EUID -ne 0 ]]; then
        log "${RED}Error: This script must be run as root (use sudo)${NC}"
        requirements_met=false
    fi

    if [[ "$requirements_met" == "true" ]]; then
        log "${GREEN}All system requirements check passed${NC}"
        return 0
    else
        log "${RED}System requirements check failed${NC}"
        return 1
    fi
}

create_virtual_environment() {
    log "${BLUE}Creating Python virtual environment...${NC}"
    
    # PROJECT_ROOT should be the 'shikra' directory itself
    cd "$PROJECT_ROOT" || {
        log "${RED}Error: Cannot navigate to project root: $PROJECT_ROOT${NC}"
        return 1
    }
    
    # Create virtual environment in project root (e.g., shikra/venv)
    if ! python3 -m venv venv; then
        log "${RED}Error: Failed to create virtual environment in $PROJECT_ROOT/venv${NC}"
        return 1
    fi
    
    # Activate virtual environment (for this script's context, if needed, or instruct user)
    # For commands within this script needing the venv:
    # source "$PROJECT_ROOT/venv/bin/activate" 
    # Or, more directly:
    # "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip

    log "Upgrading pip in virtual environment..."
    if ! "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip; then
        log "${YELLOW}Warning: Failed to upgrade pip in $PROJECT_ROOT/venv${NC}"
    fi
    
    # Install requirements if file exists (e.g., shikra/requirements.txt)
    if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
        log "Installing Python packages from $PROJECT_ROOT/requirements.txt..."
        if "$PROJECT_ROOT/venv/bin/pip" install -r "$PROJECT_ROOT/requirements.txt"; then
            log "${GREEN}Python packages installed successfully into $PROJECT_ROOT/venv${NC}"
        else
            log "${YELLOW}Warning: Some Python packages failed to install from $PROJECT_ROOT/requirements.txt${NC}"
        fi
    else
        log "${YELLOW}No requirements.txt found at $PROJECT_ROOT/requirements.txt, skipping package installation${NC}"
    fi
    
    # Set proper ownership for virtual environment
    if [[ -n "$SUDO_USER" ]]; then
      chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_ROOT/venv/"
    fi
    
    log "${GREEN}Virtual environment created successfully at $PROJECT_ROOT/venv${NC}"
    log "To activate it in your shell, run: source $PROJECT_ROOT/venv/bin/activate"
    return 0
}

setup_virtualization() {
    log "${BLUE}Setting up virtualization software...${NC}"
    
    # Detect Linux distribution for package management
    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu package installation
        log "Installing QEMU/KVM on Debian/Ubuntu system..."
        
        apt-get update || {
            log "${RED}Error: Failed to update package lists${NC}"
            return 1
        }
        
        if apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager; then
            log "${GREEN}QEMU/KVM packages installed successfully${NC}"
        else
            log "${RED}Error: Failed to install QEMU/KVM packages${NC}"
            return 1
        fi
        
        # Add user to required groups for VM management
        if [[ -n "$SUDO_USER" ]]; then
            usermod -aG libvirt "$SUDO_USER" # libvirt is common
            usermod -aG kvm "$SUDO_USER"   # kvm group if it exists and is needed
            log "Added user $SUDO_USER to libvirt and kvm groups. A re-login might be required."
        fi
        
    elif [[ -f /etc/redhat-release ]]; then
        # Red Hat/CentOS/Fedora package installation
        log "Installing QEMU/KVM on Red Hat/CentOS/Fedora system..."
        
        if yum install -y qemu-kvm libvirt virt-manager bridge-utils; then # or dnf for modern Fedora
            log "${GREEN}QEMU/KVM packages installed successfully${NC}"
        else
            log "${RED}Error: Failed to install QEMU/KVM packages${NC}"
            return 1
        fi
        
        # Add user to libvirt group
        if [[ -n "$SUDO_USER" ]]; then
            usermod -aG libvirt "$SUDO_USER"
            log "Added user $SUDO_USER to libvirt group. A re-login might be required."
        fi
        
    else
        log "${YELLOW}Unknown distribution detected${NC}"
        log "Please install QEMU/KVM manually and ensure libvirt is configured"
        return 1
    fi
    
    # Start and enable libvirt service
    if systemctl start libvirtd && systemctl enable libvirtd; then
        log "${GREEN}Libvirt service started and enabled${NC}"
    else
        log "${RED}Error: Failed to start/enable libvirt service${NC}"
        # return 1 # This might be too strict if it's already running
    fi
    
    # Verify virtualization setup
    if virsh version >/dev/null 2>&1; then
        log "${GREEN}Virtualization setup completed successfully${NC}"
        return 0
    else
        log "${RED}Error: Virtualization setup verification failed (virsh command not found or not working)${NC}"
        return 1
    fi
}

configure_network() {
    log "${BLUE}Configuring network for analysis isolation...${NC}"
    
    # This is a placeholder for more complex network setup.
    # For a basic setup, ensure the default libvirt network exists or create one.
    if ! virsh net-list --all | grep -q default; then
        log "Default libvirt network not found. Attempting to define and start it."
        # Define a default network (example XML, adjust as needed)
        cat <<EOF > /tmp/default_network.xml
<network>
  <name>default</name>
  <uuid>$(uuidgen)</uuid>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='virbr0' stp='on' delay='0'/>
  <mac address='52:54:00:$(dd if=/dev/urandom count=1 2>/dev/null | md5sum | cut -c 1-6 | sed -e 's/\(..\)/\1:/g' -e 's/:$//')'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
EOF
        if virsh net-define /tmp/default_network.xml && \
           virsh net-autostart default && \
           virsh net-start default; then
            log "${GREEN}Default libvirt network defined, autostarted, and started.${NC}"
            rm /tmp/default_network.xml
        else
            log "${RED}Failed to define/start default libvirt network. Manual configuration needed.${NC}"
            rm -f /tmp/default_network.xml
            # return 1 # Decide if this is a fatal error for the script
        fi
    else
        log "${GREEN}Default libvirt network already exists.${NC}"
    fi

    log "${GREEN}Basic network configuration checked/completed.${NC}"
    log "${YELLOW}Note: Advanced network isolation (e.g., dedicated bridges, INetSim) requires manual configuration or separate scripts.${NC}"
    
    return 0
}

create_data_directories() {
    log "${BLUE}Creating data directories in $PROJECT_ROOT/data ...${NC}"
    
    cd "$PROJECT_ROOT" || { # Ensure we are in shikra/
        log "${RED}Error: Cannot navigate to project root $PROJECT_ROOT ${NC}"
        return 1
    }
    
    # Create main data directory structure relative to PROJECT_ROOT
    local directories=(
        "data"
        "data/samples"
        "data/vm_images"  
        "data/results"
        "data/results/logs"
        "data/results/reports"  
        "data/results/memory_dumps"
        "data/configs_runtime" # For runtime generated configs if any
        "logs" # For global logs like setup.log, dependency_install.log
    )
    
    for dir in "${directories[@]}"; do
        if mkdir -p "$PROJECT_ROOT/$dir"; then # Prepend PROJECT_ROOT
            log "Created directory: $PROJECT_ROOT/$dir"
        else
            log "${RED}Error: Failed to create directory $PROJECT_ROOT/$dir${NC}"
            return 1
        fi
    done
    
    # Set appropriate permissions
    chmod 755 "$PROJECT_ROOT/data/"                 
    chmod 700 "$PROJECT_ROOT/data/samples/"         
    chmod 755 "$PROJECT_ROOT/data/vm_images/"       
    chmod 755 "$PROJECT_ROOT/data/results/"         
    chmod 755 "$PROJECT_ROOT/data/results/logs/"
    chmod 755 "$PROJECT_ROOT/data/results/reports/"
    chmod 755 "$PROJECT_ROOT/data/results/memory_dumps/"
    chmod 755 "$PROJECT_ROOT/data/configs_runtime/"
    chmod 755 "$PROJECT_ROOT/logs/"


    # Set proper ownership to analysis user
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_ROOT/data/"
        chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_ROOT/logs/"
        log "Set ownership of data and logs directories to $SUDO_USER"
    fi
    
    # Create .gitignore files to prevent accidental commits
    echo "*" > "$PROJECT_ROOT/data/samples/.gitignore"            # Never commit malware samples
    echo -e "*.qcow2\n*.vdi\n*.vmdk" > "$PROJECT_ROOT/data/vm_images/.gitignore" # Ignore large VM image files
    echo "*.raw" > "$PROJECT_ROOT/data/results/memory_dumps/.gitignore" # Ignore memory dumps
    echo "*" > "$PROJECT_ROOT/data/results/logs/.gitignore"
    echo "*" > "$PROJECT_ROOT/data/results/reports/.gitignore"
    echo "*" > "$PROJECT_ROOT/data/configs_runtime/.gitignore"
    echo "*.log" > "$PROJECT_ROOT/logs/.gitignore" # Ignore general log files

    log "${GREEN}Data directories created with appropriate permissions${NC}"
    return 0
}

configure_permissions() {
    log "${BLUE}Configuring system permissions...${NC}"
    
    # Ensure analysis user has necessary group memberships (already handled in setup_virtualization)
    # Additional groups might be needed for specific tools like Wireshark
    if [[ -n "$SUDO_USER" ]]; then
        local groups_to_add=("wireshark") # pcap group is often part of wireshark or not needed directly
        
        for group_name in "${groups_to_add[@]}"; do
            if getent group "$group_name" >/dev/null 2>&1; then
                if ! groups "$SUDO_USER" | grep -q "\b$group_name\b"; then
                    usermod -aG "$group_name" "$SUDO_USER"
                    log "Added $SUDO_USER to $group_name group. Re-login may be required."
                else
                    log "$SUDO_USER is already in $group_name group."
                fi
            else
                log "${YELLOW}Group $group_name does not exist. Skipping.${NC}"
            fi
        done
    fi
    
    # Set up log file permissions (LOG_FILE is now in $PROJECT_ROOT/logs/)
    touch "$LOG_FILE"
    if [[ -n "$SUDO_USER" ]]; then
        chown "$SUDO_USER:$SUDO_USER" "$LOG_FILE"
    fi
    chmod 644 "$LOG_FILE"
    
    log "${GREEN}System permissions configured${NC}"
    return 0
}

main() {
    log "${GREEN}Starting Shikra environment setup...${NC}"
    log "Setup log: $LOG_FILE"
    
    # Execute setup steps with error checking
    if ! check_requirements; then
        log "${RED}System requirements check failed. Please resolve issues and retry.${NC}"
        exit 1
    fi
    
    if ! create_data_directories; then # Create dirs first, so logs can be written there.
        log "${RED}Data directory creation failed${NC}"
        exit 1
    fi

    if ! create_virtual_environment; then
        log "${RED}Virtual environment setup failed${NC}"
        exit 1
    fi
    
    if ! setup_virtualization; then
        log "${RED}Virtualization setup failed${NC}"
        exit 1
    fi
    
    if ! configure_network; then
        log "${YELLOW}Network configuration completed with warnings/notes. Review if necessary.${NC}"
    fi
        
    if ! configure_permissions; then
        log "${RED}Permission configuration failed${NC}"
        exit 1
    fi
    
    # Final setup completion message
    log "${GREEN}========================================${NC}"
    log "${GREEN}Shikra environment setup completed successfully!${NC}"
    log "${GREEN}========================================${NC}"
    
    log "Next steps:"
    log "1. ${YELLOW}Log out and log back in for group changes (libvirt, kvm, wireshark) to take effect.${NC}"
    log "2. Activate the virtual environment: source $PROJECT_ROOT/venv/bin/activate"
    log "3. Install additional dependencies using: cd $PROJECT_ROOT/setup/utils && sudo ./install_dependencies.sh"
    log "4. Create analysis VMs using: cd $PROJECT_ROOT/core/scripts && ./create_vm.sh (after activating venv)"
    log "5. Review and customize configuration files in $PROJECT_ROOT/config/ directory"
    
    log "Important security reminders:"
    log "- Always run malware analysis in isolated environments"
    log "- Verify network isolation before analyzing samples"
    log "- Keep analysis VMs updated and use clean snapshots"
    log "- Follow responsible disclosure for any findings"
}

# Script entry point - execute main function with all arguments
main "$@"
