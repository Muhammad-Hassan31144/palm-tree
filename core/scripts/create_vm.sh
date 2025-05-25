#!/bin/bash
# Shikra VM Creation Script
#
# Purpose:
# This script automates the creation and configuration of virtual machines specifically
# tailored for malware analysis within the Shikra environment. It creates VMs with
# proper isolation, monitoring tools, and stealth configurations to ensure effective
# and safe malware analysis.
#
# Key Functions Implemented (Conceptual):
# - parse_arguments(): Handle command-line options for VM configuration.
# - load_vm_profile(): Load VM specifications from JSON configuration files.
# - create_base_vm(): Create the fundamental VM structure and disk image.
# - install_os(): Automate operating system installation from ISO.
# - install_analysis_tools(): Deploy monitoring and analysis tools inside VM.
# - configure_stealth(): Apply anti-detection measures to avoid evasive malware.
# - create_snapshot(): Take clean baseline snapshot for analysis resets.
#
# Usage:
#   ./create_vm.sh --name <vm_name> --profile <profile_name> [options]
#
# Examples:
#   ./create_vm.sh --name win10_analysis --profile default --os-iso /path/to/windows10.iso
#   ./create_vm.sh --name ubuntu_sandbox --profile linux_analysis --memory 8192 --disk 60G
#
# VM Profiles:
# VM profiles are JSON files in config/vm_profiles/ that define:
# - Operating system type and version
# - Hardware specifications (RAM, CPU, disk)
# - Software packages to install
# - Stealth and anti-detection settings
# - Monitoring tool configurations

# --- Script Configuration and Global Variables ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Assuming this script is in shikra/core/scripts/, then PROJECT_ROOT is shikra/
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config"
VM_PROFILES_DIR="$CONFIG_DIR/vm_profiles"
VM_IMAGES_DIR="$PROJECT_ROOT/data/vm_images" # Corrected path relative to PROJECT_ROOT
LOG_FILE="$PROJECT_ROOT/logs/vm_creation.log" # Centralized logs

# --- Command Line Arguments (to be set by parse_arguments) ---
VM_NAME=""
PROFILE_NAME=""
OS_ISO_PATH=""
MEMORY_MB=""
DISK_SIZE_GB=""
ENABLE_STEALTH=false

# --- Color Codes for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")" # Ensure log directory exists
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 --name <vm_name> --profile <profile_name> [options]"
    echo ""
    echo "Required Arguments:"
    echo "  --name <name>            Name for the new VM"
    echo "  --profile <profile>      VM profile to use (from $VM_PROFILES_DIR/)"
    echo ""
    echo "Optional Arguments:"
    echo "  --os-iso <path>          Path to OS installation ISO file"
    echo "  --memory <mb>            Memory allocation in MB (overrides profile)"
    echo "  --disk <gb>              Disk size in GB (overrides profile)"
    echo "  --stealth                Enable stealth/anti-detection features"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --name win10_lab --profile default --os-iso /isos/win10.iso"
    echo "  $0 --name custom_vm --profile evasive_malware --memory 8192 --stealth"
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name) VM_NAME="$2"; shift 2 ;;
            --profile) PROFILE_NAME="$2"; shift 2 ;;
            --os-iso) OS_ISO_PATH="$2"; shift 2 ;;
            --memory) MEMORY_MB="$2"; shift 2 ;;
            --disk) DISK_SIZE_GB="$2"; shift 2 ;;
            --stealth) ENABLE_STEALTH=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if [[ -z "$VM_NAME" || -z "$PROFILE_NAME" ]]; then
        log "${RED}Error: --name and --profile are required.${NC}"
        show_usage
        exit 1
    fi

    log "VM Name: $VM_NAME"
    log "Profile: $PROFILE_NAME"
    log "OS ISO: ${OS_ISO_PATH:-'Not specified, using profile or pre-built image logic'}"
    log "Memory: ${MEMORY_MB:-'Using profile setting'} MB"
    log "Disk: ${DISK_SIZE_GB:-'Using profile setting'} GB"
    log "Stealth: $ENABLE_STEALTH"
}

load_vm_profile() {
    log "${BLUE}Loading VM profile: $PROFILE_NAME${NC}"
    local profile_file="$VM_PROFILES_DIR/${PROFILE_NAME}.json"

    if [[ ! -f "$profile_file" ]]; then
        log "${RED}Error: VM profile not found: $profile_file${NC}"
        log "Available profiles in $VM_PROFILES_DIR/:"
        ls -1 "$VM_PROFILES_DIR"/*.json 2>/dev/null | sed 's/.*\///;s/\.json$//' | sed 's/^/  /' || log "  No profiles found."
        exit 1
    fi

    log "Profile loaded successfully: $profile_file"
    # Placeholder for actual JSON parsing and variable assignment
    # Example: MEMORY_MB_PROFILE=$(jq -r '.memory_mb // empty' "$profile_file")
    # MEMORY_MB=${MEMORY_MB:-$MEMORY_MB_PROFILE}
    # Similarly for DISK_SIZE_GB, OS_ISO_PATH (if not overridden) etc.
    # For now, we assume these are handled by a Python helper or set manually for demo
    log "${YELLOW}Placeholder: Actual profile value extraction (e.g., RAM, disk size from JSON) needs to be implemented.${NC}"
}

create_base_vm() {
    log "${BLUE}Creating base VM: $VM_NAME${NC}"
    mkdir -p "$VM_IMAGES_DIR"
    local disk_path="$VM_IMAGES_DIR/${VM_NAME}.qcow2"
    # Use profile-defined or command-line overridden disk size
    local final_disk_size="${DISK_SIZE_GB:-60}G" # Default 60GB if not set by profile or arg

    log "Creating disk image: $disk_path ($final_disk_size)"
    # Placeholder for hypervisor-specific VM creation (e.g., qemu-img, VBoxManage, virt-install)
    # Example for QEMU (using qemu-img for disk and virt-install for VM definition):
    # if ! qemu-img create -f qcow2 "$disk_path" "$final_disk_size"; then
    #     log "${RED}Failed to create disk image.${NC}"
    #     exit 1
    # fi
    # log "Disk image created."
    #
    # if ! virt-install --name "$VM_NAME" --memory "${MEMORY_MB:-4096}" --vcpus 2 \
    #                  --disk path="$disk_path",format=qcow2,bus=virtio \
    #                  --network network=default,model=virtio \
    #                  --graphics vnc,listen=0.0.0.0 --noautoconsole \
    #                  --boot cdrom,hd --os-variant detect=on,name=generic; then # Adjust os-variant
    #     log "${RED}Failed to define VM with virt-install.${NC}"
    #     exit 1
    # fi
    log "${YELLOW}Placeholder: Actual VM creation using chosen hypervisor (e.g., virt-install, VBoxManage) needs to be implemented.${NC}"
    log "${GREEN}Base VM structure for '$VM_NAME' conceptually created.${NC}"
}

install_os() {
    log "${BLUE}Starting OS installation on $VM_NAME (if ISO provided)...${NC}"
    if [[ -z "$OS_ISO_PATH" ]]; then
        log "${YELLOW}No OS ISO specified (--os-iso). Assuming pre-built image or manual installation.${NC}"
        return 0
    fi
    if [[ ! -f "$OS_ISO_PATH" ]]; then
        log "${RED}Error: OS ISO not found: $OS_ISO_PATH${NC}"
        exit 1
    fi

    log "Installing OS from: $OS_ISO_PATH"
    # Placeholder for OS installation logic
    # This would involve booting the VM from the ISO and using an answer file (autounattend.xml, preseed, kickstart)
    # Example:
    # virt-install --name "$VM_NAME" ... --location "$OS_ISO_PATH" --extra-args "ks=http://path/to/kickstart.cfg" (for Linux)
    # or modifying VM to boot from ISO and expecting an unattended install.
    log "${YELLOW}Placeholder: Automated OS installation (e.g., using answer files) needs to be implemented.${NC}"
    log "${GREEN}OS installation conceptually completed for $VM_NAME.${NC}"
}

install_analysis_tools() {
    log "${BLUE}Installing analysis tools in $VM_NAME...${NC}"
    # Placeholder for installing tools inside the VM
    # This requires VM to be running and accessible (e.g., via guest agent, SSH, WinRM)
    # Tools: Python, Sysinternals, Noriben, custom scripts, etc.
    log "${YELLOW}Placeholder: Analysis tool installation inside the VM needs to be implemented.${NC}"
    log "${GREEN}Analysis tools conceptually installed in $VM_NAME.${NC}"
}

configure_stealth() {
    if [[ "$ENABLE_STEALTH" != "true" ]]; then
        log "Stealth features disabled, skipping stealth configuration."
        return 0
    fi
    log "${BLUE}Configuring stealth measures for $VM_NAME...${NC}"
    # Placeholder for applying stealth configurations
    # This involves modifying VM hardware IDs, guest OS registry/files, faking user activity etc.
    # Could call a Python module: $PROJECT_ROOT/core/modules/vm_controller/stealth.py
    log "${YELLOW}Placeholder: Stealth configuration (modifying DMI, MAC, registry, etc.) needs to be implemented.${NC}"
    log "${GREEN}Stealth measures conceptually configured for $VM_NAME.${NC}"
}

create_snapshot() {
    log "${BLUE}Creating clean baseline snapshot for $VM_NAME...${NC}"
    local snapshot_name="clean_baseline"
    local snapshot_desc="Clean VM state after initial setup - $(date +'%Y-%m-%d %H:%M:%S')"

    # Placeholder for hypervisor-specific snapshot creation
    # Example for libvirt:
    # if ! virsh snapshot-create-as --domain "$VM_NAME" --name "$snapshot_name" --description "$snapshot_desc" --atomic; then
    #    log "${RED}Failed to create snapshot '$snapshot_name' for VM '$VM_NAME'.${NC}"
    #    exit 1
    # fi
    log "${YELLOW}Placeholder: Actual snapshot creation (e.g., virsh snapshot-create-as) needs to be implemented.${NC}"
    log "${GREEN}Clean snapshot '$snapshot_name' conceptually created for $VM_NAME.${NC}"
}

cleanup_on_error() {
    log "${YELLOW}An error occurred. Cleaning up partially created resources for $VM_NAME...${NC}"
    # Placeholder for cleanup logic
    # Example: undefine VM, remove disk image
    # if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    #     log "Undefining VM $VM_NAME..."
    #     virsh undefine "$VM_NAME" --remove-all-storage >/dev/null 2>&1 || \
    #         virsh undefine "$VM_NAME" >/dev/null 2>&1 # Try without removing storage if it fails
    # fi
    # local disk_path="$VM_IMAGES_DIR/${VM_NAME}.qcow2"
    # if [[ -f "$disk_path" ]]; then
    #     log "Removing disk image $disk_path..."
    #     rm -f "$disk_path"
    # fi
    log "${YELLOW}Placeholder: Error cleanup logic needs to be implemented.${NC}"
    log "Cleanup attempt completed."
}

# --- Main Execution ---
main() {
    log "${GREEN}--- Shikra VM Creation Script Started ---${NC}"
    trap cleanup_on_error ERR # Setup error handling

    parse_arguments "$@"
    load_vm_profile
    create_base_vm
    # The following steps assume the VM is defined and potentially OS is installed/tools are copied
    # For a fully automated script, these would be hypervisor commands or guest interactions
    install_os
    # (Potentially start VM here if needed for tool installation)
    install_analysis_tools
    configure_stealth
    # (Potentially shutdown VM here before snapshot if tools were installed on running VM)
    create_snapshot

    log "${GREEN}--- VM Creation Process Completed Successfully for $VM_NAME ---${NC}"
    log "VM Details:"
    log "  Name: $VM_NAME"
    log "  Profile: $PROFILE_NAME"
    log "  Disk Image: $VM_IMAGES_DIR/${VM_NAME}.qcow2 (conceptual)"
    log "  Snapshot: clean_baseline (conceptual)"
    log "Next steps:"
    log "1. Verify VM using hypervisor tools (e.g., 'virsh list --all')."
    log "2. If OS was not auto-installed, install it manually then run tool/stealth/snapshot steps."
    log "3. Configure network using '$PROJECT_ROOT/core/scripts/network_setup.sh'."
}

main "$@"
