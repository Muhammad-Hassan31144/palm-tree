#!/bin/bash
# Shikra Environment Cleanup Script
#
# Purpose:
# This script is responsible for cleaning up the Shikra analysis environment.
# This includes reverting VMs to clean snapshots, shutting down VMs, removing
# temporary network configurations, deleting old analysis data, and stopping
# any lingering processes related to Shikra.
#
# Key Functions Implemented (Conceptual):
# - parse_arguments(): Determine scope of cleanup (VMs, network, files, all).
# - cleanup_vms(): Shutdown and revert specified or all analysis VMs.
# - cleanup_network(): Remove temporary bridges, firewall rules created by network_setup.sh.
# - cleanup_data(): Delete old analysis results/logs based on retention policy.
# - cleanup_processes(): Kill any lingering Shikra-related processes.
#
# Usage:
#   ./cleanup.sh [--all | --vms [<vm_name>] | --network [<interface_name>] | --data [<age_days>] | --processes]
#
# Examples:
#   ./cleanup.sh --all
#   ./cleanup.sh --vms win10-analysis
#   ./cleanup.sh --network shikra-br0
#   ./cleanup.sh --data 7  (removes data older than 7 days)

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")" # shikra/
RESULTS_BASE_DIR="$PROJECT_ROOT/data/results"
LOG_FILE="$PROJECT_ROOT/logs/cleanup.log" # Centralized logs

# --- Cleanup Flags (to be set by parse_arguments) ---
CLEANUP_ALL=false
CLEANUP_VMS=false
TARGET_VM=""
CLEANUP_NETWORK=false
TARGET_NETWORK_IF=""
CLEANUP_DATA=false
DATA_RETENTION_DAYS=30 # Default: delete data older than 30 days
CLEANUP_PROCESSES=false

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --all                    Perform all cleanup actions (VMs, network, data, processes)."
    echo "  --vms [vm_name]          Clean up VMs. If vm_name is provided, only that VM."
    echo "                           Otherwise, attempts to clean all known Shikra VMs."
    echo "                           Actions: shutdown, revert to 'clean_baseline' snapshot."
    echo "  --network [if_name]      Clean up network configurations. If if_name (bridge) is provided,"
    echo "                           targets that specific interface. Otherwise, attempts to find known Shikra interfaces."
    echo "  --data [days]            Clean up old analysis data from '$RESULTS_BASE_DIR'."
    echo "                           If 'days' is provided, data older than 'days' is removed."
    echo "                           Default retention: $DATA_RETENTION_DAYS days."
    echo "  --processes              Kill lingering Shikra-related processes."
    echo "  -h, --help               Show this help message."
    echo ""
    echo "If no options are provided, a basic cleanup (VMs and default network interfaces) might be assumed or help shown."
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    if [[ $# -eq 0 ]]; then
        log "${YELLOW}No cleanup options specified. Performing default cleanup: VMs and known network interfaces.${NC}"
        CLEANUP_VMS=true
        CLEANUP_NETWORK=true # Will try to find default/known interfaces
        # CLEANUP_PROCESSES=true # Consider if this should be default
        # CLEANUP_DATA=true # Consider if this should be default with retention
        # return
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                CLEANUP_ALL=true; CLEANUP_VMS=true; CLEANUP_NETWORK=true; CLEANUP_DATA=true; CLEANUP_PROCESSES=true;
                shift ;;
            --vms)
                CLEANUP_VMS=true;
                if [[ -n "$2" && ! "$2" =~ ^-- ]]; then TARGET_VM="$2"; shift; fi;
                shift ;;
            --network)
                CLEANUP_NETWORK=true;
                if [[ -n "$2" && ! "$2" =~ ^-- ]]; then TARGET_NETWORK_IF="$2"; shift; fi;
                shift ;;
            --data)
                CLEANUP_DATA=true;
                if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then DATA_RETENTION_DAYS="$2"; shift; fi;
                shift ;;
            --processes)
                CLEANUP_PROCESSES=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter or missing argument: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if ! $CLEANUP_ALL && ! $CLEANUP_VMS && ! $CLEANUP_NETWORK && ! $CLEANUP_DATA && ! $CLEANUP_PROCESSES; then
         log "${YELLOW}No specific cleanup actions chosen. Defaulting to VMs and Network cleanup.${NC}"
         CLEANUP_VMS=true
         CLEANUP_NETWORK=true
    fi

    log "Cleanup Scope:"
    [[ "$CLEANUP_VMS" == "true" ]] && log "  VMs: Enabled ${TARGET_VM:+(Target: $TARGET_VM)}"
    [[ "$CLEANUP_NETWORK" == "true" ]] && log "  Network: Enabled ${TARGET_NETWORK_IF:+(Target Interface: $TARGET_NETWORK_IF)}"
    [[ "$CLEANUP_DATA" == "true" ]] && log "  Data: Enabled (Retention: $DATA_RETENTION_DAYS days)"
    [[ "$CLEANUP_PROCESSES" == "true" ]] && log "  Processes: Enabled"
}

cleanup_target_vms() {
    if [[ "$CLEANUP_VMS" != "true" ]]; then return; fi
    log "${BLUE}Starting VM cleanup...${NC}"

    local vms_to_clean=()
    if [[ -n "$TARGET_VM" ]]; then
        vms_to_clean=("$TARGET_VM")
    else
        log "Attempting to identify all Shikra-managed VMs..."
        # Placeholder: Logic to find all VMs managed by Shikra (e.g., by naming convention or tags if supported)
        # Example: for vm in $(virsh list --all --name | grep -E "shikra|analysis|sandbox"); do vms_to_clean+=("$vm"); done
        log "${YELLOW}Placeholder: Logic to identify all Shikra VMs needed if no specific VM is targeted.${NC}"
        # For demo, assume a known VM if none specified
        # vms_to_clean=("win10-analysis" "ubuntu-sandbox")
    fi

    if [[ ${#vms_to_clean[@]} -eq 0 && -z "$TARGET_VM" ]]; then
        log "${YELLOW}No Shikra VMs identified for cleanup.${NC}"
        return
    elif [[ ${#vms_to_clean[@]} -eq 0 && -n "$TARGET_VM" ]]; then
        log "${YELLOW}Target VM '$TARGET_VM' not found or not identifiable by current logic.${NC}"
        # Add a check: if ! virsh dominfo "$TARGET_VM" >/dev/null 2>&1; then log "${RED}VM $TARGET_VM does not exist.${NC}"; return; fi
    fi


    for vm in "${vms_to_clean[@]}"; do
        log "Processing VM: $vm"
        # Check if VM exists (hypervisor specific)
        # if ! virsh dominfo "$vm" > /dev/null 2>&1; then
        #     log "${YELLOW}VM '$vm' not found or not defined. Skipping.${NC}"
        #     continue
        # fi

        # Shutdown VM if running
        # if virsh domstate "$vm" | grep -q "running"; then
        #     log "Shutting down VM '$vm'..."
        #     virsh shutdown "$vm" >/dev/null 2>&1
        #     # Wait for shutdown, then destroy if still running
        #     sleep 5
        #     if virsh domstate "$vm" | grep -q "running"; then
        #         log "${YELLOW}VM '$vm' did not shutdown gracefully. Forcing power-off...${NC}"
        #         virsh destroy "$vm" >/dev/null 2>&1
        #     fi
        # fi
        log "${YELLOW}Placeholder: VM shutdown logic for '$vm' needed.${NC}"

        # Revert to clean_baseline snapshot if it exists
        # if virsh snapshot-list "$vm" | grep -q "clean_baseline"; then
        #     log "Reverting VM '$vm' to 'clean_baseline' snapshot..."
        #     if ! virsh snapshot-revert "$vm" clean_baseline --force; then
        #         log "${RED}Error reverting VM '$vm' to snapshot. Check hypervisor logs.${NC}"
        #     else
        #         log "VM '$vm' reverted to clean state."
        #     fi
        # else
        #     log "${YELLOW}No 'clean_baseline' snapshot found for VM '$vm'. Ensure it was created.${NC}"
        # fi
        log "${YELLOW}Placeholder: VM snapshot revert logic for '$vm' needed.${NC}"
    done
    log "${GREEN}VM cleanup conceptually completed.${NC}"
}

cleanup_target_network() {
    if [[ "$CLEANUP_NETWORK" != "true" ]]; then return; fi
    log "${BLUE}Starting network cleanup...${NC}"

    local interfaces_to_clean=()
    if [[ -n "$TARGET_NETWORK_IF" ]]; then
        interfaces_to_clean=("$TARGET_NETWORK_IF")
    else
        log "Attempting to identify all Shikra-managed network interfaces..."
        # Placeholder: Logic to find interfaces (e.g., bridges like shikra-br*, virbr-shikra*)
        # Example: for iface in $(ip -br link show type bridge | awk '{print $1}' | grep -E "shikra|analysis"); do interfaces_to_clean+=("$iface"); done
        # Example for libvirt networks: for net in $(virsh net-list --name | grep -E "shikra|analysis"); do interfaces_to_clean+=("$net"); done # Note: these are network names, not interfaces
        log "${YELLOW}Placeholder: Logic to identify Shikra network interfaces/libvirt networks needed.${NC}"
        # interfaces_to_clean=("shikra-br0" "virbr-analysis-XYZ") # Demo
    fi

    if [[ ${#interfaces_to_clean[@]} -eq 0 ]]; then
        log "${YELLOW}No Shikra network interfaces identified for cleanup.${NC}"
        return
    fi

    for if_name in "${interfaces_to_clean[@]}"; do
        log "Cleaning up network interface/configuration: $if_name"
        # Call network_setup.sh in cleanup mode for this interface/network name
        # "$SCRIPT_DIR/network_setup.sh" --cleanup --interface "$if_name"
        # The network_setup.sh script should handle removal of bridges, firewall rules, dnsmasq configs related to if_name.
        log "${YELLOW}Placeholder: Call to network_setup.sh --cleanup --interface $if_name needed.${NC}"
    done
    log "${GREEN}Network cleanup conceptually completed.${NC}"
}

cleanup_analysis_data() {
    if [[ "$CLEANUP_DATA" != "true" ]]; then return; fi
    log "${BLUE}Cleaning up old analysis data (older than $DATA_RETENTION_DAYS days) from '$RESULTS_BASE_DIR'...${NC}"
    if [[ ! -d "$RESULTS_BASE_DIR" ]]; then
        log "${YELLOW}Results directory '$RESULTS_BASE_DIR' not found. Nothing to clean.${NC}"
        return
    fi

    # find "$RESULTS_BASE_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +"$DATA_RETENTION_DAYS" -exec echo "Removing old analysis directory: {}" \; -exec rm -rf {} \;
    log "${YELLOW}Placeholder: Actual 'find ... -exec rm -rf' command for deleting old data needed.${NC}"
    log "${GREEN}Old analysis data cleanup conceptually completed.${NC}"
}

cleanup_stray_processes() {
    if [[ "$CLEANUP_PROCESSES" != "true" ]]; then return; fi
    log "${BLUE}Cleaning up lingering Shikra-related processes...${NC}"
    # Patterns for Shikra processes (tcpdump, qemu instances for analysis, python scripts, etc.)
    # pkill -f "tcpdump.*shikra"
    # pkill -f "qemu-system.*shikra-vm"
    # pkill -f "python3.*shikra/core"
    # pkill -f "noriben.py.*shikra"
    log "${YELLOW}Placeholder: 'pkill -f' commands for specific Shikra process patterns needed.${NC}"
    log "${GREEN}Lingering process cleanup conceptually completed.${NC}"
}

# --- Main Execution ---
main() {
    log "${GREEN}--- Shikra Environment Cleanup Script Started ---${NC}"
    parse_arguments "$@"

    if $CLEANUP_VMS; then cleanup_target_vms; fi
    if $CLEANUP_NETWORK; then cleanup_target_network; fi
    if $CLEANUP_DATA; then cleanup_analysis_data; fi
    if $CLEANUP_PROCESSES; then cleanup_stray_processes; fi

    log "${GREEN}--- Shikra Cleanup Process Finished ---${NC}"
    if ! $CLEANUP_VMS && ! $CLEANUP_NETWORK && ! $CLEANUP_DATA && ! $CLEANUP_PROCESSES; then
        log "${YELLOW}No specific cleanup actions were enabled or triggered.${NC}"
        show_usage
    fi
}

main "$@"
