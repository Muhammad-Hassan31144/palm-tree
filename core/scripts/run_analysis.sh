#!/bin/bash
# Shikra Main Analysis Script
#
# Purpose:
# This script orchestrates the entire malware analysis workflow. It prepares the
# environment, executes the malware sample within a VM, monitors its behavior,
# collects artifacts, and then cleans up the environment.
#
# Workflow:
# 1. Parse arguments (sample path, VM name, timeout, etc.).
# 2. Validate sample and VM.
# 3. Prepare analysis environment (revert VM to clean snapshot, setup network).
# 4. Start monitoring (network capture, behavioral monitoring tools like Noriben/Procmon).
# 5. Transfer sample to VM and execute it.
# 6. Wait for analysis duration or malware termination.
# 7. Stop monitoring and collect all artifacts (logs, memory dump, screenshots).
# 8. Generate a preliminary summary of the analysis.
# 9. Clean up the environment (shutdown VM, revert snapshot if not done by cleanup script).
#
# Usage:
#   ./run_analysis.sh --sample <path_to_sample> --vm <vm_name> [options]
#
# Examples:
#   ./run_analysis.sh --sample /data/samples/malware.exe --vm win10-analysis --timeout 300
#   ./run_analysis.sh --sample /tmp/evil.dll --vm win7-stealth --memory-dump --screenshots

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")" # shikra/
SAMPLES_DIR="$PROJECT_ROOT/data/samples"
RESULTS_BASE_DIR="$PROJECT_ROOT/data/results"
LOG_FILE="$PROJECT_ROOT/logs/run_analysis.log" # Centralized logs

# --- Analysis Parameters (to be set by parse_arguments) ---
SAMPLE_PATH=""
VM_NAME=""
ANALYSIS_TIMEOUT_SECONDS=300 # Default 5 minutes
ANALYSIS_PROFILE="default"   # For future use, e.g., different toolsets
DO_MEMORY_DUMP=false
DO_SCREENSHOTS=false
NETWORK_MODE_ANALYSIS="isolated" # Network mode to use for this analysis run

# --- Runtime Variables ---
ANALYSIS_ID=""
CURRENT_ANALYSIS_DIR="" # Specific directory for this run's results
SAMPLE_BASENAME=""
SAMPLE_HASH_SHA256=""

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - [$ANALYSIS_ID] $1" | tee -a "$LOG_FILE"
    # Also log to analysis-specific log if CURRENT_ANALYSIS_DIR is set
    if [[ -n "$CURRENT_ANALYSIS_DIR" ]]; then
        mkdir -p "$CURRENT_ANALYSIS_DIR/logs"
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$CURRENT_ANALYSIS_DIR/logs/analysis_run.log"
    fi
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 --sample <path> --vm <vm_name> [options]"
    echo ""
    echo "Required Arguments:"
    echo "  --sample <path>          Path to the malware sample."
    echo "  --vm <name>              Name of the VM to use for analysis."
    echo ""
    echo "Optional Arguments:"
    echo "  --timeout <seconds>      Analysis duration in seconds (default: 300)."
    echo "  --profile <name>         Analysis profile (default: default, for future use)."
    echo "  --memory-dump            Enable memory dump collection."
    echo "  --screenshots            Enable periodic screenshot capture."
    echo "  --network-mode <mode>    Network mode for analysis (isolated, inetsim, nat). Default: isolated."
    echo "  -h, --help               Show this help message."
    echo ""
    echo "Examples:"
    echo "  $0 --sample samples/test.exe --vm win10-clean"
    echo "  $0 --sample /tmp/mal.exe --vm win7-stealth --timeout 600 --memory-dump"
}

parse_arguments() {
    # Initialize ANALYSIS_ID early for logging context
    ANALYSIS_ID="PRE_PARSE_$(date +%Y%m%d_%H%M%S)"
    log "${BLUE}Parsing command line arguments...${NC}"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --sample) SAMPLE_PATH="$2"; shift 2 ;;
            --vm) VM_NAME="$2"; shift 2 ;;
            --timeout) ANALYSIS_TIMEOUT_SECONDS="$2"; shift 2 ;;
            --profile) ANALYSIS_PROFILE="$2"; shift 2 ;;
            --memory-dump) DO_MEMORY_DUMP=true; shift ;;
            --screenshots) DO_SCREENSHOTS=true; shift ;;
            --network-mode) NETWORK_MODE_ANALYSIS="$2"; shift 2 ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if [[ -z "$SAMPLE_PATH" || -z "$VM_NAME" ]]; then
        log "${RED}Error: --sample and --vm are required.${NC}"
        show_usage
        exit 1
    fi
    if [[ ! -f "$SAMPLE_PATH" ]]; then
        log "${RED}Error: Sample file not found: $SAMPLE_PATH${NC}"
        exit 1
    fi

    SAMPLE_BASENAME=$(basename "$SAMPLE_PATH")
    SAMPLE_HASH_SHA256=$(sha256sum "$SAMPLE_PATH" | awk '{print $1}')
    ANALYSIS_ID="$(date +%Y%m%d_%H%M%S)_${SAMPLE_BASENAME}_${SAMPLE_HASH_SHA256:0:8}"
    CURRENT_ANALYSIS_DIR="$RESULTS_BASE_DIR/$ANALYSIS_ID"
    mkdir -p "$CURRENT_ANALYSIS_DIR/logs" # Create log dir for this specific analysis

    log "--- Analysis Run Initialized ---"
    log "Analysis ID: $ANALYSIS_ID"
    log "Sample Path: $SAMPLE_PATH"
    log "Sample SHA256: $SAMPLE_HASH_SHA256"
    log "VM Name: $VM_NAME"
    log "Timeout: ${ANALYSIS_TIMEOUT_SECONDS}s"
    log "Profile: $ANALYSIS_PROFILE"
    log "Memory Dump: $DO_MEMORY_DUMP"
    log "Screenshots: $DO_SCREENSHOTS"
    log "Network Mode: $NETWORK_MODE_ANALYSIS"
    log "Results Directory: $CURRENT_ANALYSIS_DIR"
}

validate_environment() {
    log "${BLUE}Validating environment...${NC}"
    # Check if VM exists and has a clean snapshot
    # if ! virsh dominfo "$VM_NAME" > /dev/null 2>&1; then
    #     log "${RED}Error: VM '$VM_NAME' does not exist.${NC}"; exit 1;
    # fi
    # if ! virsh snapshot-list "$VM_NAME" | grep -q "clean_baseline"; then
    #     log "${RED}Error: VM '$VM_NAME' does not have a 'clean_baseline' snapshot.${NC}"; exit 1;
    # fi
    log "${YELLOW}Placeholder: VM existence and snapshot validation needed (e.g., using virsh).${NC}"

    # Check for required tools (tcpdump, hypervisor CLI, etc.)
    # command -v tcpdump >/dev/null 2>&1 || { log "${RED}tcpdump not found.${NC}"; exit 1; }
    # command -v virsh >/dev/null 2>&1 || { log "${RED}virsh not found.${NC}"; exit 1; } # Example for KVM
    log "${YELLOW}Placeholder: Required host tool checks (tcpdump, hypervisor CLI) needed.${NC}"
    log "${GREEN}Environment validation conceptually passed.${NC}"
}

prepare_analysis_vm() {
    log "${BLUE}Preparing analysis VM '$VM_NAME'...${NC}"
    # Revert VM to clean snapshot
    # log "Reverting '$VM_NAME' to 'clean_baseline' snapshot..."
    # if ! virsh snapshot-revert "$VM_NAME" clean_baseline --force; then
    #     log "${RED}Error: Failed to revert VM '$VM_NAME' to snapshot.${NC}"; exit 1;
    # fi
    # log "VM reverted to clean state."

    # Start the VM
    # log "Starting VM '$VM_NAME'..."
    # if ! virsh start "$VM_NAME"; then
    #     log "${RED}Error: Failed to start VM '$VM_NAME'.${NC}"; exit 1;
    # fi
    # log "VM started. Waiting for guest OS to boot..."
    # Add delay or check for guest agent/IP
    # sleep 30 # Basic delay, better to check for guest readiness
    log "${YELLOW}Placeholder: VM snapshot revert and start (e.g., virsh snapshot-revert, virsh start) needed.${NC}"
    log "${GREEN}VM '$VM_NAME' conceptually prepared and started.${NC}"
}

setup_analysis_network() {
    log "${BLUE}Setting up network for analysis (Mode: $NETWORK_MODE_ANALYSIS)...${NC}"
    # Call network_setup.sh with appropriate parameters for this analysis run
    # Example:
    # "$SCRIPT_DIR/network_setup.sh" --mode "$NETWORK_MODE_ANALYSIS" \
    #    --interface "shikra-an-$ANALYSIS_ID" \ # Unique interface per analysis
    #    --subnet "192.168.200.0/24" \ # Potentially dynamic subnet allocation
    #    --gateway "192.168.200.1" \
    #    --dns "192.168.200.1" # Or INetSim IP
    # if [[ $? -ne 0 ]]; then
    #    log "${RED}Failed to set up network for analysis.${NC}"; exit 1;
    # fi
    # The VM needs to be configured to use this network.
    log "${YELLOW}Placeholder: Integration with network_setup.sh for dynamic analysis network setup needed.${NC}"
    log "${GREEN}Network conceptually configured for mode '$NETWORK_MODE_ANALYSIS'.${NC}"
}

start_monitoring_tools() {
    log "${BLUE}Starting monitoring tools...${NC}"
    mkdir -p "$CURRENT_ANALYSIS_DIR/network" "$CURRENT_ANALYSIS_DIR/behavioral" "$CURRENT_ANALYSIS_DIR/screenshots"

    # Start network capture (tcpdump)
    # local pcap_file="$CURRENT_ANALYSIS_DIR/network/traffic.pcap"
    # log "Starting network capture on relevant interface to $pcap_file..."
    # sudo tcpdump -i <analysis_bridge_interface> -w "$pcap_file" -U -s0 &
    # TCPDUMP_PID=$!
    # echo $TCPDUMP_PID > "$CURRENT_ANALYSIS_DIR/network/tcpdump.pid"
    # log "tcpdump started with PID $TCPDUMP_PID."
    log "${YELLOW}Placeholder: Network capture (tcpdump) start needed.${NC}"


    # Start behavioral monitoring (e.g., Noriben/Procmon inside VM)
    # This requires guest interaction (agent, pre-configured scripts)
    # Example:
    # python3 "$PROJECT_ROOT/core/modules/monitor/noriben_wrapper.py" --vm "$VM_NAME" --action start --output-vm "/tmp/noriben_out" --timeout "$ANALYSIS_TIMEOUT_SECONDS"
    log "${YELLOW}Placeholder: Behavioral monitoring start (e.g., Noriben via guest agent) needed.${NC}"

    # Start screenshot capture if enabled
    if [[ "$DO_SCREENSHOTS" == "true" ]]; then
        log "Starting periodic screenshot capture..."
        # (while true; do virsh screenshot "$VM_NAME" "$CURRENT_ANALYSIS_DIR/screenshots/shot_$(date +%s).png"; sleep 15; done) &
        # SCREENSHOT_PID=$!
        # echo $SCREENSHOT_PID > "$CURRENT_ANALYSIS_DIR/screenshots.pid"
        log "${YELLOW}Placeholder: Screenshot capture loop needed.${NC}"
    fi
    log "${GREEN}Monitoring tools conceptually started.${NC}"
}

execute_sample_in_vm() {
    log "${BLUE}Executing sample '$SAMPLE_BASENAME' in VM '$VM_NAME'...${NC}"
    local vm_tmp_path="/tmp/$SAMPLE_BASENAME" # Path inside VM

    # Transfer sample to VM
    # log "Transferring sample to VM at $vm_tmp_path..."
    # virt-copy-in -d "$VM_NAME" "$SAMPLE_PATH" /tmp/ # Requires libguestfs-tools
    # Or use guest agent: qemu-ga-client ... file-write ...
    log "${YELLOW}Placeholder: Sample transfer to VM (e.g., virt-copy-in or guest agent) needed.${NC}"

    # Execute sample in VM
    # log "Executing sample via guest agent/command..."
    # This is highly dependent on guest OS and agent capabilities.
    # Example for Windows guest with agent:
    # qemu-ga-client "$VM_NAME" --cmd guest-exec --args "C:\tmp\$SAMPLE_BASENAME"
    # Or for Linux:
    # qemu-ga-client "$VM_NAME" --cmd guest-exec --args "/tmp/$SAMPLE_BASENAME" --capture-output
    log "${YELLOW}Placeholder: Sample execution within VM (e.g., via guest agent) needed.${NC}"

    log "Waiting for analysis duration: ${ANALYSIS_TIMEOUT_SECONDS}s..."
    sleep "$ANALYSIS_TIMEOUT_SECONDS"
    log "Analysis duration ended."
}

collect_artifacts_from_vm() {
    log "${BLUE}Collecting artifacts from VM '$VM_NAME'...${NC}"
    mkdir -p "$CURRENT_ANALYSIS_DIR/artifacts_vm"

    # Collect behavioral logs (e.g., Noriben output)
    # log "Collecting Noriben logs from VM path /tmp/noriben_out..."
    # virt-copy-out -d "$VM_NAME" /tmp/noriben_out "$CURRENT_ANALYSIS_DIR/artifacts_vm/"
    log "${YELLOW}Placeholder: Collection of behavioral logs from VM needed.${NC}"

    # Collect memory dump if enabled
    if [[ "$DO_MEMORY_DUMP" == "true" ]]; then
        log "Collecting memory dump..."
        # "$SCRIPT_DIR/memory_dump.sh" --vm "$VM_NAME" --output "$CURRENT_ANALYSIS_DIR/memory" --format raw
        # if [[ $? -ne 0 ]]; then log "${YELLOW}Memory dump collection failed.${NC}"; else log "${GREEN}Memory dump collected.${NC}"; fi
        log "${YELLOW}Placeholder: Call to memory_dump.sh needed.${NC}"
    fi
    log "${GREEN}Artifact collection from VM conceptually completed.${NC}"
}

stop_monitoring_tools() {
    log "${BLUE}Stopping monitoring tools...${NC}"

    # Stop behavioral monitoring (signal Noriben/Procmon to finalize)
    # python3 "$PROJECT_ROOT/core/modules/monitor/noriben_wrapper.py" --vm "$VM_NAME" --action stop
    log "${YELLOW}Placeholder: Behavioral monitoring stop needed.${NC}"

    # Stop network capture
    # if [[ -f "$CURRENT_ANALYSIS_DIR/network/tcpdump.pid" ]]; then
    #     TCPDUMP_PID=$(cat "$CURRENT_ANALYSIS_DIR/network/tcpdump.pid")
    #     log "Stopping tcpdump (PID $TCPDUMP_PID)..."
    #     sudo kill "$TCPDUMP_PID"
    #     wait "$TCPDUMP_PID" 2>/dev/null
    #     rm "$CURRENT_ANALYSIS_DIR/network/tcpdump.pid"
    #     log "Network capture stopped."
    # fi
    log "${YELLOW}Placeholder: Network capture stop needed.${NC}"


    # Stop screenshot capture
    # if [[ "$DO_SCREENSHOTS" == "true" && -f "$CURRENT_ANALYSIS_DIR/screenshots.pid" ]]; then
    #     SCREENSHOT_PID=$(cat "$CURRENT_ANALYSIS_DIR/screenshots.pid")
    #     log "Stopping screenshot capture (PID $SCREENSHOT_PID)..."
    #     kill "$SCREENSHOT_PID"
    #     wait "$SCREENSHOT_PID" 2>/dev/null
    #     rm "$CURRENT_ANALYSIS_DIR/screenshots.pid"
    # fi
    log "${YELLOW}Placeholder: Screenshot capture stop needed.${NC}"

    log "${GREEN}Monitoring tools conceptually stopped.${NC}"
}

generate_run_summary() {
    log "${BLUE}Generating analysis run summary...${NC}"
    local summary_file="$CURRENT_ANALYSIS_DIR/analysis_summary.json"
    # Create a JSON summary of the run
    echo "{" > "$summary_file"
    echo "  \"analysis_id\": \"$ANALYSIS_ID\"," >> "$summary_file"
    echo "  \"sample_name\": \"$SAMPLE_BASENAME\"," >> "$summary_file"
    echo "  \"sample_sha256\": \"$SAMPLE_HASH_SHA256\"," >> "$summary_file"
    echo "  \"vm_name\": \"$VM_NAME\"," >> "$summary_file"
    echo "  \"analysis_timeout_seconds\": $ANALYSIS_TIMEOUT_SECONDS," >> "$summary_file"
    echo "  \"network_mode\": \"$NETWORK_MODE_ANALYSIS\"," >> "$summary_file"
    echo "  \"memory_dump_collected\": $DO_MEMORY_DUMP," >> "$summary_file"
    echo "  \"screenshots_collected\": $DO_SCREENSHOTS," >> "$summary_file"
    echo "  \"start_time_utc\": \"$(date -u --iso-8601=seconds)\"," >> "$summary_file" # Approx start, refine
    # Add paths to collected artifacts
    echo "  \"artifacts\": {" >> "$summary_file"
    echo "    \"pcap_file\": \"network/traffic.pcap\"," >> "$summary_file" # Relative to $CURRENT_ANALYSIS_DIR
    echo "    \"behavioral_logs_dir\": \"artifacts_vm/noriben_out\"," >> "$summary_file" # Example
    [[ "$DO_MEMORY_DUMP" == "true" ]] && echo "    \"memory_dump_file\": \"memory/memory_dump.raw\"," >> "$summary_file"
    echo "    \"main_log_file\": \"logs/analysis_run.log\"" >> "$summary_file"
    echo "  }" >> "$summary_file"
    echo "}" >> "$summary_file"
    log "${GREEN}Analysis summary generated at $summary_file${NC}"
}

cleanup_analysis_environment() {
    log "${BLUE}Cleaning up analysis environment for '$VM_NAME'...${NC}"
    # Shutdown the VM
    # log "Shutting down VM '$VM_NAME'..."
    # if virsh domstate "$VM_NAME" | grep -q "running"; then
    #    virsh shutdown "$VM_NAME" >/dev/null 2>&1
    #    sleep 10 # Give time for graceful shutdown
    #    if virsh domstate "$VM_NAME" | grep -q "running"; then
    #        log "${YELLOW}VM did not shutdown gracefully, forcing power-off...${NC}"
    #        virsh destroy "$VM_NAME" >/dev/null 2>&1
    #    fi
    # fi
    # log "VM '$VM_NAME' is shut down."

    # Optional: Revert to clean snapshot again as part of this script,
    # or rely on cleanup.sh / next run's prepare_analysis_vm.
    # For safety, good to ensure it's clean if not immediately running cleanup.sh.
    # log "Reverting '$VM_NAME' to 'clean_baseline' snapshot post-analysis..."
    # virsh snapshot-revert "$VM_NAME" clean_baseline --force >/dev/null 2>&1

    # Cleanup analysis-specific network (if dynamically created)
    # "$SCRIPT_DIR/network_setup.sh" --cleanup --interface "shikra-an-$ANALYSIS_ID"
    log "${YELLOW}Placeholder: VM shutdown and optional post-analysis snapshot revert needed.${NC}"
    log "${YELLOW}Placeholder: Cleanup of dynamic analysis network (if used) needed.${NC}"
    log "${GREEN}Analysis environment cleanup conceptually completed.${NC}"
}


# --- Main Execution ---
main() {
    parse_arguments "$@" # Sets ANALYSIS_ID and CURRENT_ANALYSIS_DIR

    log "${GREEN}--- Shikra Malware Analysis Run Started ---${NC}"
    # Ensure cleanup happens even if script exits unexpectedly
    trap cleanup_analysis_environment EXIT SIGINT SIGTERM

    validate_environment
    # prepare_analysis_vm # This should revert and start the VM
    # setup_analysis_network # This should configure network for the started VM
    # start_monitoring_tools
    # execute_sample_in_vm
    # stop_monitoring_tools
    # collect_artifacts_from_vm # Collects logs, memory dump etc.
    generate_run_summary

    log "${GREEN}--- Analysis Run for '$SAMPLE_BASENAME' (ID: $ANALYSIS_ID) Completed ---${NC}"
    log "Results are stored in: $CURRENT_ANALYSIS_DIR"
    log "Next steps: Perform post-analysis using tools in '$PROJECT_ROOT/analysis/' and reporting in '$PROJECT_ROOT/reporting/'."
}

main "$@"
