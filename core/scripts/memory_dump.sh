#!/bin/bash
# Shikra Memory Dump Collection Script
#
# Purpose:
# This script automates the process of collecting memory dumps from virtual machines
# used in the Shikra malware analysis environment. Memory dumps are vital for in-depth
# forensic analysis, allowing examination of runtime data, process memory, kernel
# structures, and other volatile artifacts.
#
# Key Functions Implemented (Conceptual):
# - parse_arguments(): Handle options for VM name, output path, dump format.
# - check_vm_status(): Ensure VM is in a suitable state for dumping (usually running).
# - select_dump_tool(): Choose appropriate dump tool based on hypervisor (e.g., virsh dump, VBoxManage debugvm).
# - execute_memory_dump(): Perform the memory dump operation.
# - validate_dump(): Basic validation of the dump file (e.g., size, format).
# - compress_dump(): Optionally compress the dump file.
#
# Usage:
#   ./memory_dump.sh --vm <vm_name> --output <output_dir_path> [options]
#
# Examples:
#   ./memory_dump.sh --vm win10-analysis --output /data/results/analysis_XYZ/memory --format raw
#   ./memory_dump.sh --vm ubuntu-sandbox --output /tmp/memdumps --compress

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")" # shikra/
DEFAULT_DUMPS_DIR="$PROJECT_ROOT/data/memory_dumps" # Default if --output not specified
LOG_FILE="$PROJECT_ROOT/logs/memory_dump.log" # Centralized logs

# --- Parameters (to be set by parse_arguments) ---
VM_NAME=""
OUTPUT_PATH="" # Full path to the output dump file or directory
DUMP_FORMAT="raw" # Default format (raw, elf, kdump - hypervisor dependent)
DO_COMPRESS=false
DO_VALIDATE=false

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    if [[ -n "$OUTPUT_PATH" && -d "$(dirname "$OUTPUT_PATH")" ]]; then
         echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$(dirname "$OUTPUT_PATH")/memory_dump_run.log"
    fi
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 --vm <vm_name> --output <path_to_dump_file_or_dir> [options]"
    echo ""
    echo "Required Arguments:"
    echo "  --vm <name>              Name of the VM to dump memory from."
    echo "  --output <path>          Full path for the output dump file, or a directory"
    echo "                           where 'memory_dump.<format>' will be created."
    echo ""
    echo "Optional Arguments:"
    echo "  --format <fmt>           Dump format (e.g., raw, elf). Default: raw."
    echo "  --compress               Compress the dump file using gzip after collection."
    echo "  --validate               Perform basic validation of the dump file."
    echo "  -h, --help               Show this help message."
    echo ""
    echo "Examples:"
    echo "  $0 --vm win10-clean --output /tmp/win10_mem.raw"
    echo "  $0 --vm ubu-test --output $DEFAULT_DUMPS_DIR/my_analysis --compress --format elf"
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    while [[ $# -gt 0 ]]; do
        case $1 in
            --vm) VM_NAME="$2"; shift 2 ;;
            --output) OUTPUT_PATH="$2"; shift 2 ;;
            --format) DUMP_FORMAT="$2"; shift 2 ;;
            --compress) DO_COMPRESS=true; shift ;;
            --validate) DO_VALIDATE=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if [[ -z "$VM_NAME" || -z "$OUTPUT_PATH" ]]; then
        log "${RED}Error: --vm and --output are required.${NC}"
        show_usage
        exit 1
    fi

    # If OUTPUT_PATH is a directory, construct filename
    if [[ -d "$OUTPUT_PATH" ]]; then
        mkdir -p "$OUTPUT_PATH" # Ensure it exists
        FINAL_OUTPUT_FILE="$OUTPUT_PATH/memory_dump.${VM_NAME}.${DUMP_FORMAT}"
    else
        FINAL_OUTPUT_FILE="$OUTPUT_PATH"
        mkdir -p "$(dirname "$FINAL_OUTPUT_FILE")" # Ensure parent dir exists
    fi
    OUTPUT_PATH="$FINAL_OUTPUT_FILE" # Update OUTPUT_PATH to be the full file path

    log "VM Name: $VM_NAME"
    log "Output File: $OUTPUT_PATH"
    log "Dump Format: $DUMP_FORMAT"
    log "Compress: $DO_COMPRESS"
    log "Validate: $DO_VALIDATE"
}

check_vm_status() {
    log "${BLUE}Checking status of VM '$VM_NAME'...${NC}"
    # Example for KVM/libvirt:
    # if ! virsh domstate "$VM_NAME" | grep -q "running"; then
    #     log "${YELLOW}Warning: VM '$VM_NAME' is not currently running. Memory dump might fail or be inconsistent.${NC}"
    #     # Depending on policy, one might choose to exit or proceed with caution.
    #     # For live analysis, VM should be running. For cold dumps, it might be off.
    # fi
    log "${YELLOW}Placeholder: VM status check (e.g., virsh domstate) needed.${NC}"
    log "${GREEN}VM status check conceptually passed (assuming suitable state for dump).${NC}"
}

execute_memory_dump() {
    log "${BLUE}Starting memory dump for VM '$VM_NAME' to '$OUTPUT_PATH'...${NC}"
    local dump_start_time=$(date +%s)

    # Placeholder for hypervisor-specific dump command
    # Example for KVM/libvirt:
    # log "Using 'virsh dump' for KVM/libvirt..."
    # if ! sudo virsh dump "$VM_NAME" "$OUTPUT_PATH" --memory-only --format "$DUMP_FORMAT"; then
    #     log "${RED}Error: Memory dump failed for VM '$VM_NAME'. Check virsh logs.${NC}"
    #     exit 1
    # fi

    # Example for VirtualBox:
    # log "Using 'VBoxManage debugvm dumpguestcore' for VirtualBox..."
    # if ! VBoxManage debugvm "$VM_NAME" dumpguestcore --filename "$OUTPUT_PATH"; then
    #    log "${RED}Error: Memory dump failed for VM '$VM_NAME'. Check VBoxManage logs.${NC}"
    #    exit 1
    # fi
    # Note: VirtualBox dump format is typically raw. Format conversion might be needed if ELF is requested.
    log "${YELLOW}Placeholder: Actual memory dump command (e.g., virsh dump, VBoxManage) needs implementation.${NC}"

    if [[ ! -f "$OUTPUT_PATH" ]]; then
        log "${RED}Error: Dump file '$OUTPUT_PATH' was not created.${NC}"
        # Create a dummy file for script to proceed for demonstration
        touch "$OUTPUT_PATH"
        log "${YELLOW}Created a dummy empty dump file for demonstration purposes.${NC}"
        # exit 1 # In a real script, exit here.
    fi

    local dump_end_time=$(date +%s)
    local duration=$((dump_end_time - dump_start_time))
    log "${GREEN}Memory dump conceptually completed in ${duration}s.${NC}"
    log "Raw dump (conceptual) saved to: $OUTPUT_PATH"
}

validate_dump_file() {
    if [[ "$DO_VALIDATE" != "true" ]]; then
        return
    fi
    log "${BLUE}Validating dump file '$OUTPUT_PATH'...${NC}"
    if [[ ! -f "$OUTPUT_PATH" ]]; then
        log "${RED}Validation Error: Dump file not found at '$OUTPUT_PATH'.${NC}"; return 1;
    fi
    local file_size=$(stat -c%s "$OUTPUT_PATH")
    log "Dump file size: $file_size bytes."
    if [[ $file_size -lt 1048576 ]]; then # Less than 1MB
        log "${YELLOW}Warning: Dump file size is very small. This might indicate an issue.${NC}"
    fi

    # Basic format check (e.g., for ELF if that's the format)
    # if [[ "$DUMP_FORMAT" == "elf" ]]; then
    #    if command -v readelf >/dev/null 2>&1 && readelf -h "$OUTPUT_PATH" >/dev/null 2>&1; then
    #        log "${GREEN}ELF format header check passed.${NC}"
    #    else
    #        log "${RED}ELF format header check failed or readelf not available.${NC}"
    #    fi
    # fi
    log "${YELLOW}Placeholder: More specific dump validation (e.g., using Volatility's imageinfo) needed.${NC}"
    log "${GREEN}Basic dump validation conceptually completed.${NC}"
}

compress_dump_file() {
    if [[ "$DO_COMPRESS" != "true" ]]; then
        return
    fi
    local target_compressed_file="${OUTPUT_PATH}.gz"
    log "${BLUE}Compressing dump file '$OUTPUT_PATH' to '$target_compressed_file'...${NC}"
    if [[ ! -f "$OUTPUT_PATH" ]]; then
        log "${RED}Compression Error: Source dump file not found at '$OUTPUT_PATH'.${NC}"; return 1;
    fi

    # if gzip -c "$OUTPUT_PATH" > "$target_compressed_file"; then
    #    log "${GREEN}Dump file compressed successfully.${NC}"
    #    log "Compressed file: $target_compressed_file"
    #    # Optionally remove original raw dump after successful compression
    #    # rm "$OUTPUT_PATH"
    #    # log "Original dump file removed."
    # else
    #    log "${RED}Error: Compression failed.${NC}"; return 1;
    # fi
    log "${YELLOW}Placeholder: Actual file compression (e.g., gzip) needed.${NC}"
    # Create a dummy compressed file for script to proceed for demonstration
    touch "$target_compressed_file"
    log "${YELLOW}Created a dummy empty compressed file for demonstration purposes.${NC}"
    log "${GREEN}Dump file conceptually compressed.${NC}"
}

# --- Main Execution ---
main() {
    log "${GREEN}--- Shikra Memory Dump Script Started ---${NC}"
    parse_arguments "$@"
    check_vm_status
    execute_memory_dump
    validate_dump_file
    compress_dump_file
    log "${GREEN}--- Memory Dump Process Finished ---${NC}"
    if [[ "$DO_COMPRESS" == "true" ]]; then
        log "Final dump file (compressed): ${OUTPUT_PATH}.gz (conceptual)"
    else
        log "Final dump file: $OUTPUT_PATH (conceptual)"
    fi
    log "Next step: Analyze with Volatility or other memory forensic tools."
}

main "$@"
