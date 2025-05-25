#!/bin/bash
# Shikra Network Setup Script
#
# Purpose:
# This script configures the network environment for safe malware analysis. It sets up
# isolated networks, configures firewalls, and can enable network simulation tools
# like INetSim. This ensures malware samples can be analyzed for network behavior
# without risk to the host or external networks.
#
# Key Functions Implemented (Conceptual):
# - parse_arguments(): Handle network configuration options.
# - create_isolated_network(): Set up isolated virtual networks (e.g., libvirt bridge).
# - configure_firewall(): Apply iptables/nftables rules for isolation.
# - setup_traffic_capture_interface(): Prepare interface for tcpdump/tshark.
# - setup_dns_redirection(): Configure local DNS (e.g., dnsmasq) for sinkholing/custom responses.
# - manage_inetsim(): Start/stop INetSim for service simulation.
#
# Usage:
#   ./network_setup.sh --mode <isolated|inetsim|nat> [options]
#
# Examples:
#   ./network_setup.sh --mode isolated --interface virbr-analysis
#   ./network_setup.sh --mode inetsim --subnet 10.0.3.0/24 --inetsim-ip 10.0.3.1
#   ./network_setup.sh --cleanup

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config"
LOG_FILE="$PROJECT_ROOT/logs/network_setup.log" # Centralized logs

# --- Network Configuration Variables (to be set by parse_arguments) ---
NETWORK_MODE="isolated" # Default mode
INTERFACE_NAME=""       # E.g., virbr-shikra, shikra-br0
SUBNET_CIDR=""          # E.g., 192.168.123.0/24
GATEWAY_IP=""           # E.g., 192.168.123.1
DNS_SERVER=""           # For VMs, often same as GATEWAY_IP or INetSim IP
INETSIM_IP=""           # IP for INetSim if mode is inetsim
DO_CLEANUP=false

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")" # Ensure log directory exists
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 --mode <isolated|inetsim|nat|custom> [options]"
    echo "       $0 --cleanup"
    echo ""
    echo "Modes:"
    echo "  isolated: VMs are on an isolated network, no internet access."
    echo "  inetsim: VMs use INetSim for simulated internet services."
    echo "  nat: VMs have NAT access to the internet (use with extreme caution)."
    echo "  custom: User provides all network parameters."
    echo ""
    echo "Options for configuration modes:"
    echo "  --interface <name>       Name for the virtual bridge/network interface (e.g., shikra-br0)."
    echo "  --subnet <cidr>          Subnet for the analysis network (e.g., 192.168.100.0/24)."
    echo "  --gateway <ip>           Gateway IP for the subnet (host side of the bridge)."
    echo "  --dns <ip>               DNS server IP for VMs (can be gateway or INetSim IP)."
    echo "  --inetsim-ip <ip>        IP address INetSim should bind to (if using inetsim mode)."
    echo ""
    echo "Cleanup Option:"
    echo "  --cleanup                Remove network configurations made by this script."
    echo ""
    echo "Examples:"
    echo "  $0 --mode isolated --interface shikra-br0 --subnet 192.168.100.0/24 --gateway 192.168.100.1"
    echo "  $0 --mode inetsim --interface shikra-br0 --subnet 10.0.3.0/24 --gateway 10.0.3.254 --inetsim-ip 10.0.3.1 --dns 10.0.3.1"
    echo "  $0 --cleanup --interface shikra-br0"
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    while [[ $# -gt 0 ]]; do
        case $1 in
            --mode) NETWORK_MODE="$2"; shift 2 ;;
            --interface) INTERFACE_NAME="$2"; shift 2 ;;
            --subnet) SUBNET_CIDR="$2"; shift 2 ;;
            --gateway) GATEWAY_IP="$2"; shift 2 ;;
            --dns) DNS_SERVER="$2"; shift 2 ;;
            --inetsim-ip) INETSIM_IP="$2"; shift 2 ;;
            --cleanup) DO_CLEANUP=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    # Validate based on mode or cleanup
    if [[ "$DO_CLEANUP" == "true" ]]; then
        if [[ -z "$INTERFACE_NAME" ]]; then
            log "${RED}Error: --interface is required for --cleanup.${NC}"
            show_usage; exit 1;
        fi
        log "Cleanup mode selected for interface: $INTERFACE_NAME"
        return
    fi

    if [[ -z "$NETWORK_MODE" || -z "$INTERFACE_NAME" || -z "$SUBNET_CIDR" || -z "$GATEWAY_IP" ]]; then
        log "${RED}Error: --mode, --interface, --subnet, and --gateway are required for setup.${NC}"
        show_usage
        exit 1
    fi
    if [[ "$NETWORK_MODE" == "inetsim" && -z "$INETSIM_IP" ]]; then
        log "${RED}Error: --inetsim-ip is required for inetsim mode.${NC}"
        show_usage
        exit 1
    fi
    DNS_SERVER=${DNS_SERVER:-$GATEWAY_IP} # Default DNS to gateway if not specified
    if [[ "$NETWORK_MODE" == "inetsim" && -n "$INETSIM_IP" ]]; then
        DNS_SERVER=${DNS_SERVER:-$INETSIM_IP} # For inetsim, DNS is usually INetSim itself
    fi


    log "Network Mode: $NETWORK_MODE"
    log "Interface: $INTERFACE_NAME"
    log "Subnet: $SUBNET_CIDR"
    log "Gateway: $GATEWAY_IP"
    log "DNS for VMs: $DNS_SERVER"
    [[ "$NETWORK_MODE" == "inetsim" ]] && log "INetSim IP: $INETSIM_IP"
}

create_isolated_network() {
    log "${BLUE}Creating isolated network: $INTERFACE_NAME ($SUBNET_CIDR)...${NC}"
    # Placeholder for creating a virtual bridge and assigning IP (e.g., using ip, brctl or libvirt net-define)
    # Example using iproute2 and brctl:
    # sudo ip link add name "$INTERFACE_NAME" type bridge
    # sudo ip addr add "$GATEWAY_IP/$(echo $SUBNET_CIDR | cut -d/ -f2)" dev "$INTERFACE_NAME"
    # sudo ip link set "$INTERFACE_NAME" up
    # log "Bridge $INTERFACE_NAME created and configured with $GATEWAY_IP."

    # Example using libvirt (define a network XML and then):
    # sudo virsh net-define network.xml
    # sudo virsh net-start $(basename "$INTERFACE_NAME" .xml) # if INTERFACE_NAME is XML file
    # sudo virsh net-autostart $(basename "$INTERFACE_NAME" .xml)
    log "${YELLOW}Placeholder: Actual isolated network creation (e.g., libvirt network or bridge setup) needs implementation.${NC}"
    log "${GREEN}Isolated network '$INTERFACE_NAME' conceptually created.${NC}"
}

configure_firewall() {
    log "${BLUE}Configuring firewall for $INTERFACE_NAME...${NC}"
    local subnet_ip_part=$(echo $SUBNET_CIDR | cut -d/ -f1)
    local subnet_mask=$(echo $SUBNET_CIDR | cut -d/ -f2)

    # Placeholder for iptables/nftables rules
    # Basic isolation: Allow traffic within the subnet, allow DHCP/DNS from host to subnet, drop other outbound.
    # Example iptables rules:
    # sudo iptables -P FORWARD DROP # Default drop
    # sudo iptables -A FORWARD -i "$INTERFACE_NAME" -o "$INTERFACE_NAME" -j ACCEPT # Allow intra-bridge traffic
    # sudo iptables -A FORWARD -i "$INTERFACE_NAME" -d "$SUBNET_CIDR" -j ACCEPT # From host to VMs on bridge
    # sudo iptables -A FORWARD -s "$SUBNET_CIDR" -o "$INTERFACE_NAME" -j ACCEPT # From VMs to host on bridge
    #
    # if [[ "$NETWORK_MODE" == "isolated" ]]; then
    #    sudo iptables -A FORWARD -i "$INTERFACE_NAME" ! -o "$INTERFACE_NAME" -j DROP # Drop outbound from bridge
    #    log "Configured firewall for full isolation on $INTERFACE_NAME."
    # elif [[ "$NETWORK_MODE" == "nat" ]]; then
    #    # Requires host's internet-facing interface (e.g., eth0)
    #    local host_if="eth0" # Replace with actual host interface
    #    sudo iptables -A FORWARD -i "$INTERFACE_NAME" -o "$host_if" -j ACCEPT
    #    sudo iptables -A FORWARD -i "$host_if" -o "$INTERFACE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT
    #    sudo iptables -t nat -A POSTROUTING -s "$SUBNET_CIDR" -o "$host_if" -j MASQUERADE
    #    log "Configured firewall for NAT on $INTERFACE_NAME via $host_if."
    #    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    # elif [[ "$NETWORK_MODE" == "inetsim" ]]; then
    #    # Allow traffic from VMs to INetSim IP on specific ports, drop other outbound.
    #    sudo iptables -A FORWARD -i "$INTERFACE_NAME" -d "$INETSIM_IP" -j ACCEPT # Allow to INetSim
    #    sudo iptables -A FORWARD -i "$INTERFACE_NAME" ! -o "$INTERFACE_NAME" -j DROP # Drop other outbound
    #    log "Configured firewall for INetSim on $INTERFACE_NAME (VMs to $INETSIM_IP allowed)."
    # fi
    log "${YELLOW}Placeholder: Actual firewall rule configuration (iptables/nftables) needs implementation.${NC}"
    log "${GREEN}Firewall rules conceptually configured for $NETWORK_MODE.${NC}"
}

setup_dns_dhcp() {
    log "${BLUE}Setting up DNS/DHCP for $INTERFACE_NAME...${NC}"
    # Placeholder for dnsmasq or similar setup
    # dnsmasq can provide DHCP and DNS for the isolated network.
    # Config file /etc/dnsmasq.conf or /etc/dnsmasq.d/shikra.conf:
    # interface=$INTERFACE_NAME
    # dhcp-range=$(echo $SUBNET_CIDR | cut -d. -f1-3).100,$(echo $SUBNET_CIDR | cut -d. -f1-3).200,12h
    # dhcp-option=option:router,$GATEWAY_IP
    # dhcp-option=option:dns-server,$DNS_SERVER
    # If INetSim is DNS: address=/#/$INETSIM_IP (sinkhole all to INetSim)
    # else if local DNS: address=/#/$GATEWAY_IP (sinkhole to gateway, or specific known good IPs)
    # sudo systemctl restart dnsmasq
    log "${YELLOW}Placeholder: DNS/DHCP server (e.g., dnsmasq) configuration needs implementation.${NC}"
    log "${GREEN}DNS/DHCP conceptually configured. VMs should get IP and use $DNS_SERVER for DNS.${NC}"
}

manage_inetsim_service() {
    if [[ "$NETWORK_MODE" != "inetsim" ]]; then
        return
    fi
    log "${BLUE}Managing INetSim service...${NC}"
    local inetsim_conf_path="$CONFIG_DIR/inetsim/inetsim.conf" # Standard path for INetSim config
    # Ensure INetSim config exists and is configured to bind to $INETSIM_IP
    # if [ ! -f "$inetsim_conf_path" ]; then
    #    log "${YELLOW}INetSim config $inetsim_conf_path not found. Please create it.${NC}"
    #    # Optionally, create a basic one here.
    # else
    #    # Modify inetsim.conf to use $INETSIM_IP (e.g., using sed)
    #    # sudo sed -i "s/^service_bind_address\s.*/service_bind_address $INETSIM_IP/" "$inetsim_conf_path"
    #    # sudo sed -i "s/^dns_default_ip\s.*/dns_default_ip $INETSIM_IP/" "$inetsim_conf_path"
    # fi
    # Start INetSim (e.g., sudo systemctl start inetsim or directly: sudo inetsim --conf "$inetsim_conf_path" --data "$PROJECT_ROOT/data/inetsim_data" &)
    log "${YELLOW}Placeholder: INetSim service management (config update, start/stop) needs implementation.${NC}"
    log "${GREEN}INetSim conceptually configured to run on $INETSIM_IP.${NC}"
}

cleanup_network_config() {
    log "${YELLOW}--- Cleaning Up Network Configuration for $INTERFACE_NAME ---${NC}"
    # Placeholder for cleanup actions
    # Stop INetSim if running
    # sudo pkill inetsim
    # Remove firewall rules (requires knowing which rules were added)
    # sudo iptables -D FORWARD ... (specific rules)
    # Stop and remove dnsmasq config for this interface
    # sudo systemctl stop dnsmasq; sudo rm /etc/dnsmasq.d/shikra-$INTERFACE_NAME.conf; sudo systemctl start dnsmasq
    # Take down and delete bridge
    # sudo ip link set "$INTERFACE_NAME" down
    # sudo ip link delete "$INTERFACE_NAME" type bridge
    # Remove libvirt network
    # sudo virsh net-destroy <network_name_from_interface>; sudo virsh net-undefine <network_name_from_interface>
    log "${YELLOW}Placeholder: Actual network cleanup (firewall rules, bridge, services) needs implementation.${NC}"
    log "${GREEN}Network cleanup for '$INTERFACE_NAME' conceptually done.${NC}"
}

# --- Main Execution ---
main() {
    log "${GREEN}--- Shikra Network Setup Script Started ---${NC}"
    parse_arguments "$@"

    if [[ "$DO_CLEANUP" == "true" ]]; then
        cleanup_network_config
        log "${GREEN}--- Network Cleanup Finished ---${NC}"
        exit 0
    fi

    create_isolated_network
    configure_firewall
    setup_dns_dhcp # This should configure VMs to use DNS_SERVER
    manage_inetsim_service # If inetsim mode

    log "${GREEN}--- Network Setup Completed Successfully ---${NC}"
    log "Configuration Summary:"
    log "  Mode: $NETWORK_MODE"
    log "  Interface: $INTERFACE_NAME"
    log "  Subnet: $SUBNET_CIDR, Gateway: $GATEWAY_IP"
    log "  VMs will use DNS: $DNS_SERVER"
    [[ "$NETWORK_MODE" == "inetsim" ]] && log "  INetSim should be running on: $INETSIM_IP"
    log "Ensure your VMs are configured to use the '$INTERFACE_NAME' network."
}

main "$@"
