"""
Network Module

Purpose:
This module provides functionalities related to network monitoring, traffic capture,
and network service simulation for the Shikra malware analysis platform. It aims
to create controlled network environments where malware's network behavior can be
observed and logged safely.

Key Components (Conceptual):
- NetworkCapture: Manages packet capture using tools like tcpdump or tshark.
  This includes starting/stopping captures, applying filters, and saving PCAP files.
- FakeServices: Implements or wraps tools (like INetSim) to simulate common internet
  services (HTTP/S, DNS, FTP, SMTP, etc.). This allows malware to interact with
  these services in a controlled manner, logging all requests and responses.
- TrafficAnalyzer (Conceptual): Provides utilities to perform basic analysis on
  captured PCAP files, such as extracting DNS queries, HTTP requests, or identifying
  connections to specific IPs/ports. This might use libraries like Scapy or tshark's
  parsing capabilities.
- NetworkIsolationManager (Conceptual): Works in conjunction with host firewall settings
  (e.g., iptables, nftables) and virtual networking (bridges, NAT rules) to ensure
  the analysis VM is properly isolated or has controlled network access as per the
  analysis policy. This might be orchestrated by scripts in `core/scripts/` but could
  have Python helpers here.

Usage Examples:
    from shikra.core.modules.network import NetworkCapture, FakeServices

    # Network capture (conceptual)
    # capture_instance = NetworkCapture(interface="eth0_guest_bridge")
    # capture_instance.start_capture(output_pcap_path=Path("/tmp/analysis.pcap"),
    #                                filter_expression="not host 192.168.1.1")
    # # ... analysis runs ...
    # capture_instance.stop_capture()
    # stats = capture_instance.get_capture_stats()

    # Fake services (conceptual, wrapping INetSim or similar)
    # fake_services_manager = FakeServices(inetsim_config_path="/etc/inetsim/inetsim.conf")
    # if fake_services_manager.start_all_services(bind_ip="10.0.2.10"):
    #     # ... analysis runs, malware interacts with fake services on 10.0.2.10 ...
    #     fake_services_manager.stop_all_services()
    #     service_logs = fake_services_manager.get_interaction_logs()

Integration:
This module is primarily used by:
- `core/scripts/network_setup.sh`: For setting up the overall network environment.
- `core/scripts/run_analysis.sh`: For starting/stopping traffic capture and potentially
  managing fake services during an active analysis run.
- Post-analysis modules in `shikra/analysis/`: For processing PCAP files and service logs.
"""

from .capture import NetworkCapture
from .fake_services import FakeServices
# from .traffic_analyzer import TrafficAnalyzer # If implemented

# Version information for the module
__version__ = "0.1.0"
__author__ = "Shikra Development Team"

# Export main classes for easier import from the package level
__all__ = [
    "NetworkCapture",
    "FakeServices",
    # "TrafficAnalyzer",
]

# Default configurations or constants for the network module
DEFAULT_CAPTURE_INTERFACE = "any"  # Be careful with 'any' in production, better to specify bridge
DEFAULT_ANALYSIS_SUBNET_PROFILE = {
    "name": "shikra_isolated_net",
    "bridge_name": "shikra-br0",
    "ip_cidr": "192.168.100.1/24", # Host side of bridge
    "dhcp_range_start": "192.168.100.10",
    "dhcp_range_end": "192.168.100.50",
    "dns_server": "192.168.100.1", # Often the host/gateway itself for isolated nets
    "isolation_mode": "full_drop_external" # or "allow_to_inetsim"
}

def get_default_network_profile() -> dict:
    """Returns a copy of the default network profile settings."""
    return DEFAULT_ANALYSIS_SUBNET_PROFILE.copy()

# print("Shikra network module loaded.")
