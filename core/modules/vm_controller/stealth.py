# shikra/modules/vm_controller/stealth_advanced.py
# Purpose: Comprehensive VM anti-detection and evasion countermeasures

import logging
import random
import string
import json
import time
import hashlib
import uuid
import subprocess
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta # Keep timedelta if used elsewhere, not in current scope of changes
from collections import defaultdict # Keep if used elsewhere, not in current scope of changes
import tempfile

# Import existing stealth functions
from .stealth import (
    generate_random_serial, 
    generate_random_mac_address, 
    get_stealth_qemu_args
)

# Import VM controller modules for integration
from .run_in_vm import execute_command_in_guest
from .copy_to_vm import copy_to_guest
from .copy_from_vm import copy_from_guest # Not used in this file, but kept for completeness

logger = logging.getLogger(__name__)

class StealthLevel:
    """Enumeration of stealth levels."""
    NONE = "none"
    BASIC = "basic"
    ADVANCED = "advanced"
    PARANOID = "paranoid"

class StealthTechnique:
    """Represents a single stealth technique with metadata."""
    def __init__(self, name: str, category: str, os_target: str, 
                 risk_level: str, description: str):
        self.name = name
        self.category = category  # hardware, software, behavioral, network
        self.os_target = os_target  # windows, linux, both
        self.risk_level = risk_level  # low, medium, high
        self.description = description
        self.applied = False
        self.error_message: Optional[str] = None
        self.timestamp: Optional[str] = None

class AdvancedStealthManager:
    """
    Advanced VM stealth configuration manager with comprehensive anti-detection capabilities.
    Integrates with existing VM controller infrastructure for complete stealth deployment.
    """
    
    def __init__(self, vm_identifier: str, config: dict, hypervisor_type: str = "auto"):
        """
        Initialize the advanced stealth manager.
        
        Args:
            vm_identifier: VM name or identifier
            config: VM configuration dictionary
            hypervisor_type: Type of hypervisor (qemu, virtualbox, vmware, auto)
        """
        self.vm_identifier = vm_identifier
        self.config = config
        self.hypervisor_type = hypervisor_type.lower()
        
        # Get VM details
        self.vm_config = config.get("vms", {}).get(vm_identifier, {})
        if not self.vm_config:
            raise ValueError(f"VM '{vm_identifier}' not found in configuration")
        
        self.guest_os_type = self.vm_config.get("guest_os_type", "windows").lower()
        self.vm_name = self.vm_config.get("name", vm_identifier)
        
        # Auto-detect hypervisor if needed
        if self.hypervisor_type == "auto":
            self.hypervisor_type = self._detect_hypervisor()
        
        # Initialize stealth profile and tracking
        self.stealth_profile: Dict[str, Any] = {}
        self.applied_techniques: Dict[str, StealthTechnique] = {}
        self.stealth_artifacts: List[str] = []  # Track created files/changes for cleanup
        
        # Load default stealth databases
        self._load_stealth_databases()
        
        logger.info(f"Advanced stealth manager initialized for VM '{vm_identifier}' "
                    f"({self.hypervisor_type}, {self.guest_os_type})")

    def __enter__(self):
        """Enter the runtime context related to this object."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the runtime context related to this object."""
        # Placeholder for any cleanup logic if the manager itself held resources
        # that are not covered by cleanup_stealth_artifacts.
        if exc_type:
            logger.error(f"Exception occurred within AdvancedStealthManager context: {exc_val}",
                         exc_info=(exc_type, exc_val, exc_tb))
        # Return False to propagate exceptions by default.
        # If you want to suppress exceptions, return True.
        return False


    def _detect_hypervisor(self) -> str:
        """Auto-detect hypervisor type."""
        detection_commands = {
            "qemu": ["virsh", "--version"], # Assumes libvirt for QEMU management
            "virtualbox": ["VBoxManage", "--version"],
            "vmware": ["vmrun", "list"] # vmrun might require a VM to be running or specific paths
        }
        
        for hypervisor, cmd in detection_commands.items():
            try:
                # Use shell=False for security with list of args
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
                if result.returncode == 0:
                    logger.info(f"Auto-detected hypervisor: {hypervisor}")
                    return hypervisor
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug(f"Hypervisor detection command for {hypervisor} failed or not found.")
                continue
            except Exception as e:
                logger.warning(f"Error during hypervisor detection for {hypervisor}: {e}")
                continue
        
        logger.warning("Could not auto-detect hypervisor, defaulting to qemu")
        return "qemu"

    def _load_stealth_databases(self):
        """Load stealth technique databases and detection signatures."""
        self.vm_detection_signatures = {
            "registry_keys": {
                "windows": [
                    r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
                    r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
                    r"HKLM\SYSTEM\ControlSet001\Services\VBoxGuest",
                    r"HKLM\SYSTEM\ControlSet001\Services\VBoxMouse",
                    r"HKLM\SYSTEM\ControlSet001\Services\VBoxService",
                    r"HKLM\SYSTEM\ControlSet001\Services\VBoxSF",
                    r"HKLM\SYSTEM\ControlSet001\Services\VMTools",
                    r"HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL", # Hyper-V
                    r"HKLM\SYSTEM\ControlSet001\Services\vmdebug", # Virtual PC
                    r"HKLM\SYSTEM\ControlSet001\Services\vmmouse", # VMware
                    r"HKLM\SYSTEM\ControlSet001\Services\vmhgfs", # VMware Shared Folders
                    r"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" # Hyper-V
                ]
            },
            "file_paths": {
                "windows": [
                    r"C:\Program Files\Oracle\VirtualBox Guest Additions",
                    r"C:\Program Files\VMware\VMware Tools",
                    r"C:\Windows\System32\drivers\VBoxGuest.sys",
                    r"C:\Windows\System32\drivers\VBoxMouse.sys",
                    r"C:\Windows\System32\drivers\VBoxSF.sys",
                    r"C:\Windows\System32\drivers\VBoxVideo.sys",
                    r"C:\Windows\System32\drivers\vmhgfs.sys",
                    r"C:\Windows\System32\drivers\vmmouse.sys",
                    r"C:\Windows\System32\drivers\vmxnet.sys", # VMware NIC
                    r"C:\Windows\System32\drivers\vmci.sys", # VMware VMCI Bus Driver
                    r"C:\Windows\System32\vboxdisp.dll",
                    r"C:\Windows\System32\vboxhook.dll",
                    r"C:\Windows\System32\vboxmrxnp.dll",
                    r"C:\Windows\System32\vmsrvc.dll", # Virtual PC
                    r"C:\Windows\System32\vmtools.dll" # VMware
                ],
                "linux": [
                    "/usr/bin/VBoxClient",
                    "/usr/bin/VBoxControl",
                    "/usr/bin/VBoxService",
                    "/usr/sbin/VBoxService", # Some distributions might place it here
                    "/opt/VBoxGuestAdditions-*/init/vboxadd",
                    "/etc/init.d/vboxadd",
                    "/etc/init.d/vboxadd-service",
                    "/usr/bin/vmware-toolbox-cmd",
                    "/usr/bin/vmware-user",
                    "/etc/init.d/vmware-tools", # SysV init style
                    "/usr/lib/vmware-tools", # Common installation path
                    "/dev/vboxguest", # VirtualBox guest device
                    "/dev/vmci" # VMware VMCI device
                ]
            },
            "process_names": {
                "windows": [
                    "VBoxService.exe", "VBoxTray.exe", "VBoxClient.exe",
                    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
                    "qemu-ga.exe", # QEMU Guest Agent
                    "prl_cc.exe", "prl_tools.exe" # Parallels
                ],
                "linux": [
                    "VBoxService", "VBoxClient", "vboxadd-service",
                    "vmtoolsd", "vmware-guestd", "vmware-user-suid-wrapper",
                    "qemu-ga", # QEMU Guest Agent
                    "prl_disp_service" # Parallels
                ]
            },
            "service_names": { # Primarily for Windows
                "windows": [
                    "VBoxGuest", "VBoxMouse", "VBoxService", "VBoxSF",
                    "VMTools", "VMware Physical Disk Helper Service",
                    "VMware Snapshot Provider", "QEMU Guest Agent",
                    "vmicvss", "vmicheartbeat", "vmicshutdown", "vmicexchange", # Hyper-V services
                    "Parallels Tools"
                ]
            },
            "known_vm_mac_prefixes": [
                "00:0C:29", "00:1C:14", "00:50:56", "00:05:69", # VMware
                "08:00:27", "0A:00:27",                         # VirtualBox
                "52:54:00",                                     # QEMU/KVM
                "00:15:5D",                                     # Hyper-V (Microsoft)
                "00:1C:42"                                      # Parallels
            ],
            "vm_hardware_strings": [ # Strings found in SMBIOS, device names, etc.
                "VBOX", "VirtualBox", "Oracle Corporation", "Innotek GmbH",
                "VMware", "VMware, Inc.", "VMware Virtual Platform",
                "QEMU", "Bochs", "SeaBIOS", "KVM", "Red Hat",
                "Microsoft Corporation", "Virtual Machine", "Hyper-V", "MSFT",
                "Parallels", "Parallels Software International"
            ]
        }
        
        # Load realistic hardware profiles
        self._load_realistic_hardware_profiles()

    def _load_realistic_hardware_profiles(self):
        """Load realistic hardware manufacturer profiles for spoofing."""
        self.hardware_profiles = {
            "dell_optiplex": {
                "system_manufacturer": "Dell Inc.",
                "system_product_name": "OptiPlex 7050",
                "system_version": "1.0.0", # Often specific to BIOS or model revision
                "bios_vendor": "Dell Inc.",
                "bios_version": "2.18.0",
                "bios_date": "07/14/2022",
                "board_manufacturer": "Dell Inc.",
                "board_product_name": "0D24M8", # Motherboard model
                "chassis_manufacturer": "Dell Inc.",
                "chassis_type": "3",  # Desktop
                "mac_oui": "B8:CA:3A"  # Dell OUI
            },
            "lenovo_thinkpad": {
                "system_manufacturer": "LENOVO",
                "system_product_name": "20XW0015US", # Specific model number
                "system_version": "ThinkPad X1 Carbon Gen 9",
                "bios_vendor": "LENOVO",
                "bios_version": "N34ET49W (1.32)",
                "bios_date": "08/12/2022",
                "board_manufacturer": "LENOVO",
                "board_product_name": "20XWCTO1WW", # Baseboard product name
                "chassis_manufacturer": "LENOVO",
                "chassis_type": "10", # Notebook
                "mac_oui": "54:EE:75"  # Lenovo OUI
            },
            "hp_elitebook": {
                "system_manufacturer": "HP",
                "system_product_name": "HP EliteBook 840 G8",
                "system_version": "1.0", # Can be generic or BIOS specific
                "bios_vendor": "HP",
                "bios_version": "S70 Ver. 01.13.00",
                "bios_date": "06/15/2022",
                "board_manufacturer": "HP",
                "board_product_name": "8846", # Motherboard model
                "chassis_manufacturer": "HP",
                "chassis_type": "10", # Notebook
                "mac_oui": "3C:52:82"  # HP OUI
            }
        }

    def load_stealth_profile(self, profile_data: Dict[str, Any] = None, 
                           profile_path: str = None, stealth_level: str = StealthLevel.ADVANCED) -> bool:
        """
        Load stealth configuration from profile data or file.
        
        Args:
            profile_data: Dictionary containing stealth configuration
            profile_path: Path to JSON stealth profile file
            stealth_level: Default stealth level if not specified in profile
        """
        try:
            if profile_path:
                with open(profile_path, 'r', encoding='utf-8') as f:
                    profile_data = json.load(f)
                logger.info(f"Stealth profile loaded from: {profile_path}")
            
            if not profile_data:
                # Generate default profile based on stealth level
                profile_data = self._generate_default_profile(stealth_level)
                logger.info(f"Generated default stealth profile: {stealth_level}")
            
            self.stealth_profile = profile_data
            return True
            
        except Exception as e:
            logger.error(f"Failed to load stealth profile: {e}")
            self.stealth_profile = self._generate_default_profile(StealthLevel.BASIC) # Fallback
            return False

    def _generate_default_profile(self, stealth_level: str) -> Dict[str, Any]:
        """Generate a default stealth profile based on the specified level."""
        base_profile = {
            "stealth_level": stealth_level,
            "hardware_stealth": {"enabled": False},
            "software_stealth": {"enabled": False},
            "behavioral_stealth": {"enabled": False},
            "network_stealth": {"enabled": False}
        }
        
        if stealth_level == StealthLevel.BASIC:
            base_profile.update({
                "hardware_stealth": {
                    "enabled": True,
                    "randomize_mac": True,
                    "modify_smbios": True,
                    "hardware_profile": "dell_optiplex" # Default profile
                },
                "software_stealth": {
                    "enabled": True,
                    "hide_vm_tools": True, # Basic hiding
                    "clean_vm_registry": True # Basic cleaning
                }
            })
        
        elif stealth_level == StealthLevel.ADVANCED:
            base_profile.update({
                "hardware_stealth": {
                    "enabled": True,
                    "randomize_mac": True,
                    "modify_smbios": True,
                    "hardware_profile": "lenovo_thinkpad",
                    "randomize_disk_serial": True,
                    "cpu_modifications": True # e.g., hide hypervisor bit (QEMU)
                },
                "software_stealth": {
                    "enabled": True,
                    "hide_vm_tools": True,
                    "clean_vm_registry": True,
                    "patch_vm_artifacts": True, # More in-depth patching
                    "modify_vm_services": True
                },
                "behavioral_stealth": {
                    "enabled": True,
                    "create_user_artifacts": True,
                    "simulate_usage_patterns": True
                },
                "network_stealth": {
                    "enabled": True,
                    "populate_network_artifacts": True
                }
            })
        
        elif stealth_level == StealthLevel.PARANOID:
            base_profile.update({
                "hardware_stealth": {
                    "enabled": True,
                    "randomize_mac": True,
                    "modify_smbios": True,
                    "hardware_profile": "hp_elitebook", # Use a different profile
                    "randomize_disk_serial": True,
                    "cpu_modifications": True,
                    "advanced_timing": True # e.g., TSC, RDTSC related (complex)
                },
                "software_stealth": {
                    "enabled": True,
                    "hide_vm_tools": True,
                    "clean_vm_registry": True,
                    "patch_vm_artifacts": True,
                    "modify_vm_services": True,
                    "deep_artifact_removal": True, # More aggressive cleaning
                    "install_decoy_software": True
                },
                "behavioral_stealth": {
                    "enabled": True,
                    "create_user_artifacts": True,
                    "simulate_usage_patterns": True,
                    "generate_browsing_history": True,
                    "create_system_activity": True
                },
                "network_stealth": {
                    "enabled": True,
                    "populate_network_artifacts": True,
                    "simulate_network_history": True
                }
            })
        
        return base_profile

    def apply_all_stealth_measures(self) -> Dict[str, Any]:
        """
        Apply all enabled stealth measures based on the loaded profile.
        
        Returns:
            Dictionary with detailed results of stealth application
        """
        if not self.stealth_profile:
            logger.warning("No stealth profile loaded, cannot apply measures.")
            return {"success": False, "error": "No stealth profile loaded"}
        
        logger.info(f"Applying stealth measures for VM '{self.vm_identifier}' "
                    f"(Level: {self.stealth_profile.get('stealth_level', 'unknown')})")
        
        # Clear previous results if any
        self.applied_techniques.clear()
        self.stealth_artifacts.clear()

        results_summary = {
            "success": True, # Overall success, true until a major category fails
            "stealth_level": self.stealth_profile.get("stealth_level"),
            "applied_technique_names": [], # Names of successfully applied techniques
            "failed_technique_names": [],   # Names of failed techniques
            "warnings": [],
            "hardware_changes_summary": [],
            "software_changes_summary": [],
            "behavioral_artifacts_summary": [],
            "network_artifacts_summary": []
        }
        
        start_time = time.time()
        
        # Apply hardware stealth measures
        if self.stealth_profile.get("hardware_stealth", {}).get("enabled", False):
            hw_results = self._apply_hardware_stealth()
            results_summary["hardware_changes_summary"] = hw_results.get("changes", [])
            if not hw_results.get("success", True): # Check if this category had issues
                 results_summary["success"] = False # Mark overall as potentially problematic
            # applied_techniques and failed_techniques are now managed by self.applied_techniques

        # Apply software stealth measures
        if self.stealth_profile.get("software_stealth", {}).get("enabled", False):
            sw_results = self._apply_software_stealth()
            results_summary["software_changes_summary"] = sw_results.get("changes", [])
            if not sw_results.get("success", True):
                 results_summary["success"] = False

        # Apply behavioral stealth measures  
        if self.stealth_profile.get("behavioral_stealth", {}).get("enabled", False):
            bh_results = self._apply_behavioral_stealth()
            results_summary["behavioral_artifacts_summary"] = bh_results.get("artifacts", [])
            if not bh_results.get("success", True):
                 results_summary["success"] = False
        
        # Apply network stealth measures
        if self.stealth_profile.get("network_stealth", {}).get("enabled", False):
            net_results = self._apply_network_stealth()
            # Assuming net_results might have an "artifacts" key similar to behavioral
            results_summary["network_artifacts_summary"] = net_results.get("artifacts", []) 
            if not net_results.get("success", True):
                 results_summary["success"] = False
        
        execution_time = time.time() - start_time
        results_summary["execution_time"] = execution_time
        
        # Populate applied and failed technique names from self.applied_techniques
        for name, tech_obj in self.applied_techniques.items():
            if tech_obj.applied:
                results_summary["applied_technique_names"].append(name)
            else:
                results_summary["failed_technique_names"].append(name)

        logger.info(f"Stealth application completed in {execution_time:.2f}s. "
                    f"Success: {results_summary['success']}, "
                    f"Applied: {len(results_summary['applied_technique_names'])}, "
                    f"Failed: {len(results_summary['failed_technique_names'])}")
        
        return results_summary

    def _apply_hardware_stealth(self) -> Dict[str, Any]:
        """Apply hardware-level stealth measures."""
        logger.info("Applying hardware stealth measures")
        category_results = {"success": True, "changes": []} # Tracks success of this category
        
        hw_config = self.stealth_profile.get("hardware_stealth", {})
        profile_name = hw_config.get("hardware_profile", "dell_optiplex")
        hardware_profile = self.hardware_profiles.get(profile_name, self.hardware_profiles["dell_optiplex"])
        
        # Generate QEMU stealth arguments (if QEMU)
        if self.hypervisor_type == "qemu":
            qemu_args_tech = StealthTechnique(
                name="qemu_stealth_args", category="hardware", os_target="host", risk_level="medium",
                description="Generate and apply QEMU-specific stealth arguments."
            )
            try:
                stealth_args = self._generate_qemu_stealth_args(hardware_profile, hw_config)
                change_detail = {
                    "type": "qemu_arguments", "args": stealth_args,
                    "description": "Generated QEMU stealth arguments based on hardware profile."
                }
                category_results["changes"].append(change_detail)
                qemu_args_tech.applied = True
                qemu_args_tech.description = change_detail["description"]
            except Exception as e:
                logger.error(f"QEMU stealth args generation failed: {e}")
                qemu_args_tech.error_message = str(e)
                category_results["success"] = False
            qemu_args_tech.timestamp = datetime.now().isoformat()
            self.applied_techniques[qemu_args_tech.name] = qemu_args_tech

        # Randomize MAC address
        if hw_config.get("randomize_mac", False):
            mac_result = self._apply_mac_randomization(hardware_profile)
            if mac_result["success"]:
                category_results["changes"].append(mac_result)
            else:
                category_results["success"] = False
        
        # Apply SMBIOS modifications
        if hw_config.get("modify_smbios", False):
            smbios_result = self._apply_smbios_modifications(hardware_profile)
            if smbios_result["success"]:
                category_results["changes"].append(smbios_result)
            else:
                category_results["success"] = False
        
        # Randomize disk identifiers
        if hw_config.get("randomize_disk_serial", False):
            disk_result = self._apply_disk_randomization()
            if disk_result["success"]:
                category_results["changes"].append(disk_result)
            else:
                category_results["success"] = False
        
        # Add other hardware techniques here...

        return category_results

    def _generate_qemu_stealth_args(self, hardware_profile: Dict, hw_config: Dict) -> List[str]:
        """Generate comprehensive QEMU stealth arguments."""
        # This method itself doesn't apply a technique but supports one.
        # The technique is qemu_stealth_args handled in _apply_hardware_stealth
        vm_profile_for_stealth_func = {"stealth_options": hw_config.copy()} # Use a copy
        # Add hardware profile details to be used by get_stealth_qemu_args if it supports them
        vm_profile_for_stealth_func["stealth_options"]["smbios_manufacturer"] = hardware_profile.get("system_manufacturer")
        vm_profile_for_stealth_func["stealth_options"]["smbios_product"] = hardware_profile.get("system_product_name")
        # ... add other relevant hardware_profile fields that get_stealth_qemu_args might use

        base_args = get_stealth_qemu_args(vm_profile_for_stealth_func)
        enhanced_args = base_args.copy()
        
        # CPU modifications (example: hide hypervisor flag, enable specific features)
        if hw_config.get("cpu_modifications", False):
            cpu_model = hw_config.get("cpu_model", "host") # Default to host CPU
            cpu_features = ["-hypervisor"] # Attempt to hide hypervisor CPUID bit
            if hw_config.get("enable_rdrand", True): cpu_features.append("+rdrand")
            if hw_config.get("enable_rdseed", True): cpu_features.append("+rdseed")
            # Add more features as needed, e.g., from hardware_profile if it specified CPU details
            enhanced_args.extend(["-cpu", f"{cpu_model},{','.join(cpu_features)}"])
        
        # Machine type
        if hw_config.get("machine_type"): # e.g., "q35", "pc-i440fx-latest"
            enhanced_args.extend(["-M", hw_config["machine_type"]])
        
        # Advanced timing (placeholder for QEMU specific options like tsc frequency, rtc settings)
        if hw_config.get("advanced_timing", False):
            # Example: enhanced_args.extend(["-rtc", "base=localtime,clock=host,driftfix=slew"])
            logger.info("Advanced timing for QEMU requested but specific args are placeholders.")

        return list(set(enhanced_args)) # Remove duplicates if any

    def _apply_mac_randomization(self, hardware_profile: Dict) -> Dict[str, Any]:
        """Apply MAC address randomization using realistic OUI."""
        technique = StealthTechnique(
            name="mac_randomization", category="hardware", os_target="host", risk_level="low",
            description="Randomize MAC address using a realistic OUI."
        )
        result = {"success": False, "type": "mac_address"}
        try:
            oui = hardware_profile.get("mac_oui", "08:00:27") # Default to VirtualBox OUI if not specified
            mac_suffix = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])
            new_mac = f"{oui}:{mac_suffix}".lower()
            
            logger.info(f"Generated realistic MAC address: {new_mac}")
            technique.description = f"MAC randomized to {new_mac} using OUI {oui} from {hardware_profile.get('system_manufacturer', 'Generic Profile')}."
            technique.applied = True
            result.update({
                "success": True, "new_mac": new_mac, "oui": oui,
                "description": technique.description
            })
            # Actual application of this MAC would be part of VM config update or QEMU args
            # This method primarily generates it and records the intent.
            
        except Exception as e:
            logger.error(f"MAC randomization failed: {e}")
            technique.error_message = str(e)
            result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _apply_smbios_modifications(self, hardware_profile: Dict) -> Dict[str, Any]:
        """Apply SMBIOS/DMI string modifications."""
        technique = StealthTechnique(
            name="smbios_modifications", category="hardware", os_target="host", risk_level="medium",
            description="Modify SMBIOS/DMI strings to match a realistic hardware profile."
        )
        result = {"success": False, "type": "smbios_modifications"}
        try:
            smbios_data = {
                "system_manufacturer": hardware_profile.get("system_manufacturer"),
                "system_product_name": hardware_profile.get("system_product_name"),
                "system_version": hardware_profile.get("system_version"),
                "system_serial_number": generate_random_serial(15), # Generate a new random serial
                "system_uuid": str(uuid.uuid4()), # Generate a new UUID
                "bios_vendor": hardware_profile.get("bios_vendor"),
                "bios_version": hardware_profile.get("bios_version"),
                "bios_date": hardware_profile.get("bios_date"),
                "board_manufacturer": hardware_profile.get("board_manufacturer"),
                "board_product_name": hardware_profile.get("board_product_name"),
                "board_serial_number": generate_random_serial(12),
                "chassis_manufacturer": hardware_profile.get("chassis_manufacturer"),
                "chassis_type": hardware_profile.get("chassis_type"),
                "chassis_serial_number": generate_random_serial(10)
            }
            
            desc = f"SMBIOS spoofed as {smbios_data['system_manufacturer']} {smbios_data['system_product_name']}"
            logger.info(desc)
            technique.description = desc
            technique.applied = True
            result.update({"success": True, "data": smbios_data, "description": desc})
            # Actual application is via QEMU args: -smbios type=0,... -smbios type=1,... etc.
            # This method prepares the data.

        except Exception as e:
            logger.error(f"SMBIOS modification failed: {e}")
            technique.error_message = str(e)
            result["error"] = str(e)

        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _apply_disk_randomization(self) -> Dict[str, Any]:
        """Apply disk serial number and model randomization."""
        technique = StealthTechnique(
            name="disk_randomization", category="hardware", os_target="host", risk_level="medium",
            description="Randomize virtual disk serial number and model string."
        )
        result = {"success": False, "type": "disk_randomization"}
        try:
            # Generate plausible disk model and serial
            # Common brands: WDC, Seagate, Samsung, Crucial, Kingston
            brands = ["WDC", "Seagate", "Samsung", "Crucial", "Kingston"]
            brand = random.choice(brands)
            if brand == "WDC":
                model_prefix = f"WD{random.randint(1,8)}0EZEX" # Example: WD10EZEX (1TB Blue)
            elif brand == "Seagate":
                model_prefix = f"ST{random.randint(1,8)}000DM008" # Example: ST2000DM008 (2TB Barracuda)
            else: # Generic
                model_prefix = f"{brand.upper()}{random.randint(100,999)} SERIES"
            
            new_model = f"{model_prefix}-{generate_random_serial(6, chars=string.ascii_uppercase + string.digits)}"
            new_serial = generate_random_serial(20, chars=string.ascii_uppercase + string.digits)

            desc = f"Disk identity randomized to Model: {new_model}, Serial: {new_serial}"
            logger.info(desc)
            technique.description = desc
            technique.applied = True
            result.update({
                "success": True, "serial": new_serial, "model": new_model, "description": desc
            })
            # Actual application for QEMU: e.g., drive file=...,serial=...,model=...

        except Exception as e:
            logger.error(f"Disk randomization failed: {e}")
            technique.error_message = str(e)
            result["error"] = str(e)

        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _apply_software_stealth(self) -> Dict[str, Any]:
        """Apply software-level stealth measures in the guest OS."""
        logger.info("Applying software stealth measures")
        category_results = {"success": True, "changes": []}
        sw_config = self.stealth_profile.get("software_stealth", {})
        
        if sw_config.get("hide_vm_tools", False):
            tools_result = self._hide_vm_tools()
            if tools_result["success"]: category_results["changes"].append(tools_result)
            else: category_results["success"] = False
        
        if sw_config.get("clean_vm_registry", False) and self.guest_os_type == "windows":
            registry_result = self._clean_vm_registry()
            if registry_result["success"]: category_results["changes"].append(registry_result)
            else: category_results["success"] = False
            
        if sw_config.get("patch_vm_artifacts", False):
            patch_result = self._patch_vm_artifacts()
            if patch_result["success"]: category_results["changes"].append(patch_result)
            else: category_results["success"] = False

        if sw_config.get("modify_vm_services", False):
            services_result = self._modify_vm_services()
            if services_result["success"]: category_results["changes"].append(services_result)
            else: category_results["success"] = False # Even if partially successful, note it

        if sw_config.get("install_decoy_software", False):
            decoy_result = self._install_decoy_software()
            if decoy_result["success"]: category_results["changes"].append(decoy_result)
            else: category_results["success"] = False
            
        # Add other software techniques here...

        return category_results

    def _hide_vm_tools(self) -> Dict[str, Any]:
        """Hide or disable VM guest tools and related artifacts."""
        technique = StealthTechnique(
            name="hide_vm_tools", category="software", os_target=self.guest_os_type, risk_level="medium",
            description="Hide/rename VM tool files and disable related services."
        )
        result = {"success": True, "type": "vm_tools_hiding", "hidden_items": []}
        hidden_items_local = []
        
        try:
            file_paths = self.vm_detection_signatures["file_paths"].get(self.guest_os_type, [])
            service_names = self.vm_detection_signatures["service_names"].get(self.guest_os_type, []) # Primarily Windows

            # Hide/rename files (limited for demo)
            for file_path in file_paths[:3]: # Limit actions for safety/brevity
                new_name_suffix = "_bkp" # More subtle than "_hidden"
                if self.guest_os_type == "windows":
                    # Check existence before renaming
                    check_cmd = f'if exist "{file_path}" (echo EXISTS) else (echo NOTFOUND)'
                    stdout_check, _, rc_check = execute_command_in_guest(self.vm_identifier, check_cmd, self.config, timeout_sec=10)
                    if rc_check == 0 and "EXISTS" in stdout_check:
                        rename_cmd = f'ren "{file_path}" "{Path(file_path).name}{new_name_suffix}"'
                        self.stealth_artifacts.append(f"file:{file_path}{new_name_suffix}") # Track renamed file
                    else: continue # File doesn't exist
                else: # Linux
                    check_cmd = f'if [ -e "{file_path}" ]; then echo EXISTS; else echo NOTFOUND; fi'
                    stdout_check, _, rc_check = execute_command_in_guest(self.vm_identifier, check_cmd, self.config, timeout_sec=10)
                    if rc_check == 0 and "EXISTS" in stdout_check:
                        rename_cmd = f'mv "{file_path}" "{file_path}{new_name_suffix}"'
                        self.stealth_artifacts.append(f"file:{file_path}{new_name_suffix}") # Track renamed file
                    else: continue # File doesn't exist
                
                _, _, rc_rename = execute_command_in_guest(self.vm_identifier, rename_cmd, self.config, timeout_sec=30)
                if rc_rename == 0:
                    hidden_items_local.append(f"Renamed: {file_path} to {Path(file_path).name}{new_name_suffix}")
                    logger.debug(f"Successfully renamed VM tool file: {file_path}")
                else:
                    logger.warning(f"Failed to rename {file_path} (rc: {rc_rename})")
                    result["success"] = False # Mark partial failure

            # Stop and disable services (Windows specific for this list)
            if self.guest_os_type == "windows":
                for service_name in service_names[:2]: # Limit actions
                    stop_cmd = f'sc stop "{service_name}" 2>nul'
                    disable_cmd = f'sc config "{service_name}" start=disabled 2>nul'
                    # Check if service exists
                    query_cmd = f'sc query "{service_name}"'
                    _, _, rc_query = execute_command_in_guest(self.vm_identifier, query_cmd, self.config, timeout_sec=10)
                    if rc_query == 0: # Service exists
                        execute_command_in_guest(self.vm_identifier, stop_cmd, self.config, timeout_sec=30)
                        _, _, rc_disable = execute_command_in_guest(self.vm_identifier, disable_cmd, self.config, timeout_sec=30)
                        if rc_disable == 0:
                            hidden_items_local.append(f"Disabled service: {service_name}")
                            logger.debug(f"Successfully disabled VM service: {service_name}")
                            # Note: Re-enabling this service would be part of cleanup, complex.
                        else:
                            logger.warning(f"Failed to disable service {service_name} (rc: {rc_disable})")
                            result["success"] = False
            
            result["hidden_items"] = hidden_items_local
            technique.description = f"Attempted to hide/disable {len(hidden_items_local)} VM tool artifacts. Success: {result['success']}"
            technique.applied = result["success"] # Could be partially applied
            if not result["success"]: technique.error_message = "One or more items failed to hide/disable."

        except Exception as e:
            logger.error(f"VM tools hiding failed: {e}")
            technique.error_message = str(e)
            result["success"] = False
            result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _clean_vm_registry(self) -> Dict[str, Any]:
        """Clean VM-specific registry entries (Windows only)."""
        technique = StealthTechnique(
            name="clean_vm_registry", category="software", os_target="windows", risk_level="medium",
            description="Delete known VM-specific registry keys."
        )
        result = {"success": True, "type": "registry_cleanup", "cleaned_keys": []}
        cleaned_keys_local = []

        if self.guest_os_type != "windows":
            technique.applied = True # No action needed for non-Windows
            technique.description = "Not applicable for non-Windows OS."
            self.applied_techniques[technique.name] = technique
            return {"success": True, "description": "Not applicable for non-Windows OS."}

        try:
            registry_keys = self.vm_detection_signatures["registry_keys"].get("windows", [])
            for reg_key in registry_keys[:3]: # Limit actions
                check_cmd = f'reg query "{reg_key}" >nul 2>&1'
                _, _, rc_check = execute_command_in_guest(self.vm_identifier, check_cmd, self.config, timeout_sec=10)
                if rc_check == 0: # Key exists
                    delete_cmd = f'reg delete "{reg_key}" /f >nul 2>&1'
                    _, _, rc_delete = execute_command_in_guest(self.vm_identifier, delete_cmd, self.config, timeout_sec=30)
                    if rc_delete == 0:
                        cleaned_keys_local.append(reg_key)
                        logger.debug(f"Successfully deleted registry key: {reg_key}")
                        # Note: This is a destructive action. Original values are not backed up.
                    else:
                        logger.warning(f"Failed to delete registry key {reg_key} (rc: {rc_delete})")
                        result["success"] = False
            
            result["cleaned_keys"] = cleaned_keys_local
            technique.description = f"Attempted to clean {len(cleaned_keys_local)} VM registry entries. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "One or more registry keys failed to delete."

        except Exception as e:
            logger.error(f"Registry cleanup failed: {e}")
            technique.error_message = str(e)
            result["success"] = False
            result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _create_windows_patch_script(self) -> str:
        """Create Windows batch script for VM artifact patching (renaming)."""
        # This script renames, doesn't patch in-memory strings.
        # In-memory patching is significantly more complex.
        script_content = '''@echo off
REM VM Artifact Renaming Script
echo Starting VM artifact renaming...

REM Disable VM-related services (if they exist and if desired - this is aggressive)
REM sc config "VBoxService" start=disabled >nul 2>&1
REM sc config "VMTools" start=disabled >nul 2>&1
REM sc config "QEMU Guest Agent" start=disabled >nul 2>&1

REM Stop running VM processes (also aggressive, might break guest functionality)
REM taskkill /F /IM "VBoxTray.exe" >nul 2>&1
REM taskkill /F /IM "vmtoolsd.exe" >nul 2>&1
REM taskkill /F /IM "qemu-ga.exe" >nul 2>&1

REM Rename VM detection files (backup originals by renaming)
echo Renaming files in C:\\Windows\\System32...
cd /d C:\\Windows\\System32
if exist "vboxdisp.dll" (
    echo Renaming vboxdisp.dll
    ren "vboxdisp.dll" "vboxdisp.dll.stealth_bkp" >nul 2>&1
)
if exist "vboxhook.dll" (
    echo Renaming vboxhook.dll
    ren "vboxhook.dll" "vboxhook.dll.stealth_bkp" >nul 2>&1
)

echo Renaming files in C:\\Windows\\System32\\drivers...
cd /d C:\\Windows\\System32\\drivers
if exist "VBoxGuest.sys" (
    echo Renaming VBoxGuest.sys
    ren "VBoxGuest.sys" "VBoxGuest.sys.stealth_bkp" >nul 2>&1
)
if exist "VBoxMouse.sys" (
    echo Renaming VBoxMouse.sys
    ren "VBoxMouse.sys" "VBoxMouse.sys.stealth_bkp" >nul 2>&1
)

echo VM artifact renaming completed.
'''
        return script_content

    def _create_local_patch_script(self, script_content: str, suffix: str) -> str:
        """Create local temporary patch script file."""
        # Ensure temp directory exists or handle creation
        temp_dir = Path(tempfile.gettempdir()) / "shikra_stealth"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Use NamedTemporaryFile correctly within the temp_dir
        # Suffix should include the dot, e.g., '.bat' or '.sh'
        with tempfile.NamedTemporaryFile(mode='w', dir=temp_dir, suffix=suffix, delete=False) as f:
            f.write(script_content)
            return f.name # This is the full path to the temporary file

    def _patch_vm_artifacts(self) -> Dict[str, Any]:
        """Patch VM-specific artifacts by renaming files or modifying DMI (Linux)."""
        technique = StealthTechnique(
            name="patch_vm_artifacts", category="software", os_target=self.guest_os_type, risk_level="high",
            description="Rename known VM artifact files (Windows) or modify DMI entries (Linux)."
        )
        result = {"success": True, "type": "artifact_patching", "patched_items": []}
        patched_items_local = []

        try:
            if self.guest_os_type == "windows":
                patch_script_content = self._create_windows_patch_script()
                local_script_path = self._create_local_patch_script(patch_script_content, ".bat")
                # Define remote path ensuring Temp exists or use a known writable path
                remote_script_dir = "C:\\Windows\\Temp" # Usually writable
                remote_script_path = f"{remote_script_dir}\\vm_patch.bat"

                # Ensure remote directory exists (optional, depends on script target)
                # execute_command_in_guest(self.vm_identifier, f'mkdir "{remote_script_dir}" 2>nul', self.config)


                if copy_to_guest(self.vm_identifier, local_script_path, remote_script_path, self.config):
                    logger.info(f"Copied patch script to VM: {remote_script_path}")
                    # Execute patch script
                    stdout, stderr, rc = execute_command_in_guest(
                        self.vm_identifier, remote_script_path, self.config, timeout_sec=120
                    )
                    if rc == 0:
                        patched_items_local.append("Windows file renaming script executed.")
                        logger.info(f"Patch script executed successfully. Stdout: {stdout}")
                        # Files renamed by script: vboxdisp.dll.stealth_bkp, etc.
                        # Track these for potential cleanup
                        self.stealth_artifacts.append(f"file:C:\\Windows\\System32\\vboxdisp.dll.stealth_bkp")
                        self.stealth_artifacts.append(f"file:C:\\Windows\\System32\\vboxhook.dll.stealth_bkp")
                        self.stealth_artifacts.append(f"file:C:\\Windows\\System32\\drivers\\VBoxGuest.sys.stealth_bkp")
                        self.stealth_artifacts.append(f"file:C:\\Windows\\System32\\drivers\\VBoxMouse.sys.stealth_bkp")
                    else:
                        logger.error(f"Patch script execution failed. RC: {rc}, Stderr: {stderr}")
                        result["success"] = False
                    # Clean up script from VM
                    execute_command_in_guest(
                        self.vm_identifier, f'del "{remote_script_path}" /F /Q 2>nul', 
                        self.config, timeout_sec=30
                    )
                else:
                    logger.error("Failed to copy patch script to VM.")
                    result["success"] = False
                
                # Clean up local script
                if os.path.exists(local_script_path):
                    os.unlink(local_script_path)
            
            else:  # Linux - Modify DMI entries (requires root in guest)
                # These commands attempt to overwrite DMI files if writable.
                # This is a common technique but effectiveness varies.
                patch_commands = [
                    ('echo "Generic PC" > /sys/class/dmi/id/product_name 2>/dev/null', "DMI product_name"),
                    ('echo "Genuine OEM" > /sys/class/dmi/id/sys_vendor 2>/dev/null', "DMI sys_vendor"),
                    ('echo "BIOS Corp" > /sys/class/dmi/id/bios_vendor 2>/dev/null', "DMI bios_vendor"),
                    ('echo "1.0" > /sys/class/dmi/id/bios_version 2>/dev/null', "DMI bios_version")
                ]
                for cmd, desc in patch_commands[:2]: # Limit for demo
                    _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=30)
                    if rc == 0: # Command executed, might not mean file was writable
                        patched_items_local.append(f"Attempted DMI patch: {desc}")
                        logger.info(f"Executed DMI patch command for {desc}")
                    else:
                        logger.warning(f"Failed to execute DMI patch command for {desc}")
                        result["success"] = False # Mark partial failure
            
            result["patched_items"] = patched_items_local
            technique.description = f"Attempted to patch/rename {len(patched_items_local)} VM artifacts. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "One or more artifact patching steps failed."

        except Exception as e:
            logger.error(f"Artifact patching failed: {e}")
            technique.error_message = str(e)
            result["success"] = False
            result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result


    def _modify_vm_services(self) -> Dict[str, Any]:
        """Modify VM-related services to appear more legitimate (placeholder)."""
        technique = StealthTechnique(
            name="modify_vm_services", category="software", os_target=self.guest_os_type, risk_level="high",
            description="Rename or modify properties of VM-related services."
        )
        result = {"success": True, "type": "service_modification", "modified_services": []}
        modified_services_local = []

        try:
            if self.guest_os_type == "windows":
                # Renaming services is very complex and risky (involves registry, service control manager)
                # This is a placeholder indicating the intent, not a full implementation.
                logger.warning("Windows service renaming is a complex operation and NOT fully implemented.")
                technique.description = "Windows service modification is complex and not fully implemented (placeholder)."
                technique.applied = False # Mark as not truly applied
                technique.error_message = "NotImplemented: Windows service renaming is a placeholder."
                # raise NotImplementedError("Windows service renaming is not fully implemented due to complexity and risk.")
                # For demonstration, we'll log what would be done.
                service_renames_planned = {
                    "VBoxService": "SystemOptimizerSvc",
                    "VMTools": "HardwareMonitorSvc",
                }
                for old_name, new_name in service_renames_planned.items():
                    modified_services_local.append(f"Planned rename (not executed): {old_name} -> {new_name}")
                result["success"] = False # Indicate it's not truly successful
            else: # Linux
                # Service modification on Linux (e.g., renaming systemd units) is also complex.
                technique.description = "Linux service modification is not implemented."
                technique.applied = False
                technique.error_message = "NotImplemented: Linux service modification."
                result["success"] = False

            result["modified_services"] = modified_services_local
        
        except NotImplementedError as nie: # Catching the explicit error
            logger.warning(str(nie))
            technique.error_message = str(nie)
            result["success"] = False
            result["error"] = str(nie)
        except Exception as e:
            logger.error(f"Service modification attempt failed: {e}")
            technique.error_message = str(e)
            result["success"] = False
            result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _install_decoy_software(self) -> Dict[str, Any]:
        """Install decoy software to make the system appear more legitimate."""
        technique = StealthTechnique(
            name="install_decoy_software", category="software", os_target=self.guest_os_type, risk_level="low",
            description="Create fake installations of common software (registry, files)."
        )
        result = {"success": True, "type": "decoy_software", "installed_decoys": []}
        installed_decoys_local = []
        
        try:
            if self.guest_os_type == "windows":
                decoy_software_list = [
                    {"name": "Microsoft Office 2019", "reg_key": r"HKLM\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot", "reg_val": "Path", "reg_d": r"C:\Program Files\Microsoft Office\root\Office16", "directory": r"C:\Program Files\Microsoft Office\root\Office16", "exe": "WINWORD.EXE"},
                    {"name": "Adobe Acrobat Reader DC", "reg_key": r"HKLM\SOFTWARE\Adobe\Acrobat Reader\DC\InstallPath", "reg_val": None, "reg_d": r"C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader", "directory": r"C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader", "exe": "AcroRd32.exe"},
                    {"name": "Google Chrome", "reg_key": r"HKLM\SOFTWARE\Google\Chrome\BLBeacon", "reg_val":"version", "reg_d":"1.2.3.4", "directory": r"C:\Program Files\Google\Chrome\Application", "exe": "chrome.exe"}
                ]
                for software in decoy_software_list[:2]: # Limit for demo
                    # Create fake registry entry
                    if software["reg_val"]: # If specific value name
                         reg_cmd = f'reg add "{software["reg_key"]}" /v "{software["reg_val"]}" /t REG_SZ /d "{software["reg_d"]}" /f >nul 2>&1'
                    else: # Default value for the key
                         reg_cmd = f'reg add "{software["reg_key"]}" /ve /t REG_SZ /d "{software["reg_d"]}" /f >nul 2>&1'
                    
                    _, _, rc_reg = execute_command_in_guest(self.vm_identifier, reg_cmd, self.config, timeout_sec=30)
                    if rc_reg == 0: self.stealth_artifacts.append(f"registry:{software['reg_key']}")
                    else: result["success"] = False; logger.warning(f"Failed decoy reg for {software['name']}"); continue

                    # Create fake directory structure
                    dir_cmd = f'mkdir "{software["directory"]}" 2>nul' # mkdir might fail if path exists, 2>nul hides error
                    execute_command_in_guest(self.vm_identifier, dir_cmd, self.config, timeout_sec=30)
                    # self.stealth_artifacts.append(f"dir:{software['directory']}") # Cleanup doesn't handle dirs yet

                    # Create fake executable
                    exe_path = f'{software["directory"]}\\{software["exe"]}'
                    exe_cmd = f'echo. > "{exe_path}"' # Creates an empty file
                    _, _, rc_exe = execute_command_in_guest(self.vm_identifier, exe_cmd, self.config, timeout_sec=30)
                    if rc_exe == 0: self.stealth_artifacts.append(f"file:{exe_path}")
                    else: result["success"] = False; logger.warning(f"Failed decoy exe for {software['name']}"); continue
                    
                    installed_decoys_local.append(software["name"])
                    logger.debug(f"Created decoy software: {software['name']}")
            else: # Linux (simpler decoy)
                decoy_apps = ["/opt/common_tool/bin/tool", "/usr/local/share/appdata/app.desktop"]
                for app_path_str in decoy_apps:
                    app_path = Path(app_path_str)
                    dir_cmd = f'mkdir -p "{app_path.parent}" 2>/dev/null'
                    file_cmd = f'touch "{app_path}" 2>/dev/null'
                    execute_command_in_guest(self.vm_identifier, dir_cmd, self.config, timeout_sec=10)
                    _, _, rc_file = execute_command_in_guest(self.vm_identifier, file_cmd, self.config, timeout_sec=10)
                    if rc_file == 0:
                        installed_decoys_local.append(app_path_str)
                        self.stealth_artifacts.append(f"file:{app_path_str}")
                    else: result["success"] = False

            result["installed_decoys"] = installed_decoys_local
            technique.description = f"Created {len(installed_decoys_local)} decoy software installations. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "One or more decoy software installations failed."

        except Exception as e:
            logger.error(f"Decoy software installation failed: {e}")
            technique.error_message = str(e)
            result["success"] = False
            result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _apply_behavioral_stealth(self) -> Dict[str, Any]:
        """Apply behavioral stealth measures to simulate normal user activity."""
        logger.info("Applying behavioral stealth measures")
        category_results = {"success": True, "artifacts": []}
        bh_config = self.stealth_profile.get("behavioral_stealth", {})

        if bh_config.get("create_user_artifacts", False):
            artifacts_result = self._create_user_artifacts()
            if artifacts_result["success"]: category_results["artifacts"].extend(artifacts_result["artifacts"])
            else: category_results["success"] = False
        
        if bh_config.get("simulate_usage_patterns", False):
            usage_result = self._simulate_usage_patterns()
            if usage_result["success"]: category_results["artifacts"].extend(usage_result["artifacts"])
            else: category_results["success"] = False
            
        if bh_config.get("generate_browsing_history", False):
            browsing_result = self._generate_browsing_history()
            if browsing_result["success"]: category_results["artifacts"].extend(browsing_result["artifacts"])
            else: category_results["success"] = False

        if bh_config.get("create_system_activity", False):
            activity_result = self._create_system_activity()
            if activity_result["success"]: category_results["artifacts"].extend(activity_result["artifacts"])
            else: category_results["success"] = False
            
        return category_results

    def _create_user_artifacts(self) -> Dict[str, Any]:
        """Create realistic user files and directories."""
        technique = StealthTechnique(
            name="create_user_artifacts", category="behavioral", os_target=self.guest_os_type, risk_level="low",
            description="Create common user files (documents, desktop items)."
        )
        result = {"success": True, "artifacts": []}
        created_artifacts_local = []

        try:
            common_docs_path_win = "C:\\Users\\Public\\Documents"
            common_desktop_path_win = "C:\\Users\\Public\\Desktop"
            common_home_linux = "/home/user" # Assuming a common user 'user'
            common_docs_path_linux = f"{common_home_linux}/Documents"
            common_desktop_path_linux = f"{common_home_linux}/Desktop"

            if self.guest_os_type == "windows":
                # Ensure base paths exist
                execute_command_in_guest(self.vm_identifier, f'mkdir "{common_docs_path_win}" 2>nul', self.config)
                execute_command_in_guest(self.vm_identifier, f'mkdir "{common_desktop_path_win}" 2>nul', self.config)
                user_items = [
                    (f"{common_docs_path_win}\\Report.docx", "Placeholder report content."),
                    (f"{common_docs_path_win}\\Data.xlsx", "ID,Value\n1,100\n2,200"),
                    (f"{common_desktop_path_win}\\MyProject.lnk", "[InternetShortcut]\nURL=file:///C:/Users/Public/Documents") # Dummy lnk
                ]
            else: # Linux
                execute_command_in_guest(self.vm_identifier, f'mkdir -p "{common_docs_path_linux}" "{common_desktop_path_linux}" 2>/dev/null', self.config)
                user_items = [
                    (f"{common_docs_path_linux}/notes.txt", "Meeting notes..."),
                    (f"{common_desktop_path_linux}/run_app.desktop", "[Desktop Entry]\nName=My App\nExec=/usr/bin/gedit\nType=Application")
                ]

            for item_path, content in user_items[:2]: # Limit for demo
                cmd = f'echo "{content}" > "{item_path}"' if self.guest_os_type == "windows" else f'echo -e "{content}" > "{item_path}"'
                _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=30)
                if rc == 0:
                    created_artifacts_local.append(item_path)
                    self.stealth_artifacts.append(f"file:{item_path}")
                else: result["success"] = False
            
            result["artifacts"] = created_artifacts_local
            technique.description = f"Created {len(created_artifacts_local)} user artifacts. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "Failed to create one or more user artifacts."

        except Exception as e:
            logger.error(f"User artifacts creation failed: {e}")
            technique.error_message = str(e)
            result["success"] = False; result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _simulate_usage_patterns(self) -> Dict[str, Any]:
        """Simulate realistic system usage patterns (e.g., recent files, temp files)."""
        technique = StealthTechnique(
            name="simulate_usage_patterns", category="behavioral", os_target=self.guest_os_type, risk_level="medium",
            description="Simulate system usage like recent files, temp files, bash history."
        )
        result = {"success": True, "artifacts": []}
        simulated_patterns_local = []

        try:
            if self.guest_os_type == "windows":
                # RecentDocs (simplified - real MRU lists are more complex)
                recent_docs_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
                recent_files = ["ExistingDoc1.docx", "Spreadsheet.xlsx"]
                for i, filename in enumerate(recent_files):
                    # This creates a value, not a real MRU binary entry.
                    reg_cmd = f'reg add "{recent_docs_key}" /v "MRU{i}" /t REG_SZ /d "{filename}" /f >nul 2>&1'
                    _, _, rc = execute_command_in_guest(self.vm_identifier, reg_cmd, self.config, timeout_sec=10)
                    if rc == 0:
                        simulated_patterns_local.append(f"RecentDoc entry: {filename}")
                        # self.stealth_artifacts.append(f"registry:{recent_docs_key}\\MRU{i}") # For cleanup if needed
                    else: result["success"] = False
                
                # Temp files
                temp_dir = "C:\\Windows\\Temp"
                for i in range(2):
                    temp_file_path = f"{temp_dir}\\tmp{generate_random_serial(4)}.tmp"
                    cmd = f'echo "temp data {random.randint(1000,9999)}" > "{temp_file_path}"'
                    _, _, rc_tmp = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=10)
                    if rc_tmp == 0:
                        simulated_patterns_local.append(temp_file_path)
                        self.stealth_artifacts.append(f"file:{temp_file_path}")
                    else: result["success"] = False
            else: # Linux - Bash history
                bash_history_file = "/home/user/.bash_history" # Assuming user 'user'
                history_cmds = ["ls -la", "cd /tmp", "cat /proc/cpuinfo", "df -h"]
                history_content = "\\n".join(history_cmds)
                # Append to history file
                cmd = f'echo -e "{history_content}" >> "{bash_history_file}" 2>/dev/null'
                _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=10)
                if rc == 0:
                    simulated_patterns_local.append(f"Bash history populated in {bash_history_file}")
                    # self.stealth_artifacts.append(f"file:{bash_history_file}") # Appending, harder to clean specific lines
                else: result["success"] = False
            
            result["artifacts"] = simulated_patterns_local
            technique.description = f"Simulated {len(simulated_patterns_local)} usage patterns. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "Failed to simulate one or more usage patterns."

        except Exception as e:
            logger.error(f"Usage pattern simulation failed: {e}")
            technique.error_message = str(e)
            result["success"] = False; result["error"] = str(e)

        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _generate_browsing_history(self) -> Dict[str, Any]:
        """Generate realistic web browsing history (simplified)."""
        technique = StealthTechnique(
            name="generate_browsing_history", category="behavioral", os_target=self.guest_os_type, risk_level="low",
            description="Create fake browser history entries or files."
        )
        result = {"success": True, "artifacts": []}
        browsing_artifacts_local = []
        websites = ["www.google.com", "www.wikipedia.org", "www.github.com"]

        try:
            if self.guest_os_type == "windows":
                # IE TypedURLs (simplified)
                ie_typed_key = r"HKCU\Software\Microsoft\Internet Explorer\TypedURLs"
                for i, site in enumerate(websites):
                    cmd = f'reg add "{ie_typed_key}" /v "url{i+1}" /t REG_SZ /d "http://{site}" /f >nul 2>&1'
                    _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=10)
                    if rc == 0:
                        browsing_artifacts_local.append(f"IE TypedURL: {site}")
                        self.stealth_artifacts.append(f"registry:{ie_typed_key}\\url{i+1}")
                    else: result["success"] = False
                
                # Fake Chrome history file
                chrome_history_dir_win = "C:\\Users\\Public\\AppData\\Local\\Google\\Chrome\\User Data\\Default" # Public for simplicity
                execute_command_in_guest(self.vm_identifier, f'mkdir "{chrome_history_dir_win}" 2>nul', self.config)
                chrome_hist_file = f"{chrome_history_dir_win}\\History"
                cmd_chrome = f'echo "Fake Chrome History Data" > "{chrome_hist_file}"'
                _, _, rc_ch = execute_command_in_guest(self.vm_identifier, cmd_chrome, self.config, timeout_sec=10)
                if rc_ch == 0:
                    browsing_artifacts_local.append(chrome_hist_file)
                    self.stealth_artifacts.append(f"file:{chrome_hist_file}")
                else: result["success"] = False

            else: # Linux - Fake Firefox places.sqlite
                ff_profile_dir_linux = "/home/user/.mozilla/firefox/randomprofile.default" # Assuming user 'user'
                execute_command_in_guest(self.vm_identifier, f'mkdir -p "{ff_profile_dir_linux}" 2>/dev/null', self.config)
                ff_hist_file = f"{ff_profile_dir_linux}/places.sqlite"
                cmd_ff = f'echo "SQLite format 3" > "{ff_hist_file}"' # Minimal fake content
                _, _, rc_ff = execute_command_in_guest(self.vm_identifier, cmd_ff, self.config, timeout_sec=10)
                if rc_ff == 0:
                    browsing_artifacts_local.append(ff_hist_file)
                    self.stealth_artifacts.append(f"file:{ff_hist_file}")
                else: result["success"] = False

            result["artifacts"] = browsing_artifacts_local
            technique.description = f"Generated {len(browsing_artifacts_local)} browsing artifacts. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "Failed to generate one or more browsing artifacts."

        except Exception as e:
            logger.error(f"Browsing history generation failed: {e}")
            technique.error_message = str(e)
            result["success"] = False; result["error"] = str(e)

        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _create_system_activity(self) -> Dict[str, Any]:
        """Create system activity logs and traces (e.g., event logs, prefetch)."""
        technique = StealthTechnique(
            name="create_system_activity", category="behavioral", os_target=self.guest_os_type, risk_level="medium",
            description="Generate fake system activity like event logs or prefetch files."
        )
        result = {"success": True, "artifacts": []}
        activity_artifacts_local = []

        try:
            if self.guest_os_type == "windows":
                # Event logs (Application log, source "StealthSim")
                events_to_log = ["Application GenericApp started.", "User JohnDoe logged off."]
                for event_desc in events_to_log:
                    cmd = f'eventcreate /T INFORMATION /ID 9001 /L APPLICATION /SO StealthSim /D "{event_desc}" >nul 2>&1'
                    _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=15)
                    if rc == 0: activity_artifacts_local.append(f"Event log: {event_desc}")
                    else: result["success"] = False; logger.warning(f"Failed to create event: {event_desc}")
                
                # Prefetch files (create empty files with correct naming)
                prefetch_dir = "C:\\Windows\\Prefetch"
                common_apps = ["NOTEPAD.EXE", "CALC.EXE"]
                for app_name in common_apps:
                    # Prefetch filename format: EXECUTABLE_NAME-HASH.pf
                    pf_hash = generate_random_serial(8, chars=string.ascii_uppercase + string.digits)
                    pf_path = f"{prefetch_dir}\\{app_name}-{pf_hash}.pf"
                    cmd_pf = f'echo. > "{pf_path}"' # Create empty file
                    _, _, rc_pf = execute_command_in_guest(self.vm_identifier, cmd_pf, self.config, timeout_sec=10)
                    if rc_pf == 0:
                        activity_artifacts_local.append(pf_path)
                        self.stealth_artifacts.append(f"file:{pf_path}")
                    else: result["success"] = False
            else: # Linux - Syslog entries (using logger)
                log_entries = ["kernel: [Firmware Bug]: ACPI region does not cover the entire command space", "systemd[1]: Started User Manager for UID 1000."]
                for entry in log_entries:
                    cmd = f'logger -p user.info "Simulated: {entry}" 2>/dev/null'
                    _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=10)
                    if rc == 0: activity_artifacts_local.append(f"Syslog entry: {entry[:30]}...")
                    else: result["success"] = False
            
            result["artifacts"] = activity_artifacts_local
            technique.description = f"Created {len(activity_artifacts_local)} system activity traces. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "Failed to create one or more system activity traces."

        except Exception as e:
            logger.error(f"System activity creation failed: {e}")
            technique.error_message = str(e)
            result["success"] = False; result["error"] = str(e)

        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _apply_network_stealth(self) -> Dict[str, Any]:
        """Apply network-level stealth measures."""
        logger.info("Applying network stealth measures")
        category_results = {"success": True, "artifacts": []} # Changed "failures" to "artifacts" for consistency
        net_config = self.stealth_profile.get("network_stealth", {})

        if net_config.get("populate_network_artifacts", False):
            network_result = self._populate_network_artifacts()
            if network_result["success"]: category_results["artifacts"].extend(network_result["artifacts"])
            else: category_results["success"] = False
        
        if net_config.get("simulate_network_history", False):
            history_result = self._simulate_network_history()
            # _simulate_network_history returns a description, not artifacts list
            if not history_result["success"]: category_results["success"] = False
            else: category_results["artifacts"].append(history_result["description"])


        return category_results

    def _populate_network_artifacts(self) -> Dict[str, Any]:
        """Populate network-related artifacts like ARP cache, DNS cache (by lookups)."""
        technique = StealthTechnique(
            name="populate_network_artifacts", category="network", os_target=self.guest_os_type, risk_level="low",
            description="Populate ARP cache with fake entries and perform DNS lookups."
        )
        result = {"success": True, "artifacts": []}
        network_artifacts_local = []
        fake_arp_entries = [("192.168.1.1", "00:1a:2b:3c:4d:01"), ("192.168.1.254", "00:1a:2b:3c:4d:fe")]

        try:
            if self.guest_os_type == "windows":
                for ip, mac in fake_arp_entries:
                    cmd = f'arp -s {ip} {mac} >nul 2>&1' # Requires admin
                    _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=10)
                    if rc == 0: network_artifacts_local.append(f"ARP entry: {ip} -> {mac}")
                    else: result["success"] = False; logger.warning(f"Failed to add ARP entry {ip} (may need admin)")
                
                # Populate DNS cache by performing lookups
                dns_lookups = ["google.com", "microsoft.com"]
                for domain in dns_lookups:
                    cmd_dns = f'nslookup {domain} >nul 2>&1'
                    _, _, rc_dns = execute_command_in_guest(self.vm_identifier, cmd_dns, self.config, timeout_sec=15)
                    if rc_dns == 0: network_artifacts_local.append(f"DNS lookup: {domain}")
                    else: result["success"] = False
            else: # Linux
                for ip, mac in fake_arp_entries: # Requires root
                    cmd = f'arp -s {ip} {mac} 2>/dev/null'
                    _, _, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=10)
                    if rc == 0: network_artifacts_local.append(f"ARP entry: {ip} -> {mac}")
                    else: result["success"] = False; logger.warning(f"Failed to add ARP entry {ip} (may need root)")
                
                # DNS lookups (using getent or dig)
                dns_lookups = ["google.com", "wikipedia.org"]
                for domain in dns_lookups:
                    cmd_dns = f'getent hosts {domain} >/dev/null 2>&1 || dig +short {domain} >/dev/null 2>&1'
                    _, _, rc_dns = execute_command_in_guest(self.vm_identifier, cmd_dns, self.config, timeout_sec=15)
                    if rc_dns == 0: network_artifacts_local.append(f"DNS lookup: {domain}")
                    else: result["success"] = False

            result["artifacts"] = network_artifacts_local
            technique.description = f"Populated {len(network_artifacts_local)} network artifacts. Success: {result['success']}"
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "Failed to populate one or more network artifacts."

        except Exception as e:
            logger.error(f"Network artifacts population failed: {e}")
            technique.error_message = str(e)
            result["success"] = False; result["error"] = str(e)

        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def _simulate_network_history(self) -> Dict[str, Any]:
        """Simulate network connection history by pinging common hosts."""
        technique = StealthTechnique(
            name="simulate_network_history", category="network", os_target=self.guest_os_type, risk_level="low",
            description="Simulate network activity by pinging common external hosts."
        )
        result = {"success": True}
        target_hosts = ["8.8.8.8", "1.1.1.1", "google.com"] # Google DNS, Cloudflare DNS, Google
        ping_count = 1 # Number of pings

        try:
            hosts_pinged_successfully = 0
            for host in target_hosts[:2]: # Limit for demo
                if self.guest_os_type == "windows":
                    ping_cmd = f'ping -n {ping_count} {host} >nul 2>&1'
                else: # Linux
                    ping_cmd = f'ping -c {ping_count} {host} >/dev/null 2>&1'
                
                _, _, rc = execute_command_in_guest(self.vm_identifier, ping_cmd, self.config, timeout_sec=20)
                if rc == 0:
                    hosts_pinged_successfully +=1
                    logger.debug(f"Pinged {host} for network history simulation.")
                else:
                    logger.warning(f"Failed to ping {host} (rc: {rc})")
                    result["success"] = False # Mark partial failure if any ping fails
            
            desc = f"Simulated network connections to {hosts_pinged_successfully}/{len(target_hosts[:2])} hosts. Success: {result['success']}"
            result["description"] = desc
            technique.description = desc
            technique.applied = result["success"]
            if not result["success"]: technique.error_message = "One or more hosts failed to ping."

        except Exception as e:
            logger.error(f"Network history simulation failed: {e}")
            technique.error_message = str(e)
            result["success"] = False; result["error"] = str(e)
        
        technique.timestamp = datetime.now().isoformat()
        self.applied_techniques[technique.name] = technique
        return result

    def validate_stealth_effectiveness(self) -> Dict[str, Any]:
        """
        Validate the effectiveness of applied stealth measures by running detection tests.
        
        Returns:
            Dictionary with validation results
        """
        logger.info("Validating stealth effectiveness")
        
        validation_results = {
            "overall_effectiveness": "unknown",
            "tests_passed": 0,
            "tests_failed": 0,
            "detection_tests": [], # List of individual test result dicts
            "recommendations": []
        }
        
        try:
            # Test 1: Check for VM registry keys
            if self.guest_os_type == "windows":
                registry_test = self._test_registry_detection()
                validation_results["detection_tests"].append(registry_test)
                if registry_test["passed"]: validation_results["tests_passed"] += 1
                else: validation_results["tests_failed"] += 1
            
            # Test 2: Check for VM files
            files_test = self._test_file_detection()
            validation_results["detection_tests"].append(files_test)
            if files_test["passed"]: validation_results["tests_passed"] += 1
            else: validation_results["tests_failed"] += 1
            
            # Test 3: Check for VM processes
            process_test = self._test_process_detection()
            validation_results["detection_tests"].append(process_test)
            if process_test["passed"]: validation_results["tests_passed"] += 1
            else: validation_results["tests_failed"] += 1
            
            # Test 4: Check hardware identifiers
            hardware_test = self._test_hardware_detection()
            validation_results["detection_tests"].append(hardware_test)
            if hardware_test["passed"]: validation_results["tests_passed"] += 1
            else: validation_results["tests_failed"] += 1
            
            # Calculate overall effectiveness
            total_tests = validation_results["tests_passed"] + validation_results["tests_failed"]
            if total_tests > 0:
                effectiveness_ratio = validation_results["tests_passed"] / total_tests
                if effectiveness_ratio == 1.0: validation_results["overall_effectiveness"] = "excellent"
                elif effectiveness_ratio >= 0.75: validation_results["overall_effectiveness"] = "good"
                elif effectiveness_ratio >= 0.5: validation_results["overall_effectiveness"] = "moderate"
                else: validation_results["overall_effectiveness"] = "poor"
            else: # No tests run (e.g. only Linux tests on Windows or vice-versa if tests are conditional)
                validation_results["overall_effectiveness"] = "no_tests_applicable"

            # Generate recommendations
            validation_results["recommendations"] = self._generate_stealth_recommendations(validation_results)
            
            logger.info(f"Stealth validation completed: {validation_results['overall_effectiveness']} "
                        f"({validation_results['tests_passed']}/{total_tests} tests passed)")
            
        except Exception as e:
            logger.error(f"Stealth validation failed: {e}")
            validation_results["error"] = str(e) # Add error to results
        
        return validation_results

    def _test_registry_detection(self) -> Dict[str, Any]:
        """Test for VM detection via registry keys (Windows only)."""
        test_result = {"test_name": "Registry Detection Test", "passed": True, "detected_keys": [], "description": "Check for VM-specific registry keys"}
        if self.guest_os_type != "windows":
            test_result["passed"] = True # Or mark as not applicable
            test_result["description"] = "Not applicable for non-Windows OS."
            return test_result
            
        try:
            # Use a subset of keys for testing to avoid excessive checks
            registry_keys_to_test = self.vm_detection_signatures["registry_keys"].get("windows", [])[:5]
            for reg_key in registry_keys_to_test:
                check_cmd = f'reg query "{reg_key}" >nul 2>&1 && echo EXISTS || echo NOTFOUND'
                stdout, _, rc = execute_command_in_guest(self.vm_identifier, check_cmd, self.config, timeout_sec=10)
                if rc == 0 and "EXISTS" in stdout:
                    test_result["detected_keys"].append(reg_key)
                    test_result["passed"] = False
                    logger.warning(f"VM registry key detected post-stealth: {reg_key}")
        except Exception as e:
            logger.error(f"Registry detection test execution failed: {e}")
            test_result["error"] = str(e); test_result["passed"] = False # Mark as failed if test itself errors
        return test_result

    def _test_file_detection(self) -> Dict[str, Any]:
        """Test for VM detection via file system artifacts."""
        test_result = {"test_name": "File Detection Test", "passed": True, "detected_files": [], "description": "Check for VM-specific files/directories"}
        try:
            file_paths_to_test = self.vm_detection_signatures["file_paths"].get(self.guest_os_type, [])[:5]
            for file_path in file_paths_to_test:
                # Check for original paths, not renamed paths (e.g., .stealth_bkp)
                if self.guest_os_type == "windows":
                    check_cmd = f'if exist "{file_path}" (echo EXISTS) else (echo NOTFOUND)'
                else: # Linux
                    check_cmd = f'if [ -e "{file_path}" ]; then echo EXISTS; else echo NOTFOUND; fi'
                
                stdout, _, rc = execute_command_in_guest(self.vm_identifier, check_cmd, self.config, timeout_sec=10)
                if rc == 0 and "EXISTS" in stdout:
                    test_result["detected_files"].append(file_path)
                    test_result["passed"] = False
                    logger.warning(f"VM file/directory detected post-stealth: {file_path}")
        except Exception as e:
            logger.error(f"File detection test execution failed: {e}")
            test_result["error"] = str(e); test_result["passed"] = False
        return test_result

    def _test_process_detection(self) -> Dict[str, Any]:
        """Test for VM detection via running processes."""
        test_result = {"test_name": "Process Detection Test", "passed": True, "detected_processes": [], "description": "Check for VM-specific running processes"}
        try:
            process_names_to_check = self.vm_detection_signatures["process_names"].get(self.guest_os_type, [])
            
            if self.guest_os_type == "windows":
                # Get running processes, filter out header and empty lines
                list_cmd = 'tasklist /NH /FO CSV' # No Header, CSV format
            else: # Linux
                list_cmd = 'ps -eo comm --no-headers' # Just command names, no headers
            
            stdout, stderr, rc_list = execute_command_in_guest(self.vm_identifier, list_cmd, self.config, timeout_sec=20)
            if rc_list == 0 and stdout:
                running_processes_output = stdout.lower()
                for proc_name in process_names_to_check:
                    # For Windows CSV, proc_name might be like "VBoxService.exe"
                    # For Linux, just "VBoxService"
                    # Ensure check is robust for both
                    if self.guest_os_type == "windows":
                        # CSV format: "Image Name","PID","Session Name",...
                        if f'"{proc_name.lower()}"' in running_processes_output:
                             test_result["detected_processes"].append(proc_name)
                             test_result["passed"] = False
                             logger.warning(f"VM process detected post-stealth: {proc_name}")
                    else: # Linux, simple list of names
                        if proc_name.lower() in running_processes_output.splitlines():
                            test_result["detected_processes"].append(proc_name)
                            test_result["passed"] = False
                            logger.warning(f"VM process detected post-stealth: {proc_name}")
            elif rc_list != 0 :
                 logger.error(f"Failed to list processes for detection: {stderr}")
                 test_result["error"] = f"Failed to list processes: {stderr}"; test_result["passed"] = False

        except Exception as e:
            logger.error(f"Process detection test execution failed: {e}")
            test_result["error"] = str(e); test_result["passed"] = False
        return test_result

    def _test_hardware_detection(self) -> Dict[str, Any]:
        """Test for VM detection via hardware identifiers (SMBIOS, etc.)."""
        test_result = {"test_name": "Hardware Detection Test", "passed": True, "detected_artifacts": [], "description": "Check for VM-specific hardware identifiers"}
        try:
            # Commands to get hardware info
            if self.guest_os_type == "windows":
                check_cmds_map = {
                    'Manufacturer': 'wmic computersystem get manufacturer /value',
                    'Model': 'wmic computersystem get model /value',
                    'BIOSVendor': 'wmic bios get manufacturer /value' # BIOS Manufacturer is often telling
                }
            else: # Linux
                check_cmds_map = {
                    'SystemManufacturer': 'dmidecode -s system-manufacturer 2>/dev/null || cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "Unknown"',
                    'SystemProduct': 'dmidecode -s system-product-name 2>/dev/null || cat /sys/class/dmi/id/product_name 2>/dev/null || echo "Unknown"',
                    'BIOSVendor': 'dmidecode -s bios-vendor 2>/dev/null || cat /sys/class/dmi/id/bios_vendor 2>/dev/null || echo "Unknown"'
                }
            
            vm_hw_strings = self.vm_detection_signatures["vm_hardware_strings"]
            
            for check_type, cmd in check_cmds_map.items():
                stdout, stderr, rc = execute_command_in_guest(self.vm_identifier, cmd, self.config, timeout_sec=15)
                if rc == 0 and stdout:
                    output_val = stdout.strip().lower()
                    # For wmic /value format: "Manufacturer=Oracle Corporation"
                    if self.guest_os_type == "windows" and "=" in output_val:
                        output_val = output_val.split('=', 1)[-1]

                    for vm_str in vm_hw_strings:
                        if vm_str.lower() in output_val:
                            detected_info = f"{check_type}: '{stdout.strip()}' (contains '{vm_str}')"
                            test_result["detected_artifacts"].append(detected_info)
                            test_result["passed"] = False
                            logger.warning(f"VM hardware string detected post-stealth - {detected_info}")
                            break # Found a match for this check_type
                elif rc != 0:
                    logger.warning(f"Hardware check command for {check_type} failed: {stderr}")
                    # Don't fail the test if command fails, just means we couldn't check this aspect
        
        except Exception as e:
            logger.error(f"Hardware detection test execution failed: {e}")
            test_result["error"] = str(e); test_result["passed"] = False
        return test_result

    def _generate_stealth_recommendations(self, validation_results: Dict) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []
        
        for test in validation_results.get("detection_tests", []):
            if not test.get("passed", True): # Default to passed if key missing
                test_name = test.get("test_name", "Unknown Test")
                detected_items = test.get("detected_keys") or test.get("detected_files") or \
                                 test.get("detected_processes") or test.get("detected_artifacts") or []

                if "Registry" in test_name and detected_items:
                    recommendations.append(f"Further registry cleaning needed. Detected: {', '.join(detected_items[:2])}...")
                    recommendations.append("Consider 'paranoid' software stealth or manual registry editing for these keys.")
                elif "File" in test_name and detected_items:
                    recommendations.append(f"Further file artifact removal needed. Detected: {', '.join(detected_items[:2])}...")
                    recommendations.append("Ensure 'patch_vm_artifacts' or 'hide_vm_tools' covers these paths, or use 'paranoid' level.")
                elif "Process" in test_name and detected_items:
                    recommendations.append(f"VM-related processes still running. Detected: {', '.join(detected_items[:2])}...")
                    recommendations.append("Investigate 'hide_vm_tools' (service disabling) or 'modify_vm_services'.")
                elif "Hardware" in test_name and detected_items:
                    recommendations.append(f"Hardware identifiers still indicate a VM. Detected: {', '.join(detected_items[:2])}...")
                    recommendations.append("Verify SMBIOS hardware profile application and QEMU CPU args if applicable.")

        if validation_results.get("overall_effectiveness") in ["poor", "moderate", "unknown"]:
            recommendations.append("Consider increasing the overall stealth_level in the profile.")
            if not self.stealth_profile.get("behavioral_stealth", {}).get("enabled"):
                recommendations.append("Enable 'behavioral_stealth' to create more realistic usage patterns.")
            if not self.stealth_profile.get("network_stealth", {}).get("enabled"):
                recommendations.append("Enable 'network_stealth' to populate network artifacts.")
        
        if not recommendations and validation_results.get("overall_effectiveness") == "excellent":
            recommendations.append("Current stealth measures appear effective based on performed tests.")
            
        return list(set(recommendations)) # Remove duplicates

    def get_stealth_report(self) -> Dict[str, Any]:
        """Generate comprehensive stealth configuration report."""
        report = {
            "vm_identifier": self.vm_identifier,
            "hypervisor_type": self.hypervisor_type,
            "guest_os_type": self.guest_os_type,
            "stealth_profile_settings": self.stealth_profile, # Current profile settings
            "applied_techniques_details": {
                name: {
                    "category": tech.category,
                    "os_target": tech.os_target,
                    "risk_level": tech.risk_level,
                    "description": tech.description,
                    "applied_successfully": tech.applied, # Changed key for clarity
                    "timestamp": tech.timestamp,
                    "error_if_any": tech.error_message # Changed key for clarity
                }
                for name, tech in self.applied_techniques.items()
            },
            "created_stealth_artifacts_for_cleanup": self.stealth_artifacts, # List of items to be cleaned
            "generation_timestamp": datetime.now().isoformat()
        }
        return report

    def cleanup_stealth_artifacts(self) -> Dict[str, Any]:
        """Clean up stealth artifacts created by this manager."""
        cleanup_results = {"success": True, "cleaned_count": 0, "cleanup_errors": []}
        logger.info(f"Cleaning up {len(self.stealth_artifacts)} stealth artifacts for VM '{self.vm_identifier}'")
        
        cleaned_count_local = 0
        for artifact_entry in self.stealth_artifacts:
            try:
                entry_type, entry_path = artifact_entry.split(":", 1)
                cleanup_cmd = None

                if entry_type == "file":
                    if self.guest_os_type == "windows":
                        cleanup_cmd = f'del "{entry_path}" /F /Q >nul 2>&1'
                    else: # Linux
                        cleanup_cmd = f'rm -f "{entry_path}" 2>/dev/null'
                elif entry_type == "registry" and self.guest_os_type == "windows":
                    cleanup_cmd = f'reg delete "{entry_path}" /f >nul 2>&1'
                # Add handling for "dir" if needed, e.g., rmdir or rm -rf
                
                if cleanup_cmd:
                    _, stderr, rc = execute_command_in_guest(self.vm_identifier, cleanup_cmd, self.config, timeout_sec=30)
                    if rc == 0:
                        cleaned_count_local += 1
                        logger.debug(f"Successfully cleaned artifact: {artifact_entry}")
                    else:
                        err_msg = f"Failed to clean artifact {artifact_entry} (rc: {rc}, stderr: {stderr})"
                        logger.warning(err_msg)
                        cleanup_results["cleanup_errors"].append(err_msg)
                        cleanup_results["success"] = False
                else:
                    logger.warning(f"Unknown artifact type or OS mismatch for cleanup: {artifact_entry}")
            
            except Exception as e:
                err_msg = f"Error processing cleanup for artifact {artifact_entry}: {e}"
                logger.error(err_msg)
                cleanup_results["cleanup_errors"].append(err_msg)
                cleanup_results["success"] = False
        
        cleanup_results["cleaned_count"] = cleaned_count_local
        # Clear the list after attempting cleanup
        self.stealth_artifacts.clear() 
        logger.info(f"Stealth cleanup completed. Cleaned: {cleaned_count_local}, "
                    f"Errors: {len(cleanup_results['cleanup_errors'])}")
        return cleanup_results

    def export_stealth_config(self, output_path: str) -> bool:
        """Export current stealth configuration (profile and applied state) to a file."""
        try:
            # Use the get_stealth_report method to get comprehensive data
            export_data = self.get_stealth_report()
            export_data["export_version"] = "1.1" # Version of this export format
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Stealth configuration and report exported to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export stealth configuration: {e}")
            return False


# High-level convenience functions
def apply_stealth_to_vm(vm_identifier: str, config: dict, 
                        stealth_level: str = StealthLevel.ADVANCED,
                        custom_profile_data: Dict[str, Any] = None,
                        custom_profile_path: str = None) -> Dict[str, Any]:
    """
    Convenience function to apply stealth measures to a VM.
    
    Args:
        vm_identifier: VM to apply stealth to
        config: VM configuration
        stealth_level: Level of stealth to apply (if no custom_profile)
        custom_profile_data: Custom stealth profile data (overrides stealth_level)
        custom_profile_path: Path to custom stealth profile file (overrides data and level)
    
    Returns:
        Dictionary with stealth application results and validation
    """
    try:
        with AdvancedStealthManager(vm_identifier, config) as stealth_mgr:
            # Load stealth profile
            if custom_profile_path:
                stealth_mgr.load_stealth_profile(profile_path=custom_profile_path)
            elif custom_profile_data:
                stealth_mgr.load_stealth_profile(profile_data=custom_profile_data)
            else:
                stealth_mgr.load_stealth_profile(stealth_level=stealth_level)
            
            # Apply stealth measures
            application_results = stealth_mgr.apply_all_stealth_measures()
            
            # Validate effectiveness
            validation_results = stealth_mgr.validate_stealth_effectiveness()
            application_results["validation_after_apply"] = validation_results # Embed validation
            
            return application_results
            
    except Exception as e:
        logger.error(f"High-level stealth application failed for VM '{vm_identifier}': {e}", exc_info=True)
        return {"success": False, "error": str(e), "vm_identifier": vm_identifier}


def validate_vm_stealth(vm_identifier: str, config: dict) -> Dict[str, Any]:
    """
    Convenience function to validate VM stealth effectiveness without applying new measures.
    
    Args:
        vm_identifier: VM to validate
        config: VM configuration
    
    Returns:
        Dictionary with validation results
    """
    try:
        with AdvancedStealthManager(vm_identifier, config) as stealth_mgr:
            # Note: This validation runs independently of any applied profile by this instance.
            # It tests the current state of the VM against known detection vectors.
            return stealth_mgr.validate_stealth_effectiveness()
            
    except Exception as e:
        logger.error(f"High-level stealth validation failed for VM '{vm_identifier}': {e}", exc_info=True)
        return {"success": False, "error": str(e), "vm_identifier": vm_identifier}


def generate_stealth_profile_config(stealth_level: str = StealthLevel.ADVANCED,
                               hardware_profile_name: str = "dell_optiplex",
                               target_os_type: str = "windows") -> Dict[str, Any]:
    """
    Generate a stealth profile configuration dictionary.
    
    Args:
        stealth_level: Level of stealth measures (basic, advanced, paranoid)
        hardware_profile_name: Name of the hardware profile to emulate (e.g., "dell_optiplex")
        target_os_type: Target guest OS type ("windows" or "linux")
    
    Returns:
        Dictionary with stealth profile configuration
    """
    # Create a minimal temporary config for the manager to generate a profile
    temp_vm_id = "temp_profile_gen_vm"
    temp_host_config = {
        "vms": {
            temp_vm_id: {
                "guest_os_type": target_os_type,
                "name": temp_vm_id 
                # No actual VM operations will be performed
            }
        }
    }
    
    try:
        # Use a temporary manager instance solely for profile generation
        temp_mgr = AdvancedStealthManager(temp_vm_id, temp_host_config, hypervisor_type="qemu") # Hypervisor type doesn't matter much for profile gen
        profile = temp_mgr._generate_default_profile(stealth_level)
        
        # Customize with specified hardware profile name
        if "hardware_stealth" in profile and profile["hardware_stealth"].get("enabled"):
            if hardware_profile_name in temp_mgr.hardware_profiles:
                profile["hardware_stealth"]["hardware_profile"] = hardware_profile_name
            else:
                logger.warning(f"Hardware profile '{hardware_profile_name}' not found. Using default for level.")
        
        return profile
        
    except Exception as e:
        logger.error(f"Stealth profile generation failed: {e}", exc_info=True)
        return {}


if __name__ == "__main__":
    """
    Example usage and testing of the advanced stealth manager.
    """
    import argparse
    import sys
    
    logging.basicConfig(
        level=logging.INFO, # Set to logging.DEBUG for more verbose output
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)] # Ensure logs go to stdout
    )
    
    parser = argparse.ArgumentParser(description='Advanced VM Stealth Manager CLI')
    parser.add_argument('--vm', required=True, help='VM identifier (name/ID known to hypervisor tools)')
    parser.add_argument('--config-file', required=True, help='Path to the VM host configuration JSON file (containing VM details, paths to ssh keys etc.)')
    parser.add_argument('--stealth-level', choices=[StealthLevel.BASIC, StealthLevel.ADVANCED, StealthLevel.PARANOID], 
                        default=StealthLevel.ADVANCED, help='Stealth level to apply or generate profile for')
    parser.add_argument('--action', choices=['apply', 'validate', 'generate_profile', 'cleanup', 'full_cycle'], 
                        default='apply', help='Action to perform')
    parser.add_argument('--profile-output', help='File path to save generated profile or exported config')
    parser.add_argument('--custom-profile-input', help='File path to load a custom stealth profile from (for apply action)')

    args = parser.parse_args()
    
    try:
        # Load VM host configuration
        if not os.path.exists(args.config_file):
            print(f"Error: Configuration file not found: {args.config_file}")
            sys.exit(1)
        with open(args.config_file, 'r', encoding='utf-8') as f:
            host_config = json.load(f)
        
        if args.vm not in host_config.get("vms", {}):
            print(f"Error: VM '{args.vm}' not found in configuration file '{args.config_file}'.")
            print(f"Available VMs: {list(host_config.get('vms', {}).keys())}")
            sys.exit(1)

        print(f"\n=== Advanced VM Stealth Manager CLI ===")
        print(f"Action: {args.action}")
        print(f"VM: {args.vm}")
        if args.action != 'validate': # Stealth level relevant for apply/generate
             print(f"Stealth Level: {args.stealth_level}")

        if args.action == 'generate_profile':
            print("\n--- Generating Stealth Profile ---")
            # Determine target OS from config if possible, else default
            vm_conf = host_config["vms"][args.vm]
            target_os = vm_conf.get("guest_os_type", "windows")
            # Allow specifying hardware profile for generation via an extended arg later if needed
            default_hw_profile = "dell_optiplex" 
            
            profile_config = generate_stealth_profile_config(args.stealth_level, default_hw_profile, target_os)
            if profile_config:
                print("Generated Profile:")
                print(json.dumps(profile_config, indent=2))
                if args.profile_output:
                    with open(args.profile_output, 'w', encoding='utf-8') as pf:
                        json.dump(profile_config, pf, indent=2)
                    print(f"Profile saved to: {args.profile_output}")
            else:
                print("Profile generation failed.")

        elif args.action == 'apply' or args.action == 'full_cycle':
            print("\n--- Applying Stealth Measures ---")
            custom_profile_to_load = None
            if args.custom_profile_input:
                if not os.path.exists(args.custom_profile_input):
                    print(f"Warning: Custom profile input file '{args.custom_profile_input}' not found. Using level '{args.stealth_level}'.")
                else:
                    try:
                        with open(args.custom_profile_input, 'r', encoding='utf-8') as cpf:
                            custom_profile_to_load = json.load(cpf)
                        print(f"Loaded custom profile from: {args.custom_profile_input}")
                    except json.JSONDecodeError:
                        print(f"Error: Invalid JSON in custom profile file '{args.custom_profile_input}'. Using level '{args.stealth_level}'.")
            
            results = apply_stealth_to_vm(args.vm, host_config, args.stealth_level, custom_profile_data=custom_profile_to_load)
            
            print(f"\nApplication Overall Success: {results.get('success', False)}")
            print(f"Applied Techniques: {len(results.get('applied_technique_names', []))}")
            if results.get('failed_technique_names'):
                print(f"Failed Techniques: {results.get('failed_technique_names')}")
            
            if results.get('validation_after_apply'):
                val = results['validation_after_apply']
                print(f"\nPost-Apply Validation:")
                print(f"  Effectiveness: {val.get('overall_effectiveness', 'unknown')}")
                print(f"  Tests Passed: {val.get('tests_passed', 0)}, Failed: {val.get('tests_failed', 0)}")
                if val.get('recommendations'):
                    print("  Recommendations:")
                    for rec in val['recommendations']: print(f"    - {rec}")
            
            if args.profile_output: # Use profile_output to export the applied config/report
                 with AdvancedStealthManager(args.vm, host_config) as mgr:
                    # Need to re-load the profile that was used if it was custom
                    if custom_profile_to_load: mgr.load_stealth_profile(profile_data=custom_profile_to_load)
                    else: mgr.load_stealth_profile(stealth_level=args.stealth_level)
                    # Populate applied_techniques and artifacts by re-running parts or loading from results
                    # For simplicity, the export will reflect the profile, not the dynamic state perfectly without re-application.
                    # A better approach would be for apply_stealth_to_vm to return the manager instance or full report.
                    # For now, just export the profile that would have been used.
                    if mgr.export_stealth_config(args.profile_output):
                         print(f"Applied configuration report exported to: {args.profile_output}")


        elif args.action == 'validate':
            print("\n--- Validating Current VM Stealth ---")
            validation = validate_vm_stealth(args.vm, host_config)
            print(f"Overall Effectiveness: {validation.get('overall_effectiveness', 'unknown')}")
            print(f"Tests Passed: {validation.get('tests_passed', 0)}")
            print(f"Tests Failed: {validation.get('tests_failed', 0)}")
            if validation.get('detection_tests'):
                print("\nDetailed Test Results:")
                for test_res in validation.get('detection_tests', []):
                    status = "PASSED" if test_res.get('passed') else "FAILED"
                    detected = ""
                    if not test_res.get('passed'):
                        detected_items = test_res.get("detected_keys") or test_res.get("detected_files") or \
                                         test_res.get("detected_processes") or test_res.get("detected_artifacts")
                        if detected_items:
                            detected = f" (Detected: {', '.join(map(str, detected_items[:2]))}...)"
                    print(f"  - {test_res.get('test_name', 'N/A')}: {status}{detected}")

            if validation.get('recommendations'):
                print("\nRecommendations:")
                for rec in validation['recommendations']: print(f"  - {rec}")

        elif args.action == 'cleanup':
            print("\n--- Cleaning Up Stealth Artifacts (if tracked by a previous run) ---")
            # Cleanup needs the state of 'stealth_artifacts' from the instance that applied them.
            # This CLI call creates a new instance, so it won't know about prior artifacts unless
            # they are loaded from a saved state/report. This is a limitation of stateless CLI cleanup.
            # For a true cleanup, the apply action should perhaps save its artifact list.
            print("Warning: CLI cleanup is limited. It will attempt to clean based on a default profile's potential artifacts.")
            print("For effective cleanup, use within the same session/script that applied stealth or load a report.")
            with AdvancedStealthManager(args.vm, host_config) as stealth_mgr:
                # Attempt to load a profile to guess what might have been created.
                # This is a very rough cleanup.
                stealth_mgr.load_stealth_profile(stealth_level=args.stealth_level) 
                # Manually populate some common artifacts based on the profile for a demo cleanup
                # This is NOT ideal. A proper cleanup would use a saved list of artifacts.
                if stealth_mgr.stealth_profile.get("behavioral_stealth", {}).get("create_user_artifacts"):
                    if stealth_mgr.guest_os_type == "windows":
                        stealth_mgr.stealth_artifacts.append("file:C:\\Users\\Public\\Documents\\Report.docx") # Example
                    else:
                        stealth_mgr.stealth_artifacts.append("file:/home/user/Documents/notes.txt") # Example
                
                if stealth_mgr.stealth_artifacts:
                    print(f"Attempting cleanup of {len(stealth_mgr.stealth_artifacts)} potential artifacts...")
                    cleanup_results = stealth_mgr.cleanup_stealth_artifacts()
                    print(f"Cleanup Attempt Success: {cleanup_results.get('success', False)}")
                    print(f"Artifacts Cleaned (attempted): {cleanup_results.get('cleaned_count', 0)}")
                    if cleanup_results.get('cleanup_errors'):
                        print(f"Cleanup Errors: {cleanup_results.get('cleanup_errors')}")
                else:
                    print("No specific artifacts to clean based on default profile simulation.")

        if args.action == 'full_cycle':
            print("\n--- Cleaning Up Stealth Artifacts (Post Full Cycle) ---")
            # This assumes the 'apply_stealth_to_vm' function's manager instance somehow persisted
            # or that we can reconstruct the artifacts. For CLI, this is tricky.
            # The 'apply_stealth_to_vm' would need to return the manager or its artifact list.
            # For now, this will be a conceptual cleanup.
            print("Conceptual: A full cycle would apply, then validate, then cleanup.")
            print("Cleanup in a separate CLI call after 'apply' requires state persistence (e.g., via exported report).")


        print("\n=== Stealth Management CLI Finished ===")
        
    except FileNotFoundError as fnf_e: # Redundant due to earlier check, but good practice
        print(f"Error: A required file was not found: {fnf_e}")
        sys.exit(1)
    except json.JSONDecodeError as json_e:
        print(f"Error: Invalid JSON in a configuration or profile file: {json_e}")
        sys.exit(1)
    except ValueError as ve: # Catch ValueErrors from manager init
        print(f"Configuration Error: {ve}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logger.error("Stealth management CLI failed with an unexpected error:", exc_info=True)
        sys.exit(1)
