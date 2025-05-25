#!/usr/bin/env python3
"""
Comprehensive example demonstrating the Shikra VM Controller integration.

This script shows how to use all the VM controller components together for
complete malware analysis workflows including:
- VM snapshot management
- File operations (copy to/from VM)
- Command execution in VMs
- Stealth configuration
- Complete analysis workflows

Usage:
    python vm_controller_example.py --config config.json --malware sample.exe
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

# Import the integrated VM controller
try:
    from shikra.modules.vm_controller import (
        VMController, 
        execute_complete_analysis,
        create_vm_controller,
        VMState
    )
    from shikra.modules.vm_controller.stealth import generate_random_mac_address
except ImportError:
    # Fallback for development/testing
    import sys
    sys.path.append(str(Path(__file__).parent))
    from vm_controller_integration import (
        VMController, 
        execute_complete_analysis,
        create_vm_controller,
        VMState
    )
    from stealth import generate_random_mac_address

def setup_logging(verbose: bool = False):
    """Configure logging for the example."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f'vm_controller_example_{int(time.time())}.log')
        ]
    )

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Validate required structure
        if 'vms' not in config:
            raise ValueError("Configuration must contain 'vms' section")
        
        return config
    
    except FileNotFoundError:
        print(f"Configuration file not found: {config_path}")
        print("Creating example configuration...")
        return create_example_config(config_path)
    
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in configuration file: {e}")

def create_example_config(config_path: str) -> Dict[str, Any]:
    """Create an example configuration file."""
    example_config = {
        "vms": {
            "windows_analysis": {
                "name": "WindowsAnalysisVM",
                "ip": "192.168.122.100",
                "guest_os_type": "windows",
                "user": "Analyst",
                "password": "AnalysisPass123!",
                "stealth_profile": {
                    "hide_hypervisor_flag": True,
                    "smbios": {
                        "enable_spoofing": True,
                        "system_manufacturer": "Dell Inc.",
                        "system_product_name": "OptiPlex 7050",
                        "system_version": "1.0.0",
                        "bios_vendor": "Dell Inc.",
                        "bios_version": "2.18.0"
                    },
                    "use_localtime_rtc": True,
                    "disable_hpet": False,
                    "machine_type": "q35"
                }
            },
            "linux_analysis": {
                "name": "LinuxAnalysisVM",
                "ip": "192.168.122.101",
                "guest_os_type": "linux",
                "user": "shikra",
                "password": "linuxpass",
                "ssh_key_path": None,
                "stealth_profile": {
                    "hide_hypervisor_flag": True,
                    "use_localtime_rtc": True
                }
            }
        },
        "snapshot_metadata_dir": "/tmp/shikra_snapshots",
        "analysis_tools": {
            "windows": [
                {
                    "name": "Process Monitor",
                    "local_path": "/opt/tools/windows/procmon.exe",
                    "remote_path": "C:\\Tools\\procmon.exe"
                },
                {
                    "name": "Sysinternals Suite",
                    "local_path": "/opt/tools/windows/sysinternals/",
                    "remote_path": "C:\\Tools\\Sysinternals\\",
                    "is_directory": True
                }
            ],
            "linux": [
                {
                    "name": "strace",
                    "local_path": "/usr/bin/strace",
                    "remote_path": "/tmp/tools/strace"
                },
                {
                    "name": "tcpdump",
                    "local_path": "/usr/bin/tcpdump",
                    "remote_path": "/tmp/tools/tcpdump"
                }
            ]
        },
        "collection_paths": {
            "windows": [
                "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                "C:\\Temp\\analysis_output.txt",
                "C:\\Users\\Analyst\\AppData\\Local\\Temp\\*"
            ],
            "linux": [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/tmp/analysis_output.txt",
                "/tmp/strace_output.txt"
            ]
        }
    }
    
    # Save example configuration
    try:
        with open(config_path, 'w') as f:
            json.dump(example_config, f, indent=2)
        print(f"Example configuration created at: {config_path}")
        print("Please update the VM details (IPs, credentials) and run again.")
    except Exception as e:
        print(f"Failed to create example configuration: {e}")
    
    return example_config

def demonstrate_basic_operations(vm_id: str, config: Dict[str, Any]):
    """Demonstrate basic VM controller operations."""
    print(f"\n=== Basic Operations Demo for VM: {vm_id} ===")
    
    with VMController(vm_id, config) as controller:
        # Show VM status
        print("\n1. VM Status:")
        status = controller.get_vm_status()
        print(f"   VM State: {status['current_state']}")
        print(f"   Guest OS: {status['guest_os_type']}")
        print(f"   Snapshots: {status.get('total_snapshots', 'N/A')}")
        
        # Test command execution
        print("\n2. Command Execution Test:")
        if status['guest_os_type'] == 'windows':
            test_cmd = "echo 'Hello from Windows VM'"
        else:
            test_cmd = "echo 'Hello from Linux VM' && date"
        
        print(f"   Executing: {test_cmd}")
        stdout, stderr, rc = controller.execute_command(test_cmd, timeout_sec=30)
        
        print(f"   Return Code: {rc}")
        if stdout:
            print(f"   Output: {stdout.strip()}")
        if stderr:
            print(f"   Error: {stderr.strip()}")
        
        # Test file operations
        print("\n3. File Operations Test:")
        test_content = f"Test file created at {time.ctime()}\nVM Controller Test\n"
        local_test_file = f"/tmp/vm_test_{int(time.time())}.txt"
        
        # Create local test file
        with open(local_test_file, 'w') as f:
            f.write(test_content)
        
        # Copy to VM
        if status['guest_os_type'] == 'windows':
            remote_test_file = "C:\\Temp\\vm_test.txt"
        else:
            remote_test_file = "/tmp/vm_test.txt"
        
        print(f"   Copying {local_test_file} -> {remote_test_file}")
        if controller.copy_file_to_vm(local_test_file, remote_test_file):
            print("   ✓ File copied to VM successfully")
            
            # Verify file exists in VM
            if status['guest_os_type'] == 'windows':
                verify_cmd = f'type "{remote_test_file}"'
            else:
                verify_cmd = f'cat "{remote_test_file}"'
            
            stdout, stderr, rc = controller.execute_command(verify_cmd, timeout_sec=30)
            if rc == 0:
                print("   ✓ File verification successful")
                print(f"   Content preview: {stdout[:100]}...")
            else:
                print("   ✗ File verification failed")
        else:
            print("   ✗ File copy failed")
        
        # Test snapshot operations
        print("\n4. Snapshot Operations Test:")
        snapshots = controller.list_snapshots(detailed=False)
        print(f"   Current snapshots: {len(snapshots)}")
        
        for snap in snapshots[:3]:  # Show first 3
            print(f"   - {snap['name']}")
        
        # Create a test snapshot
        test_snapshot = f"test_snapshot_{int(time.time())}"
        print(f"   Creating test snapshot: {test_snapshot}")
        if controller.create_snapshot(test_snapshot, "Test snapshot from demo"):
            print("   ✓ Snapshot created successfully")
            
            # List snapshots again
            updated_snapshots = controller.list_snapshots(detailed=False)
            print(f"   Updated snapshot count: {len(updated_snapshots)}")
            
            # Clean up test snapshot
            if controller.delete_snapshot(test_snapshot):
                print("   ✓ Test snapshot cleaned up")
        else:
            print("   ✗ Snapshot creation failed")
        
        # Show operation history
        print("\n5. Operation History:")
        history = controller.get_operation_history(last_n=5)
        for op in history:
            status_icon = "✓" if op['success'] else "✗"
            print(f"   {status_icon} {op['operation_type']}: {op['duration']:.2f}s")
        
        # Clean up local test file
        Path(local_test_file).unlink(missing_ok=True)

def demonstrate_stealth_features(vm_id: str, config: Dict[str, Any]):
    """Demonstrate stealth configuration features."""
    print(f"\n=== Stealth Features Demo for VM: {vm_id} ===")
    
    with VMController(vm_id, config) as controller:
        # Get stealth configuration
        stealth_config = controller.get_stealth_configuration()
        
        print("\n1. Generated Stealth Configuration:")
        print(f"   Random MAC Address: {stealth_config['random_mac']}")
        print(f"   QEMU Arguments: {len(stealth_config['qemu_args'])} args")
        
        if stealth_config['qemu_args']:
            print("   Sample QEMU Args:")
            for arg in stealth_config['qemu_args'][:5]:  # Show first 5
                print(f"     {arg}")
            if len(stealth_config['qemu_args']) > 5:
                print(f"     ... and {len(stealth_config['qemu_args']) - 5} more")
        
        # Test anti-detection commands
        print("\n2. Anti-Detection Verification:")
        guest_os = controller.get_vm_status()['guest_os_type']
        
        if guest_os == 'windows':
            detection_tests = [
                ('wmic computersystem get manufacturer', 'Check system manufacturer'),
                ('wmic computersystem get model', 'Check system model'),
                ('wmic bios get serialnumber', 'Check BIOS serial'),
                ('systeminfo | findstr "System Manufacturer"', 'System info check')
            ]
        else:
            detection_tests = [
                ('dmidecode -s system-manufacturer', 'Check system manufacturer'),
                ('dmidecode -s system-product-name', 'Check system product'),
                ('lscpu | grep Hypervisor', 'Check for hypervisor flag'),
                ('dmesg | grep -i virtual', 'Check kernel messages for virtualization')
            ]
        
        for cmd, description in detection_tests:
            print(f"   Testing: {description}")
            stdout, stderr, rc = controller.execute_command(cmd, timeout_sec=30)
            
            if rc == 0 and stdout:
                # Show first line of output
                first_line = stdout.split('\n')[0].strip()
                print(f"     Result: {first_line}")
            else:
                print(f"     Result: Command failed or no output")

def demonstrate_analysis_workflow(vm_id: str, config: Dict[str, Any], 
                                malware_path: str = None):
    """Demonstrate complete malware analysis workflow."""
    print(f"\n=== Analysis Workflow Demo for VM: {vm_id} ===")
    
    # Create a dummy malware sample if none provided
    if not malware_path or not Path(malware_path).exists():
        print("   Creating dummy malware sample for demo...")
        malware_path = create_dummy_malware_sample()
    
    print(f"   Using malware sample: {malware_path}")
    
    # Get tools configuration
    guest_os = config['vms'][vm_id]['guest_os_type']
    analysis_tools = config.get('analysis_tools', {}).get(guest_os, [])
    collection_paths = config.get('collection_paths', {}).get(guest_os, [])
    
    # Setup commands based on OS
    if guest_os == 'windows':
        setup_commands = [
            'mkdir C:\\Analysis 2>nul',
            'mkdir C:\\Tools 2>nul',
            'mkdir C:\\Temp 2>nul',
            'echo Analysis environment prepared > C:\\Temp\\analysis_output.txt'
        ]
    else:
        setup_commands = [
            'mkdir -p /tmp/analysis',
            'mkdir -p /tmp/tools',
            'echo "Analysis environment prepared" > /tmp/analysis_output.txt'
        ]
    
    print(f"\n1. Preparation Phase:")
    print(f"   - Setup commands: {len(setup_commands)}")
    print(f"   - Analysis tools: {len(analysis_tools)}")
    print(f"   - Collection paths: {len(collection_paths)}")
    
    with VMController(vm_id, config) as controller:
        # Prepare analysis environment
        print("\n2. Preparing Analysis Environment...")
        env_results = controller.prepare_analysis_environment(
            setup_commands=setup_commands,
            tools_to_copy=analysis_tools[:2],  # Limit for demo
            create_baseline=True
        )
        
        print(f"   Environment setup: {'✓' if env_results['success'] else '✗'}")
        print(f"   Commands executed: {len(env_results['commands_executed'])}")
        print(f"   Tools copied: {len(env_results['tools_copied'])}")
        if env_results['baseline_snapshot']:
            print(f"   Baseline snapshot: {env_results['baseline_snapshot']}")
        
        if env_results['errors']:
            print("   Errors encountered:")
            for error in env_results['errors'][:3]:  # Show first 3 errors
                print(f"     - {error}")
        
        # Execute malware analysis
        print("\n3. Executing Malware Analysis...")
        analysis_results = controller.execute_malware_analysis(
            malware_sample_path=malware_path,
            analysis_duration=60,  # Short duration for demo
            collect_artifacts=collection_paths[:3],  # Limit collection for demo
            pre_execution_snapshot=True,
            post_execution_snapshot=True
        )
        
        print(f"   Analysis execution: {'✓' if analysis_results['success'] else '✗'}")
        print(f"   Pre-execution snapshot: {analysis_results['pre_execution_snapshot']}")
        print(f"   Post-execution snapshot: {analysis_results['post_execution_snapshot']}")
        print(f"   Artifacts collected: {len(analysis_results['artifacts_collected'])}")
        
        if analysis_results['execution_output']:
            exec_output = analysis_results['execution_output']
            print(f"   Execution return code: {exec_output['return_code']}")
        
        # Show collected artifacts
        if analysis_results['artifacts_collected']:
            print("   Collected artifacts:")
            for artifact in analysis_results['artifacts_collected']:
                artifact_size = Path(artifact).stat().st_size if Path(artifact).exists() else 0
                print(f"     - {Path(artifact).name} ({artifact_size} bytes)")
        
        # Cleanup
        print("\n4. Cleanup Phase...")
        cleanup_results = controller.cleanup_analysis_session(keep_recent_snapshots=2)
        print(f"   Cleanup: {'✓' if cleanup_results['success'] else '✗'}")
        print(f"   Snapshots pruned: {'✓' if cleanup_results['snapshots_pruned'] else '✗'}")
        
        # Final status
        print("\n5. Final Analysis Summary:")
        final_status = controller.get_vm_status()
        print(f"   VM State: {final_status['current_state']}")
        print(f"   Total snapshots: {final_status.get('total_snapshots', 'N/A')}")
        print(f"   Total operations: {final_status['total_operations']}")

def create_dummy_malware_sample() -> str:
    """Create a dummy malware sample for demonstration."""
    dummy_content = '''#!/bin/bash
# Dummy malware sample for Shikra demonstration
# This is NOT actual malware - just a harmless test script

echo "Dummy malware sample executed at $(date)"
echo "Process ID: $"
echo "Current directory: $(pwd)"
echo "Environment variables:"
env | head -10
echo "Network interfaces:"
ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Network info unavailable"
echo "Dummy malware execution completed"
'''
    
    dummy_path = f"/tmp/dummy_malware_{int(time.time())}.sh"
    with open(dummy_path, 'w') as f:
        f.write(dummy_content)
    
    # Make executable
    Path(dummy_path).chmod(0o755)
    
    return dummy_path

def demonstrate_complete_workflow(config: Dict[str, Any], malware_path: str = None):
    """Demonstrate the complete analysis workflow using the high-level function."""
    print(f"\n=== Complete Workflow Demo ===")
    
    # Select first available VM
    vm_id = list(config['vms'].keys())[0]
    guest_os = config['vms'][vm_id]['guest_os_type']
    
    print(f"Using VM: {vm_id} ({guest_os})")
    
    # Create dummy malware if needed
    if not malware_path or not Path(malware_path).exists():
        malware_path = create_dummy_malware_sample()
    
    # Get configuration
    analysis_tools = config.get('analysis_tools', {}).get(guest_os, [])
    collection_paths = config.get('collection_paths', {}).get(guest_os, [])
    
    # Setup commands
    if guest_os == 'windows':
        setup_commands = [
            'mkdir C:\\Analysis 2>nul',
            'echo Complete workflow test > C:\\Analysis\\workflow_test.txt'
        ]
    else:
        setup_commands = [
            'mkdir -p /tmp/analysis',
            'echo "Complete workflow test" > /tmp/analysis/workflow_test.txt'
        ]
    
    print(f"   Malware sample: {Path(malware_path).name}")
    print(f"   Analysis duration: 45 seconds")
    print(f"   Setup commands: {len(setup_commands)}")
    print(f"   Tools to deploy: {len(analysis_tools[:2])}")
    print(f"   Artifacts to collect: {len(collection_paths[:3])}")
    
    # Execute complete analysis
    print("\nExecuting complete analysis workflow...")
    start_time = time.time()
    
    results = execute_complete_analysis(
        vm_identifier=vm_id,
        config=config,
        malware_sample_path=malware_path,
        analysis_duration=45,
        setup_commands=setup_commands,
        analysis_tools=analysis_tools[:2],  # Limit for demo
        collect_artifacts=collection_paths[:3]  # Limit for demo
    )
    
    execution_time = time.time() - start_time
    
    # Display results
    print(f"\nComplete Workflow Results:")
    print(f"   Overall Success: {'✓' if results['overall_success'] else '✗'}")
    print(f"   Execution Time: {execution_time:.2f} seconds")
    print(f"   VM Identifier: {results['vm_identifier']}")
    print(f"   Malware Sample: {Path(results['malware_sample']).name}")
    
    # Environment preparation results
    env_results = results['environment_preparation']
    print(f"\n   Environment Preparation:")
    print(f"     Success: {'✓' if env_results['success'] else '✗'}")
    print(f"     Commands executed: {len(env_results['commands_executed'])}")
    print(f"     Tools copied: {len(env_results['tools_copied'])}")
    print(f"     Baseline snapshot: {env_results.get('baseline_snapshot', 'None')}")
    
    # Analysis results
    analysis_results = results['malware_analysis']
    print(f"\n   Malware Analysis:")
    print(f"     Success: {'✓' if analysis_results['success'] else '✗'}")
    print(f"     Pre-execution snapshot: {analysis_results.get('pre_execution_snapshot', 'None')}")
    print(f"     Post-execution snapshot: {analysis_results.get('post_execution_snapshot', 'None')}")
    print(f"     Artifacts collected: {len(analysis_results['artifacts_collected'])}")
    
    # Cleanup results
    cleanup_results = results['cleanup']
    print(f"\n   Cleanup:")
    print(f"     Success: {'✓' if cleanup_results['success'] else '✗'}")
    print(f"     Snapshots pruned: {'✓' if cleanup_results['snapshots_pruned'] else '✗'}")
    
    # VM status
    vm_status = results['vm_status']
    print(f"\n   Final VM Status:")
    print(f"     State: {vm_status['current_state']}")
    print(f"     Total operations: {vm_status['total_operations']}")
    print(f"     Total snapshots: {vm_status.get('total_snapshots', 'N/A')}")
    
    # Show any errors
    all_errors = []
    all_errors.extend(env_results.get('errors', []))
    all_errors.extend(analysis_results.get('errors', []))
    all_errors.extend(cleanup_results.get('errors', []))
    
    if all_errors:
        print(f"\n   Errors Encountered ({len(all_errors)}):")
        for error in all_errors[:5]:  # Show first 5 errors
            print(f"     - {error}")
        if len(all_errors) > 5:
            print(f"     ... and {len(all_errors) - 5} more errors")

def main():
    """Main function to run the VM controller demonstration."""
    parser = argparse.ArgumentParser(
        description="Shikra VM Controller Integration Example",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default configuration
  python vm_controller_example.py

  # Run with specific configuration and malware sample
  python vm_controller_example.py --config my_config.json --malware sample.exe

  # Run specific demo modes
  python vm_controller_example.py --demo basic --vm windows_analysis
  python vm_controller_example.py --demo stealth --vm linux_analysis
  python vm_controller_example.py --demo workflow --malware sample.bin
  python vm_controller_example.py --demo complete
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='vm_controller_config.json',
        help='Configuration file path (default: vm_controller_config.json)'
    )
    
    parser.add_argument(
        '--malware', '-m',
        help='Path to malware sample for analysis demo'
    )
    
    parser.add_argument(
        '--demo', '-d',
        choices=['basic', 'stealth', 'workflow', 'complete', 'all'],
        default='all',
        help='Demo mode to run (default: all)'
    )
    
    parser.add_argument(
        '--vm',
        help='Specific VM identifier to use for demos'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--list-vms',
        action='store_true',
        help='List available VMs in configuration and exit'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        print("Loading configuration...")
        config = load_config(args.config)
        
        # List VMs if requested
        if args.list_vms:
            print("\nAvailable VMs:")
            for vm_id, vm_config in config['vms'].items():
                print(f"  {vm_id}:")
                print(f"    Name: {vm_config.get('name', 'N/A')}")
                print(f"    OS: {vm_config.get('guest_os_type', 'N/A')}")
                print(f"    IP: {vm_config.get('ip', 'N/A')}")
                print()
            return
        
        # Validate VM selection
        available_vms = list(config['vms'].keys())
        if not available_vms:
            print("No VMs configured. Please update the configuration file.")
            return
        
        selected_vm = args.vm if args.vm else available_vms[0]
        if selected_vm not in available_vms:
            print(f"VM '{selected_vm}' not found. Available VMs: {', '.join(available_vms)}")
            return
        
        print(f"Using VM: {selected_vm}")
        print(f"Demo mode: {args.demo}")
        print("=" * 60)
        
        # Run demonstrations
        if args.demo in ['basic', 'all']:
            demonstrate_basic_operations(selected_vm, config)
        
        if args.demo in ['stealth', 'all']:
            demonstrate_stealth_features(selected_vm, config)
        
        if args.demo in ['workflow', 'all']:
            demonstrate_analysis_workflow(selected_vm, config, args.malware)
        
        if args.demo in ['complete', 'all']:
            demonstrate_complete_workflow(config, args.malware)
        
        print("\n" + "=" * 60)
        print("VM Controller demonstration completed successfully!")
        print("\nNext steps:")
        print("1. Update the configuration with your actual VM details")
        print("2. Ensure VMs are accessible and credentials are correct")
        print("3. Install required hypervisor tools (virsh, VBoxManage, etc.)")
        print("4. Integrate with your malware analysis pipeline")
        
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
        sys.exit(1)
    
    except Exception as e:
        logger.error(f"Demo failed with error: {e}")
        print(f"\nDemo failed: {e}")
        
        if args.verbose:
            import traceback
            traceback.print_exc()
        
        sys.exit(1)

if __name__ == "__main__":
    main()