# shikra/modules/vm_controller/__init__.py
# Purpose: Initializes the vm_controller package.
# This file makes Python treat the directory `vm_controller` as a package.
# It can also be used for package-level initializations or to expose specific sub-modules/functions.

import logging

logger = logging.getLogger(__name__)
logger.info("vm_controller package initialized.")

# You can selectively import key functions from your modules here to make them
# available directly from the package, e.g.:
# from .snapshot import create_snapshot, list_snapshots, revert_to_snapshot, delete_snapshot, prune_snapshots
# from .stealth import get_qemu_stealth_args
# from .run_in_vm import winrm_execute_command, ssh_execute_command
# from .copy_to_vm import winrm_copy_file_to_guest, ssh_copy_file_to_guest
# from .copy_from_vm import winrm_copy_file_from_guest, ssh_copy_file_from_guest

# Example of exposing all functions from snapshot.py (if desired, though often specific imports are better)
# from .snapshot import *

# For now, keeping it simple. Users of this package will do:
# from modules.vm_controller.snapshot import create_snapshot
# or if the utils/vm_controller_cli.py is in the project root and sys.path is adjusted:
# from vm_controller.snapshot import create_snapshot

# It's good practice to define __all__ if you use 'from .module import *'
# to specify what gets imported.
# __all__ = [
# "create_snapshot", "list_snapshots", "revert_to_snapshot", "delete_snapshot", "prune_snapshots",
# "get_qemu_stealth_args",
# "winrm_execute_command", "ssh_execute_command",
# "winrm_copy_file_to_guest", "ssh_copy_file_to_guest",
# "winrm_copy_file_from_guest", "ssh_copy_file_from_guest"
# ]

