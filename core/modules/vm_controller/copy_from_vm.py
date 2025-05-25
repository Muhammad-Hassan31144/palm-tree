# shikra/modules/vm_controller/copy_from_vm.py
# Purpose: Copies files and directories from the guest VM to the host
#          using WinRM (Windows) or SSH/SFTP (Linux).

import logging
import os
import base64
import winrm
import paramiko
import stat # For setting permissions on host for copied dirs/files from Linux

# Assuming config.py provides get_vm_credentials(vm_name_or_ip) -> (username, password/key_path, os_type)
# And get_vm_ip(vm_name) -> ip_address
# from config import get_vm_config # Example: adjust based on your config.py structure
# For now, using the same placeholder config functions as in run_in_vm.py
from .run_in_vm import _get_guest_os_type, _get_guest_credentials # Re-use for consistency

logger = logging.getLogger(__name__)

# --- WinRM File Retrieval ---
# Similar to copy_to_vm, WinRM isn't a direct file transfer protocol.
# We'll execute PowerShell on the guest to read a file, base64 encode it,
# and print to stdout. The host will capture this stdout. Suitable for smaller files.

def winrm_copy_file_from_guest(
    vm_ip: str,
    username: str,
    password: str,
    guest_file_path: str,
    host_file_path: str,
    timeout_sec: int = 300,
    transport: str = 'ntlm',
    server_cert_validation: str = 'ignore'
) -> bool:
    """
    Copies a file from a Windows guest to the host using WinRM.
    The guest file's content is base64 encoded and read from PowerShell's stdout.

    Args:
        guest_file_path (str): Full path of the file on the guest.
        host_file_path (str): Full path where the file should be saved on the host.
        Other args are same as winrm_execute_command.

    Returns:
        bool: True if successful, False otherwise.
    """
    logger.info(f"Attempting to copy '{guest_file_path}' from Windows VM {vm_ip} to host '{host_file_path}' via WinRM.")

    ps_guest_file_path = guest_file_path.replace("'", "''") # Basic escaping for PowerShell

    # PowerShell script to read file, base64 encode, and write to stdout
    ps_script = f"""
    $ErrorActionPreference = "Stop"
    $filePath = '{ps_guest_file_path}'
    try {{
        if (-not (Test-Path $filePath -PathType Leaf)) {{
            Write-Error "File not found or is a directory: $filePath"
            exit 2 # Specific exit code for file not found
        }}
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        $base64String = [System.Convert]::ToBase64String($fileBytes)
        Write-Output $base64String
        exit 0
    }} catch {{
        Write-Error "Failed to read or encode file '$filePath': $($_.Exception.Message)"
        exit 1
    }}
    """

    try:
        # Re-use winrm_execute_powershell_script from run_in_vm.py
        from .run_in_vm import winrm_execute_powershell_script as execute_ps_module_func

        std_out_bytes, std_err_bytes, rc = execute_ps_module_func(
            vm_ip, username, password, ps_script,
            timeout_sec=timeout_sec, transport=transport, server_cert_validation=server_cert_validation
        )

        if rc == 0 and std_out_bytes:
            try:
                # The output is the base64 string, potentially with newlines if it's long.
                base64_content = std_out_bytes.decode('utf-8').strip()
                file_bytes = base64.b64decode(base64_content)

                # Ensure host directory exists
                host_dir = os.path.dirname(host_file_path)
                if host_dir:
                    os.makedirs(host_dir, exist_ok=True)
                
                with open(host_file_path, 'wb') as f:
                    f.write(file_bytes)
                logger.info(f"Successfully copied '{guest_file_path}' from {vm_ip} to '{host_file_path}'.")
                return True
            except Exception as e:
                logger.error(f"Failed to decode base64 content or write to host file '{host_file_path}': {e}")
                if std_err_bytes: logger.error(f"WinRM copy (decode/write error) stderr: {std_err_bytes.decode('utf-8', errors='replace')}")
                return False
        elif rc == 2: # Specific exit code for file not found on guest
            logger.error(f"File '{guest_file_path}' not found on guest VM {vm_ip}.")
            if std_err_bytes: logger.error(f"WinRM copy stderr: {std_err_bytes.decode('utf-8', errors='replace')}")
            return False
        else:
            logger.error(f"Failed to retrieve file '{guest_file_path}' from {vm_ip}. RC: {rc}")
            if std_err_bytes: logger.error(f"WinRM copy stderr: {std_err_bytes.decode('utf-8', errors='replace')}")
            if std_out_bytes: logger.error(f"WinRM copy stdout (error case): {std_out_bytes.decode('utf-8', errors='replace')}")
            return False

    except Exception as e:
        logger.error(f"Unexpected error during WinRM file retrieval from {vm_ip}: {e}")
        return False

# --- SSH/SFTP File Retrieval (using Paramiko) ---
from .copy_to_vm import _get_sftp_client # Reuse SFTP client helper

def ssh_copy_file_from_guest(
    vm_ip: str,
    username: str,
    guest_file_path: str,
    host_file_path: str,
    password: str = None,
    ssh_key_path: str = None,
    port: int = 22,
    timeout_sec: int = 300
) -> bool:
    """
    Copies a single file from a Linux guest to the host using SFTP (Paramiko).

    Args:
        guest_file_path (str): Full path of the file on the guest.
        host_file_path (str): Full path where the file should be saved on the host.
        Other args are same as ssh_execute_command.

    Returns:
        bool: True if successful, False otherwise.
    """
    logger.info(f"Attempting SSH (SFTP) copy of {vm_ip}:{guest_file_path} to host '{host_file_path}'")
    sftp = None
    ssh = None # To close the underlying SSH connection
    try:
        sftp = _get_sftp_client(vm_ip, username, password, ssh_key_path, port, timeout_sec)
        if not sftp:
            return False
        ssh = sftp.get_channel().get_transport().get_security_options().client

        # Ensure host directory exists
        host_dir = os.path.dirname(host_file_path)
        if host_dir:
            os.makedirs(host_dir, exist_ok=True)

        sftp.get(guest_file_path, host_file_path)
        logger.info(f"Successfully copied {vm_ip}:{guest_file_path} to '{host_file_path}' via SFTP.")
        return True
    except FileNotFoundError: # For sftp.get if remote file doesn't exist
        logger.error(f"Remote file not found on {vm_ip}:{guest_file_path}")
        return False
    except Exception as e:
        logger.error(f"Error during SFTP file retrieval from {vm_ip}:{guest_file_path}: {e}")
        return False
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()
            logger.debug(f"SSH connection for SFTP to {vm_ip} closed.")


def ssh_copy_directory_from_guest(
    vm_ip: str,
    username: str,
    guest_dir_path: str,
    host_dir_path: str,
    password: str = None,
    ssh_key_path: str = None,
    port: int = 22,
    timeout_sec: int = 600
) -> bool:
    """
    Copies a directory recursively from a Linux guest to the host using SFTP (Paramiko).

    Args:
        guest_dir_path (str): Path to the directory on the guest.
        host_dir_path (str): Path on the host where the directory contents will be placed.
                             The directory itself (basename of guest_dir_path) will be created under host_dir_path.
        Other args are same as ssh_execute_command.

    Returns:
        bool: True if all contents copied successfully, False otherwise.
    """
    logger.info(f"Attempting SSH (SFTP) recursive copy of directory {vm_ip}:{guest_dir_path} to host '{host_dir_path}'")
    sftp = None
    ssh = None
    try:
        sftp = _get_sftp_client(vm_ip, username, password, ssh_key_path, port, timeout_sec)
        if not sftp:
            return False
        ssh = sftp.get_channel().get_transport().get_security_options().client

        # Ensure base host directory exists
        # The target directory on host will be host_dir_path + basename(guest_dir_path)
        guest_basename = os.path.basename(guest_dir_path.rstrip('/\\'))
        final_host_target_dir = os.path.join(host_dir_path, guest_basename)
        os.makedirs(final_host_target_dir, exist_ok=True)

        # Walk the remote directory
        # Paramiko's SFTP client doesn't have a direct recursive get.
        # We need to listdir, check type, and recurse or get.
        
        def _sftp_walk(remote_path):
            path_items = []
            for entry in sftp.listdir_attr(remote_path):
                entry_remote_path = os.path.join(remote_path, entry.filename).replace("\\", "/")
                if stat.S_ISDIR(entry.st_mode):
                    path_items.append({'type': 'dir', 'path': entry_remote_path, 'name': entry.filename})
                    path_items.extend(_sftp_walk(entry_remote_path))
                else:
                    path_items.append({'type': 'file', 'path': entry_remote_path, 'name': entry.filename})
            return path_items

        remote_items = [{'type': 'dir', 'path': guest_dir_path, 'name': ''}] # Start with the root dir itself
        remote_items.extend(_sftp_walk(guest_dir_path))

        for item in remote_items:
            relative_path_from_guest_root = os.path.relpath(item['path'], guest_dir_path if item['name'] else os.path.dirname(guest_dir_path))
            current_host_path = os.path.join(final_host_target_dir, relative_path_from_guest_root)

            if item['type'] == 'dir':
                os.makedirs(current_host_path, exist_ok=True)
                logger.debug(f"Created host directory: {current_host_path}")
            else: # file
                logger.debug(f"Copying remote file: {item['path']} -> {current_host_path}")
                sftp.get(item['path'], current_host_path)
        
        logger.info(f"Successfully copied directory {vm_ip}:{guest_dir_path} to '{final_host_target_dir}' via SFTP.")
        return True

    except Exception as e:
        logger.error(f"Error during SFTP directory retrieval from {vm_ip}:{guest_dir_path}: {e}")
        return False
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()
            logger.debug(f"SSH connection for SFTP to {vm_ip} closed.")


# --- Generic Copy Function (selects based on OS type) ---
def copy_from_guest(
    vm_identifier: str,
    guest_path: str,
    host_path: str,
    config: dict, # Pass the global/profile config here
    is_directory: bool = False,
    timeout_sec: int = 300
) -> bool:
    """
    Copies a file or directory from the specified guest VM to the host.

    Args:
        vm_identifier (str): Name or IP of the VM.
        guest_path (str): Path to the file or directory on the guest.
        host_path (str): Path on the host where the file/directory should be saved.
                         If copying a directory, this is the parent directory on the host.
        config (dict): Configuration dictionary containing VM details.
        is_directory (bool): True if guest_path is a directory to be copied recursively.
        timeout_sec (int): Timeout for the operation.

    Returns:
        bool: True if successful, False otherwise.
    """
    os_type = _get_guest_os_type(vm_identifier, config)
    ip, user, password, ssh_key_path = _get_guest_credentials(vm_identifier, config)

    if not ip:
        logger.error(f"Could not determine IP for VM identifier '{vm_identifier}'. Cannot copy from guest.")
        return False

    if os_type == "windows":
        if is_directory:
            logger.warning("Recursive directory copy from Windows via WinRM is not directly supported by this basic implementation. Consider zipping on guest and copying the zip.")
            return False # Not implemented robustly
        else: # It's a file
            return winrm_copy_file_from_guest(
                ip, user, password, guest_path, host_path, timeout_sec=timeout_sec
            )
    elif os_type == "linux":
        if is_directory:
            return ssh_copy_directory_from_guest(
                ip, user, guest_path, host_path, password, ssh_key_path, timeout_sec=timeout_sec
            )
        else:
            return ssh_copy_file_from_guest(
                ip, user, guest_path, host_path, password, ssh_key_path, timeout_sec=timeout_sec
            )
    else:
        logger.error(f"Unsupported OS type '{os_type}' for VM '{vm_identifier}'. Cannot copy from guest.")
        return False


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    mock_config_data = { # Same mock config as in run_in_vm.py
        "vms": {
            "MyWindowsVM": {
                "ip": "192.168.122.111", "guest_os_type": "windows", # Replace with your Win VM IP
                "user": "Analyst", "password": "Password123!"      # Replace with Win creds
            },
            "MyLinuxVM": {
                "ip": "192.168.122.222", "guest_os_type": "linux",   # Replace with your Lin VM IP
                "user": "shikrauser", "password": "linuxpassword", "ssh_key_path": None # Replace with Lin creds
            }
        }
    }
    logger.info("--- Testing copy_from_vm.py ---")

    # Create a dummy host directory for receiving files
    test_host_receive_dir = "test_host_data_received_from_guest"
    os.makedirs(test_host_receive_dir, exist_ok=True)

    # --- Test Windows VM (WinRM file retrieval) ---
    win_vm_id = "MyWindowsVM"
    if win_vm_id in mock_config_data["vms"]:
        logger.info(f"\n--- Testing Windows VM Copy From Guest: {win_vm_id} ---")
        # IMPORTANT: Ensure this file exists on your Windows guest for testing!
        win_guest_source_file = "C:\\Windows\\System32\\drivers\\etc\\hosts" # A common small text file
        win_host_dest_file = os.path.join(test_host_receive_dir, f"{win_vm_id}_hosts.txt")
        
        logger.info(f"Copying file '{win_guest_source_file}' from Windows guest to host at '{win_host_dest_file}'")
        if copy_from_guest(win_vm_id, win_guest_source_file, win_host_dest_file, mock_config_data, is_directory=False):
             logger.info(f"  WinRM file copy from guest successful. Host file: {win_host_dest_file}")
        else:
             logger.error("  WinRM file copy from guest failed.")
        logger.warning("  WinRM directory copy from guest is not implemented in this example.")
    else:
        logger.warning(f"Windows VM '{win_vm_id}' not in mock_config_data. Skipping Windows copy-from tests.")

    # --- Test Linux VM (SSH/SFTP file and directory retrieval) ---
    linux_vm_id = "MyLinuxVM"
    if linux_vm_id in mock_config_data["vms"]:
        logger.info(f"\n--- Testing Linux VM Copy From Guest: {linux_vm_id} ---")
        # IMPORTANT: Ensure these files/dirs exist on your Linux guest for testing!
        # e.g., on guest: echo "Hello from Linux guest" > /tmp/guest_sample.txt
        # mkdir -p /tmp/guest_dir_to_copy/subdir && echo "sub file" > /tmp/guest_dir_to_copy/subdir/sub.txt
        linux_guest_source_file = "/etc/hostname" # A common small text file
        linux_host_dest_file = os.path.join(test_host_receive_dir, f"{linux_vm_id}_hostname.txt")
        
        logger.info(f"Copying single file '{linux_guest_source_file}' from Linux guest to host at '{linux_host_dest_file}'")
        if copy_from_guest(linux_vm_id, linux_guest_source_file, linux_host_dest_file, mock_config_data, is_directory=False):
            logger.info(f"  SSH single file copy from guest successful. Host file: {linux_host_dest_file}")
        else:
            logger.error("  SSH single file copy from guest failed.")

        linux_guest_source_dir = "/etc/default" # A common directory with a few files
        linux_host_dest_parent_dir = test_host_receive_dir # Copied dir will be inside this
        logger.info(f"Copying directory '{linux_guest_source_dir}' from Linux guest to host under '{linux_host_dest_parent_dir}'")
        if copy_from_guest(linux_vm_id, linux_guest_source_dir, linux_host_dest_parent_dir, mock_config_data, is_directory=True):
            logger.info(f"  SSH directory copy from guest successful. Host parent dir: {linux_host_dest_parent_dir}")
        else:
            logger.error("  SSH directory copy from guest failed.")
    else:
        logger.warning(f"Linux VM '{linux_vm_id}' not in mock_config_data. Skipping Linux copy-from tests.")
    
    logger.info(f"Test files received in: {test_host_receive_dir}")

