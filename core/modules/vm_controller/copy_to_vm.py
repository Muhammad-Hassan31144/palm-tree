# shikra/modules/vm_controller/copy_to_vm.py
# Purpose: Copies files and directories from the host to the guest VM
#          using WinRM (Windows) or SSH/SFTP (Linux).

import logging
import os
import base64
import winrm
import paramiko

# Assuming config.py provides get_vm_credentials(vm_name_or_ip) -> (username, password/key_path, os_type)
# And get_vm_ip(vm_name) -> ip_address
# from config import get_vm_config # Example: adjust based on your config.py structure
# For now, using the same placeholder config functions as in run_in_vm.py
from .run_in_vm import _get_guest_os_type, _get_guest_credentials # Re-use for consistency

logger = logging.getLogger(__name__)

# --- WinRM File Copy ---
# WinRM is not primarily designed for large file transfers.
# Common methods:
# 1. Execute PowerShell to create a file from base64 encoded content (for small files/scripts).
# 2. Execute PowerShell to download from a host-accessible share or HTTP server.
# 3. Use tools like `winrm-fs` (a separate utility) or more complex PowerShell remoting.
# We'll implement method 1 for simplicity for small files.

def winrm_copy_text_file_to_guest(
    vm_ip: str,
    username: str,
    password: str,
    host_file_content: str, # Content of the file as a string
    guest_file_path: str,
    timeout_sec: int = 300,
    transport: str = 'ntlm',
    server_cert_validation: str = 'ignore'
) -> bool:
    """
    Copies content to a file on a Windows guest using WinRM by executing PowerShell.
    This method is suitable for text files or small binary files (after base64 encoding).

    Args:
        host_file_content (str): The string content to write to the guest file.
        guest_file_path (str): Full path where the file should be created on the guest.
        Other args are same as winrm_execute_command.

    Returns:
        bool: True if successful, False otherwise.
    """
    logger.info(f"Attempting to copy content to '{guest_file_path}' on Windows VM {vm_ip} via WinRM.")

    # Escape guest_file_path for PowerShell command
    # Simple escaping for paths, might need to be more robust for complex paths
    ps_guest_file_path = guest_file_path.replace("'", "''")

    # Create PowerShell script to write the file
    # For binary data, it should be base64 encoded by the caller and decoded here.
    # This example assumes text content.
    # To handle potential single quotes in host_file_content, we can use PowerShell's here-strings
    # or replace single quotes with double single quotes if embedding directly.
    # A safer way for arbitrary content is base64 encoding.

    try:
        # Base64 encode the content to handle special characters safely in PowerShell
        encoded_content_bytes = base64.b64encode(host_file_content.encode('utf-8'))
        encoded_content_str = encoded_content_bytes.decode('utf-8')

        ps_script = f"""
        $ErrorActionPreference = "Stop"
        try {{
            $filePath = '{ps_guest_file_path}'
            $base64Content = '{encoded_content_str}'
            $bytes = [System.Convert]::FromBase64String($base64Content)
            
            # Ensure directory exists
            $parentDir = Split-Path -Path $filePath
            if (-not (Test-Path $parentDir)) {{
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
            }}
            
            [System.IO.File]::WriteAllBytes($filePath, $bytes)
            Write-Host "File '$filePath' created successfully."
            exit 0
        }} catch {{
            Write-Error "Failed to create file '$filePath': $($_.Exception.Message)"
            exit 1
        }}
        """
        
        # Re-use winrm_execute_powershell_script from run_in_vm.py if it's in the same package
        # For now, let's make a direct call to winrm.Session for clarity or import if structured.
        from .run_in_vm import winrm_execute_powershell_script as execute_ps_module_func
        
        std_out, std_err, rc = execute_ps_module_func(
            vm_ip, username, password, ps_script, 
            timeout_sec=timeout_sec, transport=transport, server_cert_validation=server_cert_validation
        )

        if rc == 0:
            logger.info(f"Successfully copied content to '{guest_file_path}' on {vm_ip}.")
            if std_out: logger.debug(f"WinRM copy stdout: {std_out.decode('utf-8', errors='replace')}")
            return True
        else:
            logger.error(f"Failed to copy content to '{guest_file_path}' on {vm_ip}. RC: {rc}")
            if std_err: logger.error(f"WinRM copy stderr: {std_err.decode('utf-8', errors='replace')}")
            if std_out: logger.error(f"WinRM copy stdout (error case): {std_out.decode('utf-8', errors='replace')}")
            return False

    except Exception as e:
        logger.error(f"Unexpected error during WinRM file copy to {vm_ip}: {e}")
        return False

# --- SSH/SFTP File Copy (using Paramiko) ---
def _get_sftp_client(vm_ip: str, username: str, password: str = None, ssh_key_path: str = None, port: int = 22, timeout_sec: int = 30):
    """Helper to establish an SFTP client connection."""
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if ssh_key_path:
            pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path) # Or other key types
            ssh_client.connect(vm_ip, port=port, username=username, pkey=pkey, timeout=timeout_sec)
        elif password:
            ssh_client.connect(vm_ip, port=port, username=username, password=password, timeout=timeout_sec, allow_agent=False, look_for_keys=False)
        else:
            logger.error("SFTP connection requires either a password or an SSH key path.")
            return None
        
        sftp_client = ssh_client.open_sftp()
        logger.debug(f"SFTP client connected to {username}@{vm_ip}:{port}")
        return sftp_client
    except Exception as e:
        logger.error(f"Failed to establish SFTP connection to {username}@{vm_ip}:{port}: {e}")
        if 'ssh_client' in locals() and ssh_client:
            ssh_client.close()
        return None

def ssh_copy_file_to_guest(
    vm_ip: str,
    username: str,
    host_file_path: str,
    guest_file_path: str,
    password: str = None,
    ssh_key_path: str = None,
    port: int = 22,
    timeout_sec: int = 300 # Longer timeout for file transfer
) -> bool:
    """
    Copies a single file from host to a Linux guest using SFTP (Paramiko).

    Args:
        host_file_path (str): Path to the local file on the host.
        guest_file_path (str): Full path where the file should be placed on the guest.
        Other args are same as ssh_execute_command.

    Returns:
        bool: True if successful, False otherwise.
    """
    if not os.path.exists(host_file_path):
        logger.error(f"Host file '{host_file_path}' not found for SSH copy.")
        return False
    if not os.path.isfile(host_file_path):
        logger.error(f"Host path '{host_file_path}' is not a file for SSH copy.")
        return False

    logger.info(f"Attempting SSH (SFTP) copy of '{host_file_path}' to {vm_ip}:{guest_file_path}")
    sftp = None
    ssh = None # To close the underlying SSH connection
    try:
        sftp = _get_sftp_client(vm_ip, username, password, ssh_key_path, port, timeout_sec)
        if not sftp:
            return False
        
        ssh = sftp.get_channel().get_transport().get_security_options().client # Get underlying SSHClient

        # Ensure remote directory exists
        guest_dir = os.path.dirname(guest_file_path)
        if guest_dir: # Only if there's a directory part
            try:
                sftp.stat(guest_dir)
            except FileNotFoundError:
                logger.info(f"Remote directory '{guest_dir}' does not exist. Creating it.")
                # Create directory recursively (mkdir -p equivalent)
                # This is a bit simplified; a robust solution would walk the path.
                # For now, we assume the user might need to ensure deep paths exist or we create one level.
                # A more robust mkdir -p:
                current_dir = ""
                for part in guest_dir.strip('/').split('/'):
                    current_dir += "/" + part
                    try:
                        sftp.stat(current_dir)
                    except FileNotFoundError:
                        sftp.mkdir(current_dir)
                
        sftp.put(host_file_path, guest_file_path)
        logger.info(f"Successfully copied '{host_file_path}' to {vm_ip}:{guest_file_path} via SFTP.")
        return True
    except Exception as e:
        logger.error(f"Error during SFTP file copy to {vm_ip}:{guest_file_path}: {e}")
        return False
    finally:
        if sftp:
            sftp.close()
        if ssh: # Paramiko's SFTPClient doesn't close the SSHClient automatically
            ssh.close()
            logger.debug(f"SSH connection for SFTP to {vm_ip} closed.")


def ssh_copy_directory_to_guest(
    vm_ip: str,
    username: str,
    host_dir_path: str,
    guest_dir_path: str,
    password: str = None,
    ssh_key_path: str = None,
    port: int = 22,
    timeout_sec: int = 600 # Longer for directories
) -> bool:
    """
    Copies a directory recursively from host to a Linux guest using SFTP (Paramiko).

    Args:
        host_dir_path (str): Path to the local directory on the host.
        guest_dir_path (str): Path where the directory should be placed on the guest.
                              The directory itself (basename of host_dir_path) will be created under guest_dir_path.
        Other args are same as ssh_execute_command.

    Returns:
        bool: True if all files copied successfully, False otherwise.
    """
    if not os.path.exists(host_dir_path):
        logger.error(f"Host directory '{host_dir_path}' not found for SSH copy.")
        return False
    if not os.path.isdir(host_dir_path):
        logger.error(f"Host path '{host_dir_path}' is not a directory for SSH copy.")
        return False

    logger.info(f"Attempting SSH (SFTP) recursive copy of directory '{host_dir_path}' to {vm_ip}:{guest_dir_path}")
    sftp = None
    ssh = None
    try:
        sftp = _get_sftp_client(vm_ip, username, password, ssh_key_path, port, timeout_sec)
        if not sftp:
            return False
        ssh = sftp.get_channel().get_transport().get_security_options().client

        # Create the base remote directory if it doesn't exist
        # guest_dir_path is where the host_dir_path's content will go, under a dir named like host_dir_path's basename
        base_remote_target_dir = os.path.join(guest_dir_path, os.path.basename(host_dir_path.rstrip('/\\')))
        
        logger.debug(f"Ensuring remote base directory '{base_remote_target_dir}' exists.")
        try:
            sftp.stat(base_remote_target_dir)
        except FileNotFoundError:
            logger.info(f"Remote base directory '{base_remote_target_dir}' does not exist. Creating it.")
            # Create directory recursively
            current_dir_path = ""
            for part in base_remote_target_dir.strip('/').split('/'):
                if not part: continue # Handle leading slash
                current_dir_path = f"{current_dir_path}/{part}" if current_dir_path else f"/{part}"
                try:
                    sftp.stat(current_dir_path)
                except FileNotFoundError:
                    sftp.mkdir(current_dir_path)


        for root, dirs, files in os.walk(host_dir_path):
            relative_path = os.path.relpath(root, host_dir_path)
            if relative_path == ".":
                remote_root = base_remote_target_dir
            else:
                remote_root = os.path.join(base_remote_target_dir, relative_path)

            for dir_name in dirs:
                remote_dir_path = os.path.join(remote_root, dir_name).replace("\\", "/")
                try:
                    sftp.stat(remote_dir_path)
                except FileNotFoundError:
                    logger.debug(f"Creating remote directory: {remote_dir_path}")
                    sftp.mkdir(remote_dir_path)
            
            for file_name in files:
                local_file_path = os.path.join(root, file_name)
                remote_file_path = os.path.join(remote_root, file_name).replace("\\", "/")
                logger.debug(f"Copying file: {local_file_path} -> {remote_file_path}")
                sftp.put(local_file_path, remote_file_path)
        
        logger.info(f"Successfully copied directory '{host_dir_path}' to {vm_ip}:{base_remote_target_dir} via SFTP.")
        return True

    except Exception as e:
        logger.error(f"Error during SFTP directory copy to {vm_ip}:{guest_dir_path}: {e}")
        return False
    finally:
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()
            logger.debug(f"SSH connection for SFTP to {vm_ip} closed.")


# --- Generic Copy Function (selects based on OS type) ---
def copy_to_guest(
    vm_identifier: str,
    host_path: str,
    guest_path: str,
    config: dict, # Pass the global/profile config here
    is_directory: bool = False,
    timeout_sec: int = 300
) -> bool:
    """
    Copies a file or directory from host to the specified guest VM.

    Args:
        vm_identifier (str): Name or IP of the VM.
        host_path (str): Path to the file or directory on the host.
        guest_path (str): Path (for file) or parent directory (for directory) on the guest.
        config (dict): Configuration dictionary containing VM details.
        is_directory (bool): True if host_path is a directory to be copied recursively.
        timeout_sec (int): Timeout for the operation.

    Returns:
        bool: True if successful, False otherwise.
    """
    os_type = _get_guest_os_type(vm_identifier, config)
    ip, user, password, ssh_key_path = _get_guest_credentials(vm_identifier, config)

    if not ip:
        logger.error(f"Could not determine IP for VM identifier '{vm_identifier}'. Cannot copy.")
        return False
    
    if not os.path.exists(host_path):
        logger.error(f"Host path '{host_path}' does not exist.")
        return False

    if os_type == "windows":
        if is_directory:
            logger.warning("Recursive directory copy to Windows via WinRM is not directly supported by this basic implementation. Consider zipping and unzipping, or using PowerShell for shares.")
            # For a directory, one might iterate, read each file, and use winrm_copy_text_file_to_guest
            # Or, more practically, zip the dir, copy the zip, then execute unzip command.
            # This is a placeholder for a more complex implementation.
            return False # Not implemented for directories robustly
        else: # It's a file
            try:
                with open(host_path, 'rb') as f: # Read as bytes for base64
                    # For winrm_copy_text_file_to_guest, we re-encode to utf-8 string after b64.
                    # The function expects string content, but it will base64 encode it.
                    # This is a bit awkward. Let's assume it's text for now.
                    # If it's binary, the caller of winrm_copy_text_file_to_guest
                    # should handle the base64 encoding of the raw bytes.
                    # For simplicity, let's assume text files are the primary use case here.
                    file_content = ""
                    try:
                        with open(host_path, 'r', encoding='utf-8') as f_text:
                            file_content = f_text.read()
                    except UnicodeDecodeError:
                        logger.warning(f"File {host_path} is not UTF-8 text. Attempting binary->base64->string.")
                        with open(host_path, 'rb') as f_bin:
                             # The winrm_copy_text_file_to_guest will re-encode this to base64.
                             # This is not ideal. A dedicated binary copy function for WinRM would be better.
                             # For now, this will likely corrupt binary files if not handled carefully.
                             # Let's assume the function is primarily for text based content or small scripts.
                             # A better winrm_copy_binary_file would take bytes, b64encode, then send.
                            logger.error("Binary file copy to Windows via this WinRM method is not reliably implemented. Use for text files.")
                            return False # Mark as not fully supported for arbitrary binary files

                return winrm_copy_text_file_to_guest(
                    ip, user, password, file_content, guest_path, timeout_sec=timeout_sec
                )
            except Exception as e:
                logger.error(f"Failed to read host file {host_path} for WinRM copy: {e}")
                return False

    elif os_type == "linux":
        if is_directory:
            return ssh_copy_directory_to_guest(
                ip, user, host_path, guest_path, password, ssh_key_path, timeout_sec=timeout_sec
            )
        else:
            return ssh_copy_file_to_guest(
                ip, user, host_path, guest_path, password, ssh_key_path, timeout_sec=timeout_sec
            )
    else:
        logger.error(f"Unsupported OS type '{os_type}' for VM '{vm_identifier}'. Cannot copy.")
        return False


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    mock_config_data = { # Same mock config as in run_in_vm.py
        "vms": {
            "MyWindowsVM": {
                "ip": "192.168.122.111", "guest_os_type": "windows",
                "user": "Analyst", "password": "Password123!"
            },
            "MyLinuxVM": {
                "ip": "192.168.122.222", "guest_os_type": "linux",
                "user": "shikrauser", "password": "linuxpassword", "ssh_key_path": None
            }
        }
    }
    logger.info("--- Testing copy_to_vm.py ---")

    # Create dummy host files/dirs for testing
    test_host_dir = "test_host_data_to_copy"
    test_host_file = os.path.join(test_host_dir, "sample_to_copy.txt")
    test_host_subdir = os.path.join(test_host_dir, "subdir_to_copy")
    test_host_subfile = os.path.join(test_host_subdir, "sub_sample.txt")

    if not os.path.exists(test_host_dir): os.makedirs(test_host_dir)
    if not os.path.exists(test_host_subdir): os.makedirs(test_host_subdir)
    with open(test_host_file, "w") as f: f.write("Hello from host - Shikra test file.\nWith special chars: '\"!@#$%^&*()")
    with open(test_host_subfile, "w") as f: f.write("Hello from host subdirectory.")


    # --- Test Windows VM (WinRM file copy) ---
    win_vm_id = "MyWindowsVM"
    if win_vm_id in mock_config_data["vms"]:
        logger.info(f"\n--- Testing Windows VM Copy: {win_vm_id} ---")
        # Note: guest_path for winrm_copy_text_file_to_guest is the full file path
        win_guest_file_path = "C:\\Temp\\shikra_copied_sample.txt" 
        logger.info(f"Copying text file '{test_host_file}' to Windows guest at '{win_guest_file_path}'")
        
        # Read content for winrm_copy_text_file_to_guest
        file_content_to_copy = ""
        with open(test_host_file, 'r', encoding='utf-8') as f:
            file_content_to_copy = f.read()

        if copy_to_guest(win_vm_id, test_host_file, win_guest_file_path, mock_config_data, is_directory=False):
             logger.info("  WinRM text file copy successful.")
        else:
             logger.error("  WinRM text file copy failed.")
        # Directory copy to Windows is marked as not implemented robustly
        logger.warning("  WinRM directory copy is not fully implemented in this example.")

    else:
        logger.warning(f"Windows VM '{win_vm_id}' not in mock_config_data. Skipping Windows copy tests.")

    # --- Test Linux VM (SSH/SFTP file and directory copy) ---
    linux_vm_id = "MyLinuxVM"
    if linux_vm_id in mock_config_data["vms"]:
        logger.info(f"\n--- Testing Linux VM Copy: {linux_vm_id} ---")
        linux_guest_base_dir = "/tmp/shikra_guest_data" # Base dir on guest
        linux_guest_file_path = f"{linux_guest_base_dir}/sample_copied.txt"
        
        logger.info(f"Copying single file '{test_host_file}' to Linux guest at '{linux_guest_file_path}'")
        if copy_to_guest(linux_vm_id, test_host_file, linux_guest_file_path, mock_config_data, is_directory=False):
            logger.info("  SSH single file copy successful.")
        else:
            logger.error("  SSH single file copy failed.")

        logger.info(f"Copying directory '{test_host_dir}' to Linux guest under '{linux_guest_base_dir}'")
        # For directory copy, guest_path is the parent directory on the guest.
        # The copied directory will be created inside it.
        if copy_to_guest(linux_vm_id, test_host_dir, linux_guest_base_dir, mock_config_data, is_directory=True):
            logger.info("  SSH directory copy successful.")
        else:
            logger.error("  SSH directory copy failed.")
    else:
        logger.warning(f"Linux VM '{linux_vm_id}' not in mock_config_data. Skipping Linux copy tests.")

    # Cleanup dummy host files/dirs
    # import shutil
    # if os.path.exists(test_host_dir): shutil.rmtree(test_host_dir)
    logger.info("Test files/dirs created in current directory. Remove 'test_host_data_to_copy' manually if desired.")
