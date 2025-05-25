# shikra/modules/vm_controller/run_in_vm.py
# Purpose: Executes commands and scripts within the guest VM using WinRM (Windows) or SSH (Linux).

import logging
import subprocess # For local SSH client if paramiko is not preferred for simple cases
import winrm
import paramiko # For SSH client functionality in Python

# Assuming config.py provides get_vm_credentials(vm_name_or_ip) -> (username, password/key_path, os_type)
# And get_vm_ip(vm_name) -> ip_address
# from config import get_vm_config # Example: adjust based on your config.py structure

logger = logging.getLogger(__name__)

# --- Configuration Placeholders (replace with actual config loading) ---
# These would be fetched from your central config.py based on vm_name or vm_profile
def _get_guest_os_type(vm_identifier: str, config: dict) -> str:
    """Determines guest OS type from configuration."""
    # Example: config might be your loaded global config or a specific vm_profile
    # This is a placeholder; implement based on your config structure.
    vm_details = config.get("vms", {}).get(vm_identifier, {})
    return vm_details.get("guest_os_type", "windows").lower() # Default to windows

def _get_guest_credentials(vm_identifier: str, config: dict) -> tuple:
    """Fetches guest credentials (ip, user, pass/key) from configuration."""
    # Placeholder
    vm_details = config.get("vms", {}).get(vm_identifier, {})
    ip = vm_details.get("ip", "192.168.122.100") # Example IP
    user = vm_details.get("user", "Analyst")
    password = vm_details.get("password", "password")
    ssh_key_path = vm_details.get("ssh_key_path", None)
    return ip, user, password, ssh_key_path

# --- WinRM Execution ---
def winrm_execute_command(
    vm_ip: str,
    username: str,
    password: str,
    command: str,
    timeout_sec: int = 300,
    transport: str = 'ntlm', # or 'kerberos', 'ssl', 'plaintext'
    server_cert_validation: str = 'ignore' # for 'ssl' transport
) -> tuple:
    """
    Executes a command on a Windows guest using WinRM.

    Args:
        vm_ip (str): IP address or hostname of the Windows VM.
        username (str): Username for WinRM authentication.
        password (str): Password for WinRM authentication.
        command (str): The command to execute (e.g., "powershell.exe -Command Get-Process").
        timeout_sec (int): Timeout for the WinRM operation.
        transport (str): WinRM transport protocol.
        server_cert_validation (str): Server certificate validation mode for SSL.

    Returns:
        tuple: (std_out (bytes), std_err (bytes), return_code (int))
               Returns (None, None, -1) on connection failure or major error.
    """
    logger.info(f"Attempting WinRM command on {vm_ip}: {command[:100]}{'...' if len(command) > 100 else ''}")
    session = None
    try:
        # Ensure WinRM endpoint is correctly formatted
        endpoint = f"http://{vm_ip}:5985/wsman" # Default HTTP
        if transport == 'ssl':
            endpoint = f"https://{vm_ip}:5986/wsman" # Default HTTPS

        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport=transport,
            server_cert_validation=server_cert_validation,
            read_timeout_sec=timeout_sec,
            operation_timeout_sec=timeout_sec
        )
        logger.debug(f"WinRM session created for {vm_ip} with transport {transport}")
        
        # WinRM typically runs commands via cmd.exe. For PowerShell, explicitly call it.
        # If the command is already a full powershell command, it's fine.
        # For simple commands, cmd.exe is the shell.
        # Example: if command is "Get-Process", it should be "powershell.exe -Command Get-Process"
        
        result = session.run_cmd(command) # For simple cmd commands
        # For PowerShell scripts or complex commands:
        # result = session.run_ps(command_or_script_content)

        logger.info(f"WinRM command executed on {vm_ip}. Return code: {result.status_code}")
        return result.std_out, result.std_err, result.status_code

    except winrm.exceptions.WinRMTransportError as e:
        logger.error(f"WinRM Transport Error connecting to {vm_ip}: {e}")
        return None, str(e).encode('utf-8'), -1
    except winrm.exceptions.WinRMOperationTimeoutError as e:
        logger.error(f"WinRM Operation Timeout on {vm_ip} for command: {command[:50]}... : {e}")
        return None, str(e).encode('utf-8'), -1
    except winrm.exceptions.WinRMError as e: # Catch other WinRM errors
        logger.error(f"WinRM Error on {vm_ip}: {e}")
        return None, str(e).encode('utf-8'), -1
    except Exception as e:
        logger.error(f"Unexpected error during WinRM execution on {vm_ip}: {e}")
        return None, str(e).encode('utf-8'), -1


def winrm_execute_powershell_script(
    vm_ip: str,
    username: str,
    password: str,
    script_content: str,
    timeout_sec: int = 600,
    transport: str = 'ntlm',
    server_cert_validation: str = 'ignore'
) -> tuple:
    """
    Executes a PowerShell script content on a Windows guest using WinRM.

    Args:
        script_content (str): The PowerShell script content as a string.
        Other args are same as winrm_execute_command.

    Returns:
        tuple: (std_out (bytes), std_err (bytes), return_code (int))
    """
    logger.info(f"Attempting WinRM PowerShell script execution on {vm_ip}: {script_content[:100]}{'...' if len(script_content) > 100 else ''}")
    session = None
    try:
        endpoint = f"http://{vm_ip}:5985/wsman"
        if transport == 'ssl':
            endpoint = f"https://{vm_ip}:5986/wsman"

        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport=transport,
            server_cert_validation=server_cert_validation,
            read_timeout_sec=timeout_sec,
            operation_timeout_sec=timeout_sec
        )
        result = session.run_ps(script_content)
        logger.info(f"WinRM PowerShell script executed on {vm_ip}. Return code: {result.status_code}")
        return result.std_out, result.std_err, result.status_code
    except Exception as e:
        logger.error(f"Unexpected error during WinRM PowerShell script execution on {vm_ip}: {e}")
        return None, str(e).encode('utf-8'), -1


# --- SSH Execution (using Paramiko) ---
def ssh_execute_command(
    vm_ip: str,
    username: str,
    command: str,
    password: str = None,
    ssh_key_path: str = None,
    port: int = 22,
    timeout_sec: int = 300
) -> tuple:
    """
    Executes a command on a Linux guest using SSH (Paramiko).

    Args:
        vm_ip (str): IP address or hostname of the Linux VM.
        username (str): Username for SSH authentication.
        command (str): The command to execute.
        password (str, optional): Password for SSH authentication.
        ssh_key_path (str, optional): Path to the private SSH key.
        port (int): SSH port.
        timeout_sec (int): Timeout for the SSH connection and command execution.

    Returns:
        tuple: (std_out (str), std_err (str), return_code (int))
               Returns (None, None, -1) on connection failure or major error.
    """
    logger.info(f"Attempting SSH command on {vm_ip}:{port}: {command[:100]}{'...' if len(command) > 100 else ''}")
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Automatically add host key

        if ssh_key_path:
            logger.debug(f"Connecting to {vm_ip} using username '{username}' and key '{ssh_key_path}'")
            pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path) # Or Ed25519Key etc.
            client.connect(vm_ip, port=port, username=username, pkey=pkey, timeout=timeout_sec)
        elif password:
            logger.debug(f"Connecting to {vm_ip} using username '{username}' and password.")
            client.connect(vm_ip, port=port, username=username, password=password, timeout=timeout_sec, allow_agent=False, look_for_keys=False)
        else:
            logger.error("SSH connection requires either a password or an SSH key path.")
            return None, "SSH auth method not specified", -1

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec)
        exit_status = stdout.channel.recv_exit_status() # Blocks until command finishes
        
        out_data = stdout.read().decode('utf-8', errors='replace')
        err_data = stderr.read().decode('utf-8', errors='replace')

        logger.info(f"SSH command executed on {vm_ip}. Return code: {exit_status}")
        return out_data, err_data, exit_status

    except paramiko.AuthenticationException as e:
        logger.error(f"SSH Authentication failed for {username}@{vm_ip}: {e}")
        return None, str(e), -1
    except paramiko.SSHException as e:
        logger.error(f"SSH connection or protocol error for {vm_ip}: {e}")
        return None, str(e), -1
    except Exception as e:
        logger.error(f"Unexpected error during SSH execution on {vm_ip}: {e}")
        return None, str(e), -1
    finally:
        if client:
            client.close()

# --- Generic Execution Function (selects based on OS type) ---
def execute_command_in_guest(
    vm_identifier: str, # Could be VM name or IP
    command: str,
    config: dict, # Pass the global/profile config here
    timeout_sec: int = 300,
    is_powershell_script: bool = False # For Windows, if 'command' is PS script content
) -> tuple:
    """
    Executes a command in the specified guest VM, choosing WinRM or SSH based on OS type.

    Args:
        vm_identifier (str): Name or IP of the VM.
        command (str): Command string or PowerShell script content.
        config (dict): Configuration dictionary containing VM details (IP, creds, OS type).
        timeout_sec (int): Execution timeout.
        is_powershell_script (bool): If True and OS is Windows, treats 'command' as PS script content.

    Returns:
        tuple: (output (str/bytes), error (str/bytes), return_code (int))
    """
    os_type = _get_guest_os_type(vm_identifier, config)
    ip, user, password, ssh_key_path = _get_guest_credentials(vm_identifier, config)

    if not ip:
        logger.error(f"Could not determine IP for VM identifier '{vm_identifier}'. Cannot execute command.")
        return None, "IP address not found in config", -1

    if os_type == "windows":
        if is_powershell_script:
            return winrm_execute_powershell_script(ip, user, password, command, timeout_sec=timeout_sec)
        else:
            return winrm_execute_command(ip, user, password, command, timeout_sec=timeout_sec)
    elif os_type == "linux":
        return ssh_execute_command(ip, user, command, password=password, ssh_key_path=ssh_key_path, timeout_sec=timeout_sec)
    else:
        logger.error(f"Unsupported OS type '{os_type}' for VM '{vm_identifier}'. Cannot execute command.")
        return None, f"Unsupported OS type: {os_type}".encode('utf-8'), -1


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # --- Example Configuration (Mimic what your config.py would provide) ---
    mock_config_data = {
        "vms": {
            "MyWindowsVM": { # Replace with your actual VM name/identifier used in config
                "ip": "192.168.122.111", # Replace with your Windows VM's IP
                "guest_os_type": "windows",
                "user": "Analyst",       # Replace with your Windows VM's username
                "password": "Password123!" # Replace with your Windows VM's password
            },
            "MyLinuxVM": { # Replace with your actual VM name/identifier used in config
                "ip": "192.168.122.222", # Replace with your Linux VM's IP
                "guest_os_type": "linux",
                "user": "shikrauser",    # Replace with your Linux VM's username
                "password": "linuxpassword", # Or use ssh_key_path
                "ssh_key_path": None # "/path/to/your/id_rsa"
            }
        }
    }
    logger.info("--- Testing run_in_vm.py ---")

    # --- Test Windows VM (WinRM) ---
    # Ensure WinRM is configured on your Windows VM:
    # In PowerShell (as Admin):
    # Enable-PSRemoting -Force
    # winrm quickconfig -q
    # winrm set winrm/config/service/auth '@{Basic="true"}'
    # winrm set winrm/config/service '@{AllowUnencrypted="true"}' (for HTTP, not recommended for production)
    # For NTLM, ensure network profile is Private/Domain, or adjust firewall.
    
    win_vm_id = "MyWindowsVM" # Identifier used in mock_config_data
    if win_vm_id in mock_config_data["vms"]:
        logger.info(f"\n--- Testing Windows VM: {win_vm_id} ---")
        
        # Test basic command
        win_cmd = "whoami"
        logger.info(f"Executing WinRM command: {win_cmd}")
        stdout, stderr, rc = execute_command_in_guest(win_vm_id, win_cmd, mock_config_data)
        if rc != -1:
            logger.info(f"  Return Code: {rc}")
            logger.info(f"  Stdout:\n{stdout.decode('utf-8', errors='replace') if stdout else ''}")
            logger.info(f"  Stderr:\n{stderr.decode('utf-8', errors='replace') if stderr else ''}")
        else:
            logger.error("  WinRM command execution failed.")

        # Test PowerShell script content
        ps_script = "$PSVersionTable.PSVersion; Get-Date"
        logger.info(f"Executing WinRM PowerShell script content: {ps_script}")
        stdout_ps, stderr_ps, rc_ps = execute_command_in_guest(win_vm_id, ps_script, mock_config_data, is_powershell_script=True)
        if rc_ps != -1:
            logger.info(f"  Return Code: {rc_ps}")
            logger.info(f"  Stdout:\n{stdout_ps.decode('utf-8', errors='replace') if stdout_ps else ''}")
            logger.info(f"  Stderr:\n{stderr_ps.decode('utf-8', errors='replace') if stderr_ps else ''}")
        else:
            logger.error("  WinRM PowerShell script execution failed.")
    else:
        logger.warning(f"Windows VM '{win_vm_id}' not in mock_config_data. Skipping Windows tests.")


    # --- Test Linux VM (SSH) ---
    # Ensure SSH server is running on your Linux VM and accessible.
    # Ensure user/password or key-based auth is set up.
    linux_vm_id = "MyLinuxVM" # Identifier used in mock_config_data
    if linux_vm_id in mock_config_data["vms"]:
        logger.info(f"\n--- Testing Linux VM: {linux_vm_id} ---")
        linux_cmd = "uname -a; date; id"
        logger.info(f"Executing SSH command: {linux_cmd}")
        stdout_ssh, stderr_ssh, rc_ssh = execute_command_in_guest(linux_vm_id, linux_cmd, mock_config_data)

        if rc_ssh != -1:
            logger.info(f"  Return Code: {rc_ssh}")
            logger.info(f"  Stdout:\n{stdout_ssh if stdout_ssh else ''}") # Already decoded by ssh_execute_command
            logger.info(f"  Stderr:\n{stderr_ssh if stderr_ssh else ''}") # Already decoded
        else:
            logger.error("  SSH command execution failed.")
    else:
        logger.warning(f"Linux VM '{linux_vm_id}' not in mock_config_data. Skipping Linux tests.")

