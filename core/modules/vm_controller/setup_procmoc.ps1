# setup_procmon.ps1
# Purpose: Configure Windows VM for optimal ProcMon behavioral monitoring
# This script prepares the Windows environment for Shikra analysis

param(
    [string]$ProcMonPath = "C:\Windows\Temp\procmon.exe",
    [string]$ConfigPath = "C:\Windows\Temp\procmon_config.pmc",
    [switch]$Verbose,
    [switch]$AcceptEula
)

# Enable verbose output if requested
if ($Verbose) {
    $VerbosePreference = "Continue"
}

Write-Host "=== Shikra ProcMon Setup Script ===" -ForegroundColor Cyan
Write-Host "Configuring Windows VM for behavioral monitoring..." -ForegroundColor Green

# Function to write log messages
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Check if running as Administrator
function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Configure Windows settings for optimal monitoring
function Optimize-WindowsForMonitoring {
    Write-Log "Optimizing Windows settings for monitoring..."
    
    try {
        # Disable Windows Defender real-time protection temporarily
        Write-Log "Temporarily disabling Windows Defender real-time protection..."
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        
        # Disable UAC temporarily for smoother monitoring
        Write-Log "Configuring UAC settings..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -ErrorAction SilentlyContinue
        
        # Increase process monitoring limits
        Write-Log "Configuring system limits for monitoring..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "NonPagedPoolSize" -Value 0 -ErrorAction SilentlyContinue
        
        # Configure event log sizes
        Write-Log "Configuring event log retention..."
        wevtutil sl System /ms:100000000 2>$null
        wevtutil sl Application /ms:100000000 2>$null
        wevtutil sl Security /ms:100000000 2>$null
        
        Write-Log "Windows optimization completed" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error optimizing Windows: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Verify ProcMon installation
function Test-ProcMonInstallation {
    Write-Log "Verifying ProcMon installation..."
    
    if (-not (Test-Path $ProcMonPath)) {
        Write-Log "ProcMon executable not found at: $ProcMonPath" -Level "ERROR"
        return $false
    }
    
    # Test ProcMon execution
    try {
        $output = & $ProcMonPath /? 2>&1
        if ($output -match "Process Monitor") {
            Write-Log "ProcMon verification successful" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "ProcMon verification failed - unexpected output" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error testing ProcMon: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Accept ProcMon EULA
function Accept-ProcMonEula {
    Write-Log "Accepting ProcMon EULA..."
    
    try {
        # Accept EULA by running ProcMon with /AcceptEula flag
        $process = Start-Process -FilePath $ProcMonPath -ArgumentList "/AcceptEula" -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 2
        
        if (-not $process.HasExited) {
            $process.Kill()
        }
        
        Write-Log "ProcMon EULA accepted" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error accepting EULA: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Create optimized ProcMon configuration
function New-ProcMonConfiguration {
    Write-Log "Creating optimized ProcMon configuration..."
    
    # Since PMC files are binary, we'll create a registry-based configuration
    # that ProcMon will read, or use command-line filtering
    
    try {
        # Create a PowerShell script that will configure ProcMon via registry
        $configScript = @"
# ProcMon Registry Configuration
`$regPath = "HKCU:\Software\Sysinternals\Process Monitor"
if (-not (Test-Path `$regPath)) {
    New-Item -Path `$regPath -Force | Out-Null
}

# Configure basic filtering settings
Set-ItemProperty -Path `$regPath -Name "FilterRules" -Value "ProcessName;contains;system;Exclude" -ErrorAction SilentlyContinue
Set-ItemProperty -Path `$regPath -Name "ShowImage" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path `$regPath -Name "ShowNetwork" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path `$regPath -Name "ShowProcess" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path `$regPath -Name "ShowRegistry" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path `$regPath -Name "ShowFile" -Value 1 -ErrorAction SilentlyContinue

Write-Host "ProcMon registry configuration completed"
"@
        
        # Execute the configuration
        Invoke-Expression $configScript
        
        Write-Log "ProcMon configuration created successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error creating configuration: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Configure Windows services for monitoring
function Optimize-ServicesForMonitoring {
    Write-Log "Optimizing Windows services for monitoring..."
    
    try {
        # Stop unnecessary services that generate noise
        $servicesToStop = @(
            "Themes",
            "TabletInputService", 
            "WSearch",
            "BITS"
        )
        
        foreach ($service in $servicesToStop) {
            try {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq "Running") {
                    Write-Log "Stopping service: $service"
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Log "Could not stop service $service : $($_.Exception.Message)" -Level "WARN"
            }
        }
        
        # Configure additional services
        Write-Log "Service optimization completed" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error optimizing services: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Create monitoring directories
function New-MonitoringDirectories {
    Write-Log "Creating monitoring directories..."
    
    $directories = @(
        "C:\Shikra\Logs",
        "C:\Shikra\Config", 
        "C:\Shikra\Tools",
        "C:\Windows\Temp\ProcMonLogs"
    )
    
    foreach ($dir in $directories) {
        try {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-Log "Created directory: $dir"
            }
        }
        catch {
            Write-Log "Error creating directory $dir : $($_.Exception.Message)" -Level "WARN"
        }
    }
    
    return $true
}

# Configure system for malware analysis safety
function Set-AnalysisSafetyMeasures {
    Write-Log "Configuring analysis safety measures..."
    
    try {
        # Disable automatic updates
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 1 -ErrorAction SilentlyContinue
        
        # Disable error reporting
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -ErrorAction SilentlyContinue
        
        # Disable system restore
        Disable-ComputerRestore -Drive "C:" -ErrorAction SilentlyContinue
        
        # Configure firewall to allow monitoring
        Write-Log "Configuring Windows Firewall..."
        netsh advfirewall set allprofiles state off 2>$null
        
        Write-Log "Safety measures configured" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error configuring safety measures: $($_.Exception.Message)" -Level "WARN"
        return $true  # Non-critical, continue
    }
}

# Generate system information report
function New-SystemInfoReport {
    Write-Log "Generating system information report..."
    
    try {
        $systemInfo = @{
            "ComputerName" = $env:COMPUTERNAME
            "OSVersion" = (Get-WmiObject -Class Win32_OperatingSystem).Caption
            "Architecture" = (Get-WmiObject -Class Win32_Processor).Architecture
            "TotalMemory" = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            "AvailableSpace" = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB, 2)
            "ConfigurationTime" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "ProcMonPath" = $ProcMonPath
            "ConfigPath" = $ConfigPath
        }
        
        $reportPath = "C:\Shikra\Logs\system_info.json"
        $systemInfo | ConvertTo-Json | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-Log "System information report saved to: $reportPath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Error generating system info: $($_.Exception.Message)" -Level "WARN"
        return $true  # Non-critical
    }
}

# Main execution flow
function Main {
    Write-Log "Starting Shikra ProcMon setup..." -Level "SUCCESS"
    
    # Check administrator rights
    if (-not (Test-AdminRights)) {
        Write-Log "This script must be run as Administrator!" -Level "ERROR"
        exit 1
    }
    
    $success = $true
    
    # Create necessary directories
    if (-not (New-MonitoringDirectories)) {
        $success = $false
    }
    
    # Generate system information
    New-SystemInfoReport | Out-Null
    
    # Verify ProcMon installation
    if (-not (Test-ProcMonInstallation)) {
        Write-Log "ProcMon installation verification failed!" -Level "ERROR"
        $success = $false
    }
    else {
        # Accept EULA if requested or if ProcMon is present
        if ($AcceptEula -or (Test-Path $ProcMonPath)) {
            Accept-ProcMonEula | Out-Null
        }
        
        # Create ProcMon configuration
        New-ProcMonConfiguration | Out-Null
    }
    
    # Optimize Windows for monitoring
    if (-not (Optimize-WindowsForMonitoring)) {
        Write-Log "Windows optimization had issues, but continuing..." -Level "WARN"
    }
    
    # Optimize services
    Optimize-ServicesForMonitoring | Out-Null
    
    # Set safety measures
    Set-AnalysisSafetyMeasures | Out-Null
    
    if ($success) {
        Write-Log "=== Shikra ProcMon setup completed successfully! ===" -Level "SUCCESS"
        Write-Log "VM is ready for behavioral monitoring" -Level "SUCCESS"
        
        # Display final status
        Write-Host "`n=== SETUP SUMMARY ===" -ForegroundColor Cyan
        Write-Host "ProcMon Path: $ProcMonPath" -ForegroundColor White
        Write-Host "Config Path: $ConfigPath" -ForegroundColor White
        Write-Host "Monitoring Directory: C:\Shikra\Logs" -ForegroundColor White
        Write-Host "System optimized for malware analysis" -ForegroundColor Green
        Write-Host "Ready for Shikra behavioral monitoring!" -ForegroundColor Green
        
        exit 0
    }
    else {
        Write-Log "=== Setup completed with errors ===" -Level "ERROR"
        Write-Log "Please review the errors above and retry if necessary" -Level "WARN"
        exit 1
    }
}

# Execute main function
Main