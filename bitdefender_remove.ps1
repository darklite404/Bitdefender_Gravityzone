#Requires -Version 5.1
<#
.SYNOPSIS
    Automates the uninstallation of Bitdefender Endpoint Security Tools (BEST).
.DESCRIPTION
    This script downloads the BEST uninstallation tool, runs it with brute-force and password parameters,
    and then performs cleanup of specified registry keys and folders.
    It requires Administrator privileges to run.
.NOTES
    Password for uninstall: P@ssw0rd
#>

# Script Parameters
$UninstallToolUrl = "http://download.bitdefender.com/SMB/Hydra/release/bst_win/uninstallTool/BEST_uninstallTool.exe"
$UninstallToolName = "BEST_uninstallTool.exe"
$InstallPath = "C:\" # Working directory for the tool and default download location
$UninstallPassword = "P@ssw0rd"

# Determine script's directory and potential tool locations
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ToolPathInScriptDir = Join-Path -Path $ScriptDir -ChildPath $UninstallToolName
$ToolPathInCDrive = Join-Path -Path $InstallPath -ChildPath $UninstallToolName # This is C:\BEST_uninstallTool.exe

$EffectiveUninstallToolPath = $null # This will store the path to the tool we will actually use

# Registry and Folder Paths for Cleanup
$RegistryPathsToRemove = @(
    "HKLM:\SOFTWARE\Endpoint Security.remove", # As per prompt, including '.remove'
    "HKLM:\SOFTWARE\Bitdefender"
)
$FolderPathsToRemove = @(
    "C:\Program Files\Bitdefender",
    "C:\Program Files (x86)\Bitdefender"
)

# --- Administrator Privileges Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges are required to run this script."
    Write-Host "Attempting to re-launch with Administrator privileges..."
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $MyInvocation.MyCommand.Definition)
    }
    catch {
        Write-Error "Failed to re-launch as Administrator: $($_.Exception.Message)"
    }
    Exit
}

Write-Host "Running with Administrator privileges."

# --- Determine Uninstall Tool Path and Download if Necessary ---
Write-Host "Checking for existing uninstall tool..."
if (Test-Path $ToolPathInScriptDir) {
    Write-Host "Uninstall tool found in script directory: $ToolPathInScriptDir"
    $EffectiveUninstallToolPath = $ToolPathInScriptDir
}
elseif (Test-Path $ToolPathInCDrive) {
    Write-Host "Uninstall tool found in C:\ drive: $ToolPathInCDrive. Skipping download."
    $EffectiveUninstallToolPath = $ToolPathInCDrive
}
else {
    Write-Host "Uninstall tool not found locally. Downloading to $ToolPathInCDrive..."
    try {
        Invoke-WebRequest -Uri $UninstallToolUrl -OutFile $ToolPathInCDrive -UseBasicParsing
        Write-Host "Successfully downloaded $UninstallToolName to $ToolPathInCDrive."
        $EffectiveUninstallToolPath = $ToolPathInCDrive
    }
    catch {
        Write-Error "Failed to download the uninstall tool: $($_.Exception.Message)"
        Exit 1
    }
}

if ($null -eq $EffectiveUninstallToolPath) {
    Write-Error "Could not determine a valid path for the uninstall tool. Exiting."
    Exit 1
}

# --- Run Uninstall Tool ---
Write-Host "Attempting to run the Bitdefender uninstall tool..."
Write-Host "Command: `"$EffectiveUninstallToolPath`" /bruteForce /password=$UninstallPassword"

try {
    # Change directory to C:\ as per instructions for running the tool
    Set-Location -Path $InstallPath
    Write-Host "Changed current directory to C:\"

    $Process = Start-Process -FilePath $EffectiveUninstallToolPath -ArgumentList "/bruteForce /password=$UninstallPassword" -Wait -PassThru -WorkingDirectory $InstallPath
    
    if ($Process.ExitCode -eq 0) {
        Write-Host "Bitdefender uninstall tool executed successfully."
    } else {
        Write-Warning "Bitdefender uninstall tool exited with code: $($Process.ExitCode)."
        Write-Warning "If uninstallation failed due to password issues and no password should be used, try:"
        Write-Warning "`"$EffectiveUninstallToolPath`" /bruteForce /destructive"
        # Optionally, you could attempt the destructive command here if the first one fails.
        # For now, we proceed to cleanup as per the initial request.
    }
}
catch {
    Write-Error "Failed to run the uninstall tool: $($_.Exception.Message)"
    # Decide if you want to exit or proceed to cleanup even if uninstaller fails
    # For now, proceeding to cleanup as per prompt.
}

# --- Cleanup Process ---
Write-Host "Starting cleanup process..."

# Remove Registry Entries
foreach ($regPath in $RegistryPathsToRemove) {
    Write-Host "Attempting to remove registry key: $regPath"
    if (Test-Path $regPath) {
        try {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed registry key: $regPath"
        }
        catch {
            Write-Warning "Could not remove registry key $regPath : $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Registry key not found: $regPath"
    }
}

# Remove Folders
foreach ($folderPath in $FolderPathsToRemove) {
    Write-Host "Attempting to remove folder: $folderPath"
    if (Test-Path $folderPath) {
        try {
            Remove-Item -Path $folderPath -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully removed folder: $folderPath"
        }
        catch {
            Write-Warning "Could not remove folder $folderPath : $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Folder not found: $folderPath"
    }
}

Write-Host "Bitdefender uninstallation and cleanup script finished."
Write-Host "It is recommended to restart the computer to ensure all changes take effect."
