# Version 1.0
# Test on Windows server 2022 | Windows 10
# Author: Pichet Jarunithi
# Description: This script checks network connectivity and DNS resolution on Clients Machine.
# It tests connectivity to a list of URLs and checks for issues with network adapters.
# It generates a log file with the results and summarizes any issues found.
# Usage: Run the script in PowerShell with administrative privileges.
# Ensure the script is run with administrative privileges to access network adapter information and perform connectivity tests.


# Display system information
$hostname = (Get-ComputerInfo -Property CsName).CsName
$networkAdapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -ne $null }

Write-Output "System Information:"
Write-Output "Hostname: $hostname"

# Display adapter options
Write-Output "Select an adapter to check:"
$adapterOptions = @()
$index = 1
foreach ($adapter in $networkAdapters) {
    Write-Output "$index. $($adapter.InterfaceAlias)"
    $adapterOptions += $adapter
    $index++
}
Write-Output "$index. All Adapters"

# Automatically select the only adapter if there's just one
if ($networkAdapters.Count -eq 1) {
    Write-Output "Only one adapter detected: $($networkAdapters[0].InterfaceAlias). Automatically selecting it."
    $selection = 1
} else {
    # Get user selection
    $selection = Read-Host "Enter the number corresponding to your choice"
}

if ($selection -eq $index) {
    Write-Output "You selected: All Adapters"
} elseif ($selection -gt 0 -and $selection -lt $index) {
    $networkAdapters = @($adapterOptions[$selection - 1])
    Write-Output "You selected: $($networkAdapters[0].InterfaceAlias)"
} else {
    Write-Output "Invalid selection. Exiting."
    exit
}

$urls = @(
    "cloud.gravityzone.bitdefender.com",
    "cloudgz.gravityzone.bitdefender.com",
    "cloudap.gravityzone.bitdefender.com",

    "cloud-ecs.gravityzone.bitdefender.com",
    "cloudgz-ecs.gravityzone.bitdefender.com",
    "cloudap-ecs.gravityzone.bitdefender.com",

    "eu-lurker-input.gravityzone.bitdefender.com",
    "us-lurker-input.gravityzone.bitdefender.com",
    "ap-lurker-input.gravityzone.bitdefender.com",

    "cloudap-sens.gravityzone.bitdefender.com",
    "cloudeu-sens.gravityzone.bitdefender.com",
    "cloudgz-sens.gravityzone.bitdefender.com",

    "upgrade.bitdefender.com",
    "download.bitdefender.com",
    "update-cloud.2d585.cdn.bitdefender.net",

    "nimbus.bitdefender.net",
    "mclb-gcp.nimbus.bitdefender.net",
    "eu.nimbus.bitdefender.net",
    "us.nimbus.bitdefender.net",
    "elb-fra-gcp.nimbus.bitdefender.net",
    "elb-ned-gcp.nimbus.bitdefender.net",
    "elb-nvi-gcp.nimbus.bitdefender.net",
    "elb-ore-gcp.nimbus.bitdefender.net",
    "elb-iow-gcp.nimbus.bitdefender.net",
    "elb-tky-gcp.nimbus.bitdefender.net",

    "cloud-lcs.gravityzone.bitdefender.com",
    "cloudgz-lcs.gravityzone.bitdefender.com",
    "cloudap-lcs.gravityzone.bitdefender.com",

    "ingestors-eu.bmdr.bitdefender.com",
    "ingestors-us.bmdr.bitdefender.com",
    "ingestors-ap.bmdr.bitdefender.com",

    "cloud-wbs-endpoints.gravityzone.bitdefender.com",
    "cloudap-wbs-endpoints.gravityzone.bitdefender.com",
    "cloudgz-wbs-endpoints.gravityzone.bitdefender.com",

    "sandbox-portal.gravityzone.bitdefender.com",
    "sandbox-portal-us.gravityzone.bitdefender.com",

    "ap-sin-support-tool01.s3.ap-southeast-1.amazonaws.com",
    "eu-fra-support-tool01.s3.eu-central-1.amazonaws.com",
    "us-nvi-support-tool01.s3.us-east-1.amazonaws.com",
    "eu-prod-rbx-support-tool.s3.eu-west-par.io.cloud.ovh.net",

    "crl3.digicert.com",
    "crl4.digicert.com",
    "ocsp.digicert.com"
)

# Initialize a hashtable to store issues
$issues = @{}

# Generate log file name
$timestamp = (Get-Date).ToString("yyyyMMdd-HH-mm-ss")
$logFile = "$PSScriptRoot\$timestamp-NetworkConnectionTest.log"

# Redirect output to log file
Start-Transcript -Path $logFile -Append

# Function to check network connectivity
function Test-Network {
    param (
        [string]$url,
        [string]$sourceIP
    )
    try {
        $response = Test-Connection -ComputerName $url -Count 1 -Source $sourceIP -ErrorAction Stop
        if ($response.StatusCode -eq 0) {
            Write-Output "$url is reachable from $sourceIP."
        }
    } catch {
        Write-Output "$url is not reachable from $sourceIP."
        $issues[$url] = "Check network"
    }
}

# Function to resolve DNS and test all resolved IPs
function Test-DNS {
    param (
        [string]$url,
        [string]$sourceIP,
        [string[]]$dnsServers
    )
    try {
        $dnsResults = Resolve-DnsName -Name $url -Server $dnsServers -ErrorAction Stop
        $resolvedIPs = $dnsResults | Where-Object { $_.QueryType -eq "A" } | Select-Object -ExpandProperty IPAddress
        if ($resolvedIPs.Count -gt 0) {
            Write-Output "$url resolved to IPs: $($resolvedIPs -join ', ') from $sourceIP"
            foreach ($ip in $resolvedIPs) {
                Test-Network -url $ip -sourceIP $sourceIP
                Test-Port443 -url $ip
            }
        } else {
            Write-Output "$url resolved but no A records found from $sourceIP."
            $issues[$url] = "Check DNS (No A records found)"
        }
    } catch {
        Write-Output "$url could not be resolved from $sourceIP using DNS servers: $($dnsServers -join ', ')"
        $issues[$url] = "Check DNS (DNS servers: $($dnsServers -join ', '))"
    }
}

# Function to test connectivity on port 443
function Test-Port443 {
    param (
        [string]$url
    )
    try {
        $response = Test-NetConnection -ComputerName $url -Port 443 -InformationLevel Detailed -ErrorAction Stop

        if ($response.TcpTestSucceeded) {
            Write-Output "$url is reachable on port 443."
        } else {
            Write-Output "$url is not reachable on port 443. Remote IP: $($response.RemoteAddress)"
            $issues[$url] = "Check port 443 connectivity (Remote IP: $($response.RemoteAddress))"
        }
    } catch {
        Write-Output "$url is not reachable on port 443. Error: $($_.Exception.Message)"
        $issues[$url] = "Check port 443 connectivity (Error: $($_.Exception.Message))"
    }
}

# Initialize a hashtable to store issues per adapter
$adapterIssues = @{} 

# Display selected adapter(s) information
foreach ($adapter in $networkAdapters) {
    Write-Output "Testing on Adapter: $($adapter.InterfaceAlias)"
    Write-Output "IP Address: $($adapter.IPv4Address.IPAddress)"
    Write-Output "Subnet: $($adapter.IPv4Address.PrefixLength)"
    Write-Output "Gateway: $($adapter.IPv4DefaultGateway.NextHop)"
    Write-Output "DNS Servers: $($adapter.DnsServer.ServerAddresses -join ', ')"
    Write-Output ""

    # Test all URLs for the current adapter
    $sourceIP = $adapter.IPv4Address.IPAddress
    $dnsServers = $adapter.DnsServer.ServerAddresses
    $adapterIssues[$adapter.InterfaceAlias] = @{} 
    foreach ($url in $urls) {
        Write-Output "Checking $url on Adapter: $($adapter.InterfaceAlias) using IP: $sourceIP..."
        Test-DNS -url $url -sourceIP $sourceIP -dnsServers $dnsServers
        if ($issues.ContainsKey($url)) {
            $adapterIssues[$adapter.InterfaceAlias][$url] = $issues[$url]
        }
        Write-Output ""
    }
}

# Summarize issues per adapter
Write-Output "Summary of Issues:"
if ($adapterIssues.Count -eq 0) {
    Write-Output "No issues detected."
} else {
    foreach ($adapter in $adapterIssues.Keys) {
        Write-Output "Adapter: $adapter"
        if ($adapterIssues[$adapter].Count -eq 0) {
            Write-Output "  No issues detected."
        } else {
            foreach ($key in $adapterIssues[$adapter].Keys) {
                Write-Output "  ${key}: $($adapterIssues[$adapter][$key])"
            }
        }
        Write-Output ""
    }
}

# Stop logging
Stop-Transcript
