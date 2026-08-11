#requires -Version 5.1

<#
.SYNOPSIS
Checks whether a Windows endpoint can connect to a Bitdefender BEST Relay.

.DESCRIPTION
Resolves the supplied Relay name and tests source-bound TCP connectivity from each
selected IPv4 adapter to the BEST Relay ports documented for endpoint communication:
7074, 7076, and 7079.

The script does not use ping because ICMP may be blocked while the required TCP ports
remain reachable. It writes a transcript and a CSV report next to the script by default.
Exit code 0 means all tests passed, 1 means one or more Relay tests failed, and 2 means
the check could not complete.

.PARAMETER RelayAddress
DNS name or IPv4 address of the BEST Relay to test.

.PARAMETER AdapterAlias
Tests only the named network adapter or adapters. By default, all active IPv4 adapters
with a default gateway are tested (or all active IPv4 adapters if none has a gateway).

.PARAMETER Ports
Relay TCP ports to test. The default ports are 7074, 7076, and 7079.

.PARAMETER TimeoutSeconds
Timeout for each TCP connection attempt. The default is 5 seconds.

.PARAMETER RetryCount
Number of retries after a failed Relay/IP/port attempt. The default is 1 retry.

.PARAMETER OutputDirectory
Directory for the transcript and CSV report. The default is the script directory.

.EXAMPLE
.\BESTendpointrelaynetworkcheckAugust2026.ps1 -RelayAddress relay01.contoso.local

Tests all required Relay ports through all active routed IPv4 adapters.

.EXAMPLE
.\BESTendpointrelaynetworkcheckAugust2026.ps1 `
    -RelayAddress 192.0.2.25 `
    -AdapterAlias "Ethernet"

Tests the Relay IP only through the Ethernet adapter.

.NOTES
Version: 1.0.1
Author: Pichet Jarunithi
Data source: https://www.bitdefender.com/business/support/en/77209-1603896-gravityzone-cloud-instance-3.html
Source publication date: 2026-08-11
Source last modified date: 2026-07-28

Port 7075 is not tested. Bitdefender documents 7075 as a localhost port used by the
Relay update server for its own configuration, not as an endpoint-to-Relay port.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias("Relay")]
    [ValidateNotNullOrEmpty()]
    [string]$RelayAddress,

    [Alias("InterfaceAlias")]
    [string[]]$AdapterAlias,

    [ValidateNotNullOrEmpty()]
    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(7074, 7076, 7079),

    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 5,

    [ValidateRange(0, 3)]
    [int]$RetryCount = 1,

    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$documentationUrl = "https://www.bitdefender.com/business/support/en/77209-1603896-gravityzone-cloud-instance-3.html"
$portPurposes = @{
    7074 = "Agent messages, deployment, and product/security content updates"
    7076 = "Encrypted Bitdefender Global Protective Network messages through Relay"
    7079 = "Product/security content updates and update staging"
}

function Get-AdapterDisplayName {
    param ([Parameter(Mandatory = $true)]$Adapter)

    $interfaceAliasProperty = $Adapter.PSObject.Properties["InterfaceAlias"]
    if ($null -ne $interfaceAliasProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$interfaceAliasProperty.Value)) {
        return [string]$interfaceAliasProperty.Value
    }

    $netAdapterProperty = $Adapter.PSObject.Properties["NetAdapter"]
    if ($null -ne $netAdapterProperty -and $null -ne $netAdapterProperty.Value) {
        $netAdapterNameProperty = $netAdapterProperty.Value.PSObject.Properties["Name"]
        if ($null -ne $netAdapterNameProperty -and
            -not [string]::IsNullOrWhiteSpace([string]$netAdapterNameProperty.Value)) {
            return [string]$netAdapterNameProperty.Value
        }
    }

    $descriptionProperty = $Adapter.PSObject.Properties["InterfaceDescription"]
    if ($null -ne $descriptionProperty -and
        -not [string]::IsNullOrWhiteSpace([string]$descriptionProperty.Value)) {
        return [string]$descriptionProperty.Value
    }

    $indexProperty = $Adapter.PSObject.Properties["InterfaceIndex"]
    if ($null -ne $indexProperty -and $null -ne $indexProperty.Value) {
        return "InterfaceIndex $($indexProperty.Value)"
    }

    return "Unknown IPv4 adapter"
}

function Resolve-RelayIPv4 {
    param (
        [Parameter(Mandatory = $true)][string]$HostName,
        [string[]]$DnsServers
    )

    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$parsedAddress)) {
        if ($parsedAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            return [PSCustomObject]@{
                Success   = $false
                Addresses = @()
                DnsServer = "IP literal"
                Error     = "Only IPv4 targets are supported."
            }
        }

        return [PSCustomObject]@{
            Success   = $true
            Addresses = @($parsedAddress.IPAddressToString)
            DnsServer = "IP literal"
            Error     = ""
        }
    }

    $addresses = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.Generic.List[string]
    $serversUsed = New-Object System.Collections.Generic.List[string]
    $serversToTry = @($DnsServers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($serversToTry.Count -eq 0) {
        $serversToTry = @([string]::Empty)
    }

    foreach ($dnsServer in $serversToTry) {
        try {
            $resolveParameters = @{
                Name        = $HostName
                Type        = "A"
                DnsOnly     = $true
                NoHostsFile = $true
                ErrorAction = "Stop"
            }

            if (-not [string]::IsNullOrWhiteSpace($dnsServer)) {
                $resolveParameters.Server = $dnsServer
                $serversUsed.Add($dnsServer)
            } else {
                $serversUsed.Add("System default")
            }

            $records = @(Resolve-DnsName @resolveParameters)
            foreach ($record in $records) {
                $ipProperty = $record.PSObject.Properties["IPAddress"]
                if ($null -eq $ipProperty -or [string]::IsNullOrWhiteSpace([string]$ipProperty.Value)) {
                    continue
                }

                $recordAddress = $null
                if ([System.Net.IPAddress]::TryParse([string]$ipProperty.Value, [ref]$recordAddress) -and
                    $recordAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $addresses.Add($recordAddress.IPAddressToString)
                }
            }
        } catch {
            $serverLabel = if ([string]::IsNullOrWhiteSpace($dnsServer)) { "System default" } else { $dnsServer }
            $errors.Add("${serverLabel}: $($_.Exception.Message)")
        }
    }

    $uniqueAddresses = @($addresses | Sort-Object -Unique)
    [PSCustomObject]@{
        Success   = ($uniqueAddresses.Count -gt 0)
        Addresses = $uniqueAddresses
        DnsServer = (@($serversUsed | Sort-Object -Unique) -join "; ")
        Error     = ($errors -join " | ")
    }
}

function Test-BoundTcpPort {
    param (
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$SourceAddress,
        [Parameter(Mandatory = $true)][int]$Timeout
    )

    $client = $null
    $connectResult = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $localIp = [System.Net.IPAddress]::Parse($SourceAddress)
        $remoteIp = [System.Net.IPAddress]::Parse($RemoteAddress)
        $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
        $client.Client.Bind([System.Net.IPEndPoint]::new($localIp, 0))

        $connectResult = $client.BeginConnect($remoteIp, $Port, $null, $null)
        if (-not $connectResult.AsyncWaitHandle.WaitOne($Timeout * 1000, $false)) {
            throw "TCP connection timed out after $Timeout second(s)."
        }
        $client.EndConnect($connectResult)
        $stopwatch.Stop()

        return [PSCustomObject]@{
            Success   = $true
            LatencyMs = $stopwatch.ElapsedMilliseconds
            Error     = ""
        }
    } catch {
        $stopwatch.Stop()
        return [PSCustomObject]@{
            Success   = $false
            LatencyMs = $stopwatch.ElapsedMilliseconds
            Error     = $_.Exception.Message
        }
    } finally {
        if ($null -ne $connectResult) {
            $connectResult.AsyncWaitHandle.Close()
        }
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
}

function Test-RelayPort {
    param (
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$AdapterName,
        [Parameter(Mandatory = $true)][string]$SourceAddress,
        [string[]]$DnsServers,
        [Parameter(Mandatory = $true)][int]$Timeout,
        [Parameter(Mandatory = $true)][int]$Retries
    )

    $dnsResult = Resolve-RelayIPv4 -HostName $HostName -DnsServers $DnsServers
    if (-not $dnsResult.Success) {
        return [PSCustomObject]@{
            Adapter     = $AdapterName
            SourceIP    = $SourceAddress
            Relay       = $HostName
            Port        = $Port
            Purpose     = $Purpose
            DNS         = "FAIL"
            TCP         = "SKIPPED"
            Status      = "FAIL"
            ResolvedIPs = ""
            WorkingIPs  = ""
            LatencyMs   = ""
            Detail      = if ([string]::IsNullOrWhiteSpace($dnsResult.Error)) { "No IPv4 A records returned." } else { $dnsResult.Error }
        }
    }

    $workingAddresses = New-Object System.Collections.Generic.List[string]
    $latencies = New-Object System.Collections.Generic.List[long]
    $attemptErrors = New-Object System.Collections.Generic.List[string]

    foreach ($remoteAddress in $dnsResult.Addresses) {
        $testResult = $null
        $attemptNumber = 0
        do {
            $attemptNumber++
            $testResult = Test-BoundTcpPort `
                -RemoteAddress $remoteAddress `
                -Port $Port `
                -SourceAddress $SourceAddress `
                -Timeout $Timeout

            if (-not $testResult.Success -and $attemptNumber -le $Retries) {
                Start-Sleep -Milliseconds 250
            }
        } while (-not $testResult.Success -and $attemptNumber -le $Retries)

        if ($testResult.Success) {
            $workingAddresses.Add($remoteAddress)
            $latencies.Add($testResult.LatencyMs)
        } else {
            $attemptErrors.Add("${remoteAddress} after $attemptNumber attempt(s): $($testResult.Error)")
        }
    }

    $status = if ($workingAddresses.Count -eq 0) {
        "FAIL"
    } elseif ($workingAddresses.Count -lt $dnsResult.Addresses.Count) {
        "WARNING"
    } else {
        "PASS"
    }

    $tcpStatus = if ($status -eq "WARNING") { "PARTIAL" } else { $status }

    [PSCustomObject]@{
        Adapter     = $AdapterName
        SourceIP    = $SourceAddress
        Relay       = $HostName
        Port        = $Port
        Purpose     = $Purpose
        DNS         = "PASS"
        TCP         = $tcpStatus
        Status      = $status
        ResolvedIPs = ($dnsResult.Addresses -join "; ")
        WorkingIPs  = ($workingAddresses -join "; ")
        LatencyMs   = ($latencies -join "; ")
        Detail      = ($attemptErrors -join " | ")
    }
}

function Write-RelayTestResult {
    param ([Parameter(Mandatory = $true)]$Result)

    $message = "[{0}] {1}:{2} via {3}" -f $Result.Status, $Result.Relay, $Result.Port, $Result.SourceIP
    switch ($Result.Status) {
        "PASS"    { Write-Host $message -ForegroundColor Green }
        "WARNING" { Write-Host $message -ForegroundColor Yellow }
        default   { Write-Host $message -ForegroundColor Red }
    }

    Write-Host "       $($Result.Purpose)"
    if ($Result.Status -ne "PASS") {
        Write-Host "       $($Result.Detail)"
    }
}

$scriptExitCode = 2
$transcriptStarted = $false
$timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss", [System.Globalization.CultureInfo]::InvariantCulture)

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { (Get-Location).Path } else { $PSScriptRoot }
}

try {
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $logFile = Join-Path $OutputDirectory "$timestamp-BEST-Endpoint-To-Relay-Check.log"
    $csvFile = Join-Path $OutputDirectory "$timestamp-BEST-Endpoint-To-Relay-Check.csv"
    Start-Transcript -Path $logFile -Force | Out-Null
    $transcriptStarted = $true

    Write-Host "BEST Endpoint-to-Relay Network Check" -ForegroundColor Cyan
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Started:  $((Get-Date).ToString('u'))"
    Write-Host "Relay:    $RelayAddress"
    Write-Host "Ports:    $(@($Ports | Sort-Object -Unique) -join ', ')"
    Write-Host "Source:   $documentationUrl"
    Write-Host ""

    if ($null -eq (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        throw "Get-NetIPConfiguration is unavailable. Run this script on a supported Windows endpoint."
    }
    if ($null -eq (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        throw "Resolve-DnsName is unavailable. Run this script on a supported Windows endpoint."
    }

    $activeAdapters = @(Get-NetIPConfiguration | Where-Object {
        $null -ne $_.IPv4Address -and
        @($_.IPv4Address).Count -gt 0 -and
        $null -ne $_.NetAdapter -and
        $_.NetAdapter.Status -eq "Up"
    })

    $requestedAdapterAliases = @($AdapterAlias | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($requestedAdapterAliases.Count -gt 0) {
        $selectedAdapters = @($activeAdapters | Where-Object { (Get-AdapterDisplayName -Adapter $_) -in $requestedAdapterAliases })
        $selectedAdapterNames = @($selectedAdapters | ForEach-Object { Get-AdapterDisplayName -Adapter $_ })
        $missingAdapters = @($requestedAdapterAliases | Where-Object { $_ -notin $selectedAdapterNames })
        if ($missingAdapters.Count -gt 0) {
            throw "Active IPv4 adapter(s) not found: $($missingAdapters -join ', ')"
        }
    } else {
        $selectedAdapters = @($activeAdapters | Where-Object { $null -ne $_.IPv4DefaultGateway })
        if ($selectedAdapters.Count -eq 0) {
            $selectedAdapters = $activeAdapters
        }
    }

    if ($selectedAdapters.Count -eq 0) {
        throw "No active IPv4 network adapters were found."
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($adapter in $selectedAdapters) {
        $adapterName = Get-AdapterDisplayName -Adapter $adapter
        $sourceAddresses = @($adapter.IPv4Address | ForEach-Object { $_.IPAddress } | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            -not $_.StartsWith("169.254.") -and
            $_ -ne "127.0.0.1"
        } | Sort-Object -Unique)

        if ($sourceAddresses.Count -eq 0) {
            Write-Warning "Skipping ${adapterName}: no usable IPv4 source address."
            continue
        }

        $dnsServers = @()
        if ($null -ne $adapter.DnsServer) {
            $dnsServers = @($adapter.DnsServer.ServerAddresses | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
        }
        $gateway = if ($null -eq $adapter.IPv4DefaultGateway) { "None" } else { $adapter.IPv4DefaultGateway.NextHop }

        Write-Host "Adapter: $adapterName" -ForegroundColor Cyan
        Write-Host "  Source IP(s):  $($sourceAddresses -join ', ')"
        Write-Host "  Gateway:       $gateway"
        Write-Host "  DNS server(s): $(if ($dnsServers.Count -eq 0) { 'System default' } else { $dnsServers -join ', ' })"

        foreach ($sourceAddress in $sourceAddresses) {
            foreach ($port in @($Ports | Sort-Object -Unique)) {
                $purpose = if ($portPurposes.ContainsKey($port)) {
                    $portPurposes[$port]
                } else {
                    "Custom Relay TCP port"
                }

                $result = Test-RelayPort `
                    -HostName $RelayAddress `
                    -Port $port `
                    -Purpose $purpose `
                    -AdapterName $adapterName `
                    -SourceAddress $sourceAddress `
                    -DnsServers $dnsServers `
                    -Timeout $TimeoutSeconds `
                    -Retries $RetryCount
                $results.Add($result)
                Write-RelayTestResult -Result $result
            }
        }
        Write-Host ""
    }

    if ($results.Count -eq 0) {
        throw "No Relay tests were run."
    }

    $results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    $failedResults = @($results | Where-Object { $_.Status -eq "FAIL" })
    $warningResults = @($results | Where-Object { $_.Status -eq "WARNING" })
    $passedResults = @($results | Where-Object { $_.Status -eq "PASS" })

    Write-Host "Summary" -ForegroundColor Cyan
    Write-Host "  Passed:   $($passedResults.Count)"
    Write-Host "  Warnings: $($warningResults.Count)"
    Write-Host "  Failed:   $($failedResults.Count)"
    Write-Host "  CSV:      $csvFile"
    Write-Host "  Log:      $logFile"

    if ($failedResults.Count -gt 0) {
        Write-Host ""
        Write-Host "Failed Relay tests" -ForegroundColor Red
        $failedResults |
            Select-Object Adapter, SourceIP, Relay, Port, Purpose, DNS, TCP, Detail |
            Format-Table -AutoSize |
            Out-String |
            Write-Host
        Write-Host "Result: This endpoint has one or more connectivity problems with the BEST Relay." -ForegroundColor Red
        $scriptExitCode = 1
    } elseif ($warningResults.Count -gt 0) {
        Write-Host "Result: Relay connectivity works, but one or more resolved IP paths failed. Review the warnings." -ForegroundColor Yellow
        $scriptExitCode = 0
    } else {
        Write-Host "Result: This endpoint can connect to the BEST Relay on every tested port." -ForegroundColor Green
        $scriptExitCode = 0
    }
} catch {
    Write-Host "Relay check could not complete: $($_.Exception.Message)" -ForegroundColor Red
    $scriptExitCode = 2
} finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
}

exit $scriptExitCode
