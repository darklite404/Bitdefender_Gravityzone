#requires -Version 5.1

<#
.SYNOPSIS
Checks whether a Windows endpoint can reach Bitdefender GravityZone Cloud Instance 3.

.DESCRIPTION
Tests the Security Agent destinations documented by Bitdefender for GravityZone Cloud
Instance 3. For each selected IPv4 adapter, the script checks DNS resolution, binds the
TCP connection to that adapter's source address, and validates TLS 1.2 where applicable.

ICMP/ping is intentionally not used because a service can block ICMP while TCP 443 works.
The script writes a transcript and a machine-readable CSV report next to the script by
default. Exit code 0 means all tests passed, 1 means one or more destinations failed, and
2 means the script could not complete.

.PARAMETER AdapterAlias
Tests only the named network adapter or adapters. By default, all active IPv4 adapters
with a default gateway are tested (or all active IPv4 adapters if none has a gateway).

.PARAMETER ConnectionMode
Direct tests Bitdefender cloud destinations. Relay tests only the supplied RelayAddress
on ports 7074, 7076, and 7079. Both performs both sets of tests.

.PARAMETER RelayAddress
DNS name or IPv4 address of the BEST Relay. Required for Relay and Both modes.

.PARAMETER CoreOnly
Skips feature-dependent destinations such as EDR, MDR, vCenter integration, Remote Shell,
Live Search, and remote support log upload.

.PARAMETER TimeoutSeconds
Timeout for each TCP connection and TLS handshake. The default is 5 seconds.

.PARAMETER RetryCount
Number of retries after a failed destination/IP attempt. The default is 1 retry.

.PARAMETER OutputDirectory
Directory for the transcript and CSV report. The default is the script directory.

.EXAMPLE
.\BESTagentnetworkcheckAugust2026.ps1

Tests all active routed IPv4 adapters against all documented direct-cloud destinations.

.EXAMPLE
.\BESTagentnetworkcheckAugust2026.ps1 -AdapterAlias "Ethernet" -CoreOnly

Tests only core services through the Ethernet adapter.

.EXAMPLE
.\BESTagentnetworkcheckAugust2026.ps1 -ConnectionMode Relay -RelayAddress relay01.contoso.local

Tests endpoint-to-Relay connectivity on ports 7074, 7076, and 7079.

.NOTES
Version: 2.0.1
Author: Pichet Jarunithi
Data source: https://www.bitdefender.com/business/support/en/77209-1603896-gravityzone-cloud-instance-3.html
Source publication date: 2026-08-11
Source last modified date: 2026-07-28
#>

[CmdletBinding()]
param (
    [Alias("InterfaceAlias")]
    [string[]]$AdapterAlias,

    [ValidateSet("Direct", "Relay", "Both")]
    [string]$ConnectionMode = "Direct",

    [string]$RelayAddress,

    [switch]$CoreOnly,

    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 5,

    [ValidateRange(0, 3)]
    [int]$RetryCount = 1,

    [string]$OutputDirectory
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$documentationUrl = "https://www.bitdefender.com/business/support/en/77209-1603896-gravityzone-cloud-instance-3.html"

function New-Endpoint {
    param (
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][bool]$UseTls,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    [PSCustomObject]@{
        HostName = $HostName
        Port     = $Port
        UseTls   = $UseTls
        Scope    = $Scope
        Purpose  = $Purpose
    }
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

function Resolve-TargetIPv4 {
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
        # An empty string is used as the system-resolver marker because @($null)
        # becomes an empty array in Windows PowerShell.
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

function Test-BoundConnection {
    param (
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$SourceAddress,
        [Parameter(Mandatory = $true)][bool]$UseTls,
        [Parameter(Mandatory = $true)][int]$Timeout
    )

    $client = $null
    $connectResult = $null
    $tlsResult = $null
    $sslStream = $null
    $certificate = $null
    $tcpSucceeded = $false
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
        $tcpSucceeded = $true

        $tlsInformation = "Not requested"
        if ($UseTls) {
            $sslStream = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
            $clientCertificates = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new()
            $tlsResult = $sslStream.BeginAuthenticateAsClient(
                $HostName,
                $clientCertificates,
                [System.Security.Authentication.SslProtocols]::Tls12,
                $true,
                $null,
                $null
            )

            if (-not $tlsResult.AsyncWaitHandle.WaitOne($Timeout * 1000, $false)) {
                throw "TLS 1.2 handshake timed out after $Timeout second(s)."
            }
            $sslStream.EndAuthenticateAsClient($tlsResult)

            if (-not $sslStream.IsAuthenticated -or -not $sslStream.IsEncrypted) {
                throw "TLS 1.2 did not create an authenticated, encrypted session."
            }

            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
            $certificateName = $certificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName,
                $false
            )
            $tlsInformation = "$($sslStream.SslProtocol); certificate $certificateName; expires $($certificate.NotAfter.ToString('u'))"
        }

        $stopwatch.Stop()
        return [PSCustomObject]@{
            Success    = $true
            TcpSuccess = $true
            TlsSuccess = $true
            LatencyMs  = $stopwatch.ElapsedMilliseconds
            TlsInfo    = $tlsInformation
            Error      = ""
        }
    } catch {
        $stopwatch.Stop()
        return [PSCustomObject]@{
            Success    = $false
            TcpSuccess = $tcpSucceeded
            TlsSuccess = $false
            LatencyMs  = $stopwatch.ElapsedMilliseconds
            TlsInfo    = ""
            Error      = $_.Exception.Message
        }
    } finally {
        if ($null -ne $certificate) {
            $certificate.Dispose()
        }
        if ($null -ne $sslStream) {
            $sslStream.Dispose()
        }
        if ($null -ne $tlsResult) {
            $tlsResult.AsyncWaitHandle.Close()
        }
        if ($null -ne $connectResult) {
            $connectResult.AsyncWaitHandle.Close()
        }
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
}

function Test-DocumentedEndpoint {
    param (
        [Parameter(Mandatory = $true)]$Endpoint,
        [Parameter(Mandatory = $true)][string]$AdapterName,
        [Parameter(Mandatory = $true)][string]$SourceAddress,
        [string[]]$DnsServers,
        [Parameter(Mandatory = $true)][int]$Timeout,
        [Parameter(Mandatory = $true)][int]$Retries
    )

    $dnsResult = Resolve-TargetIPv4 -HostName $Endpoint.HostName -DnsServers $DnsServers
    if (-not $dnsResult.Success) {
        return [PSCustomObject]@{
            Adapter     = $AdapterName
            SourceIP    = $SourceAddress
            Scope       = $Endpoint.Scope
            Destination = $Endpoint.HostName
            Port        = $Endpoint.Port
            DNS         = "FAIL"
            TCP         = "SKIPPED"
            TLS         = if ($Endpoint.UseTls) { "SKIPPED" } else { "N/A" }
            Status      = "FAIL"
            ResolvedIPs = ""
            WorkingIPs  = ""
            LatencyMs   = ""
            Purpose     = $Endpoint.Purpose
            Detail      = if ([string]::IsNullOrWhiteSpace($dnsResult.Error)) { "No IPv4 A records returned." } else { $dnsResult.Error }
        }
    }

    $workingAddresses = New-Object System.Collections.Generic.List[string]
    $tcpWorkingAddresses = New-Object System.Collections.Generic.List[string]
    $attemptErrors = New-Object System.Collections.Generic.List[string]
    $latencies = New-Object System.Collections.Generic.List[long]
    $tlsDetails = New-Object System.Collections.Generic.List[string]

    foreach ($remoteAddress in $dnsResult.Addresses) {
        $testResult = $null
        $attemptNumber = 0
        do {
            $attemptNumber++
            $testResult = Test-BoundConnection `
                -HostName $Endpoint.HostName `
                -RemoteAddress $remoteAddress `
                -Port $Endpoint.Port `
                -SourceAddress $SourceAddress `
                -UseTls $Endpoint.UseTls `
                -Timeout $Timeout

            if (-not $testResult.Success -and $attemptNumber -le $Retries) {
                Start-Sleep -Milliseconds 250
            }
        } while (-not $testResult.Success -and $attemptNumber -le $Retries)

        if ($testResult.TcpSuccess) {
            $tcpWorkingAddresses.Add($remoteAddress)
        }

        if ($testResult.Success) {
            $workingAddresses.Add($remoteAddress)
            $latencies.Add($testResult.LatencyMs)
            if ($Endpoint.UseTls -and -not [string]::IsNullOrWhiteSpace($testResult.TlsInfo)) {
                $tlsDetails.Add("${remoteAddress}: $($testResult.TlsInfo)")
            }
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

    $tcpStatus = if ($tcpWorkingAddresses.Count -eq 0) {
        "FAIL"
    } elseif ($tcpWorkingAddresses.Count -lt $dnsResult.Addresses.Count) {
        "PARTIAL"
    } else {
        "PASS"
    }

    $tlsStatus = if (-not $Endpoint.UseTls) {
        "N/A"
    } elseif ($workingAddresses.Count -eq 0) {
        "FAIL"
    } elseif ($workingAddresses.Count -lt $dnsResult.Addresses.Count) {
        "PARTIAL"
    } else {
        "PASS"
    }

    [PSCustomObject]@{
        Adapter     = $AdapterName
        SourceIP    = $SourceAddress
        Scope       = $Endpoint.Scope
        Destination = $Endpoint.HostName
        Port        = $Endpoint.Port
        DNS         = "PASS"
        TCP         = $tcpStatus
        TLS         = $tlsStatus
        Status      = $status
        ResolvedIPs = ($dnsResult.Addresses -join "; ")
        WorkingIPs  = ($workingAddresses -join "; ")
        LatencyMs   = ($latencies -join "; ")
        Purpose     = $Endpoint.Purpose
        Detail      = (@($tlsDetails) + @($attemptErrors) -join " | ")
    }
}

function Write-TestResult {
    param ([Parameter(Mandatory = $true)]$Result)

    $message = "[{0}] {1}:{2} via {3} ({4})" -f $Result.Status, $Result.Destination, $Result.Port, $Result.SourceIP, $Result.Scope

    switch ($Result.Status) {
        "PASS"    { Write-Host $message -ForegroundColor Green }
        "WARNING" { Write-Host $message -ForegroundColor Yellow }
        default   { Write-Host $message -ForegroundColor Red }
    }

    if ($Result.Status -ne "PASS") {
        Write-Host "       $($Result.Detail)"
    }
}

$directEndpoints = @(
    (New-Endpoint "cloudap.gravityzone.bitdefender.com" 443 $true "Core" "Setup Downloader package deployment"),
    (New-Endpoint "cloudap-ecs.gravityzone.bitdefender.com" 443 $true "Core" "Security Agent communication with Communication Server"),
    (New-Endpoint "upgrade.bitdefender.com" 443 $true "Core" "Encrypted product updates"),
    (New-Endpoint "nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "mclb-gcp.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "eu.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "us.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "elb-fra-gcp.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "elb-ned-gcp.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "elb-nvi-gcp.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "elb-ore-gcp.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "elb-iow-gcp.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "elb-tky-gcp.nimbus.bitdefender.net" 443 $true "Core" "Bitdefender Global Protective Network"),
    (New-Endpoint "update-cloud.2d585.cdn.bitdefender.net" 443 $true "Core" "Encrypted signature and product updates"),
    (New-Endpoint "download.bitdefender.com" 443 $true "Core" "Encrypted product updates"),
    (New-Endpoint "lc-bootstrap-ap.cirrus.gravityzone.bitdefender.com" 443 $true "Core" "Security Agent communication with GravityZone Cloud Services"),
    (New-Endpoint "crl3.digicert.com" 80 $false "Core" "Certificate revocation list access (documented example)"),
    (New-Endpoint "crl4.digicert.com" 80 $false "Core" "Certificate revocation list access (documented example)"),
    (New-Endpoint "ocsp.digicert.com" 80 $false "Core" "Certificate status access (documented example)"),
    (New-Endpoint "ap-lurker-input.gravityzone.bitdefender.com" 443 $true "Feature" "EDR traffic"),
    (New-Endpoint "cloudap-sens.gravityzone.bitdefender.com" 443 $true "Feature" "vCenter server integration"),
    (New-Endpoint "ingestors-ap.bmdr.bitdefender.com" 443 $true "Feature" "MDR communication"),
    (New-Endpoint "cloudap-wbs-endpoints.gravityzone.bitdefender.com" 443 $true "Feature" "Remote Shell and Live Search with TLS inspection or certificate pinning"),
    (New-Endpoint "ap-sin-support-tool01.s3.ap-southeast-1.amazonaws.com" 443 $true "Feature" "Remote troubleshooting log upload")
)

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

    $logFile = Join-Path $OutputDirectory "$timestamp-GravityZoneCloud3-NetworkCheck.log"
    $csvFile = Join-Path $OutputDirectory "$timestamp-GravityZoneCloud3-NetworkCheck.csv"
    Start-Transcript -Path $logFile -Force | Out-Null
    $transcriptStarted = $true

    Write-Host "GravityZone Cloud Instance 3 Network Check" -ForegroundColor Cyan
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Started:  $((Get-Date).ToString('u'))"
    Write-Host "Mode:     $ConnectionMode"
    Write-Host "Source:   $documentationUrl"
    Write-Host ""

    if ($ConnectionMode -in @("Relay", "Both") -and [string]::IsNullOrWhiteSpace($RelayAddress)) {
        throw "RelayAddress is required when ConnectionMode is Relay or Both."
    }

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

    $endpoints = New-Object System.Collections.Generic.List[object]
    if ($ConnectionMode -in @("Direct", "Both")) {
        foreach ($endpoint in $directEndpoints) {
            if (-not $CoreOnly -or $endpoint.Scope -eq "Core") {
                $endpoints.Add($endpoint)
            }
        }
    }
    if ($ConnectionMode -in @("Relay", "Both")) {
        $endpoints.Add((New-Endpoint $RelayAddress 7074 $false "Relay" "Agent communication, deployment, product and security content updates"))
        $endpoints.Add((New-Endpoint $RelayAddress 7076 $false "Relay" "Encrypted Bitdefender Global Protective Network messages through Relay"))
        $endpoints.Add((New-Endpoint $RelayAddress 7079 $false "Relay" "Product and security content updates and update staging"))
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
        Write-Host "  Source IP(s): $($sourceAddresses -join ', ')"
        Write-Host "  Gateway:      $gateway"
        Write-Host "  DNS server(s): $(if ($dnsServers.Count -eq 0) { 'System default' } else { $dnsServers -join ', ' })"

        foreach ($sourceAddress in $sourceAddresses) {
            foreach ($endpoint in $endpoints) {
                $result = Test-DocumentedEndpoint `
                    -Endpoint $endpoint `
                    -AdapterName $adapterName `
                    -SourceAddress $sourceAddress `
                    -DnsServers $dnsServers `
                    -Timeout $TimeoutSeconds `
                    -Retries $RetryCount
                $results.Add($result)
                Write-TestResult -Result $result
            }
        }
        Write-Host ""
    }

    if ($results.Count -eq 0) {
        throw "No network tests were run."
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
        Write-Host "Failed destinations" -ForegroundColor Red
        $failedResults |
            Select-Object Adapter, SourceIP, Scope, Destination, Port, DNS, TCP, TLS, Detail |
            Format-Table -AutoSize |
            Out-String |
            Write-Host
        Write-Host "Result: The endpoint has one or more GravityZone connectivity problems." -ForegroundColor Red
        $scriptExitCode = 1
    } elseif ($warningResults.Count -gt 0) {
        Write-Host "Result: Cloud connectivity works, but one or more resolved IP paths failed. Review the warnings." -ForegroundColor Yellow
        $scriptExitCode = 0
    } else {
        Write-Host "Result: No GravityZone connectivity problems were detected." -ForegroundColor Green
        $scriptExitCode = 0
    }
} catch {
    Write-Host "Network check could not complete: $($_.Exception.Message)" -ForegroundColor Red
    $scriptExitCode = 2
} finally {
    if ($transcriptStarted) {
        Stop-Transcript | Out-Null
    }
}

exit $scriptExitCode
