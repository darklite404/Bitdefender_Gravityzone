# Bitdefender_Gravityzone
Just a KB for Thai Community
visit : https://บิทไทย.com/wordpress

## GravityZone Cloud Instance 3 network checker (August 2026)

`BESTagentnetworkcheckAugust2026.ps1` checks a Windows endpoint's DNS,
source-bound TCP connectivity, and TLS 1.2 connectivity to the current Security
Agent destinations for GravityZone Cloud Instance 3. It also supports endpoint-to-
Relay tests on ports 7074, 7076, and 7079.

The destination list is based on Bitdefender's
[GravityZone Cloud Instance 3 documentation](https://www.bitdefender.com/business/support/en/77209-1603896-gravityzone-cloud-instance-3.html),
published August 11, 2026 and last modified July 28, 2026.

Run a direct-cloud test from all active routed IPv4 adapters:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\BESTagentnetworkcheckAugust2026.ps1
```

Test a specific adapter and only core services:

```powershell
.\BESTagentnetworkcheckAugust2026.ps1 -AdapterAlias "Ethernet" -CoreOnly
```

Test connectivity from an endpoint to a Relay:

```powershell
.\BESTagentnetworkcheckAugust2026.ps1 `
    -ConnectionMode Relay `
    -RelayAddress relay01.example.local
```

The script creates a transcript (`.log`) and detailed results (`.csv`) in the
script directory. Exit code `0` means all destinations passed (or only partial-IP
warnings occurred), `1` means at least one destination failed, and `2` means the
check could not complete. A failed destination/IP test is retried once by default;
use `-RetryCount 0` to disable retries.

## Dedicated endpoint-to-Relay checker

Use `BESTendpointrelaynetworkcheckAugust2026.ps1` when you only need to verify
that a Windows endpoint can resolve and connect to its BEST Relay on TCP ports
7074, 7076, and 7079:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\BESTendpointrelaynetworkcheckAugust2026.ps1 `
    -RelayAddress relay01.example.local
```

To test a specific adapter or a Relay IP address:

```powershell
.\BESTendpointrelaynetworkcheckAugust2026.ps1 `
    -RelayAddress 192.0.2.25 `
    -AdapterAlias "Ethernet"
```

The Relay checker uses source-bound TCP connections, retries transient failures,
creates `.log` and `.csv` evidence, and returns exit codes `0`, `1`, or `2` for
success, connectivity failure, or an incomplete test respectively.
