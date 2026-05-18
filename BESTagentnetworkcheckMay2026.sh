#!/bin/bash

# Version 1.0
# Test on Ubuntu 22.04
# Author: Pichet Jarunithi
# This script checks network connectivity and DNS resolution for Bitdefender GravityZone URLs.
# Ensure the script has executable permissions >> chmod +x check.sh
# and required dependencies are installed before running.
# Error !! cannot execute: required file not found >> sudo apt install dos2unix >> dos2unix check.sh
# To run : ./check.sh

if [[ ! -x "$0" ]]; then
    echo "The script does not have executable permissions. Adding executable permissions..."
    chmod +x "$0"
fi

# Check if required dependencies are installed
function check_dependencies {
    local dependencies=("dig" "ping" "nc")
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            echo "Error: Required dependency '$dep' is not installed. Please install it and try again."
            exit 1
        fi
    done
}

# Call the dependency check function
check_dependencies

# Function to check and install dependencies
function install_dependencies {
    echo "Checking operating system..."
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os=$ID
        echo "Detected OS: $os"
        if [[ $os == "centos" || $os == "rhel" ]]; then
            echo "Installing dependencies on CentOS/RHEL..."
            sudo yum install -y bind-utils net-tools nc
        elif [[ $os == "ubuntu" || $os == "debian" ]]; then
            echo "Installing dependencies on Ubuntu/Debian..."
            sudo apt update
            sudo apt install -y dnsutils net-tools netcat
        else
            echo "Unsupported operating system: $os"
            exit 1
        fi
    else
        echo "Unable to detect operating system. Exiting."
        exit 1
    fi
}

# Check and install dependencies
install_dependencies

# Display system information
hostname=$(hostname)
network_adapters=$(ip -o -4 addr show | awk '{print $2, $4}')
echo "System Information:"
echo "Hostname: $hostname"
echo "Network Adapters:"
echo "$network_adapters"

# Display adapter options
echo "Select an adapter to check:"
adapter_options=()
index=1
while IFS= read -r line; do
    adapter_options+=("$line")
    echo "$index. $line"
    ((index++))
done <<< "$network_adapters"
echo "$index. All Adapters"

# Get user selection
read -p "Enter the number corresponding to your choice: " selection
if [[ $selection -eq $index ]]; then
    echo "You selected: All Adapters"
elif [[ $selection -gt 0 && $selection -lt $index ]]; then
    selected_adapter="${adapter_options[$((selection - 1))]}"
    echo "You selected: $selected_adapter"
else
    echo "Invalid selection. Exiting."
    exit 1
fi

# List of URLs to check
urls=(
    "cloud.gravityzone.bitdefender.com"
    "cloudgz.gravityzone.bitdefender.com"
    "cloudap.gravityzone.bitdefender.com"

    "cloud-ecs.gravityzone.bitdefender.com"
    "cloudgz-ecs.gravityzone.bitdefender.com"
    "cloudap-ecs.gravityzone.bitdefender.com"

    "eu-lurker-input.gravityzone.bitdefender.com"
    "us-lurker-input.gravityzone.bitdefender.com"
    "ap-lurker-input.gravityzone.bitdefender.com"

    "cloudap-sens.gravityzone.bitdefender.com"
    "cloudeu-sens.gravityzone.bitdefender.com"
    "cloudgz-sens.gravityzone.bitdefender.com"

    "upgrade.bitdefender.com"
    "download.bitdefender.com"
    "update-cloud.2d585.cdn.bitdefender.net"

    "nimbus.bitdefender.net"
    "mclb-gcp.nimbus.bitdefender.net"
    "eu.nimbus.bitdefender.net"
    "us.nimbus.bitdefender.net"
    "elb-fra-gcp.nimbus.bitdefender.net"
    "elb-ned-gcp.nimbus.bitdefender.net"
    "elb-nvi-gcp.nimbus.bitdefender.net"
    "elb-ore-gcp.nimbus.bitdefender.net"
    "elb-iow-gcp.nimbus.bitdefender.net"
    "elb-tky-gcp.nimbus.bitdefender.net"

    "cloud-lcs.gravityzone.bitdefender.com"
    "cloudgz-lcs.gravityzone.bitdefender.com"
    "cloudap-lcs.gravityzone.bitdefender.com"

    "ingestors-eu.bmdr.bitdefender.com"
    "ingestors-us.bmdr.bitdefender.com"
    "ingestors-ap.bmdr.bitdefender.com"

    "cloud-wbs-endpoints.gravityzone.bitdefender.com"
    "cloudap-wbs-endpoints.gravityzone.bitdefender.com"
    "cloudgz-wbs-endpoints.gravityzone.bitdefender.com"

    "sandbox-portal.gravityzone.bitdefender.com"
    "sandbox-portal-us.gravityzone.bitdefender.com"

    "ap-sin-support-tool01.s3.ap-southeast-1.amazonaws.com"
    "eu-fra-support-tool01.s3.eu-central-1.amazonaws.com"
    "us-nvi-support-tool01.s3.us-east-1.amazonaws.com"
    "eu-prod-rbx-support-tool.s3.eu-west-par.io.cloud.ovh.net"

    "crl3.digicert.com"
    "crl4.digicert.com"
    "ocsp.digicert.com"
)

# Function to resolve DNS and test all resolved IPs
function test_dns {
    local url=$1
    local resolved_ips
    resolved_ips=$(dig +short "$url" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    if [[ -n $resolved_ips ]]; then
        echo "$url resolved to IPs: $resolved_ips"
        for ip in $resolved_ips; do
            test_network "$ip"
            test_port443 "$ip"
        done
    else
        echo "$url could not be resolved."
        issues["$url"]="Check DNS"
    fi
}

# Function to check network connectivity
function test_network {
    local ip=$1
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        echo "$ip is reachable."
    else
        echo "$ip is not reachable."
        issues["$ip"]="Check network"
    fi
}

# Function to test connectivity on port 443
function test_port443 {
    local ip=$1
    if nc -z -w 3 "$ip" 443 &>/dev/null; then
        echo "$ip is reachable on port 443."
    else
        echo "$ip is not reachable on port 443."
        issues["$ip"]="Check port 443 connectivity"
    fi
}

# Initialize issues array
declare -A issues

# Test all URLs
for url in "${urls[@]}"; do
    echo "Checking $url..."
    test_dns "$url"
    echo ""
done

# Summarize issues
echo "Summary of Issues:"
if [[ ${#issues[@]} -eq 0 ]]; then
    echo "No issues detected."
else
    for key in "${!issues[@]}"; do
        echo "$key: ${issues[$key]}"
    done
fi
