#!/bin/bash

# 🚀 RavenWatch v1.0 — Passive Recon
# Author: invisigoth29 

# OS Detection
OS=$(uname -s)
case "$OS" in
    Darwin)
        OS_TYPE="mac"
        ;;
    Linux)
        OS_TYPE="linux"
        ;;
    *)
        echo "[!] Unsupported OS: $OS. This script supports macOS and Linux only."
        exit 1
        ;;
esac

# Ensure Go bin is in PATH
if [ -d "$HOME/go/bin" ]; then
    export PATH="$HOME/go/bin:$PATH"
fi

timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
workspace="recon_$timestamp"
mkdir -p "$workspace"/{subdomains,ports,httpx}

error_log="$workspace/error.log"

input_arg="$1"
if [ -z "$input_arg" ]; then
    echo "Usage: RavenWatch.sh <domains.txt|ips.txt|single_domain>"
    exit 1
fi

if [ -f "$input_arg" ]; then
    targets="$input_arg"
else
    echo "$input_arg" > "$workspace/single_domain.txt"
    targets="$workspace/single_domain.txt"
fi

# Detect input type
input_type="unknown"
if grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$targets"; then
    input_type="domains"
    echo "[*] Detected domain input - will perform subdomain enumeration"
elif grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$targets"; then
    input_type="ips"
    echo "[*] Detected IP input - will perform network scanning"
fi

# ===== Utility =====
run() {
    echo "[*] $1"
    eval "$2"
    if [ $? -ne 0 ]; then
        echo "[!] Error during: $1"
        echo "[!] Failed: $2" | tee -a "$error_log"
    else
        echo "[+] Completed: $1"
    fi
}

# ===== Tool Setup =====
tools=(
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder
    github.com/projectdiscovery/dnsx/cmd/dnsx
    github.com/projectdiscovery/httpx/cmd/httpx
)
tool_names=(subfinder dnsx httpx)

if ! command -v go &> /dev/null; then
    echo "[!] Go is not installed. Install Go to continue."
    exit 1
fi

install_tool() {
    local tool_name="$1"
    local tool_path="$2"
    
    if ! command -v "$tool_name" &> /dev/null; then
        echo "[+] Installing missing tool: $tool_name"
        go install "$tool_path@latest"
        
        # Check if tool is now available in PATH
        if ! command -v "$tool_name" &> /dev/null; then
            if [ -f "$HOME/go/bin/$tool_name" ]; then
                echo "[*] Tool installed to $HOME/go/bin/$tool_name"
                echo "[*] Note: Ensure $HOME/go/bin is in your PATH"
            else
                echo "[!] Failed to install $tool_name"
                return 1
            fi
        else
            echo "[+] Successfully installed: $tool_name"
        fi
    else
        echo "[+] Found: $tool_name"
    fi
}

echo "[*] Checking Go tools..."
for i in "${!tool_names[@]}"; do
    install_tool "${tool_names[$i]}" "${tools[$i]}"
done

install_tool "uncover" "github.com/projectdiscovery/uncover/cmd/uncover"

# ===== HTTPX Live Host Detection =====
httpx_scan() {
    echo "[*] Phase 1b: HTTPX Live Host Detection"

    if [ ! -s "$workspace/subdomains/hosts.txt" ]; then
        echo "[!] No resolved hosts to probe with httpx. Skipping."
        return 1
    fi

    echo "[*] Probing with httpx (common ports + HTTP/HTTPS schema)..."
    httpx -l "$workspace/subdomains/hosts.txt" \
        -ports 80,443,8080,8443,8000,9443 \
        -follow-redirects \
        -tls-probe \
        -status-code \
        -title \
        -match-regex "$input_arg" \
        -retries 2 \
        -timeout 5 \
        -no-color \
        -o "$workspace/httpx/live.txt"

    if [ ! -s "$workspace/httpx/live.txt" ]; then
        echo "[!] No live HTTP services detected. Debugging..."
        httpx -l "$workspace/subdomains/hosts.txt" \
            -follow-redirects \
            -tls-probe \
            -match-regex "$input_arg" \
            -debug \
            -o "$workspace/httpx/live_debug.txt"
        echo "[DEBUG] Check $workspace/httpx/live_debug.txt for details."
    else
        echo "[+] Live HTTP services: $(wc -l < "$workspace/httpx/live.txt")"
    fi
}

# ===== Domain Enumeration =====
enumerate_subdomains() {
    if [ "$input_type" == "domains" ]; then
        echo "[*] Phase 1: Subdomain Enumeration"
        run "Running subfinder" "subfinder -dL '$targets' -silent -o '$workspace/subdomains/subdomains.txt'"
        # Resolve hosts using dnsx
        if [ -s "$workspace/subdomains/subdomains.txt" ]; then
            # Get resolved domain names
            dnsx -l "$workspace/subdomains/subdomains.txt" -silent -o "$workspace/subdomains/resolved.txt"
            # Get IP addresses for uncover - extract IPs from dnsx response
            dnsx -l "$workspace/subdomains/subdomains.txt" -silent -resp | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > "$workspace/subdomains/ips.txt"
            
            # Create hosts.txt with both domains and IPs for maximum compatibility
            if [ -s "$workspace/subdomains/resolved.txt" ] && [ -s "$workspace/subdomains/ips.txt" ]; then
                # Combine resolved domains and their IPs
                cat "$workspace/subdomains/resolved.txt" "$workspace/subdomains/ips.txt" | sort -u > "$workspace/subdomains/hosts.txt"
                echo "[+] Found $(wc -l < "$workspace/subdomains/subdomains.txt") subdomains"  
                echo "[+] Resolved hosts: $(wc -l < "$workspace/subdomains/resolved.txt")"
                echo "[+] Unique IPs: $(wc -l < "$workspace/subdomains/ips.txt")"
                httpx_scan
            elif [ -s "$workspace/subdomains/resolved.txt" ]; then
                # Fallback to just resolved domains if IP extraction fails
                cp "$workspace/subdomains/resolved.txt" "$workspace/subdomains/hosts.txt"
                echo "[+] Found $(wc -l < "$workspace/subdomains/subdomains.txt") subdomains"
                echo "[+] Resolved hosts: $(wc -l < "$workspace/subdomains/resolved.txt")"
                echo "[!] Warning: Could not extract IP addresses, using domain names"
                httpx_scan
            else
                echo "[!] No hosts resolved from subdomains"
            fi
        else
            echo "[!] No subdomains found"
        fi
    else
        # For IP targets, create both targets.txt and hosts.txt for compatibility
        cp "$targets" "$workspace/subdomains/targets.txt"
        cp "$targets" "$workspace/subdomains/hosts.txt"
        echo "[*] Skipping subdomain enumeration for IP targets"
        echo "[+] IP targets: $(wc -l < "$workspace/subdomains/targets.txt")"
    fi
}

# ===== Uncover Phase =====
uncover_scan() {
    echo "[*] Phase 2: Uncover Scan"
    if ! command -v uncover &> /dev/null; then
        echo "[!] uncover not installed, skipping uncover scan"
        return 0
    fi

    # Determine input file based on what's available
    input_file=""
    if [ -s "$workspace/subdomains/hosts.txt" ]; then
        input_file="$workspace/subdomains/hosts.txt"
        echo "[*] Using resolved hosts from subdomain enumeration"
    elif [ -s "$workspace/subdomains/targets.txt" ]; then
        input_file="$workspace/subdomains/targets.txt"
        echo "[*] Using direct IP targets"
    elif [ -s "$targets" ]; then
        input_file="$targets"
        echo "[*] Using original input file"
    else
        echo "[!] No valid input file found for uncover scan. Skipping."
        return 1
    fi

    echo "[*] Processing $(wc -l < "$input_file") targets with uncover..."
    
    result_count=0
    while read -r host; do
        # Skip empty lines
        [ -z "$host" ] && continue
        
        echo "[*] Running uncover on $host"
        temp_results=$(uncover -q "$host" -e shodan,netlas,hunter -silent 2>>"$error_log")
        if [ -n "$temp_results" ]; then
            echo "$temp_results" >> "$workspace/uncover_results.txt"
            result_count=$((result_count + 1))
            echo "[+] Found results for $host"
        else
            echo "[-] No results for $host in OSINT databases"
        fi
    done < "$input_file"

    if [ ! -s "$workspace/uncover_results.txt" ]; then
        echo "[!] No OSINT results found for any targets. This is normal if:"
        echo "    - Targets are private/internal IPs not indexed by search engines"
        echo "    - Domains/IPs are new or low-profile"
        echo "    - No API keys configured for Shodan/Netlas/Hunter (using free tier)"
        echo "    - Network connectivity issues"
        echo "    - Check $error_log for error details if needed"
    else
        echo "[+] Uncover results: $(wc -l < "$workspace/uncover_results.txt") entries from $result_count targets saved to $workspace/uncover_results.txt"
    fi
}

# ===== Main Workflow =====
echo "[*] Starting RavenWatch workflow..."
enumerate_subdomains
uncover_scan

# ===== Summary =====
echo "[+] RavenWatch complete! 📦 Output saved in: $workspace"
echo "[+] Summary:"
echo "    - Subdomains: $( [ -f "$workspace/subdomains/subdomains.txt" ] && wc -l < "$workspace/subdomains/subdomains.txt" || echo 0 )"
echo "    - Resolved hosts: $( [ -f "$workspace/subdomains/resolved.txt" ] && wc -l < "$workspace/subdomains/resolved.txt" || echo 0 )"
echo "    - Live HTTP services: $( [ -f "$workspace/httpx/live.txt" ] && wc -l < "$workspace/httpx/live.txt" || echo 0 )"
echo "    - Uncover results (from hosts): $( [ -f "$workspace/uncover_results.txt" ] && wc -l < "$workspace/uncover_results.txt" || echo 0 )"

[ -s "$error_log" ] && echo "[!] Errors logged to: $error_log" || rm -f "$error_log"