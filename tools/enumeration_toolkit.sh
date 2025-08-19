#!/bin/bash

# 🔍 Enumeration Toolkit v1.0 — Service Enumeration
# Author: invisigoth29 
# Based on: 2-Enumeration/service-checklist.md

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
workspace="enumeration_$timestamp"
mkdir -p "$workspace"/{ports,web,smb,rdp,ldap,dns,reports}

error_log="$workspace/error.log"

# Parse command line arguments
TARGET=""
SCAN_TYPE="all"
PORTS=""
THREADS=50
VERBOSE=false

show_usage() {
    echo "Usage: $0 -t <target> [options]"
    echo ""
    echo "Required:"
    echo "  -t <target>     Target (IP, domain, or file with targets)"
    echo ""
    echo "Options:"
    echo "  -s <type>       Scan type: all, ports, web, smb, rdp, ldap, dns"
    echo "  -p <ports>      Ports to scan (default: common ports)"
    echo "  -n <threads>    Number of threads (default: 50)"
    echo "  -v              Verbose output"
    echo "  -h              Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.1                    # Full enumeration"
    echo "  $0 -t example.com -s web             # Web enumeration only"
    echo "  $0 -t targets.txt -p 80,443,8080     # Custom ports"
    echo "  $0 -t 10.0.0.0/24 -s ports -n 100    # Port scan with 100 threads"
}

while getopts "t:s:p:n:vh" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        s) SCAN_TYPE="$OPTARG" ;;
        p) PORTS="$OPTARG" ;;
        n) THREADS="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "[!] Target is required"
    show_usage
    exit 1
fi

# ===== Utility Functions =====
run() {
    echo "[*] $1"
    if [ "$VERBOSE" = true ]; then
        eval "$2"
    else
        eval "$2" >/dev/null 2>&1
    fi
    if [ $? -ne 0 ]; then
        echo "[!] Error during: $1"
        echo "[!] Failed: $2" | tee -a "$error_log"
    else
        echo "[+] Completed: $1"
    fi
}

log_info() {
    echo "[*] $1"
}

log_success() {
    echo "[+] $1"
}

log_error() {
    echo "[!] $1" | tee -a "$error_log"
}

# ===== Tool Setup =====
tools=(
    github.com/projectdiscovery/nuclei/v2/cmd/nuclei
    github.com/projectdiscovery/httpx/cmd/httpx
    github.com/projectdiscovery/dnsx/cmd/dnsx
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder
    github.com/projectdiscovery/naabu/v2/cmd/naabu
    github.com/projectdiscovery/ffuf/cmd/ffuf
    github.com/projectdiscovery/feroxbuster/cmd/feroxbuster
    github.com/projectdiscovery/whatweb/cmd/whatweb
)
tool_names=(nuclei httpx dnsx subfinder naabu ffuf feroxbuster whatweb)

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

# ===== Target Processing =====
process_targets() {
    if [ -f "$TARGET" ]; then
        targets_file="$TARGET"
        log_info "Processing targets from file: $TARGET"
    else
        echo "$TARGET" > "$workspace/single_target.txt"
        targets_file="$workspace/single_target.txt"
        log_info "Processing single target: $TARGET"
    fi
    
    # Detect if targets are IPs or domains
    if grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$targets_file"; then
        TARGET_TYPE="ip"
        log_info "Detected IP targets"
    else
        TARGET_TYPE="domain"
        log_info "Detected domain targets"
    fi
}

# ===== Port Scanning =====
port_scan() {
    log_info "Phase 1: Port Scanning"
    
    # Set default ports if not specified
    if [ -z "$PORTS" ]; then
        PORTS="21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080,8443"
    fi
    
    log_info "Scanning ports: $PORTS"
    
    # Use naabu for fast port scanning
    if command -v naabu &> /dev/null; then
        run "Running naabu port scan" "naabu -l '$targets_file' -p '$PORTS' -rate '$THREADS' -silent -o '$workspace/ports/open_ports.txt'"
    else
        # Fallback to nmap
        if command -v nmap &> /dev/null; then
            run "Running nmap port scan" "nmap -sS -p '$PORTS' -iL '$targets_file' -oN '$workspace/ports/nmap_scan.txt'"
            # Extract open ports from nmap output
            grep -E "^[0-9]+/tcp.*open" "$workspace/ports/nmap_scan.txt" | awk '{print $1}' | cut -d'/' -f1 > "$workspace/ports/open_ports.txt"
        else
            log_error "Neither naabu nor nmap found. Install one to continue."
            return 1
        fi
    fi
    
    if [ -s "$workspace/ports/open_ports.txt" ]; then
        log_success "Found $(wc -l < "$workspace/ports/open_ports.txt") open ports"
    else
        log_error "No open ports found"
    fi
}

# ===== Version Fingerprinting =====
version_fingerprint() {
    log_info "Phase 2: Version Fingerprinting"
    
    if [ ! -s "$workspace/ports/open_ports.txt" ]; then
        log_error "No open ports to fingerprint"
        return 1
    fi
    
    # Use httpx for HTTP services
    if command -v httpx &> /dev/null; then
        run "Running httpx version detection" "httpx -l '$targets_file' -ports 80,443,8080,8443 -title -tech-detect -status-code -silent -o '$workspace/ports/http_services.txt'"
    fi
    
    # Use nmap for detailed version detection
    if command -v nmap &> /dev/null; then
        run "Running nmap version detection" "nmap -sV -iL '$targets_file' -oN '$workspace/ports/version_scan.txt'"
    fi
    
    # Use whatweb for web technologies
    if command -v whatweb &> /dev/null && [ -s "$workspace/ports/http_services.txt" ]; then
        run "Running whatweb technology detection" "whatweb -i '$workspace/ports/http_services.txt' --no-errors --log-json '$workspace/ports/whatweb_results.json'"
    fi
}

# ===== HTTP/Web Enumeration =====
web_enumeration() {
    log_info "Phase 3: HTTP/Web Enumeration"
    
    if [ ! -s "$workspace/ports/http_services.txt" ]; then
        log_error "No HTTP services found for web enumeration"
        return 1
    fi
    
    # Directory brute force with ffuf
    if command -v ffuf &> /dev/null; then
        log_info "Running directory brute force with ffuf"
        while read -r url; do
            domain=$(echo "$url" | sed 's|^https\?://||' | sed 's|/.*||')
            run "Brute forcing directories on $domain" "ffuf -u '$url/FUZZ' -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -o '$workspace/web/ffuf_$domain.txt' -of csv"
        done < "$workspace/ports/http_services.txt"
    fi
    
    # Alternative with feroxbuster
    if command -v feroxbuster &> /dev/null; then
        log_info "Running directory brute force with feroxbuster"
        while read -r url; do
            domain=$(echo "$url" | sed 's|^https\?://||' | sed 's|/.*||')
            run "Brute forcing directories on $domain" "feroxbuster -u '$url' -w /usr/share/wordlists/dirb/common.txt -o '$workspace/web/feroxbuster_$domain.txt'"
        done < "$workspace/ports/http_services.txt"
    fi
    
    # Test default files
    log_info "Testing default files"
    while read -r url; do
        domain=$(echo "$url" | sed 's|^https\?://||' | sed 's|/.*||')
        for file in robots.txt sitemap.xml .git/config .env; do
            run "Testing $file on $domain" "curl -s -o '$workspace/web/${domain}_${file//\//_}' '$url/$file'"
        done
    done < "$workspace/ports/http_services.txt"
    
    # Analyze HTTP headers
    log_info "Analyzing HTTP headers"
    while read -r url; do
        domain=$(echo "$url" | sed 's|^https\?://||' | sed 's|/.*||')
        run "Analyzing headers for $domain" "curl -s -I '$url' -o '$workspace/web/${domain}_headers.txt'"
    done < "$workspace/ports/http_services.txt"
}

# ===== SMB Enumeration =====
smb_enumeration() {
    log_info "Phase 4: SMB Enumeration"
    
    # Check for SMB ports (139, 445)
    if grep -q "139\|445" "$workspace/ports/open_ports.txt" 2>/dev/null; then
        log_info "SMB ports detected, starting enumeration"
        
        # SMB share listing with smbclient
        if command -v smbclient &> /dev/null; then
            while read -r target; do
                run "Listing SMB shares on $target" "smbclient -L //$target -N 2>/dev/null | tee '$workspace/smb/shares_$target.txt'"
            done < "$targets_file"
        fi
        
        # Enum4linux-ng (if available)
        if command -v enum4linux-ng &> /dev/null; then
            while read -r target; do
                run "Running enum4linux-ng on $target" "enum4linux-ng -A '$target' -o '$workspace/smb/enum4linux_$target.txt'"
            done < "$targets_file"
        fi
        
        # Null session test
        log_info "Testing null sessions"
        while read -r target; do
            run "Testing null session on $target" "smbclient //$target/IPC$ -N 2>/dev/null && echo 'Null session successful' || echo 'Null session failed' | tee '$workspace/smb/null_session_$target.txt'"
        done < "$targets_file"
    else
        log_info "No SMB ports detected, skipping SMB enumeration"
    fi
}

# ===== RDP Enumeration =====
rdp_enumeration() {
    log_info "Phase 5: RDP Enumeration"
    
    # Check for RDP port (3389)
    if grep -q "3389" "$workspace/ports/open_ports.txt" 2>/dev/null; then
        log_info "RDP port detected, starting enumeration"
        
        # Test RDP connectivity
        while read -r target; do
            run "Testing RDP connectivity to $target" "nc -zv '$target' 3389 2>&1 | tee '$workspace/rdp/connectivity_$target.txt'"
        done < "$targets_file"
        
        # Check for RDP security settings
        if command -v nmap &> /dev/null; then
            while read -r target; do
                run "Scanning RDP security on $target" "nmap -p 3389 --script rdp-ntlm-info '$target' -oN '$workspace/rdp/rdp_scan_$target.txt'"
            done < "$targets_file"
        fi
    else
        log_info "No RDP port detected, skipping RDP enumeration"
    fi
}

# ===== LDAP Enumeration =====
ldap_enumeration() {
    log_info "Phase 6: LDAP Enumeration"
    
    # Check for LDAP ports (389, 636)
    if grep -q "389\|636" "$workspace/ports/open_ports.txt" 2>/dev/null; then
        log_info "LDAP ports detected, starting enumeration"
        
        # LDAP search
        if command -v ldapsearch &> /dev/null; then
            while read -r target; do
                run "Running LDAP search on $target" "ldapsearch -H ldap://$target:389 -x -s base -b '' 2>/dev/null | tee '$workspace/ldap/search_$target.txt'"
            done < "$targets_file"
        fi
        
        # BloodHound (if available)
        if command -v bloodhound &> /dev/null; then
            log_info "BloodHound available - consider running: bloodhound -d <domain> -u <username> -p <password> -c All"
        fi
        
        # Nmap LDAP scripts
        if command -v nmap &> /dev/null; then
            while read -r target; do
                run "Running LDAP nmap scripts on $target" "nmap -p 389,636 --script ldap-search '$target' -oN '$workspace/ldap/nmap_ldap_$target.txt'"
            done < "$targets_file"
        fi
    else
        log_info "No LDAP ports detected, skipping LDAP enumeration"
    fi
}

# ===== DNS Enumeration =====
dns_enumeration() {
    log_info "Phase 7: DNS Enumeration"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        # Zone transfer attempt
        while read -r domain; do
            run "Attempting zone transfer for $domain" "dig AXFR '$domain' @$domain 2>/dev/null | tee '$workspace/dns/zone_transfer_$domain.txt'"
        done < "$targets_file"
        
        # Subdomain brute force
        if command -v dnsx &> /dev/null; then
            run "Brute forcing subdomains" "dnsx -d '$targets_file' -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -silent -o '$workspace/dns/subdomains.txt'"
        fi
        
        # DNS enumeration with subfinder
        if command -v subfinder &> /dev/null; then
            run "Running subfinder" "subfinder -dL '$targets_file' -silent -o '$workspace/dns/subfinder_results.txt'"
        fi
    else
        log_info "IP targets detected, skipping DNS enumeration"
    fi
}

# ===== Report Generation =====
generate_report() {
    log_info "Generating enumeration report"
    
    report_file="$workspace/reports/enumeration_report.txt"
    
    {
        echo "=== Enumeration Report ==="
        echo "Generated: $(date)"
        echo "Target: $TARGET"
        echo "Scan Type: $SCAN_TYPE"
        echo ""
        
        echo "=== Port Scan Results ==="
        if [ -s "$workspace/ports/open_ports.txt" ]; then
            echo "Open ports found:"
            cat "$workspace/ports/open_ports.txt"
        else
            echo "No open ports found"
        fi
        echo ""
        
        echo "=== HTTP Services ==="
        if [ -s "$workspace/ports/http_services.txt" ]; then
            echo "HTTP services:"
            cat "$workspace/ports/http_services.txt"
        else
            echo "No HTTP services found"
        fi
        echo ""
        
        echo "=== SMB Enumeration ==="
        if [ -d "$workspace/smb" ] && [ "$(ls -A "$workspace/smb" 2>/dev/null)" ]; then
            echo "SMB enumeration results available in: $workspace/smb/"
        else
            echo "No SMB enumeration performed or no results"
        fi
        echo ""
        
        echo "=== RDP Enumeration ==="
        if [ -d "$workspace/rdp" ] && [ "$(ls -A "$workspace/rdp" 2>/dev/null)" ]; then
            echo "RDP enumeration results available in: $workspace/rdp/"
        else
            echo "No RDP enumeration performed or no results"
        fi
        echo ""
        
        echo "=== LDAP Enumeration ==="
        if [ -d "$workspace/ldap" ] && [ "$(ls -A "$workspace/ldap" 2>/dev/null)" ]; then
            echo "LDAP enumeration results available in: $workspace/ldap/"
        else
            echo "No LDAP enumeration performed or no results"
        fi
        echo ""
        
        echo "=== DNS Enumeration ==="
        if [ -d "$workspace/dns" ] && [ "$(ls -A "$workspace/dns" 2>/dev/null)" ]; then
            echo "DNS enumeration results available in: $workspace/dns/"
        else
            echo "No DNS enumeration performed or no results"
        fi
        echo ""
        
        echo "=== Next Steps ==="
        echo "1. Review open ports and services"
        echo "2. Analyze web application vulnerabilities"
        echo "3. Test for misconfigurations in SMB/RDP/LDAP"
        echo "4. Follow up with targeted exploitation"
        echo ""
        
        echo "=== Files Generated ==="
        find "$workspace" -type f -name "*.txt" -o -name "*.json" | sort
        
    } > "$report_file"
    
    log_success "Report generated: $report_file"
}

# ===== Main Workflow =====
main() {
    log_info "Starting Enumeration Toolkit..."
    process_targets
    
    case "$SCAN_TYPE" in
        "all")
            port_scan
            version_fingerprint
            web_enumeration
            smb_enumeration
            rdp_enumeration
            ldap_enumeration
            dns_enumeration
            ;;
        "ports")
            port_scan
            version_fingerprint
            ;;
        "web")
            port_scan
            version_fingerprint
            web_enumeration
            ;;
        "smb")
            port_scan
            smb_enumeration
            ;;
        "rdp")
            port_scan
            rdp_enumeration
            ;;
        "ldap")
            port_scan
            ldap_enumeration
            ;;
        "dns")
            dns_enumeration
            ;;
        *)
            log_error "Invalid scan type: $SCAN_TYPE"
            exit 1
            ;;
    esac
    
    generate_report
    
    # Summary
    log_success "Enumeration complete! 📦 Output saved in: $workspace"
    log_success "Summary:"
    echo "    - Open ports: $( [ -f "$workspace/ports/open_ports.txt" ] && wc -l < "$workspace/ports/open_ports.txt" || echo 0 )"
    echo "    - HTTP services: $( [ -f "$workspace/ports/http_services.txt" ] && wc -l < "$workspace/ports/http_services.txt" || echo 0 )"
    echo "    - Report: $workspace/reports/enumeration_report.txt"
    
    [ -s "$error_log" ] && log_error "Errors logged to: $error_log" || rm -f "$error_log"
}

# Run main function
main
