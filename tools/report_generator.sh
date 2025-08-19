#!/bin/bash

# 📋 Report Generator v1.0 — Pentest Report Builder
# Author: invisigoth29 
# Based on: 5-Reporting/report-template.md
# CVE Integration: https://github.com/CVEProject/cvelistV5/tree/main

# OS Detection
OS=$(uname -s)
case "$OS" in
    Darwin)
        OS_TYPE="mac"
        PACKAGE_MANAGER="brew"
        ;;
    Linux)
        OS_TYPE="linux"
        PACKAGE_MANAGER="apt"
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
workspace="report_$timestamp"
mkdir -p "$workspace"/{screenshots,artifacts,evidence,reports}

error_log="$workspace/error.log"

# Parse command line arguments
ENUMERATION_DIR=""
EXPLOITATION_DIR=""
REPORT_TYPE="full"
CLIENT_NAME=""
TARGET_ENVIRONMENT=""
TEAM_MEMBERS=""
OUTPUT_FORMAT="markdown"

show_usage() {
    echo "Usage: $0 -e <enumeration_dir> -x <exploitation_dir> [options]"
    echo ""
    echo "Required:"
    echo "  -e <dir>        Directory containing enumeration results"
    echo "  -x <dir>        Directory containing exploitation results"
    echo ""
    echo "Options:"
    echo "  -c <name>       Client name"
    echo "  -t <env>        Target environment"
    echo "  -m <members>    Team members (comma-separated)"
    echo "  -r <type>       Report type: full, executive, technical"
    echo "  -f <format>     Output format: markdown, html, pdf"
    echo "  -v              Verbose output"
    echo "  -h              Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 -e enum_results -x exploit_results -c 'Acme Corp' -t 'Production'"
    echo "  $0 -e enum_results -x exploit_results -r executive -f html"
}

while getopts "e:x:c:t:m:r:f:vh" opt; do
    case $opt in
        e) ENUMERATION_DIR="$OPTARG" ;;
        x) EXPLOITATION_DIR="$OPTARG" ;;
        c) CLIENT_NAME="$OPTARG" ;;
        t) TARGET_ENVIRONMENT="$OPTARG" ;;
        m) TEAM_MEMBERS="$OPTARG" ;;
        r) REPORT_TYPE="$OPTARG" ;;
        f) OUTPUT_FORMAT="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [ -z "$ENUMERATION_DIR" ] || [ -z "$EXPLOITATION_DIR" ]; then
    echo "[!] Both enumeration and exploitation directories are required"
    show_usage
    exit 1
fi

if [ ! -d "$ENUMERATION_DIR" ]; then
    echo "[!] Enumeration directory not found: $ENUMERATION_DIR"
    exit 1
fi

if [ ! -d "$EXPLOITATION_DIR" ]; then
    echo "[!] Exploitation directory not found: $EXPLOITATION_DIR"
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

log_warning() {
    echo "[!] $1"
}

# ===== CVE Database Integration =====
setup_cve_database() {
    log_info "Setting up CVE database integration..."
    
    # Create CVE cache directory
    mkdir -p "$workspace/cve_cache"
    
    # Check if CVE database is already cloned
    if [ ! -d "$workspace/cve_cache/cvelistV5" ]; then
        log_info "Cloning CVE database from GitHub..."
        git clone https://github.com/CVEProject/cvelistV5.git "$workspace/cve_cache/cvelistV5" 2>/dev/null
        if [ $? -ne 0 ]; then
            log_warning "Failed to clone CVE database. CVE information will be limited."
            return 1
        fi
    else
        log_info "Updating existing CVE database..."
        cd "$workspace/cve_cache/cvelistV5"
        git pull origin main 2>/dev/null
        cd - > /dev/null
    fi
    
    log_success "CVE database ready"
}

get_cve_info() {
    local cve_id="$1"
    local cve_file="$workspace/cve_cache/cvelistV5/cves/$cve_id.json"
    
    if [ -f "$cve_file" ]; then
        # Extract CVE information using jq if available
        if command -v jq &> /dev/null; then
            local description=$(jq -r '.containers.cna.descriptions[0].value' "$cve_file" 2>/dev/null)
            local severity=$(jq -r '.containers.cna.metrics[0].cvssV3_1.baseSeverity' "$cve_file" 2>/dev/null)
            local score=$(jq -r '.containers.cna.metrics[0].cvssV3_1.baseScore' "$cve_file" 2>/dev/null)
            
            echo "CVE: $cve_id"
            echo "Severity: $severity (Score: $score)"
            echo "Description: $description"
        else
            # Fallback to grep for basic info
            echo "CVE: $cve_id"
            echo "Description: $(grep -o '"value": "[^"]*"' "$cve_file" | head -1 | cut -d'"' -f4)"
        fi
    else
        echo "CVE: $cve_id (Information not available in local database)"
    fi
}

# ===== Tool Installation =====
install_tools() {
    log_info "Installing required tools for report generation..."
    
    # Install jq for JSON parsing
    if ! command -v jq &> /dev/null; then
        case "$PACKAGE_MANAGER" in
            "brew")
                brew install jq
                ;;
            "apt")
                sudo apt install -y jq
                ;;
        esac
    fi
    
    # Install pandoc for format conversion
    if ! command -v pandoc &> /dev/null; then
        case "$PACKAGE_MANAGER" in
            "brew")
                brew install pandoc
                ;;
            "apt")
                sudo apt install -y pandoc
                ;;
        esac
    fi
    
    # Install wkhtmltopdf for HTML to PDF conversion
    if [ "$OUTPUT_FORMAT" = "pdf" ] && ! command -v wkhtmltopdf &> /dev/null; then
        case "$PACKAGE_MANAGER" in
            "brew")
                brew install wkhtmltopdf
                ;;
            "apt")
                sudo apt install -y wkhtmltopdf
                ;;
        esac
    fi
}

# ===== Data Processing =====
process_enumeration_data() {
    log_info "Processing enumeration data..."
    
    # Extract key information from enumeration results
    if [ -f "$ENUMERATION_DIR/ports/open_ports.txt" ]; then
        cp "$ENUMERATION_DIR/ports/open_ports.txt" "$workspace/evidence/open_ports.txt"
        OPEN_PORTS_COUNT=$(wc -l < "$ENUMERATION_DIR/ports/open_ports.txt")
    fi
    
    if [ -f "$ENUMERATION_DIR/ports/http_services.txt" ]; then
        cp "$ENUMERATION_DIR/ports/http_services.txt" "$workspace/evidence/http_services.txt"
        HTTP_SERVICES_COUNT=$(wc -l < "$ENUMERATION_DIR/ports/http_services.txt")
    fi
    
    if [ -f "$ENUMERATION_DIR/subdomains/subdomains.txt" ]; then
        cp "$ENUMERATION_DIR/subdomains/subdomains.txt" "$workspace/evidence/subdomains.txt"
        SUBDOMAINS_COUNT=$(wc -l < "$ENUMERATION_DIR/subdomains/subdomains.txt")
    fi
    
    # Process SMB enumeration results
    if [ -d "$ENUMERATION_DIR/smb" ]; then
        find "$ENUMERATION_DIR/smb" -name "*.txt" -exec cp {} "$workspace/evidence/" \;
    fi
    
    # Process DNS enumeration results
    if [ -d "$ENUMERATION_DIR/dns" ]; then
        find "$ENUMERATION_DIR/dns" -name "*.txt" -exec cp {} "$workspace/evidence/" \;
    fi
}

process_exploitation_data() {
    log_info "Processing exploitation data..."
    
    # Extract vulnerability findings
    if [ -f "$EXPLOITATION_DIR/web/nuclei_results.txt" ]; then
        cp "$EXPLOITATION_DIR/web/nuclei_results.txt" "$workspace/evidence/web_vulnerabilities.txt"
        WEB_VULNS_COUNT=$(grep -c "critical\|high" "$EXPLOITATION_DIR/web/nuclei_results.txt" 2>/dev/null || echo 0)
    fi
    
    if [ -f "$EXPLOITATION_DIR/infrastructure/nuclei_network_results.txt" ]; then
        cp "$EXPLOITATION_DIR/infrastructure/nuclei_network_results.txt" "$workspace/evidence/infrastructure_vulnerabilities.txt"
        INFRA_VULNS_COUNT=$(grep -c "critical\|high" "$EXPLOITATION_DIR/infrastructure/nuclei_network_results.txt" 2>/dev/null || echo 0)
    fi
    
    # Process default credentials findings
    if [ -f "$EXPLOITATION_DIR/infrastructure/ssh_default_creds.txt" ]; then
        cp "$EXPLOITATION_DIR/infrastructure/ssh_default_creds.txt" "$workspace/evidence/ssh_default_creds.txt"
    fi
    
    if [ -f "$EXPLOITATION_DIR/infrastructure/ftp_default_creds.txt" ]; then
        cp "$EXPLOITATION_DIR/infrastructure/ftp_default_creds.txt" "$workspace/evidence/ftp_default_creds.txt"
    fi
    
    # Process WordPress findings
    if [ -d "$EXPLOITATION_DIR/web" ]; then
        find "$EXPLOITATION_DIR/web" -name "wpscan_*.txt" -exec cp {} "$workspace/evidence/" \;
    fi
    
    # Process Metasploit results
    if [ -f "$EXPLOITATION_DIR/infrastructure/metasploit_results.txt" ]; then
        cp "$EXPLOITATION_DIR/infrastructure/metasploit_results.txt" "$workspace/evidence/metasploit_results.txt"
    fi
    
    # Process secrets found
    if [ -d "$EXPLOITATION_DIR/web" ]; then
        find "$EXPLOITATION_DIR/web" -name "*secrets*.txt" -exec cp {} "$workspace/evidence/" \;
    fi
}

# ===== Finding Generation =====
generate_findings() {
    log_info "Generating findings from vulnerability data..."
    
    findings_file="$workspace/findings.md"
    
    {
        echo "# Findings"
        echo ""
        
        # Process web vulnerabilities
        if [ -s "$workspace/evidence/web_vulnerabilities.txt" ]; then
            echo "## Web Application Vulnerabilities"
            echo ""
            
            # Extract and format each vulnerability
            while IFS= read -r line; do
                if [[ "$line" =~ \[([^\]]+)\] ]]; then
                    severity="${BASH_REMATCH[1]}"
                    if [[ "$severity" =~ (critical|high|medium) ]]; then
                        echo "### Web Vulnerability - $severity"
                        echo "- **Severity**: $severity"
                        echo "- **Affected**: Web Application"
                        echo "- **Description**: $line"
                        
                        # Extract CVE if present
                        if [[ "$line" =~ CVE-[0-9]{4}-[0-9]+ ]]; then
                            cve_id="${BASH_REMATCH[0]}"
                            echo "- **CVE**: $cve_id"
                            echo "- **CVE Details**:"
                            echo '```'
                            get_cve_info "$cve_id"
                            echo '```'
                        fi
                        
                        echo "- **Impact**: Potential unauthorized access, data exposure, or system compromise"
                        echo "- **Recommendation**: Review and patch affected components"
                        echo "- **Evidence**: \`evidence/web_vulnerabilities.txt\`"
                        echo ""
                    fi
                fi
            done < "$workspace/evidence/web_vulnerabilities.txt"
        fi
        
        # Process infrastructure vulnerabilities
        if [ -s "$workspace/evidence/infrastructure_vulnerabilities.txt" ]; then
            echo "## Infrastructure Vulnerabilities"
            echo ""
            
            while IFS= read -r line; do
                if [[ "$line" =~ \[([^\]]+)\] ]]; then
                    severity="${BASH_REMATCH[1]}"
                    if [[ "$severity" =~ (critical|high|medium) ]]; then
                        echo "### Infrastructure Vulnerability - $severity"
                        echo "- **Severity**: $severity"
                        echo "- **Affected**: Network Infrastructure"
                        echo "- **Description**: $line"
                        
                        if [[ "$line" =~ CVE-[0-9]{4}-[0-9]+ ]]; then
                            cve_id="${BASH_REMATCH[0]}"
                            echo "- **CVE**: $cve_id"
                            echo "- **CVE Details**:"
                            echo '```'
                            get_cve_info "$cve_id"
                            echo '```'
                        fi
                        
                        echo "- **Impact**: Potential system compromise or unauthorized access"
                        echo "- **Recommendation**: Apply security patches and review configurations"
                        echo "- **Evidence**: \`evidence/infrastructure_vulnerabilities.txt\`"
                        echo ""
                    fi
                fi
            done < "$workspace/evidence/infrastructure_vulnerabilities.txt"
        fi
        
        # Process default credentials
        if [ -s "$workspace/evidence/ssh_default_creds.txt" ]; then
            echo "## Default Credentials - SSH"
            echo ""
            echo "### SSH Default Credentials Found"
            echo "- **Severity**: High"
            echo "- **Affected**: SSH Services"
            echo "- **Description**: Default SSH credentials discovered"
            echo "- **Impact**: Unauthorized system access"
            echo "- **Recommendation**: Change default credentials immediately"
            echo "- **Evidence**: \`evidence/ssh_default_creds.txt\`"
            echo ""
        fi
        
        if [ -s "$workspace/evidence/ftp_default_creds.txt" ]; then
            echo "### FTP Default Credentials Found"
            echo "- **Severity**: High"
            echo "- **Affected**: FTP Services"
            echo "- **Description**: Default FTP credentials discovered"
            echo "- **Impact**: Unauthorized file access"
            echo "- **Recommendation**: Change default credentials immediately"
            echo "- **Evidence**: \`evidence/ftp_default_creds.txt\`"
            echo ""
        fi
        
        # Process WordPress vulnerabilities
        find "$workspace/evidence" -name "wpscan_*.txt" | while read -r file; do
            if [ -s "$file" ]; then
                domain=$(basename "$file" | sed 's/wpscan_\(.*\)\.txt/\1/')
                echo "## WordPress Vulnerabilities - $domain"
                echo ""
                echo "### WordPress Security Issues"
                echo "- **Severity**: Medium"
                echo "- **Affected**: WordPress Site ($domain)"
                echo "- **Description**: WordPress security vulnerabilities detected"
                echo "- **Impact**: Potential website compromise"
                echo "- **Recommendation**: Update WordPress, themes, and plugins"
                echo "- **Evidence**: \`evidence/$(basename "$file")\`"
                echo ""
            fi
        done
        
        # Process exposed secrets
        find "$workspace/evidence" -name "*secrets*.txt" | while read -r file; do
            if [ -s "$file" ]; then
                echo "## Exposed Secrets"
                echo ""
                echo "### Sensitive Information Exposure"
                echo "- **Severity**: High"
                echo "- **Affected**: Web Applications"
                echo "- **Description**: Sensitive information found in source code"
                echo "- **Impact**: Credential exposure, API key compromise"
                echo "- **Recommendation**: Remove sensitive data from client-side code"
                echo "- **Evidence**: \`evidence/$(basename "$file")\`"
                echo ""
            fi
        done
        
    } > "$findings_file"
    
    log_success "Findings generated: $findings_file"
}

# ===== Report Generation =====
generate_report() {
    log_info "Generating pentest report..."
    
    report_file="$workspace/reports/pentest_report.md"
    
    # Get engagement dates
    engagement_start=$(date -d "7 days ago" +"%Y-%m-%d")
    engagement_end=$(date +"%Y-%m-%d")
    
    {
        echo "# Penetration Testing Report"
        echo ""
        echo "## Executive Summary"
        echo ""
        echo "This report presents the findings of a comprehensive penetration test conducted against the **$TARGET_ENVIRONMENT** environment for **$CLIENT_NAME**."
        echo ""
        echo "### Key Findings"
        echo "- **Total Vulnerabilities**: $((WEB_VULNS_COUNT + INFRA_VULNS_COUNT))"
        echo "- **Critical/High Severity**: $((WEB_VULNS_COUNT + INFRA_VULNS_COUNT))"
        echo "- **Open Ports Discovered**: ${OPEN_PORTS_COUNT:-0}"
        echo "- **Web Services**: ${HTTP_SERVICES_COUNT:-0}"
        echo "- **Subdomains**: ${SUBDOMAINS_COUNT:-0}"
        echo ""
        
        echo "### Risk Assessment"
        if [ $((WEB_VULNS_COUNT + INFRA_VULNS_COUNT)) -gt 10 ]; then
            echo "**Overall Risk Level: HIGH**"
            echo "The target environment contains multiple critical and high-severity vulnerabilities that require immediate attention."
        elif [ $((WEB_VULNS_COUNT + INFRA_VULNS_COUNT)) -gt 5 ]; then
            echo "**Overall Risk Level: MEDIUM**"
            echo "Several security issues were identified that should be addressed promptly."
        else
            echo "**Overall Risk Level: LOW**"
            echo "Limited security issues were found, but regular security assessments are recommended."
        fi
        echo ""
        
        echo "## Engagement Details"
        echo ""
        echo "- **Client**: $CLIENT_NAME"
        echo "- **Target Environment**: $TARGET_ENVIRONMENT"
        echo "- **Engagement Period**: $engagement_start to $engagement_end"
        echo "- **Team Members**: $TEAM_MEMBERS"
        echo "- **Report Generated**: $(date)"
        echo ""
        
        echo "## Methodology"
        echo ""
        echo "### Phase 1: Reconnaissance"
        echo "- Passive information gathering"
        echo "- Subdomain enumeration"
        echo "- DNS analysis"
        echo ""
        
        echo "### Phase 2: Enumeration"
        echo "- Port scanning and service identification"
        echo "- Version fingerprinting"
        echo "- Web application mapping"
        echo "- Infrastructure service enumeration"
        echo ""
        
        echo "### Phase 3: Exploitation"
        echo "- Vulnerability assessment using automated tools"
        echo "- Manual testing of identified issues"
        echo "- Default credential testing"
        echo "- Web application security testing"
        echo ""
        
        echo "## Technical Findings"
        echo ""
        
        # Include findings
        if [ -f "$workspace/findings.md" ]; then
            cat "$workspace/findings.md"
        fi
        
        echo "## Recommendations"
        echo ""
        echo "### Immediate Actions (Critical/High Severity)"
        echo "1. Patch all identified vulnerabilities"
        echo "2. Change default credentials"
        echo "3. Remove sensitive information from client-side code"
        echo "4. Implement proper access controls"
        echo ""
        
        echo "### Short-term Actions (Medium Severity)"
        echo "1. Update software and applications"
        echo "2. Implement security headers"
        echo "3. Configure proper logging and monitoring"
        echo "4. Conduct security awareness training"
        echo ""
        
        echo "### Long-term Actions"
        echo "1. Establish regular security assessments"
        echo "2. Implement secure development practices"
        echo "3. Deploy security monitoring tools"
        echo "4. Create incident response procedures"
        echo ""
        
        echo "## Appendix"
        echo ""
        echo "### Tools Used"
        echo "- **Reconnaissance**: Subfinder, DNSx, HTTPX"
        echo "- **Enumeration**: Nmap, Nuclei, Katana"
        echo "- **Exploitation**: Metasploit, Hydra, SQLMap"
        echo "- **Web Testing**: WPScan, Wfuzz, Burp Suite"
        echo ""
        
        echo "### Evidence Files"
        echo "All evidence files are stored in the \`evidence/\` directory:"
        echo ""
        find "$workspace/evidence" -type f -name "*.txt" | while read -r file; do
            echo "- \`$(basename "$file")\`"
        done
        echo ""
        
        echo "### CVE Database"
        echo "CVE information sourced from the official CVE database:"
        echo "https://github.com/CVEProject/cvelistV5/tree/main"
        echo ""
        
        echo "### Report Metadata"
        echo "- **Report Version**: 1.0"
        echo "- **Generated By**: Report Generator v1.0"
        echo "- **CVE Database Version**: $(date -r "$workspace/cve_cache/cvelistV5" 2>/dev/null || echo 'Unknown')"
        echo ""
        
    } > "$report_file"
    
    log_success "Report generated: $report_file"
}

# ===== Format Conversion =====
convert_format() {
    if [ "$OUTPUT_FORMAT" = "html" ]; then
        log_info "Converting to HTML format..."
        pandoc "$workspace/reports/pentest_report.md" -o "$workspace/reports/pentest_report.html" --standalone --css="$workspace/style.css"
        log_success "HTML report: $workspace/reports/pentest_report.html"
    elif [ "$OUTPUT_FORMAT" = "pdf" ]; then
        log_info "Converting to PDF format..."
        pandoc "$workspace/reports/pentest_report.md" -o "$workspace/reports/pentest_report.pdf" --pdf-engine=wkhtmltopdf
        log_success "PDF report: $workspace/reports/pentest_report.pdf"
    fi
}

# ===== Main Workflow =====
main() {
    log_info "Starting Report Generator..."
    
    install_tools
    setup_cve_database
    process_enumeration_data
    process_exploitation_data
    generate_findings
    generate_report
    convert_format
    
    # Summary
    log_success "Report generation complete! 📋"
    log_success "Output files:"
    echo "    - Markdown Report: $workspace/reports/pentest_report.md"
    if [ "$OUTPUT_FORMAT" = "html" ]; then
        echo "    - HTML Report: $workspace/reports/pentest_report.html"
    elif [ "$OUTPUT_FORMAT" = "pdf" ]; then
        echo "    - PDF Report: $workspace/reports/pentest_report.pdf"
    fi
    echo "    - Evidence Files: $workspace/evidence/"
    echo "    - CVE Database: $workspace/cve_cache/cvelistV5/"
    
    [ -s "$error_log" ] && log_error "Errors logged to: $error_log" || rm -f "$error_log"
}

# Run main function
main
