#!/bin/bash

################################################################################
# Web Application Pentesting - Reconnaissance Automation Script
# OWASP WSTG v4.2 Information Gathering Phase
# Usage: ./recon.sh target.com [output_dir]
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TARGET="${1:-}"
OUTPUT_DIR="${2:-.}/recon-$(date +%s)}"
TIMEOUT=10

# Validate input
if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Usage: $0 <target> [output_directory]${NC}"
    echo -e "${RED}[!] Example: $0 target.com${NC}"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo -e "${BLUE}[*] Reconnaissance started for: $TARGET${NC}"
echo -e "${BLUE}[*] Output directory: $OUTPUT_DIR${NC}"
echo ""

# Helper functions
log_section() {
    echo -e "${BLUE}[*] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

log_error() {
    echo -e "${RED}[-] $1${NC}"
}

log_info() {
    echo -e "${YELLOW}[i] $1${NC}"
}

run_command() {
    local desc=$1
    local cmd=$2
    local outfile=$3
    
    log_info "$desc"
    if timeout $TIMEOUT bash -c "$cmd" > "$outfile" 2>&1; then
        log_success "✓ Completed: $desc"
    else
        log_error "✗ Failed or timeout: $desc"
    fi
    echo ""
}

################################################################################
# 1. SEARCH ENGINE RECONNAISSANCE (WSTG-INFO-01)
################################################################################

log_section "PHASE 1: Search Engine Reconnaissance (WSTG-INFO-01)"

# 1.1 Google dorking for sensitive data
run_command \
    "Google dorking: site:$TARGET password OR api_key" \
    "echo 'Manual: Check Google for: site:$TARGET password' && echo 'Manual: Check Google for: site:$TARGET api_key' && echo 'Manual: Check Google for: site:$TARGET filetype:sql' && echo 'Manual: Check Google for: site:$TARGET config'" \
    "$OUTPUT_DIR/01_google-dorking.txt"

# 1.2 GitHub credential search
run_command \
    "GitHub search: credentials in $TARGET repos" \
    "echo 'Manual: Check GitHub for: site:github.com $TARGET password' && echo 'Manual: Check GitHub for: site:github.com $TARGET api_key' && echo 'Manual: Check GitHub for: site:github.com $TARGET .env'" \
    "$OUTPUT_DIR/02_github-search.txt"

# 1.3 Subdomain enumeration
log_info "Subdomain enumeration - attempting multiple methods"

if command -v subfinder &> /dev/null; then
    run_command \
        "Subfinder: subdomain enumeration" \
        "subfinder -d $TARGET -silent 2>/dev/null || echo 'subfinder not found'" \
        "$OUTPUT_DIR/03_subdomains-subfinder.txt"
else
    log_error "subfinder not installed (install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
fi

if command -v amass &> /dev/null; then
    run_command \
        "Amass: subdomain enumeration" \
        "amass enum -d $TARGET -passive 2>/dev/null || echo 'amass not found'" \
        "$OUTPUT_DIR/04_subdomains-amass.txt"
else
    log_error "amass not installed (install with: go install -v github.com/OWASP/Amass/v3/...@master)"
fi

# DNS records
run_command \
    "DNS enumeration: A, AAAA, MX, NS, TXT records" \
    "dig $TARGET ANY +short 2>/dev/null" \
    "$OUTPUT_DIR/05_dns-any.txt"

run_command \
    "DNS: Nameservers" \
    "dig $TARGET NS +short 2>/dev/null" \
    "$OUTPUT_DIR/06_dns-ns.txt"

run_command \
    "DNS: MX records" \
    "dig $TARGET MX +short 2>/dev/null" \
    "$OUTPUT_DIR/07_dns-mx.txt"

# Reverse DNS
run_command \
    "Reverse DNS lookup (whois)" \
    "whois $TARGET 2>/dev/null | head -50" \
    "$OUTPUT_DIR/08_whois.txt"

echo ""

################################################################################
# 2. WEB SERVER FINGERPRINTING (WSTG-INFO-02)
################################################################################

log_section "PHASE 2: Web Server Fingerprinting (WSTG-INFO-02)"

# Check HTTP (port 80)
run_command \
    "HTTP Banner (port 80)" \
    "curl -I http://$TARGET 2>/dev/null | head -20" \
    "$OUTPUT_DIR/09_http-banner.txt"

# Check HTTPS (port 443)
run_command \
    "HTTPS Banner (port 443)" \
    "curl -I https://$TARGET 2>/dev/null | head -20" \
    "$OUTPUT_DIR/10_https-banner.txt"

# Full header enumeration HTTPS
run_command \
    "Full HTTPS headers" \
    "curl -v https://$TARGET 2>&1 | grep -i '^<\\|^>\\|^\\*' | head -40" \
    "$OUTPUT_DIR/11_https-headers-full.txt"

# SSL/TLS certificate info
run_command \
    "SSL/TLS Certificate Information" \
    "echo | openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -E 'Subject:|Issuer:|Not Before|Not After|Public-Key'" \
    "$OUTPUT_DIR/12_ssl-cert-info.txt"

# Certificate dates
run_command \
    "Certificate Expiration" \
    "echo | openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null" \
    "$OUTPUT_DIR/13_ssl-cert-expiration.txt"

# WAF detection
if command -v wafw00f &> /dev/null; then
    run_command \
        "WAF detection" \
        "wafw00f https://$TARGET 2>/dev/null || echo 'wafw00f not found'" \
        "$OUTPUT_DIR/14_waf-detection.txt"
else
    log_error "wafw00f not installed (install with: pip install wafw00f)"
fi

# Technology stack (if curl + jq available)
run_command \
    "Technology stack detection (via HTML meta tags)" \
    "curl -s https://$TARGET 2>/dev/null | grep -iE 'x-powered-by|generator|framework|platform' | head -20" \
    "$OUTPUT_DIR/15_tech-stack.txt"

# Nmap service version detection
if command -v nmap &> /dev/null; then
    run_command \
        "Nmap service version detection" \
        "nmap -sV -p 80,443 $TARGET 2>/dev/null || echo 'nmap execution' > /dev/null" \
        "$OUTPUT_DIR/16_nmap-service-version.txt"
else
    log_error "nmap not installed"
fi

# HTTP methods
run_command \
    "HTTP Methods allowed (OPTIONS)" \
    "curl -X OPTIONS -v https://$TARGET 2>&1 | grep -E 'Allow:|^<|^>'" \
    "$OUTPUT_DIR/17_http-methods.txt"

echo ""

################################################################################
# 3. METAFILES & CONFIGURATION REVIEW (WSTG-INFO-03)
################################################################################

log_section "PHASE 3: Metafiles & Configuration Review (WSTG-INFO-03)"

# robots.txt
run_command \
    "robots.txt enumeration" \
    "curl -s https://$TARGET/robots.txt" \
    "$OUTPUT_DIR/18_robots.txt"

# sitemap.xml
run_command \
    "sitemap.xml enumeration" \
    "curl -s https://$TARGET/sitemap.xml" \
    "$OUTPUT_DIR/19_sitemap.xml"

# .well-known directory
run_command \
    ".well-known/security.txt" \
    "curl -s https://$TARGET/.well-known/security.txt" \
    "$OUTPUT_DIR/20_security.txt"

# .git directory
run_command \
    "Check for .git directory" \
    "curl -s -o /dev/null -w 'HTTP %{http_code}' https://$TARGET/.git/config && curl -s https://$TARGET/.git/config | head -20" \
    "$OUTPUT_DIR/21_git-config.txt"

# .svn directory
run_command \
    "Check for .svn directory" \
    "curl -s https://$TARGET/.svn/entries | head -10" \
    "$OUTPUT_DIR/22_svn-entries.txt"

# .env file
run_command \
    "Check for .env file" \
    "curl -s https://$TARGET/.env | head -20" \
    "$OUTPUT_DIR/23_env-file.txt"

# Backup files
run_command \
    "Check for backup files" \
    "for ext in .bak .backup .old .orig .tmp; do echo \"Testing *.php\$ext\" && curl -s -o /dev/null -w \"index.php\$ext: %{http_code}\n\" https://$TARGET/index.php\$ext; done" \
    "$OUTPUT_DIR/24_backup-files.txt"

# web.config (ASP.NET)
run_command \
    "Check for web.config" \
    "curl -s https://$TARGET/web.config | head -20" \
    "$OUTPUT_DIR/25_web-config.txt"

# Source maps
run_command \
    "Check for source maps (.js.map)" \
    "curl -s https://$TARGET/app.js.map | head -10" \
    "$OUTPUT_DIR/26_source-map.txt"

echo ""

################################################################################
# 4. DIRECTORY & FILE ENUMERATION (WSTG-INFO-04 to 06)
################################################################################

log_section "PHASE 4: Directory & File Enumeration (WSTG-INFO-04 to 06)"

# Check for common admin paths
log_info "Checking common admin paths..."
ADMIN_PATHS=(
    "/admin"
    "/administrator"
    "/admin.php"
    "/wp-admin"
    "/administrator"
    "/api/admin"
    "/dashboard"
    "/login"
    "/api/login"
    "/api/auth"
    "/api"
    "/api/v1"
    "/api/v2"
    "/api/users"
)

> "$OUTPUT_DIR/27_admin-paths.txt"
for path in "${ADMIN_PATHS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" https://$TARGET$path 2>/dev/null)
    if [ "$status" != "000" ]; then
        echo "[$status] https://$TARGET$path" >> "$OUTPUT_DIR/27_admin-paths.txt"
    fi
done
log_success "✓ Checked common admin paths"
echo ""

# Directory enumeration with ffuf (if installed)
if command -v ffuf &> /dev/null; then
    log_info "Directory enumeration with ffuf (top 50 paths)"
    ffuf -u https://$TARGET/FUZZ -w <(echo -e "admin\napi\nconfig\nupload\ndownload\ndata\nindex\nlogin\nlogout\nadmin\ndashboard\nprofile\nsettings\nusers\nproducts\nservices\ncms\napp\ntest\ndebug") -mc 200,301,302 -silent >> "$OUTPUT_DIR/28_ffuf-directories.txt" 2>/dev/null || true
    log_success "✓ Directory enumeration completed"
else
    log_error "ffuf not installed (install with: go install github.com/ffuf/ffuf@latest)"
fi
echo ""

################################################################################
# 5. SUMMARY REPORT
################################################################################

log_section "RECONNAISSANCE SUMMARY"

echo "" | tee "$OUTPUT_DIR/99_summary.txt"
echo "Target: $TARGET" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "Scan Date: $(date)" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "Output Directory: $OUTPUT_DIR" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "" | tee -a "$OUTPUT_DIR/99_summary.txt"

echo "Files Generated:" | tee -a "$OUTPUT_DIR/99_summary.txt"
ls -lh "$OUTPUT_DIR" | awk '{if (NR>1) print "  " $9 " (" $5 ")"}' | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "" | tee -a "$OUTPUT_DIR/99_summary.txt"

echo "Next Steps:" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "  1. Review all enumeration files for sensitive data" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "  2. Verify subdomains and resolve IP addresses" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "  3. Check admin paths and test default credentials" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "  4. Review security headers for missing protections" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "  5. Proceed to configuration & deployment testing (WSTG-CONFIG)" | tee -a "$OUTPUT_DIR/99_summary.txt"
echo "" | tee -a "$OUTPUT_DIR/99_summary.txt"

echo -e "${GREEN}[✓] Reconnaissance phase complete${NC}"
echo -e "${GREEN}[✓] Results saved to: $OUTPUT_DIR${NC}"
