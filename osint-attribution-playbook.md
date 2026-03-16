# OSINT Attribution Playbook
**Goal: Attribute Website to Real-World Actor** | Last Updated: 2026-03-08

---

## Overview

This playbook provides a systematic methodology for gathering Open Source Intelligence (OSINT) to attribute a website to a real-world actor (individual, organization, threat group, etc.).

**Key Objectives:**
1. Identify the registrant and operators
2. Map infrastructure and hosting patterns
3. Identify team members and affiliates
4. Discover historical operations and aliases
5. Establish behavioral patterns and signatures
6. Link to known threat actors or organizations
7. Document findings with attribution confidence

**Attribution Phases:**
1. Domain & Registrant Analysis
2. Network Infrastructure Investigation
3. Web Application Fingerprinting
4. Personnel & Team Identification
5. Content & Behavior Analysis
6. Historical & Temporal Analysis
7. Technical Pattern Matching
8. Correlation & Link Analysis
9. Attribution Confidence Assessment
10. Documentation & Reporting

---

## Phase 1: Domain & Registrant Analysis

### 1.1 Domain Registration Details (WHOIS/RDAP)
**Objective:** Extract registrant information from domain registration

**Tools:**
- `whois` command
- WHOIS lookup sites (whois.com, whois.net, domaintools.com)
- RDAP (Registrant Data Access Protocol)
- Domain registrar websites directly

**Checklist:**
- [ ] Query WHOIS for registrant name
- [ ] Extract registrant email address
- [ ] Note registrant organization
- [ ] Document registrant phone number
- [ ] Record registrant street address
- [ ] Check registrant city, state, country
- [ ] Note registration date
- [ ] Check expiration date
- [ ] Identify registrar used
- [ ] Check WHOIS privacy/proxy service (if used)
- [ ] Review name server information
- [ ] Check if WHOIS is redacted or exposed

**Commands:**
```bash
whois target.com

# RDAP query
whois -h whois.nic.net target.com

# Query specific registrar
whois -h whois.godaddy.com target.com

# Check WHOIS history
# Use DomainTools, ICANN WHOIS archive

# Multiple domain WHOIS
for domain in $(cat domains.txt); do whois $domain; done
```

**Analysis:**
```
Registrant: John Doe
Email: john.doe@email.com
Organization: ACME Corp
Address: 123 Main St, Austin, TX 78701
Phone: +1.512.555.1234
Registered: 2024-01-15
Expires: 2025-01-15
Registrar: GoDaddy
```

### 1.2 WHOIS History & Changes
**Objective:** Track domain registration changes over time

**Tools:**
- ICANN WHOIS Archive
- DomainTools WHOIS History
- Wayback Machine (archive.org)
- RoboTXT

**Checklist:**
- [ ] Retrieve WHOIS snapshots over time
- [ ] Note registrant name changes
- [ ] Track email address changes
- [ ] Monitor name server changes
- [ ] Document address changes
- [ ] Identify registrar migrations
- [ ] Note privacy/proxy service adoption
- [ ] Track registrant organization changes
- [ ] Identify patterns in changes (daily, weekly, coordinated)

**Testing:**
```bash
# Check WHOIS history on DomainTools
# Search for target.com on archive.org
# Review each snapshot for registrant changes

# Identify all registrants across time
# Compile list of all emails used
# Compile list of all addresses used
# Compile list of all names used
```

### 1.3 Associated Domains (Registrant Clustering)
**Objective:** Find other domains owned by the same registrant

**Tools:**
- DomainTools (registrant reverse lookup)
- SecurityTrails
- Shodan
- Censys
- ViewDNS
- DNS dumpster

**Checklist:**
- [ ] Search registrant name for other domains
- [ ] Search registrant email for other domains
- [ ] Search registrant phone for other domains
- [ ] Search registrant address for other domains
- [ ] Identify domain name patterns
- [ ] Note domain registration dates (correlation)
- [ ] Check for domain parking/bulk registrations
- [ ] Identify legitimate vs malicious domains

**Commands:**
```bash
# Reverse registrant lookup on DomainTools
# Search: john.doe@email.com

# DNS enumeration
nslookup -type=ANY target.com
dig +nocmd target.com any +multiline

# Find subdomains
assetfinder target.com
sublist3r -d target.com

# Reverse lookup
dig +short target.com

# Check all A records
host target.com
```

### 1.4 Email Analysis (Registrant Email)
**Objective:** Investigate the registrant's email address

**Checklist:**
- [ ] Email format (personal vs business)
- [ ] Email provider (Gmail, Yahoo, corporate, privacy service)
- [ ] Username patterns
- [ ] Registration date of email account
- [ ] Email reuse across domains
- [ ] Email reputation (spam databases, breach records)
- [ ] HaveIBeenPwned database search
- [ ] Leaked credential databases search

**Commands:**
```bash
# Check if email in breaches
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/john.doe@email.com"

# Search for email in leaks
grep -r "john.doe@email.com" leaks/

# Reverse email search
# Use Google, DomainTools, SecurityTrails
site:github.com john.doe@email.com
```

### 1.5 Physical Address Analysis
**Objective:** Investigate registrant's physical address

**Checklist:**
- [ ] Verify address validity (Google Maps, street view)
- [ ] Check if residential vs commercial
- [ ] Identify businesses at that address
- [ ] Check business registrations in that location
- [ ] Identify other companies in building
- [ ] Check property ownership records
- [ ] Identify neighbors/adjacent businesses
- [ ] Street view for signage/clues

**Tools:**
- Google Maps/Street View
- Business registration databases
- Property records (county assessor)
- Business Improvement Bureaus
- LinkedIn company searches

---

## Phase 2: Network Infrastructure Investigation

### 2.1 IP Address Analysis
**Objective:** Identify hosting provider and IP history

**Tools:**
- whois (IP lookups)
- MaxMind GeoIP
- Shodan
- Censys
- Censys Mass Scan
- Team Cymru Whois
- ViewDNS

**Checklist:**
- [ ] Query IP WHOIS (hosting provider)
- [ ] Identify Autonomous System (ASN)
- [ ] Get geolocation (country, city, coordinates)
- [ ] Identify datacenter location
- [ ] Check IP reputation (spam, malware)
- [ ] Review reverse DNS
- [ ] Check IP historical records
- [ ] Identify shared hosting indicators
- [ ] Note IP registration organization

**Commands:**
```bash
# IP WHOIS lookup
whois 93.184.216.34

# ASN information
whois -h whois.cymru.com " -v 93.184.216.34"

# MaxMind GeoIP
geoiplookup 93.184.216.34

# Shodan IP search
shodan host 93.184.216.34

# Censys IP information
censys ipv4 93.184.216.34

# Reverse DNS
host 93.184.216.34
nslookup 93.184.216.34

# IP reputation
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=93.184.216.34"
```

### 2.2 DNS Analysis
**Objective:** Investigate DNS records and configuration

**Checklist:**
- [ ] A record (IPv4 address)
- [ ] AAAA record (IPv6 address)
- [ ] MX records (email servers)
- [ ] NS records (name servers)
- [ ] TXT records (SPF, DKIM, DMARC, verification)
- [ ] CNAME records (canonical names)
- [ ] SOA record (start of authority)
- [ ] SRV records (service records)
- [ ] DNS provider/operator
- [ ] DNS history (changes over time)

**Commands:**
```bash
# Full DNS record dump
dig target.com +nocmd any +multiline

# Specific record types
dig target.com A
dig target.com AAAA
dig target.com MX
dig target.com NS
dig target.com TXT

# Zone transfer attempt
dig @ns1.target.com target.com axfr

# DNS history
# Use SecurityTrails, ViewDNS, or DomainTools
```

### 2.3 Name Server Analysis
**Objective:** Investigate name servers hosting domain

**Checklist:**
- [ ] Name server hostnames
- [ ] Name server IP addresses
- [ ] Name server provider
- [ ] Other domains on same name servers
- [ ] Name server software (if detectable)
- [ ] Name server configuration patterns
- [ ] DNS provider reputation
- [ ] Name server change history

**Commands:**
```bash
# Get name servers
nslookup -type=NS target.com

# Reverse lookup (find domains on same NS)
# Use Shodan, Censys, SecurityTrails
shodan search "ns: ns1.example.com"

# Query name server directly
dig @ns1.target.com target.com

# NS records history
# Check SecurityTrails for NS history
```

### 2.4 Hosting Provider Investigation
**Objective:** Identify and research the hosting provider

**Checklist:**
- [ ] Hosting provider name
- [ ] Hosting provider reputation
- [ ] Hosting provider abuse policies
- [ ] Other domains on same hosting
- [ ] Hosting provider technical support
- [ ] Known abuse by hosting provider
- [ ] Datacenter location
- [ ] Hosting provider history/ownership

**Commands:**
```bash
# Identify hosting provider from IP
whois <ip_address>

# Find other sites on same host
# Using Shodan
shodan search "ip: 93.184.216.34"

# Using Censys
censys ipv4 93.184.216.34

# Check for shared hosting
curl -v https://<ip_address> -H "Host: target.com"
```

### 2.5 SSL/TLS Certificate Analysis
**Objective:** Investigate SSL certificates for attribution clues

**Tools:**
- crt.sh (Certificate Transparency)
- Censys (certificate search)
- SSL Labs
- OpenSSL

**Checklist:**
- [ ] Certificate issuer
- [ ] Certificate Common Name (CN)
- [ ] Certificate Subject Alternative Names (SAN)
- [ ] Certificate validity dates
- [ ] Certificate organization
- [ ] Certificate organizational unit
- [ ] Certificate locality/country
- [ ] Certificate serial number
- [ ] Certificate key size and algorithm
- [ ] Certificate fingerprint
- [ ] Certificate transparency logs
- [ ] Other domains with similar certificates
- [ ] Certificate reuse patterns

**Commands:**
```bash
# Get certificate from website
openssl s_client -connect target.com:443 -servername target.com

# Extract certificate details
openssl x509 -in cert.pem -text -noout

# Certificate Transparency search (crt.sh)
curl "https://crt.sh/?q=target.com&output=json"

# Search Censys for similar certificates
censys certificates query --query "parsed.names: example.com"

# SHA256 fingerprint
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### 2.6 ASN & Routing Analysis
**Objective:** Investigate Autonomous System Network

**Checklist:**
- [ ] ASN number
- [ ] ASN organization
- [ ] ASN country
- [ ] BGP announcements
- [ ] IP prefix size
- [ ] Other ASN prefixes (for actor infrastructure)
- [ ] ASN history (previous owners)
- [ ] Routing patterns

**Commands:**
```bash
# Get ASN from IP
whois -h whois.cymru.com " -v <ip_address>"

# ASN details from RIPE NCC
whois -h whois.ripe.net AS<asn>

# BGP announcements
bgpstream

# Check other IPs in ASN
shodan search "asn: AS<asn>"
```

---

## Phase 3: Web Application Fingerprinting

### 3.1 Technology Stack Identification
**Objective:** Identify software, frameworks, and technologies used

**Tools:**
- Wappalyzer
- BuiltWith
- Shodan
- Censys
- HTTP response headers analysis
- Manual source code review

**Checklist:**
- [ ] Web server (Apache, Nginx, IIS, etc.)
- [ ] Server version
- [ ] Backend language (PHP, Python, Java, Node, etc.)
- [ ] Web framework (Django, Rails, Laravel, etc.)
- [ ] CMS (WordPress, Drupal, Joomla, etc.)
- [ ] JavaScript frameworks (React, Vue, Angular, etc.)
- [ ] JavaScript library versions
- [ ] Analytics platform (Google Analytics ID, Matomo, etc.)
- [ ] CDN provider
- [ ] Database software (visible in errors)
- [ ] Third-party services (Stripe, PayPal, etc.)
- [ ] Custom applications
- [ ] API endpoints and versions

**Commands:**
```bash
# HTTP headers
curl -I https://target.com

# Full response analysis
curl -v https://target.com

# Wappalyzer CLI
wappalyzer https://target.com

# BuiltWith API (requires key)
curl "https://api.builtwith.com/v17/api.json?KEY=<key>&LOOKUP=target.com"

# Check for WordPress
curl https://target.com/wp-admin

# Check for Drupal
curl https://target.com/sites/all/themes/

# Shodan search
shodan search "http.title: target.com"
```

### 3.2 Source Code Analysis
**Objective:** Analyze HTML, JavaScript, and source code for attribution clues

**Checklist:**
- [ ] HTML comments (developer names, internal notes)
- [ ] JavaScript comments
- [ ] Unminified JavaScript analysis
- [ ] Source maps (.js.map files)
- [ ] API endpoints in JavaScript
- [ ] Configuration hardcoded in code
- [ ] Developer tools/analytics IDs
- [ ] Author metadata
- [ ] Email addresses in code
- [ ] Internal IP addresses in code
- [ ] Usernames in code
- [ ] CSS class names (developer patterns)
- [ ] Git references (intentional or leaked)
- [ ] Build tool signatures

**Commands:**
```bash
# Download and analyze source
curl https://target.com -o index.html
cat index.html | grep -i "developer\|email\|name\|author"

# Extract JavaScript files
curl https://target.com | grep -o 'src="[^"]*\.js"'

# Analyze unminified JS
cat app.js | grep -E "//.*:|console.log|var.*="

# Search for email/author info
cat *.js *.html | grep -E "([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)"

# Check for source maps
curl https://target.com/app.js.map

# Git repository exposure
curl https://target.com/.git/config
```

### 3.3 Google Analytics & Tracking IDs
**Objective:** Use tracking IDs to find associated properties

**Tools:**
- BuiltWith (tracking ID search)
- Google Analytics IDs
- Hotjar IDs
- Segment IDs
- etc.

**Checklist:**
- [ ] Google Analytics ID (UA-XXXXX)
- [ ] Google Analytics 4 ID (G-XXXXX)
- [ ] Google Site Verification
- [ ] Hotjar ID
- [ ] Segment ID
- [ ] Mixpanel ID
- [ ] Heap Analytics ID
- [ ] Other tracking codes

**Commands:**
```bash
# Extract Google Analytics ID from source
curl https://target.com | grep -o "UA-[0-9]*"
curl https://target.com | grep -o "G-[A-Z0-9]*"

# Search for tracking ID usage
# Use BuiltWith's tracking ID search
# Input: UA-XXXXX
# Returns: Other sites using same ID

# Manual search on internet
site:google.com "UA-XXXXX"
```

**Analysis:**
If same Google Analytics ID appears on multiple domains, those domains likely belong to same actor.

### 3.4 CMS-Specific Fingerprinting
**Objective:** Identify CMS and customizations

**For WordPress:**
```bash
# Check wp-content, wp-includes
curl https://target.com/wp-content/
curl https://target.com/wp-includes/

# Check version
curl https://target.com/ | grep "wp-content/themes\|wp-includes"

# Enumerate plugins
curl https://target.com/wp-content/plugins/

# WordPress user enumeration
curl https://target.com/?author=1

# Check wp-json for users (if exposed)
curl https://target.com/wp-json/wp/v2/users
```

**For Drupal:**
```bash
# Check for Drupal signatures
curl https://target.com/sites/all/themes/
curl https://target.com/sites/all/modules/

# Drupal version from CHANGELOG
curl https://target.com/CHANGELOG.txt

# Enumerate modules
for mod in admin ctools views rules; do
  curl -s "https://target.com/sites/all/modules/$mod" | head -1
done
```

**For Joomla:**
```bash
# Check for Joomla structure
curl https://target.com/components/
curl https://target.com/modules/

# Version from XML
curl https://target.com/administrator/manifests/files/joomla.xml
```

### 3.5 API Endpoint Discovery
**Objective:** Identify and map API endpoints

**Checklist:**
- [ ] /api/ endpoints
- [ ] /v1/, /v2/ versioned endpoints
- [ ] /rest/ endpoints
- [ ] /graphql endpoints
- [ ] /swagger, /openapi endpoints
- [ ] API documentation
- [ ] API keys in responses
- [ ] API usage patterns

**Commands:**
```bash
# Common API paths
curl https://target.com/api/
curl https://target.com/api/v1/
curl https://target.com/api/users
curl https://target.com/graphql

# API documentation
curl https://target.com/docs/api
curl https://target.com/swagger.json
curl https://target.com/openapi.json

# Wayback Machine API search
curl "https://archive.org/wayback/available?url=target.com/api/*"

# Parameter discovery
arjun -u https://target.com
paramspider -d target.com
```

---

## Phase 4: Personnel & Team Identification

### 4.1 Email Address Analysis
**Objective:** Find and analyze all email addresses associated with actor

**Checklist:**
- [ ] Registrant email
- [ ] Administrative contact email
- [ ] Technical contact email
- [ ] Support email (from website)
- [ ] Email from whois/rdap
- [ ] Email from SSL certificates
- [ ] Email from source code comments
- [ ] Email from error messages
- [ ] Email from metadata
- [ ] Email from social media profiles

**Commands:**
```bash
# Extract emails from domain
curl https://target.com | grep -o '[a-zA-Z0-9._-]*@target.com'

# Search for emails on Google
site:target.com email
site:target.com contact

# Email harvesting
theHarvester -d target.com -b google,linkedin,twitter

# Extract from source
curl https://target.com -s | grep -o '[a-zA-Z0-9._-]*@[a-zA-Z0-9._-]*'

# Check certificates for email
curl https://target.com | grep -o '[a-zA-Z0-9._-]*@[a-zA-Z0-9._-]*'
```

### 4.2 Social Media & Profile Analysis
**Objective:** Find social media accounts belonging to registrant/team

**Tools:**
- Google Search
- LinkedIn
- Twitter/X
- GitHub
- GitLab
- Facebook
- Instagram
- YouTube
- Reddit
- Stack Overflow
- Medium

**Checklist:**
- [ ] Google search: registrant name
- [ ] Google search: email address
- [ ] LinkedIn profile (by name, email)
- [ ] Twitter/X account
- [ ] GitHub profile and repositories
- [ ] GitLab profile
- [ ] Facebook profile
- [ ] Instagram account
- [ ] YouTube channel
- [ ] Reddit user
- [ ] Stack Overflow profile
- [ ] Medium articles
- [ ] Patreon/Ko-fi accounts
- [ ] Personal websites
- [ ] Blog posts

**Commands:**
```bash
# Google search
"John Doe" email
"John Doe" linkedin
"john.doe@example.com"

# GitHub search
site:github.com "John Doe"
site:github.com john.doe@example.com

# Check for associated usernames
# john.doe, johndoe, jdoe, john_doe

# LinkedIn advanced search
site:linkedin.com "John Doe"

# GitHub projects
curl "https://api.github.com/users/johndoe/repos"

# GitLab projects
curl "https://gitlab.com/api/v4/users/johndoe"
```

### 4.3 GitHub Repository Analysis
**Objective:** Analyze repositories for attribution and infrastructure clues

**Checklist:**
- [ ] Repository ownership
- [ ] Repository commit history
- [ ] Commit author names/emails
- [ ] Repository description and README
- [ ] Code patterns and style
- [ ] Dependencies used
- [ ] Configuration files
- [ ] Sensitive data in repo (accidentally committed)
- [ ] Repository fork history
- [ ] Repository stars/forks by other known actors
- [ ] Issue/PR discussion patterns
- [ ] Code review patterns

**Commands:**
```bash
# List all repositories by user
curl "https://api.github.com/users/johndoe/repos?per_page=100"

# Get specific repo info
curl "https://api.github.com/repos/johndoe/target-project"

# Get commit history
curl "https://api.github.com/repos/johndoe/target-project/commits"

# Clone repo and analyze
git clone https://github.com/johndoe/target-project
cd target-project

# View commit authors
git log --oneline --all | head -20

# Check .git/config
cat .git/config

# Find hardcoded credentials in history
git log -S "password" -p
git log -S "api_key" -p

# Search for email addresses in code
git log --all -S "example@email.com"
```

### 4.4 Team Member Identification
**Objective:** Identify other team members and collaborators

**Checklist:**
- [ ] Co-authors on GitHub
- [ ] Server administrators (from server banners)
- [ ] Email address patterns (lastname@domain)
- [ ] LinkedIn employee connections
- [ ] GitHub collaborators
- [ ] Forum/Reddit co-posters
- [ ] Stack Overflow collaborators
- [ ] Blog co-authors
- [ ] Project contributors

**Commands:**
```bash
# GitHub API for collaborators
curl "https://api.github.com/repos/johndoe/project/contributors"

# Find other members
# Check org repos
curl "https://api.github.com/orgs/acmecorp/members"

# LinkedIn org employees
site:linkedin.com "ACME Corp"
```

---

## Phase 5: Content & Behavior Analysis

### 5.1 Writing Style & Linguistic Analysis
**Objective:** Identify actor through unique writing patterns

**Checklist:**
- [ ] Common phrases or expressions
- [ ] Spelling/grammar patterns
- [ ] Language preference (English, etc.)
- [ ] Punctuation habits
- [ ] Abbreviations commonly used
- [ ] Technical vocabulary
- [ ] Cultural references
- [ ] Slang or colloquialisms
- [ ] Response timing patterns
- [ ] Known aliases or personas

**Analysis:**
- Collect all available writing samples (commits, posts, emails, website content)
- Analyze for unique patterns
- Compare against known threat actors
- Look for distinctive phrases or typos

### 5.2 Website Content Analysis
**Objective:** Analyze website for operational security and attribution clues

**Checklist:**
- [ ] Website purpose and service offered
- [ ] Product/service descriptions
- [ ] Pricing and business model
- [ ] Customer testimonials
- [ ] Team/about page
- [ ] Contact information
- [ ] Terms of service
- [ ] Privacy policy
- [ ] Domains mentioned in content
- [ ] Services advertised
- [ ] Timing of content updates
- [ ] Content in multiple languages
- [ ] References to current events
- [ ] Geolocation clues in content

**Commands:**
```bash
# Get website content
curl https://target.com -o site.html

# Extract all text
lynx -dump https://target.com > site.txt

# Search for specific phrases
cat site.txt | grep -i "bitcoin\|monero\|payment\|ship\|deliver"

# Check language
# Use browser DevTools to check Content-Language header
```

### 5.3 Operational Security (OPSEC) Indicators
**Objective:** Identify OPSEC failures revealing actor location/identity

**Checklist:**
- [ ] Timezone indicators (timestamps, posting times)
- [ ] Language clues (UI language, content language)
- [ ] Location references (place names, local services)
- [ ] Currency preferences
- [ ] Payment method preferences
- [ ] Accidental personal info disclosure
- [ ] Server misconfiguration revealing info
- [ ] Metadata in images/documents
- [ ] Geolocation data in photos
- [ ] Misconfigured CDN/proxy
- [ ] DNS leaks
- [ ] Hosting provider choice (regional)
- [ ] Vacation/absence patterns
- [ ] Work hours pattern

### 5.4 Service/Product Fingerprinting
**Objective:** Identify service offered to attribute to known groups

**Checklist:**
- [ ] Type of service (phishing, malware, ransomware, botnet, etc.)
- [ ] Pricing model
- [ ] Payment methods accepted
- [ ] Service reputation
- [ ] Known users/customers of service
- [ ] Competing services (to compare)
- [ ] Service uniqueness
- [ ] Known attribution of service
- [ ] Operational history

**Example Analysis:**
```
Service: Custom Botnet C&C Panel
Price: $500/month
Payment: Bitcoin, Monero
Features: 1000+ bots, DDoS, worm propagation
Known use by: APT-XX (from threat reports)
→ Likely operated by same group or allied actor
```

---

## Phase 6: Historical & Temporal Analysis

### 6.1 Wayback Machine & Internet Archive
**Objective:** Review website history and changes over time

**Tools:**
- archive.org (Wayback Machine)
- Archive-It
- Common Crawl

**Checklist:**
- [ ] First snapshot date
- [ ] Major content changes
- [ ] Design/style changes
- [ ] Historical team information
- [ ] Historical contact information
- [ ] Version history of services
- [ ] Historical pricing
- [ ] When site went offline (if applicable)
- [ ] Content evolution over time

**Commands:**
```bash
# Query Wayback Machine API
curl "https://archive.org/wayback/available?url=target.com&output=json"

# Get all snapshots
curl "https://web.archive.org/web/*/target.com" -s | grep -o 'href="/web/[0-9]*' | cut -d/ -f4

# View specific snapshots
# https://web.archive.org/web/20200101000000*/target.com

# Python script to analyze changes
python3 << 'EOF'
import requests
import json

url = "https://archive.org/wayback/available?url=target.com&output=json"
resp = requests.get(url).json()
snapshots = resp['archived_snapshots']['snapshot']

for snapshot in snapshots[-10:]:  # Last 10
    ts = snapshot['timestamp']
    print(f"Snapshot: {ts[:4]}-{ts[4:6]}-{ts[6:8]}")
EOF
```

### 6.2 DNS History
**Objective:** Track DNS changes and registrant transitions

**Tools:**
- SecurityTrails
- ViewDNS
- DomainTools DNS History
- Passive DNS databases (Farsight Security)

**Checklist:**
- [ ] Historical A records (IP changes)
- [ ] Historical NS records (name server changes)
- [ ] Historical MX records
- [ ] Historical registrant changes
- [ ] Domain age
- [ ] IP address historical ownership
- [ ] Name server provider changes
- [ ] Correlation of changes with events

### 6.3 Threat Intelligence Integration
**Objective:** Cross-reference with known threat intelligence

**Sources:**
- MITRE ATT&CK framework
- Shodan (historical data)
- Censys (certificate history)
- Recorded Future
- CrowdStrike Intel
- Mandiant reports
- APT reports
- Malware analysis reports (hybrid-analysis.com, virustotal.com)

**Checklist:**
- [ ] Search threat intel databases for domain
- [ ] Search threat intel for IP address
- [ ] Search threat intel for registrant email
- [ ] Search threat intel for hosting provider
- [ ] Check malware analysis databases
- [ ] Review APT reports for IOCs match
- [ ] Check ransomware databases
- [ ] Search darknet forums for references
- [ ] Check leaked data for domain/actor

---

## Phase 7: Technical Pattern Matching

### 7.1 Malware Analysis & Code Patterns
**Objective:** Identify malware code if applicable and find patterns

**Tools:**
- VirusTotal
- Hybrid Analysis
- URLhaus
- PhishTank
- Any.run

**Checklist:**
- [ ] Submit site to VirusTotal
- [ ] Check for malware/phishing detection
- [ ] Review detections and analysis
- [ ] Analyze malware samples (if found)
- [ ] Review code patterns in malware
- [ ] Compare against known malware families
- [ ] Identify command & control patterns
- [ ] Check for code reuse with other malware
- [ ] Analyze obfuscation techniques

### 7.2 Server Misconfiguration Patterns
**Objective:** Identify consistent misconfiguration patterns

**Checklist:**
- [ ] Directory listing enabled
- [ ] Unnecessary services running
- [ ] Default pages/files present
- [ ] Error message revealing info
- [ ] Backup files exposed
- [ ] Git repository exposed
- [ ] Configuration files exposed
- [ ] Consistent security headers (or lack thereof)
- [ ] Consistent firewall rules
- [ ] Similar SSL certificate configuration

### 7.3 Infrastructure Reuse Indicators
**Objective:** Identify shared infrastructure across operations

**Checklist:**
- [ ] Same IP address used for multiple domains
- [ ] Same name server used for multiple domains
- [ ] Same hosting provider for multiple domains
- [ ] Same SSL certificate for multiple domains
- [ ] Same registrant email for multiple domains
- [ ] Same registrant address for multiple domains
- [ ] Same payment processor
- [ ] Same analytics ID
- [ ] Same custom code/framework
- [ ] Same software versions

**Commands:**
```bash
# Find other sites on same IP
shodan host <ip_address>

# Find other domains on same NS
shodan search "ns: ns1.example.com"

# Find other sites with same certificate
censys ipv4 certificates.parsed.names: target.com

# Find other domains by registrant
# Use DomainTools, SecurityTrails
```

### 7.4 Timing & Correlation Analysis
**Objective:** Correlate events and timing to identify connections

**Checklist:**
- [ ] Domain registration timing
- [ ] Content update timing
- [ ] Server configuration change timing
- [ ] Staff activity timing (commits, posts)
- [ ] Service changes timing
- [ ] Uptime/downtime patterns
- [ ] Maintenance window patterns
- [ ] Response time patterns
- [ ] Update frequency patterns
- [ ] Correlation with public events
- [ ] Correlation with known threat actor activities

---

## Phase 8: Correlation & Link Analysis

### 8.1 Domain Portfolio Mapping
**Objective:** Map all related domains and infrastructure

**Output:**
```
Actor: Unknown
Associated Domains:
  - target.com (primary)
  - target-mirror.com (2020-present)
  - target-backup.xyz (2019-2020)
  - acme-service.com (affiliate)

Associated IP Addresses:
  - 93.184.216.34 (target.com, 2020-present)
  - 192.0.2.1 (target.com, 2019-2020)
  - 198.51.100.5 (shared hosting, 5 other domains)

Associated Email Addresses:
  - admin@target.com
  - john.doe@gmail.com
  - support@acme-service.com

Associated Hosting Providers:
  - DigitalOcean (3 domains)
  - Vultr (2 domains)
  - Namecheap (registrar)

Team Members:
  - John Doe (GitHub: johndoe, Twitter: @johndoe)
  - Jane Smith (GitHub: janesmith, email: jane@company.com)
```

### 8.2 Threat Actor Linking
**Objective:** Connect to known threat actors

**Process:**
1. Gather all IOCs (Indicators of Compromise)
2. Query threat intelligence databases
3. Review published reports
4. Correlate with known attack patterns
5. Cross-reference with APT groups

**Output:**
```
Attribution Hypothesis: Likely operated by APT-28

Confidence Level: HIGH

Supporting Evidence:
- Similar infrastructure patterns (AS12345)
- Matching code signature (custom C2)
- Similar target profile (US Defense contractors)
- Timing correlation with known APT-28 campaigns
- Language analysis matches known APT-28 communications

Alternative Attribution:
- APT-29 (medium confidence) - similar infrastructure
- Unattributed group using APT-28 tools (low confidence)
```

### 8.3 Graph Database Construction
**Objective:** Build relationship graph for visualization

**Tools:**
- Neo4j
- Gephi
- Shodan Graphs
- Custom scripts

**Nodes:**
- Domain
- IP Address
- Email Address
- Organization
- Person
- ASN
- Certificate

**Relationships:**
- hosted_on (domain → IP)
- registered_by (domain → email)
- contains (email → domain)
- owned_by (domain → organization)
- employee_of (person → organization)
- uses (person → email)
- etc.

---

## Phase 9: Attribution Confidence Assessment

### 9.1 Confidence Scoring
**Objective:** Rate confidence in attribution

**Scoring:**
```
HIGH CONFIDENCE (85-100%):
- Multiple independent evidence sources
- Strong indicator correlation
- Historical precedent
- Corroboration with threat intelligence
- Code/behavior signature matches

MEDIUM CONFIDENCE (50-85%):
- Several evidence sources
- Pattern matching with possible alternatives
- Circumstantial evidence
- Possible misattribution

LOW CONFIDENCE (0-50%):
- Single source or weak sources
- Multiple competing hypotheses
- Significant uncertainty
- Could be false flag/impersonation
```

### 9.2 Evidence Weighting
**Objective:** Rate importance of evidence

**High Weight:**
- Technical indicators (code, infrastructure)
- Threat intelligence corroboration
- Operational patterns
- Unique signatures

**Medium Weight:**
- Social media profiles
- Email addresses
- Linguistic analysis
- Timing patterns

**Low Weight:**
- Circumstantial timing
- Geographic guesses
- Assumption-based connections
- Single data points

### 9.3 Alternative Hypotheses
**Objective:** Document competing explanations

```
Primary Hypothesis: APT-28 (90% confidence)
- Similar infrastructure patterns
- Code signature matches
- Timing correlation

Alternative 1: Copycat group using APT-28 tools (7% confidence)
- Public tools could explain similarities
- Timing doesn't perfectly match

Alternative 2: False flag operation (3% confidence)
- Unlikely but possible
- Would require sophisticated actor
```

---

## Phase 10: Documentation & Reporting

### 10.1 Attribution Report Template
**Objective:** Document findings professionally

**Report Structure:**
```
TITLE: Attribution Analysis of [Target.com]
DATE: 2026-03-08
ANALYST: [Your Name]
CLASSIFICATION: [Public/Internal/Confidential]

EXECUTIVE SUMMARY
- Primary attribution with confidence
- Key supporting evidence
- Implications

METHODOLOGY
- Tools and sources used
- Analysis process
- Limitations

FINDINGS
1. Domain & Registrant
   - Registrant: [Info]
   - Email: [Info]
   - Address: [Info]
   
2. Infrastructure
   - Primary IP: [Info]
   - Hosting Provider: [Info]
   - Name Servers: [Info]
   
3. Technical Fingerprinting
   - Web Server: [Info]
   - CMS/Framework: [Info]
   - Unique signatures: [Info]
   
4. Team Identification
   - Team Members: [Info]
   - Social Media: [Info]
   - Code Analysis: [Info]
   
5. Historical Analysis
   - Domain History: [Timeline]
   - Content Evolution: [Timeline]
   - Service Changes: [Timeline]

ATTRIBUTION
- Primary Attribution: [Actor Name]
- Confidence Level: [80%]
- Supporting Evidence: [Enumerated]
- Alternative Hypotheses: [Listed]

CORRELATION WITH KNOWN ACTORS
- Similar to APT-28 (high)
- Similar to Lazarus (low)
- Similar to FIN7 (medium)

REFERENCES
- [List sources, IOCs, threat reports]

APPENDICES
- IOC List
- Timeline
- Relationship Graph
- Source Code Analysis
- WHOIS Records
```

### 10.2 Indicator of Compromise (IOC) List
**Objective:** Create shareable IOC list

```
DOMAINS:
- target.com
- target-mirror.com
- target-backup.xyz

IP ADDRESSES:
- 93.184.216.34
- 192.0.2.1
- 198.51.100.5

EMAIL ADDRESSES:
- admin@target.com
- john.doe@gmail.com
- support@acme-service.com

NAME SERVERS:
- ns1.target.com (93.184.216.34)
- ns2.target.com (192.0.2.1)

SSL CERTIFICATE FINGERPRINTS:
- SHA256: a1b2c3d4e5f6...

REGISTRANT INFORMATION:
- Name: John Doe
- Email: john.doe@gmail.com
- Phone: +1.512.555.1234
- Address: 123 Main St, Austin, TX 78701

ASSOCIATED ACCOUNTS:
- GitHub: johndoe
- Twitter: @johndoe
- LinkedIn: /in/johndoe

HOSTING PROVIDERS:
- DigitalOcean (AS14061)
- Vultr (AS20473)
```

### 10.3 Timeline Creation
**Objective:** Build chronological timeline of events

```
2020-01-15
- target.com registered
- Registrant: John Doe
- Registrant email: john.doe@gmail.com

2020-02-01
- Site hosted on 93.184.216.34
- DigitalOcean datacenter

2020-06-15
- First blog post published
- Content analysis matches APT-28 TTPs

2020-09-20
- John Doe GitHub account created
- Commits to suspicious repositories

2021-03-10
- Domain moved to 192.0.2.1
- Name servers changed to Vultr

2021-06-01
- Target-mirror.com registered
- Same registrant email

2022-01-15
- Analytics ID links to related domains
- Cross-site tracking identified

2023-05-20
- Domain registered by WHOIS proxy service
- Obfuscation of registrant info

2024-01-08
- Current status: Active
- Hosting: Vultr AS20473
- Registrant: WHOIS Privacy
```

---

## Tools & Resources

### Domain/WHOIS Tools
- whois, nslookup, dig
- DomainTools
- SecurityTrails
- ViewDNS
- ICANN WHOIS
- RoboTXT

### IP & Network Tools
- MaxMind GeoIP
- Shodan
- Censys
- ASN databases (RIPE, ARIN)
- BGPStream
- Team Cymru

### Certificate Tools
- crt.sh
- Censys Certificates
- SSL Labs
- OpenSSL

### Web Fingerprinting
- Wappalyzer
- BuiltWith
- Retire.js

### Email/Person Search
- theHarvester
- Hunter.io
- Clearbit
- LinkedIn
- GitHub

### Archive & Historical
- archive.org (Wayback Machine)
- Common Crawl
- Farsight Passive DNS

### Threat Intelligence
- VirusTotal
- Hybrid Analysis
- URLhaus
- PhishTank
- MITRE ATT&CK
- Recorded Future
- Shodan (threat lists)

### Graph & Visualization
- Neo4j
- Gephi
- Graphviz
- Cytoscape

### Automation & Scripting
- Python (requests, BeautifulSoup, selenium)
- Bash/Zsh
- jq (JSON processing)
- curl

---

## Operational Notes

### OPSEC Considerations
- Use VPN/proxy when querying
- Rotate user agents
- Avoid direct fingerprinting requests
- Use archived data when possible
- Document all queries for audit
- Consider target's monitoring capability

### Legal Considerations
- Ensure authorized research
- Comply with CFAA if US-based
- Respect privacy laws
- Don't access systems without authorization
- Document legal basis for assessment

### Data Handling
- Protect sensitive information
- Secure storage of findings
- Controlled distribution
- Data retention policies
- Sanitize reports for sharing

---

**Last Updated:** 2026-03-08
**Version:** 1.0
