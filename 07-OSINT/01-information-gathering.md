# 1. Information Gathering - WSTG-INFO Tests

## WSTG-INFO-02 | Fingerprint Web Server

**Description:** Identify the web server type, version, and runtime environment to discover known vulnerabilities.

**Example Commands:**
```bash
curl -I https://target.com
nmap -sV -p 80,443 target.com
nikto -h https://target.com
```

**Expected Output (Vulnerable):**
```
Server: Apache/2.4.1
X-Powered-By: PHP/5.3.8
```

---

## WSTG-INFO-03 | Review Webserver Metafiles for Information Leakage

**Description:** Check for exposed metafiles (robots.txt, sitemap.xml, .well-known files).

**Example Commands:**
```bash
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
curl https://target.com/.well-known/security.txt
ffuf -u https://target.com/FUZZ -w metafiles.txt
```

---

## WSTG-INFO-05 | Review Webpage Content for Information Leakage

**Description:** Analyze HTML comments, JavaScript files, and page source for secrets, API keys, credentials.

**Example Commands:**
```bash
curl -s https://target.com | grep -i "api\|key\|secret\|password\|token"
curl -s https://target.com/app.js | grep -i "api\|endpoint\|token"
```

---

## WSTG-INFO-06 | Identify Application Entry Points

**Description:** Map all input vectors (forms, API endpoints, headers, URL parameters).

**Example Commands:**
```bash
curl -s https://target.com | grep -oE 'action="[^"]*"|href="[^"]*"' | sort -u
curl -s https://target.com/swagger.json
curl -s https://target.com/api/v1
```

---

## WSTG-INFO-07 | Map Execution Paths Through Application

**Description:** Document the flow of legitimate user requests through the application.

**Example Commands:**
```bash
curl -v -c cookies.txt https://target.com/login
curl -L https://target.com/page
curl -b cookies.txt https://target.com/dashboard
```

---

## WSTG-INFO-08 | Fingerprint Web Application Framework

**Description:** Identify the framework (Rails, Django, Spring, etc.) by analyzing headers and error messages.

**Example Commands:**
```bash
curl -I https://target.com
curl https://target.com/web.config
curl https://target.com/composer.json
curl -s https://target.com | grep -i "powered by\|x-framework\|set-cookie"
```

---

**Resource Links:**
- WSTG-INFO-02: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server
- WSTG-INFO-03: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage
- WSTG-INFO-05: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage
- WSTG-INFO-06: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points
- WSTG-INFO-07: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application
- WSTG-INFO-08: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
