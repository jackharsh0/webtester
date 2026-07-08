# 🔒 WebTester - Website Security Scanner

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/jackharsh0/webtester.svg)](https://github.com/jackharsh0/webtester)
[![Forks](https://img.shields.io/github/forks/jackharsh0/webtester.svg)](https://github.com/jackharsh0/webtester)
[![Issues](https://img.shields.io/github/issues/jackharsh0/webtester.svg)](https://github.com/jackharsh0/webtester)

A powerful **website security scanner** and **penetration testing tool** that downloads websites locally and runs **65+ security checks** including **WordPress vulnerabilities**, **SQL injection testing**, **XSS detection**, and **CSP header generation**.

---

## 🎯 What This Tool Does

| Feature | Description |
|---------|-------------|
| **Website Downloader** | Downloads HTML, CSS, JS, images, PDFs locally |
| **65+ Security Checks** | Comprehensive vulnerability scanning |
| **SQL Injection Scanner** | Safe penetration testing with proof generation |
| **WordPress Scanner** | 15+ WordPress-specific security checks |
| **CSP Generator** | Auto-generate Content-Security-Policy headers |
| **Client Reports** | Professional security reports for clients |

---

## 🔥 Security Features

### Critical Vulnerabilities Detected
- 🔴 Exposed `.env` files with API keys and secrets
- 🔴 Exposed `.git` directories with source code
- 🔴 Database files publicly accessible
- 🔴 Private keys and certificates exposed
- 🔴 Hardcoded passwords in source code

### High-Risk Vulnerabilities
- 🟠 SQL Injection (Error-based, Boolean-based, Time-based)
- 🟠 Cross-Site Scripting (XSS)
- 🟠 Command Injection
- 🟠 File Inclusion (LFI/RFI)
- 🟠 Missing security headers (CSP, HSTS, X-Frame-Options)

### Medium-Risk Vulnerabilities
- 🟡 Server information disclosure
- 🟡 Directory listing enabled
- 🟡 Admin panels accessible
- 🟡 Default credentials
- 🟡 Outdated software versions

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/jackharsh0/webtester.git

# Navigate to project folder
cd webtester

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Website Scan
```bash
python webtester.py https://example.com
```

### SQL Injection Testing
```bash
python webtester.py https://example.com --sqli
```

### CSP Header Generation
```bash
python webtester.py https://example.com --csp
```

### Generate CSP from Existing Scan
```bash
python webtester.py --csp-only data/example_com https://example.com
```

---

## 📊 Sample Output

```
============================================================
WEBTESTER - Website Security Scanner v2.0
============================================================

Target: https://example.com
Time: 2024-01-15 10:30:00

PHASE 1: DOWNLOADING WEBSITE
[✓] Downloaded: index.html (15.2 KB)
[✓] Total: 47 files (12.5 MB)

PHASE 2: SECURITY SCANNING
[1/65] .env files...
[2/65] Git exposure...
[3/65] Security headers...
...

SCAN RESULTS
  CRITICAL: 2
  HIGH: 5
  MEDIUM: 8
  LOW: 12
  Total Issues: 27
```

---

## 🛡️ SQL Injection Scanner

### Safe Testing (No Data Modification)
The SQL injection scanner only **reads data** to prove vulnerabilities exist:
- ✅ Detects SQL injection flaws
- ✅ Collects proof (database version, name, user)
- ✅ Generates client-ready reports
- ❌ Does NOT delete data
- ❌ Does NOT modify data
- ❌ Does NOT execute harmful commands

### Proof Collection
When a vulnerability is found, the scanner safely extracts:
- Database version
- Database name
- Current user
- Number of tables
- Table names

---

## 📁 Project Structure

```
webtester/
├── webtester.py          # Main entry point
├── scraper.py            # Website downloader
├── scanner.py            # 65+ security checks
├── sqli_scanner.py       # SQL injection testing
├── csp_generator.py      # CSP header generator
├── requirements.txt      # Python dependencies
├── LICENSE               # MIT License
├── CONTRIBUTING.md       # Contribution guidelines
└── README.md             # This file
```

---

## 🎯 What You Can Prove to Clients

| Vulnerability | What You Can Demonstrate |
|---------------|--------------------------|
| **SQL Injection** | Show database access without authorization |
| **Exposed Secrets** | Prove .env files are publicly accessible |
| **Missing Headers** | Document security header vulnerabilities |
| **WordPress Issues** | Show plugin/theme vulnerabilities |
| **XSS Vulnerabilities** | Demonstrate script injection risks |

---

## 📋 Complete Security Checks (65+)

### Secrets & Credentials (10 checks)
- Exposed .env files
- Exposed .git directories
- Exposed .svn directories
- Exposed config files
- Exposed backup files
- Exposed database files
- Exposed private keys
- Exposed credentials files
- API keys in source code
- Hardcoded passwords

### Security Headers (7 checks)
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

### SSL/TLS Security (5 checks)
- SSL certificate validity
- TLS protocol version
- Weak cipher suites
- HTTP to HTTPS redirect
- Mixed content detection

### Injection Vulnerabilities (7 checks)
- SQL injection
- XSS vulnerabilities
- Command injection
- Directory traversal
- File inclusion (LFI/RFI)
- XML External Entity (XXE)
- Insecure deserialization

### WordPress Specific (15 checks)
- WordPress version exposure
- XML-RPC enabled
- readme.html exposure
- license.txt exposure
- debug.log exposure
- wp-config.php backups
- Uploads directory listing
- wp-includes exposure
- User enumeration
- REST API exposure
- Vulnerable plugins
- File editing enabled
- Outdated versions
- .htaccess protection
- WPScan fingerprinting

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Use only on websites you own or have permission to test. Unauthorized access to computer systems is illegal.

---

## 📧 Contact

- **GitHub**: [jackharsh0](https://github.com/jackharsh0)
- **Email**: jackisharsh@gmail.com
- **Repository**: [webtester](https://github.com/jackharsh0/webtester)

---

## 🌟 Star This Repository

If you find this tool useful, please give it a ⭐ star on GitHub!

---

**Built for the security community** 🔒