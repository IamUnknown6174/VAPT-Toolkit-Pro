# 🛡️ VAPT Toolkit Pro (Python)

A professional, menu-driven VAPT (Vulnerability Assessment and Penetration Testing) toolkit written in pure Bash. This tool is designed for security researchers, sysadmins, and bug hunters to perform quick, automated security checks directly from the terminal.

![VAPT Toolkit Banner](https://img.shields.io/badge/VAPT-Toolkit--Pro-magenta?style=for-the-badge)
![Bash](https://img.shields.io/badge/Shell_Script-121011?style=for-the-badge&logo=gnu-bash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🚀 Key Features

*   **Unified Interface**: One command to rule them all. Access all tools via a beautiful ASCII-art menu.
*   **Modular Design**: Use the master toolkit or run standalone modules for specific tasks.
*   **No Heavy Dependencies**: Built using standard tools like `curl`, `openssl`, and `dig`. Works on macOS (Bash 3+) and Linux.
*   **Comprehensive Scanning**: Covers 10+ critical vulnerability areas.

## 🛠️ Included Modules

| Module | Description |
| :--- | :--- |
| **MSH Check** | HTTP Security Header Scanner (CSP, HSTS, XFO, etc.) with weakness detection. |
| **DNS Misconfig** | Origin Exposure Checker for WAF/CDN bypass detection. |
| **SRI Check** | Subresource Integrity validator for external JavaScript. |
| **SSL/TLS Audit** | Certificate validity, TLS version support, and cipher strength analysis. |
| **Cookie Security** | Security flag verification (Secure, HttpOnly, SameSite). |
| **HTTP Methods** | Dangerous method enumeration (PUT, DELETE, TRACE/XST). |
| **Port Scanner** | Built-in timeout-based port scanner (no `nmap` required). |
| **Redirect Check** | Validates HTTP to HTTPS redirect chains and SEO status codes. |
| **Server Disclosure** | Detects sensitive info leaks in `Server`, `X-Powered-By`, etc. |
| **CORS Check** | Advanced misconfiguration scanner (Wildcard, Reflection, Null Origin). |

## 📥 Installation & Usage

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/VAPT-Toolkit-Pro.git
cd VAPT-Toolkit-Pro
```

### 2. Set Permissions
```bash
chmod +x VAPTToolkit.sh modules/*.sh
```

### 3. Run the Toolkit
```bash
./VAPTToolkit.sh
```

### 4. Use Standalone Modules
You can also run specific modules directly from the `modules/` directory:
```bash
./modules/SSLCheck.sh example.com
```

## 📋 Requirements
*   `bash` (Compatible with Bash 3.2+ on macOS and Bash 4.0+ on Linux)
*   `curl`
*   `openssl`
*   `dig` (part of `bind-utils` or `dnsutils`)

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer
*This tool is for educational purposes and authorized security testing only. Running this against targets without permission is illegal.*
