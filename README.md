# 🔍 SniperSayer

**Advanced Automated Security Scanner**  
*Author: SaudiLinux*  
*GitHub: https://github.com/SaudiLinux*  
*Email: SaudiLinux1@gmail.com*

SniperSayer is a comprehensive automated security scanning tool inspired by Sn1per, designed to perform systematic reconnaissance, vulnerability assessment, and reporting for web applications and network infrastructure.

## 🚀 Features

### Core Capabilities
- **Reconnaissance**: WHOIS, DNS queries, subdomain enumeration, SSL certificate analysis
- **Port Scanning**: Nmap integration with multiple scan types (TCP, UDP, stealth)
- **Vulnerability Scanning**: Nikto, WPScan, and custom vulnerability checks
- **CMS Detection**: WordPress, Joomla, Drupal, and other CMS platforms
- **Multi-format Reporting**: JSON, HTML, CSV reports with executive summaries
- **Configurable Scan Modes**: Stealth, Report, Full, and Quick scanning modes

### Scan Modes
- **🥷 Stealth**: Minimal footprint, top 100 ports, limited vulnerability checks
- **📊 Report**: Balanced scanning for comprehensive reporting
- **🔍 Full**: Complete reconnaissance, all ports, extensive vulnerability scanning
- **⚡ Quick**: Fast preliminary assessment for quick insights

## 📋 Installation

### Prerequisites
- Python 3.7 or higher
- Nmap (for port scanning)
- Nikto (for web vulnerability scanning)
- WPScan (for WordPress security scanning)

### System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3-pip nmap nikto wpscan whois dnsutils
```

#### CentOS/RHEL/Fedora
```bash
sudo yum install epel-release
sudo yum install python3-pip nmap nikto wpscan whois bind-utils
```

#### Windows
1. Install Python 3.7+ from [python.org](https://python.org)
2. Install Nmap from [nmap.org](https://nmap.org)
3. Install Nikto and WPScan via package managers or manually

### Python Dependencies
```bash
pip install -r requirements.txt
```

## 🎯 Usage

### Basic Usage
```bash
# Quick scan
python SniperSayer.py target.com

# Specific scan mode
python SniperSayer.py target.com --mode stealth
python SniperSayer.py target.com --mode report
python SniperSayer.py target.com --mode full

# Custom output directory
python SniperSayer.py target.com --output custom_reports

# Verbose output
python SniperSayer.py target.com --verbose
```

### Advanced Usage
```bash
# Multiple targets
python SniperSayer.py target1.com target2.com --mode report

# Custom configuration
python SniperSayer.py target.com --config custom_config.json

# Generate reports only
python SniperSayer.py target.com --mode report --reports-only
```

### Command Line Options
```
usage: SniperSayer.py [-h] [--mode {stealth,report,full,quick}]
                     [--output OUTPUT] [--config CONFIG]
                     [--verbose] [--reports-only]
                     target [target ...]

positional arguments:
  target                Target domain or IP address

optional arguments:
  -h, --help           show this help message and exit
  --mode {stealth,report,full,quick}
                      Scan mode (default: report)
  --output OUTPUT      Output directory for reports (default: reports)
  --config CONFIG      Custom configuration file (default: config.json)
  --verbose            Enable verbose output
  --reports-only       Only generate reports from existing data
```

## ⚙️ Configuration

### Configuration Files
- **config.json**: Main configuration file
- **config_template.json**: Template for custom configurations

### Scan Mode Configuration

#### Stealth Mode
- Minimal footprint
- Top 100 ports only
- Limited vulnerability checks
- Stealthy timing

#### Report Mode
- Balanced approach
- Top 1000 ports
- Full reconnaissance
- Comprehensive vulnerability scanning

#### Full Mode
- All ports (1-65535)
- Complete reconnaissance
- All vulnerability checks
- Subdomain enumeration
- Directory bruteforce

#### Quick Mode
- Fast assessment
- Top 50 ports
- Basic reconnaissance
- Quick vulnerability checks

### Custom Configuration
Create `config.json` or use the template:
```bash
python config.py template
```

### Environment Variables
```bash
export SNIPERSAYER_OUTPUT_DIR=/custom/path
export SNIPERSAYER_LOG_LEVEL=DEBUG
export SNIPERSAYER_MAX_THREADS=20
```

## 📊 Reports

### Report Formats
- **JSON**: Machine-readable format with raw data
- **HTML**: Professional web-based report
- **CSV**: Spreadsheet-compatible findings

### Report Structure
```
reports/
├── report_target_YYYYMMDD_HHMMSS.json
├── report_target_YYYYMMDD_HHMMSS.html
├── report_target_YYYYMMDD_HHMMSS.csv
├── recon_target.json
├── portscan_target.json
└── vulnscan_target.json
```

### Report Contents
- Executive summary with risk score
- Severity-based findings
- Detailed vulnerability information
- Actionable recommendations
- Raw scan data

## 🛠️ Modules

### Reconnaissance Module (`modules/recon.py`)
- WHOIS lookups
- DNS queries (A, AAAA, MX, TXT, NS)
- Subdomain enumeration
- SSL certificate analysis
- HTTP headers inspection

### Port Scanning Module (`modules/portscan.py`)
- Nmap integration
- Multiple scan types (TCP, UDP, SYN, ACK)
- Service version detection
- OS fingerprinting
- Script scanning

### Vulnerability Scanning (`modules/vulnscan.py`)
- Nikto web scanner
- WPScan for WordPress
- CMS detection
- Security headers check
- Admin panel discovery
- Backup file detection

### Reporting Module (`modules/reporter.py`)
- Multi-format report generation
- Finding categorization
- Risk scoring
- Executive summaries
- Recommendations

## 🔧 Development

### Project Structure
```
SniperSayer/
├── SniperSayer.py          # Main entry point
├── config.py              # Configuration management
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── config.json           # Configuration file
└── modules/
    ├── __init__.py
    ├── recon.py          # Reconnaissance module
    ├── portscan.py       # Port scanning module
    ├── vulnscan.py       # Vulnerability scanning
    └── reporter.py       # Report generation
```

### Adding Custom Modules
1. Create new module in `modules/`
2. Import in main script
3. Add configuration in `config.py`
4. Update documentation

### Testing
```bash
# Test individual modules
python -m modules.recon target.com
python -m modules.portscan target.com
python -m modules.vulnscan target.com
python -m modules.reporter target.com
```

## 🚨 Security Considerations

### Legal Usage
- Only scan systems you own or have explicit permission to test
- Respect robots.txt and rate limits
- Follow responsible disclosure practices

### Network Impact
- Stealth mode minimizes network traffic
- Report mode provides balanced scanning
- Full mode may generate significant traffic

### Data Protection
- Scan results are stored locally
- Sensitive data is not transmitted
- Reports can be encrypted if needed

## 🤝 Contributing

### Bug Reports
1. Check existing issues
2. Provide detailed reproduction steps
3. Include scan logs and configuration

### Feature Requests
1. Describe the use case
2. Suggest implementation approach
3. Consider security implications

### Code Contributions
1. Fork the repository
2. Create feature branch
3. Follow existing code style
4. Add tests and documentation
5. Submit pull request

## 📞 Support

### Contact
- **Author**: SaudiLinux
- **GitHub**: https://github.com/SaudiLinux
- **Email**: SaudiLinux1@gmail.com

### Resources
- [GitHub Issues](https://github.com/SaudiLinux/SniperSayer/issues)
- [Wiki](https://github.com/SaudiLinux/SniperSayer/wiki)
- [Security Best Practices](https://owasp.org/www-project-web-security-testing-guide/)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by Sn1per security framework
- Built with open-source security tools
- Community contributions and feedback
- Security researchers and penetration testers

---

**⚠️ Important**: This tool is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems.