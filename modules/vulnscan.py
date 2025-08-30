#!/usr/bin/env python3
"""
SniperSayer Vulnerability Scanner Module
Author: SaudiLinux (https://github.com/SaudiLinux)
Email: SaudiLinux1@gmail.com

This module provides vulnerability scanning capabilities using:
- Nikto: Web server scanner
- WPScan: WordPress security scanner
- CMS detection and specialized scanning
- Custom vulnerability checks
"""

import subprocess
import json
import os
import re
import requests
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


class VulnScanner:
    """Main vulnerability scanner class"""
    
    def __init__(self, target, output_dir="reports"):
        self.target = target
        self.output_dir = output_dir
        self.results = {
            'nikto': [],
            'wpscan': [],
            'cms_detection': {},
            'custom_checks': [],
            'summary': {}
        }
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
    
    def detect_cms(self, url):
        """Detect CMS type and version"""
        print(f"[+] Detecting CMS for {url}")
        
        cms_info = {
            'cms': 'unknown',
            'version': None,
            'detected_by': [],
            'confidence': 0
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            content = response.text.lower()
            headers = response.headers
            
            # WordPress detection
            wp_indicators = [
                'wp-content',
                'wp-includes',
                'wordpress',
                '/xmlrpc.php',
                'wp-json/wp/v2'
            ]
            
            for indicator in wp_indicators:
                if indicator.lower() in content or indicator.lower() in str(headers):
                    cms_info['cms'] = 'wordpress'
                    cms_info['detected_by'].append(indicator)
                    cms_info['confidence'] += 20
                    break
            
            # Joomla detection
            joomla_indicators = [
                '/administrator/',
                'joomla',
                'option=com_',
                '/media/system/js/'
            ]
            
            for indicator in joomla_indicators:
                if indicator.lower() in content:
                    cms_info['cms'] = 'joomla'
                    cms_info['detected_by'].append(indicator)
                    cms_info['confidence'] += 20
                    break
            
            # Drupal detection
            drupal_indicators = [
                'drupal',
                '/sites/default/',
                '/misc/drupal.js',
                'node/'
            ]
            
            for indicator in drupal_indicators:
                if indicator.lower() in content:
                    cms_info['cms'] = 'drupal'
                    cms_info['detected_by'].append(indicator)
                    cms_info['confidence'] += 20
                    break
            
            # Try to get version from generator meta tag
            generator_match = re.search(r'<meta name="generator" content="([^"]+)"', content)
            if generator_match:
                generator = generator_match.group(1).lower()
                if 'wordpress' in generator:
                    cms_info['cms'] = 'wordpress'
                    version_match = re.search(r'wordpress\s+([\d.]+)', generator)
                    if version_match:
                        cms_info['version'] = version_match.group(1)
                elif 'joomla' in generator:
                    cms_info['cms'] = 'joomla'
                    version_match = re.search(r'joomla!?\s+([\d.]+)', generator)
                    if version_match:
                        cms_info['version'] = version_match.group(1)
                elif 'drupal' in generator:
                    cms_info['cms'] = 'drupal'
                    version_match = re.search(r'drupal\s+([\d.]+)', generator)
                    if version_match:
                        cms_info['version'] = version_match.group(1)
            
            # Check for common files
            cms_files = {
                'wordpress': ['wp-login.php', 'wp-admin/admin-ajax.php', 'xmlrpc.php'],
                'joomla': ['administrator/index.php', 'index.php/component/users/'],
                'drupal': ['user/login', 'admin/']
            }
            
            for cms, files in cms_files.items():
                for file_path in files:
                    try:
                        check_url = f"{url.rstrip('/')}/{file_path}"
                        check_response = requests.head(check_url, timeout=5, verify=False)
                        if check_response.status_code == 200:
                            cms_info['cms'] = cms
                            cms_info['detected_by'].append(file_path)
                            cms_info['confidence'] += 15
                            break
                    except:
                        pass
            
        except Exception as e:
            print(f"[!] Error detecting CMS: {e}")
        
        self.results['cms_detection'] = cms_info
        return cms_info
    
    def run_nikto(self, target_url=None, mode="standard"):
        """Run Nikto vulnerability scanner"""
        if not target_url:
            target_url = f"http://{self.target}"
        
        print(f"[+] Running Nikto scan on {target_url}")
        
        # Prepare Nikto command
        nikto_cmd = [
            "nikto",
            "-h", target_url,
            "-output", f"{self.output_dir}/nikto_{self.target}.xml",
            "-Format", "xml"
        ]
        
        # Add mode-specific options
        if mode == "stealth":
            nikto_cmd.extend(["-Tuning", "1234567890"])
        elif mode == "full":
            nikto_cmd.extend(["-Tuning", "1234567890", "-Plugins", "all"])
        
        try:
            result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=600)
            
            if os.path.exists(f"{self.output_dir}/nikto_{self.target}.xml"):
                self.parse_nikto_results(f"{self.output_dir}/nikto_{self.target}.xml")
            else:
                print("[!] Nikto XML output not found")
                
        except subprocess.TimeoutExpired:
            print("[!] Nikto scan timed out")
        except FileNotFoundError:
            print("[!] Nikto not found. Please install Nikto")
        except Exception as e:
            print(f"[!] Error running Nikto: {e}")
    
    def parse_nikto_results(self, xml_file):
        """Parse Nikto XML results"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for item in root.findall('.//item'):
                vuln = {
                    'id': item.get('id', 'N/A'),
                    'osvdb': item.get('osvdbid', 'N/A'),
                    'method': item.get('method', 'N/A'),
                    'url': item.find('uri').text if item.find('uri') is not None else 'N/A',
                    'description': item.find('description').text if item.find('description') is not None else 'N/A',
                    'severity': self._get_severity_level(item.find('description').text) if item.find('description') is not None else 'info'
                }
                self.results['nikto'].append(vuln)
                
            print(f"[+] Parsed {len(self.results['nikto'])} Nikto findings")
            
        except Exception as e:
            print(f"[!] Error parsing Nikto results: {e}")
    
    def run_wpscan(self, target_url=None, mode="standard"):
        """Run WPScan for WordPress sites"""
        if not target_url:
            target_url = f"http://{self.target}"
        
        print(f"[+] Running WPScan on {target_url}")
        
        # Prepare WPScan command
        wpscan_cmd = [
            "wpscan",
            "--url", target_url,
            "--format", "json",
            "--output", f"{self.output_dir}/wpscan_{self.target}.json"
        ]
        
        # Add mode-specific options
        if mode == "stealth":
            wpscan_cmd.extend(["--stealthy"])
        elif mode == "full":
            wpscan_cmd.extend(["--enumerate", "ap,at,cb,dbe,tt,u,m"])
        else:
            wpscan_cmd.extend(["--enumerate", "vp,vt,cb,dbe,u"])
        
        try:
            result = subprocess.run(wpscan_cmd, capture_output=True, text=True, timeout=900)
            
            if os.path.exists(f"{self.output_dir}/wpscan_{self.target}.json"):
                self.parse_wpscan_results(f"{self.output_dir}/wpscan_{self.target}.json")
            else:
                print("[!] WPScan JSON output not found")
                
        except subprocess.TimeoutExpired:
            print("[!] WPScan scan timed out")
        except FileNotFoundError:
            print("[!] WPScan not found. Please install WPScan")
        except Exception as e:
            print(f"[!] Error running WPScan: {e}")
    
    def parse_wpscan_results(self, json_file):
        """Parse WPScan JSON results"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Parse vulnerabilities
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    vuln_info = {
                        'type': 'wordpress_core',
                        'title': vuln.get('title', 'N/A'),
                        'fixed_in': vuln.get('fixed_in', 'N/A'),
                        'references': vuln.get('references', {}),
                        'severity': self._get_severity_level(vuln.get('title', ''))
                    }
                    self.results['wpscan'].append(vuln_info)
            
            # Parse plugin vulnerabilities
            if 'plugins' in data:
                for plugin_name, plugin_data in data['plugins'].items():
                    if 'vulnerabilities' in plugin_data:
                        for vuln in plugin_data['vulnerabilities']:
                            vuln_info = {
                                'type': 'plugin',
                                'name': plugin_name,
                                'title': vuln.get('title', 'N/A'),
                                'fixed_in': vuln.get('fixed_in', 'N/A'),
                                'severity': self._get_severity_level(vuln.get('title', ''))
                            }
                            self.results['wpscan'].append(vuln_info)
            
            # Parse theme vulnerabilities
            if 'themes' in data:
                for theme_name, theme_data in data['themes'].items():
                    if 'vulnerabilities' in theme_data:
                        for vuln in theme_data['vulnerabilities']:
                            vuln_info = {
                                'type': 'theme',
                                'name': theme_name,
                                'title': vuln.get('title', 'N/A'),
                                'fixed_in': vuln.get('fixed_in', 'N/A'),
                                'severity': self._get_severity_level(vuln.get('title', ''))
                            }
                            self.results['wpscan'].append(vuln_info)
            
            # Parse users
            if 'users' in data:
                for user in data['users']:
                    user_info = {
                        'type': 'user_enumeration',
                        'username': user.get('username', 'N/A'),
                        'id': user.get('id', 'N/A'),
                        'severity': 'medium'
                    }
                    self.results['wpscan'].append(user_info)
            
            print(f"[+] Parsed {len(self.results['wpscan'])} WPScan findings")
            
        except Exception as e:
            print(f"[!] Error parsing WPScan results: {e}")
    
    def run_custom_checks(self, target_url=None):
        """Run custom vulnerability checks"""
        if not target_url:
            target_url = f"http://{self.target}"
        
        print(f"[+] Running custom vulnerability checks on {target_url}")
        
        checks = [
            self._check_robots_txt,
            self._check_admin_panels,
            self._check_backup_files,
            self._check_directory_listing,
            self._check_security_headers
        ]
        
        for check in checks:
            try:
                check(target_url)
            except Exception as e:
                print(f"[!] Error in custom check: {e}")
    
    def _check_robots_txt(self, target_url):
        """Check robots.txt for sensitive paths"""
        try:
            robots_url = f"{target_url.rstrip('/')}/robots.txt"
            response = requests.get(robots_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                sensitive_paths = re.findall(r'Disallow:\s*(/[^\s]+)', response.text)
                if sensitive_paths:
                    self.results['custom_checks'].append({
                        'type': 'robots_txt',
                        'url': robots_url,
                        'sensitive_paths': sensitive_paths,
                        'severity': 'low'
                    })
                    print(f"[+] Found {len(sensitive_paths)} paths in robots.txt")
        except Exception as e:
            pass
    
    def _check_admin_panels(self, target_url):
        """Check for common admin panels"""
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/admin.php',
            '/login', '/admin/login', '/panel', '/adminpanel',
            '/administrator/index.php', '/admin.html', '/admin.asp'
        ]
        
        found_panels = []
        for path in admin_paths:
            try:
                check_url = f"{target_url.rstrip('/')}{path}"
                response = requests.get(check_url, timeout=5, verify=False)
                
                if response.status_code == 200 and len(response.text) > 100:
                    found_panels.append({
                        'path': path,
                        'url': check_url,
                        'title': self._extract_title(response.text)
                    })
            except:
                pass
        
        if found_panels:
            self.results['custom_checks'].append({
                'type': 'admin_panels',
                'panels': found_panels,
                'severity': 'medium'
            })
            print(f"[+] Found {len(found_panels)} admin panels")
    
    def _check_backup_files(self, target_url):
        """Check for common backup files"""
        backup_extensions = ['.bak', '.old', '.backup', '.zip', '.tar.gz', '.sql']
        common_files = ['index', 'config', 'database', 'wp-config', '.env']
        
        found_backups = []
        
        for filename in common_files:
            for ext in backup_extensions:
                backup_file = f"{filename}{ext}"
                try:
                    check_url = f"{target_url.rstrip('/')}/{backup_file}"
                    response = requests.head(check_url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        if 'text' not in content_type.lower():
                            found_backups.append({
                                'file': backup_file,
                                'url': check_url,
                                'content_type': content_type
                            })
                except:
                    pass
        
        if found_backups:
            self.results['custom_checks'].append({
                'type': 'backup_files',
                'files': found_backups,
                'severity': 'high'
            })
            print(f"[+] Found {len(found_backups)} backup files")
    
    def _check_directory_listing(self, target_url):
        """Check for directory listing enabled"""
        common_dirs = ['/uploads/', '/images/', '/files/', '/documents/', '/backups/']
        
        found_listings = []
        for directory in common_dirs:
            try:
                check_url = f"{target_url.rstrip('/')}{directory}"
                response = requests.get(check_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    # Check for directory listing indicators
                    if "index of" in response.text.lower() or "parent directory" in response.text.lower():
                        found_listings.append({
                            'directory': directory,
                            'url': check_url
                        })
            except:
                pass
        
        if found_listings:
            self.results['custom_checks'].append({
                'type': 'directory_listing',
                'directories': found_listings,
                'severity': 'medium'
            })
            print(f"[+] Found {len(found_listings)} directories with listing enabled")
    
    def _check_security_headers(self, target_url):
        """Check for missing security headers"""
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'Referrer-Policy': 'Referrer policy'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append({
                        'header': header,
                        'description': description
                    })
            
            if missing_headers:
                self.results['custom_checks'].append({
                    'type': 'missing_security_headers',
                    'missing_headers': missing_headers,
                    'severity': 'low'
                })
                print(f"[+] Found {len(missing_headers)} missing security headers")
                
        except Exception as e:
            pass
    
    def _extract_title(self, html_content):
        """Extract page title from HTML"""
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        return title_match.group(1).strip() if title_match else "N/A"
    
    def _get_severity_level(self, description):
        """Determine severity level based on description"""
        description = description.lower()
        
        high_keywords = ['sql injection', 'rce', 'remote code', 'command injection', 'file upload', 'xss']
        medium_keywords = ['information disclosure', 'directory traversal', 'csrf', 'brute force']
        
        for keyword in high_keywords:
            if keyword in description:
                return 'high'
        
        for keyword in medium_keywords:
            if keyword in description:
                return 'medium'
        
        return 'low'
    
    def run_full_scan(self, target_url=None, mode="standard"):
        """Run complete vulnerability scan"""
        if not target_url:
            target_url = f"http://{self.target}"
        
        print(f"[+] Starting full vulnerability scan for {target_url}")
        
        # Detect CMS first
        cms_info = self.detect_cms(target_url)
        
        # Run Nikto
        self.run_nikto(target_url, mode)
        
        # Run WPScan if WordPress detected
        if cms_info['cms'] == 'wordpress':
            self.run_wpscan(target_url, mode)
        
        # Run custom checks
        self.run_custom_checks(target_url)
        
        # Generate summary
        self.generate_summary()
        
        return self.results
    
    def generate_summary(self):
        """Generate scan summary"""
        summary = {
            'total_vulnerabilities': 0,
            'severity_counts': {'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'scan_types': {
                'nikto': len(self.results['nikto']),
                'wpscan': len(self.results['wpscan']),
                'custom_checks': len(self.results['custom_checks'])
            },
            'cms_detected': self.results['cms_detection']
        }
        
        # Count vulnerabilities by severity
        for vuln_type in ['nikto', 'wpscan', 'custom_checks']:
            for vuln in self.results[vuln_type]:
                severity = vuln.get('severity', 'info')
                if severity in summary['severity_counts']:
                    summary['severity_counts'][severity] += 1
                    summary['total_vulnerabilities'] += 1
        
        self.results['summary'] = summary
        
        print(f"[+] Scan completed. Found {summary['total_vulnerabilities']} vulnerabilities")
        print(f"    High: {summary['severity_counts']['high']}")
        print(f"    Medium: {summary['severity_counts']['medium']}")
        print(f"    Low: {summary['severity_counts']['low']}")
    
    def save_results(self, filename=None):
        """Save results to JSON file"""
        if not filename:
            filename = f"{self.output_dir}/vulnscan_{self.target}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving results: {e}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python vulnscan.py <target> [url]")
        sys.exit(1)
    
    target = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = VulnScanner(target)
    results = scanner.run_full_scan(target_url)
    scanner.save_results()
    
    print(json.dumps(results['summary'], indent=2))