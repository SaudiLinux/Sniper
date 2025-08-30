#!/usr/bin/env python3
"""
Reconnaissance Module for SniperSayer
Handles WHOIS, DNS, and ping operations for target information gathering
"""

import socket
import subprocess
import json
import dns.resolver
import dns.reversename
import whois
import requests
from urllib.parse import urlparse
import logging
import concurrent.futures
import time

class Reconnaissance:
    """Reconnaissance class for gathering target information"""
    
    def __init__(self, target):
        self.target = target
        self.logger = logging.getLogger('SniperSayer.Reconnaissance')
        
        # Clean target URL
        self.clean_target = self._clean_target(target)
        
    def _clean_target(self, target):
        """Clean and normalize target URL/hostname"""
        # Remove protocol prefixes
        target = target.replace('http://', '').replace('https://', '').replace('ftp://', '')
        # Remove trailing slashes
        target = target.rstrip('/')
        return target
    
    def get_whois(self):
        """Get WHOIS information for the target"""
        self.logger.info(f"Getting WHOIS information for {self.clean_target}")
        
        try:
            # Get WHOIS data
            domain_info = whois.whois(self.clean_target)
            
            # Extract relevant information
            whois_data = {
                "domain_name": domain_info.domain_name,
                "registrar": domain_info.registrar,
                "creation_date": str(domain_info.creation_date) if domain_info.creation_date else None,
                "expiration_date": str(domain_info.expiration_date) if domain_info.expiration_date else None,
                "updated_date": str(domain_info.updated_date) if domain_info.updated_date else None,
                "name_servers": domain_info.name_servers,
                "status": domain_info.status,
                "emails": domain_info.emails,
                "org": domain_info.org,
                "country": domain_info.country,
                "raw_data": str(domain_info)
            }
            
            return whois_data
            
        except Exception as e:
            self.logger.error(f"Error getting WHOIS: {str(e)}")
            return {"error": str(e)}
    
    def get_dns_info(self):
        """Get comprehensive DNS information"""
        self.logger.info(f"Getting DNS information for {self.clean_target}")
        
        dns_info = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "srv_records": [],
            "reverse_dns": [],
            "dns_servers": []
        }
        
        try:
            # A Records (IPv4)
            try:
                answers = dns.resolver.resolve(self.clean_target, 'A')
                dns_info["a_records"] = [str(answer) for answer in answers]
            except:
                pass
            
            # AAAA Records (IPv6)
            try:
                answers = dns.resolver.resolve(self.clean_target, 'AAAA')
                dns_info["aaaa_records"] = [str(answer) for answer in answers]
            except:
                pass
            
            # MX Records (Mail Exchange)
            try:
                answers = dns.resolver.resolve(self.clean_target, 'MX')
                dns_info["mx_records"] = [
                    {"priority": answer.preference, "exchange": str(answer.exchange)}
                    for answer in answers
                ]
            except:
                pass
            
            # NS Records (Name Servers)
            try:
                answers = dns.resolver.resolve(self.clean_target, 'NS')
                dns_info["ns_records"] = [str(answer) for answer in answers]
            except:
                pass
            
            # TXT Records (Text)
            try:
                answers = dns.resolver.resolve(self.clean_target, 'TXT')
                dns_info["txt_records"] = [str(answer) for answer in answers]
            except:
                pass
            
            # CNAME Records (Canonical Name)
            try:
                answers = dns.resolver.resolve(self.clean_target, 'CNAME')
                dns_info["cname_records"] = [str(answer) for answer in answers]
            except:
                pass
            
            # SRV Records (Service)
            try:
                answers = dns.resolver.resolve(self.clean_target, 'SRV')
                dns_info["srv_records"] = [
                    {"priority": answer.priority, "weight": answer.weight, 
                     "port": answer.port, "target": str(answer.target)}
                    for answer in answers
                ]
            except:
                pass
            
            # Reverse DNS for IP addresses
            for ip in dns_info["a_records"]:
                try:
                    reverse_name = dns.reversename.from_address(ip)
                    reverse_answer = dns.resolver.resolve(reverse_name, 'PTR')
                    dns_info["reverse_dns"].append({
                        "ip": ip,
                        "hostname": str(reverse_answer[0])
                    })
                except:
                    dns_info["reverse_dns"].append({
                        "ip": ip,
                        "hostname": "No PTR record"
                    })
            
            return dns_info
            
        except Exception as e:
            self.logger.error(f"Error getting DNS info: {str(e)}")
            return {"error": str(e)}
    
    def ping_test(self):
        """Perform ping test to check target availability"""
        self.logger.info(f"Performing ping test for {self.clean_target}")
        
        try:
            # Determine ping command based on OS
            if subprocess.os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', self.clean_target]
            else:  # Unix-like
                cmd = ['ping', '-c', '4', self.clean_target]
            
            # Execute ping command
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Parse ping results
            ping_data = {
                "reachable": result.returncode == 0,
                "response_time": None,
                "packets_sent": 4,
                "packets_received": 0,
                "packet_loss": 100,
                "raw_output": result.stdout
            }
            
            if result.returncode == 0:
                # Extract response time and packet statistics
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'time=' in line.lower() or 'time<' in line.lower():
                        if 'time=' in line:
                            time_part = line.split('time=')[1].split()[0]
                            ping_data["response_time"] = float(time_part.replace('ms', ''))
                    
                    # Parse packet statistics
                    if 'packets transmitted' in line.lower():
                        parts = line.split(',')
                        for part in parts:
                            if 'received' in part:
                                ping_data["packets_received"] = int(part.strip().split()[0])
                            elif 'packet loss' in part:
                                loss_str = part.strip().split('%')[0]
                                ping_data["packet_loss"] = float(loss_str)
            
            return ping_data
            
        except subprocess.TimeoutExpired:
            return {"reachable": False, "error": "Ping timeout", "raw_output": ""}
        except Exception as e:
            self.logger.error(f"Error during ping test: {str(e)}")
            return {"reachable": False, "error": str(e), "raw_output": ""}
    
    def enumerate_subdomains(self, wordlist_path=None):
        """Enumerate subdomains using DNS brute force"""
        self.logger.info("Starting subdomain enumeration")
        
        if not wordlist_path:
            # Use default wordlist
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 'test',
                'staging', 'app', 'mobile', 'support', 'help', 'docs', 'cdn', 'media',
                'static', 'secure', 'login', 'account', 'portal', 'dashboard', 'panel'
            ]
        else:
            # Load custom wordlist
            try:
                with open(wordlist_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except:
                wordlist = ['www', 'mail', 'ftp', 'admin', 'blog']
        
        discovered_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.clean_target}"
                answers = dns.resolver.resolve(full_domain, 'A')
                return {
                    "subdomain": full_domain,
                    "ip_addresses": [str(answer) for answer in answers]
                }
            except:
                return None
        
        # Use threading for faster enumeration
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, subdomain): subdomain 
                for subdomain in wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    discovered_subdomains.append(result)
        
        return {
            "total_tested": len(wordlist),
            "discovered": len(discovered_subdomains),
            "subdomains": discovered_subdomains
        }
    
    def get_http_headers(self, port=80, protocol="http"):
        """Get HTTP headers for web services"""
        self.logger.info(f"Getting HTTP headers for {protocol}://{self.clean_target}:{port}")
        
        try:
            url = f"{protocol}://{self.clean_target}:{port}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            headers_info = {
                "url": response.url,
                "status_code": response.status_code,
                "server": response.headers.get('Server', 'Unknown'),
                "content_type": response.headers.get('Content-Type', 'Unknown'),
                "headers": dict(response.headers),
                "response_time": response.elapsed.total_seconds()
            }
            
            return headers_info
            
        except Exception as e:
            self.logger.error(f"Error getting HTTP headers: {str(e)}")
            return {"error": str(e)}
    
    def get_ssl_certificate(self, port=443):
        """Get SSL certificate information"""
        self.logger.info(f"Getting SSL certificate for {self.clean_target}:{port}")
        
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            
            with socket.create_connection((self.clean_target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.clean_target) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "serial_number": cert['serialNumber'],
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter'],
                        "san": cert.get('subjectAltName', []),
                        "valid": datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') > datetime.now()
                    }
                    
                    return cert_info
                    
        except Exception as e:
            self.logger.error(f"Error getting SSL certificate: {str(e)}")
            return {"error": str(e)}
    
    def run_full_recon(self):
        """Run complete reconnaissance workflow"""
        self.logger.info("Running complete reconnaissance")
        
        recon_results = {
            "whois": self.get_whois(),
            "dns": self.get_dns_info(),
            "ping": self.ping_test(),
            "http_headers": {},
            "ssl_certificate": {}
        }
        
        # Get HTTP headers for common ports
        common_ports = [80, 443, 8080, 8443]
        for port in common_ports:
            protocol = "https" if port in [443, 8443] else "http"
            recon_results["http_headers"][str(port)] = self.get_http_headers(port, protocol)
        
        # Get SSL certificate for HTTPS ports
        for port in [443, 8443]:
            recon_results["ssl_certificate"][str(port)] = self.get_ssl_certificate(port)
        
        return recon_results