#!/usr/bin/env python3
"""
SniperSayer - Automated Security Scanning Tool
Author: SaudiLinux
Email: SaudiLinux1@gmail.com
GitHub: https://github.com/SaudiLinux

A comprehensive automated security scanning tool that performs reconnaissance,
port scanning, vulnerability assessment, and reporting in a single integrated workflow.
"""

import argparse
import sys
import os
import json
import datetime
from pathlib import Path
import logging

# Import custom modules
from modules.recon import Reconnaissance
from modules.portscan import PortScanner
from modules.vulnscan import VulnScanner
from modules.reporter import ReportGenerator
from config import ConfigManager

__version__ = "1.0.0"
__author__ = "SaudiLinux"

class SniperSayer:
    """Main SniperSayer class that orchestrates the entire scanning process"""
    
    def __init__(self, target, mode="full", output_dir="reports"):
        self.target = target
        self.mode = mode
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Setup logging
        self.setup_logging()
        
        # Initialize modules
        self.config = ConfigManager(mode)
        self.recon = Reconnaissance(target)
        self.port_scanner = PortScanner(target)
        self.vuln_scanner = VulnScanner(target)
        self.reporter = ReportGenerator(target, self.output_dir, self.timestamp)
        
        # Results storage
        self.results = {
            "target": target,
            "mode": mode,
            "timestamp": self.timestamp,
            "reconnaissance": {},
            "port_scan": {},
            "vulnerabilities": {},
            "summary": {}
        }
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(f'snipersayer_{self.timestamp}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('SniperSayer')
    
    def run_reconnaissance(self):
        """Run reconnaissance phase"""
        self.logger.info(f"Starting reconnaissance for {self.target}")
        
        try:
            # WHOIS lookup
            self.results["reconnaissance"]["whois"] = self.recon.get_whois()
            
            # DNS information
            self.results["reconnaissance"]["dns"] = self.recon.get_dns_info()
            
            # Ping test
            self.results["reconnaissance"]["ping"] = self.recon.ping_test()
            
            # Subdomain enumeration (if enabled)
            if self.config.get_setting("recon.subdomain_enum"):
                self.results["reconnaissance"]["subdomains"] = self.recon.enumerate_subdomains()
            
            self.logger.info("Reconnaissance phase completed")
            
        except Exception as e:
            self.logger.error(f"Error during reconnaissance: {str(e)}")
            self.results["reconnaissance"]["error"] = str(e)
    
    def run_port_scan(self):
        """Run port scanning phase"""
        self.logger.info("Starting port scanning phase")
        
        try:
            # Get scan parameters from config
            scan_type = self.config.get_setting("portscan.type")
            ports = self.config.get_setting("portscan.ports")
            
            # Run Nmap scan
            self.results["port_scan"] = self.port_scanner.scan(
                scan_type=scan_type,
                ports=ports,
                stealth=self.mode == "stealth"
            )
            
            self.logger.info("Port scanning phase completed")
            
        except Exception as e:
            self.logger.error(f"Error during port scanning: {str(e)}")
            self.results["port_scan"]["error"] = str(e)
    
    def run_vulnerability_scan(self):
        """Run vulnerability scanning phase"""
        self.logger.info("Starting vulnerability scanning phase")
        
        try:
            # Get open ports for scanning
            open_ports = self.results["port_scan"].get("open_ports", [])
            
            # HTTP/HTTPS services scanning
            web_services = [p for p in open_ports if p.get('service') in ['http', 'https']]
            for service in web_services:
                port = service.get('port')
                protocol = service.get('service')
                
                # Nikto scan
                if self.config.get_setting("vulscan.nikto.enabled"):
                    self.results["vulnerabilities"][f"nikto_{port}"] = \
                        self.vuln_scanner.nikto_scan(port, protocol)
                
                # WPScan for WordPress
                if self.config.get_setting("vulscan.wpscan.enabled"):
                    self.results["vulnerabilities"][f"wpscan_{port}"] = \
                        self.vuln_scanner.wpscan(port, protocol)
            
            # CMS detection
            if self.config.get_setting("vulscan.cms_detection.enabled"):
                self.results["vulnerabilities"]["cms_detection"] = \
                    self.vuln_scanner.detect_cms(open_ports)
            
            # Brute force attacks (if enabled)
            if self.mode == "full" and self.config.get_setting("vulscan.bruteforce.enabled"):
                self.results["vulnerabilities"]["bruteforce"] = \
                    self.vuln_scanner.bruteforce_attack(open_ports)
            
            self.logger.info("Vulnerability scanning phase completed")
            
        except Exception as e:
            self.logger.error(f"Error during vulnerability scanning: {str(e)}")
            self.results["vulnerabilities"]["error"] = str(e)
    
    def generate_summary(self):
        """Generate summary of findings"""
        summary = {
            "total_open_ports": len(self.results["port_scan"].get("open_ports", [])),
            "critical_vulnerabilities": 0,
            "medium_vulnerabilities": 0,
            "low_vulnerabilities": 0,
            "services_detected": []
        }
        
        # Count vulnerabilities
        for scan_type, results in self.results["vulnerabilities"].items():
            if isinstance(results, dict) and "vulnerabilities" in results:
                for vuln in results["vulnerabilities"]:
                    severity = vuln.get("severity", "low").lower()
                    if severity == "critical":
                        summary["critical_vulnerabilities"] += 1
                    elif severity == "medium":
                        summary["medium_vulnerabilities"] += 1
                    else:
                        summary["low_vulnerabilities"] += 1
        
        # Extract services
        for port in self.results["port_scan"].get("open_ports", []):
            service = port.get("service", "unknown")
            if service not in summary["services_detected"]:
                summary["services_detected"].append(service)
        
        self.results["summary"] = summary
    
    def run_full_scan(self):
        """Run complete scanning workflow"""
        self.logger.info(f"Starting {self.mode} mode scan for {self.target}")
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Run scanning phases
        self.run_reconnaissance()
        self.run_port_scan()
        self.run_vulnerability_scan()
        
        # Generate summary
        self.generate_summary()
        
        # Generate reports
        self.reporter.generate_all_reports(self.results)
        
        self.logger.info(f"Scan completed. Reports saved to {self.output_dir}")
        return self.results

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="SniperSayer - Automated Security Scanning Tool",
        epilog="Example: python SniperSayer.py example.com --mode full"
    )
    
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("--mode", choices=["stealth", "report", "full"], 
                       default="full", help="Scanning mode")
    parser.add_argument("--output", default="reports", 
                       help="Output directory for reports")
    parser.add_argument("--config", help="Custom configuration file")
    parser.add_argument("--version", action="version", 
                       version=f"SniperSayer v{__version__}")
    
    args = parser.parse_args()
    
    try:
        # Initialize and run scanner
        scanner = SniperSayer(
            target=args.target,
            mode=args.mode,
            output_dir=args.output
        )
        
        results = scanner.run_full_scan()
        
        # Print summary
        print(f"\n{'='*50}")
        print(f"SniperSayer Scan Summary")
        print(f"{'='*50}")
        print(f"Target: {results['target']}")
        print(f"Mode: {results['mode']}")
        print(f"Scan Date: {results['timestamp']}")
        print(f"Open Ports: {results['summary']['total_open_ports']}")
        print(f"Critical Vulnerabilities: {results['summary']['critical_vulnerabilities']}")
        print(f"Medium Vulnerabilities: {results['summary']['medium_vulnerabilities']}")
        print(f"Low Vulnerabilities: {results['summary']['low_vulnerabilities']}")
        print(f"Services Detected: {', '.join(results['summary']['services_detected'])}")
        print(f"{'='*50}")
        print(f"Reports saved to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()