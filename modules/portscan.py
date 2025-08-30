#!/usr/bin/env python3
"""
Port Scanning Module for SniperSayer
Handles Nmap integration for comprehensive port and service detection
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import logging
import re
import socket
from typing import Dict, List, Any

class PortScanner:
    """Port scanning class using Nmap for comprehensive port and service detection"""
    
    def __init__(self, target):
        self.target = target
        self.logger = logging.getLogger('SniperSayer.PortScanner')
        self.nmap_path = self._find_nmap()
        
    def _find_nmap(self):
        """Find nmap executable in system PATH"""
        try:
            # Try to find nmap in PATH
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            
            # Try Windows path
            result = subprocess.run(['where', 'nmap'], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
                
            # Default paths
            possible_paths = [
                '/usr/bin/nmap',
                '/usr/local/bin/nmap',
                'C:\\Program Files (x86)\\Nmap\\nmap.exe',
                'C:\\Program Files\\Nmap\\nmap.exe'
            ]
            
            for path in possible_paths:
                try:
                    subprocess.run([path, '--version'], capture_output=True, timeout=5)
                    return path
                except:
                    continue
            
            raise FileNotFoundError("Nmap not found. Please install nmap.")
            
        except Exception as e:
            self.logger.error(f"Error finding nmap: {str(e)}")
            raise
    
    def _parse_nmap_xml(self, xml_output):
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            
            scan_results = {
                "scan_info": {},
                "open_ports": [],
                "closed_ports": [],
                "filtered_ports": [],
                "os_detection": [],
                "service_detection": []
            }
            
            # Get scan information
            scan_elem = root.find('scaninfo')
            if scan_elem is not None:
                scan_results["scan_info"] = {
                    "type": scan_elem.get('type'),
                    "protocol": scan_elem.get('protocol'),
                    "numservices": scan_elem.get('numservices'),
                    "services": scan_elem.get('services')
                }
            
            # Parse hosts
            for host in root.findall('host'):
                # Get host information
                host_info = {
                    "address": None,
                    "hostname": None,
                    "status": None,
                    "os": None,
                    "ports": []
                }
                
                # Address
                address = host.find('address')
                if address is not None:
                    host_info["address"] = address.get('addr')
                
                # Hostname
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname = hostnames.find('hostname')
                    if hostname is not None:
                        host_info["hostname"] = hostname.get('name')
                
                # Status
                status = host.find('status')
                if status is not None:
                    host_info["status"] = status.get('state')
                
                # OS Detection
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host_info["os"] = {
                            "name": osmatch.get('name'),
                            "accuracy": osmatch.get('accuracy'),
                            "osclass": []
                        }
                        
                        for osclass in osmatch.findall('osclass'):
                            host_info["os"]["osclass"].append({
                                "type": osclass.get('type'),
                                "vendor": osclass.get('vendor'),
                                "osfamily": osclass.get('osfamily'),
                                "osgen": osclass.get('osgen'),
                                "accuracy": osclass.get('accuracy')
                            })
                
                # Ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_info = {
                            "port": int(port.get('portid')),
                            "protocol": port.get('protocol'),
                            "state": None,
                            "service": None,
                            "version": None,
                            "product": None,
                            "cpe": [],
                            "scripts": []
                        }
                        
                        # State
                        state = port.find('state')
                        if state is not None:
                            port_info["state"] = state.get('state')
                        
                        # Service
                        service = port.find('service')
                        if service is not None:
                            port_info["service"] = service.get('name')
                            port_info["version"] = service.get('version')
                            port_info["product"] = service.get('product')
                            
                            # CPE
                            for cpe in service.findall('cpe'):
                                port_info["cpe"].append(cpe.text)
                        
                        # Scripts (NSE)
                        for script in port.findall('script'):
                            script_info = {
                                "id": script.get('id'),
                                "output": script.get('output')
                            }
                            port_info["scripts"].append(script_info)
                        
                        host_info["ports"].append(port_info)
                        
                        # Add to appropriate category
                        if port_info["state"] == "open":
                            scan_results["open_ports"].append(port_info)
                        elif port_info["state"] == "closed":
                            scan_results["closed_ports"].append(port_info)
                        elif port_info["state"] == "filtered":
                            scan_results["filtered_ports"].append(port_info)
                
                scan_results["service_detection"].append(host_info)
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Error parsing Nmap XML: {str(e)}")
            return {"error": str(e)}
    
    def _build_nmap_command(self, scan_type="tcp", ports=None, stealth=False, 
                           os_detection=True, service_detection=True, scripts=None):
        """Build Nmap command based on parameters"""
        
        cmd = [self.nmap_path]
        
        # Scan type options
        scan_options = {
            "tcp": "-sS",      # TCP SYN scan
            "udp": "-sU",      # UDP scan
            "comprehensive": "-sS -sU",  # TCP + UDP
            "stealth": "-sS",  # TCP SYN (stealth)
            "intense": "-sS -sV -O -A",  # Intense scan
            "quick": "-F",     # Fast scan
            "ping": "-sn"      # Ping scan only
        }
        
        # Add scan type
        if scan_type in scan_options:
            cmd.extend(scan_options[scan_type].split())
        else:
            cmd.extend(["-sS"])  # Default to TCP SYN
        
        # Stealth options
        if stealth:
            cmd.extend([
                "-T2",      # Paranoid timing
                "--max-parallelism", "1",
                "--max-retries", "2",
                "--host-timeout", "300s"
            ])
        else:
            cmd.extend(["-T4"])  # Aggressive timing
        
        # Port specification
        if ports:
            if isinstance(ports, list):
                port_str = ','.join(map(str, ports))
            else:
                port_str = str(ports)
            cmd.extend(["-p", port_str])
        else:
            # Default ports based on scan type
            if scan_type == "quick":
                cmd.extend(["-F"])  # Top 100 ports
            elif scan_type == "udp":
                cmd.extend(["-p", "1-1000"])  # Common UDP ports
            else:
                cmd.extend(["-p", "1-65535"])  # All ports
        
        # Service and OS detection
        if service_detection:
            cmd.extend(["-sV"])
        
        if os_detection and not stealth:
            cmd.extend(["-O"])
        
        # Default scripts
        default_scripts = [
            "http-title",
            "http-server-header",
            "http-headers",
            "ssl-cert",
            "ftp-anon",
            "ssh-hostkey",
            "smtp-commands"
        ]
        
        if scripts:
            script_args = ','.join(scripts)
            cmd.extend(["--script", script_args])
        elif not stealth:
            script_args = ','.join(default_scripts)
            cmd.extend(["--script", script_args])
        
        # Output format
        cmd.extend(["-oX", "-"])  # XML output to stdout
        
        # Add target
        cmd.append(self.target)
        
        return cmd
    
    def scan(self, scan_type="tcp", ports=None, stealth=False, timeout=300):
        """Perform port scan using Nmap"""
        
        self.logger.info(f"Starting {scan_type} port scan for {self.target}")
        
        try:
            # Build command
            cmd = self._build_nmap_command(
                scan_type=scan_type,
                ports=ports,
                stealth=stealth,
                os_detection=not stealth,  # Skip OS detection in stealth mode
                service_detection=True
            )
            
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Execute scan
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            if result.returncode not in [0, 1]:  # Nmap returns 1 for some non-critical errors
                raise Exception(f"Nmap scan failed: {result.stderr}")
            
            # Parse XML output
            scan_results = self._parse_nmap_xml(result.stdout)
            
            # Add additional metadata
            scan_results["scan_metadata"] = {
                "target": self.target,
                "scan_type": scan_type,
                "stealth_mode": stealth,
                "command": ' '.join(cmd),
                "scan_duration": None,  # Could parse from XML
                "timestamp": None
            }
            
            # Extract top services
            services = {}
            for port in scan_results["open_ports"]:
                service = port.get("service", "unknown")
                if service in services:
                    services[service] += 1
                else:
                    services[service] = 1
            
            scan_results["top_services"] = services
            
            self.logger.info(f"Port scan completed. Found {len(scan_results['open_ports'])} open ports")
            
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Nmap scan timed out")
            return {"error": "Scan timeout", "open_ports": []}
        except Exception as e:
            self.logger.error(f"Error during port scan: {str(e)}")
            return {"error": str(e), "open_ports": []}
    
    def quick_scan(self):
        """Perform quick scan of top ports"""
        return self.scan(scan_type="quick")
    
    def comprehensive_scan(self):
        """Perform comprehensive TCP and UDP scan"""
        return self.scan(scan_type="comprehensive")
    
    def stealth_scan(self):
        """Perform stealth scan"""
        return self.scan(scan_type="stealth", stealth=True)
    
    def udp_scan(self):
        """Perform UDP scan"""
        return self.scan(scan_type="udp")
    
    def service_detection_scan(self, ports):
        """Perform detailed service detection on specific ports"""
        return self.scan(
            scan_type="intense",
            ports=ports,
            stealth=False
        )
    
    def ping_sweep(self):
        """Perform ping sweep to check host availability"""
        try:
            cmd = [self.nmap_path, "-sn", self.target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse output for host status
                lines = result.stdout.split('\n')
                is_up = any("Host is up" in line for line in lines)
                
                return {
                    "reachable": is_up,
                    "raw_output": result.stdout
                }
            else:
                return {"reachable": False, "error": result.stderr}
                
        except Exception as e:
            self.logger.error(f"Error during ping sweep: {str(e)}")
            return {"reachable": False, "error": str(e)}
    
    def get_service_versions(self, ports):
        """Get detailed service versions for specified ports"""
        if not ports:
            return {"error": "No ports specified"}
        
        return self.scan(
            scan_type="intense",
            ports=ports,
            stealth=False
        )