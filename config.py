#!/usr/bin/env python3
"""
SniperSayer Configuration System
Author: SaudiLinux (https://github.com/SaudiLinux)
Email: SaudiLinux1@gmail.com

Configuration management for different scan modes and settings
"""

import json
import os
from typing import Dict, Any


class ConfigManager:
    """Configuration management for SniperSayer"""
    
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            except json.JSONDecodeError:
                print(f"[!] Invalid config file, using defaults")
                self.config = self._get_default_config()
        else:
            self.config = self._get_default_config()
            self.save_config()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"[+] Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"[!] Error saving config: {e}")
    
    def _get_default_config(self):
        """Get default configuration for all scan modes"""
        return {
            "general": {
                "output_dir": "reports",
                "log_level": "INFO",
                "timeout": 300,
                "user_agent": "SniperSayer/1.0 (Security Scanner)",
                "max_threads": 10
            },
            "modes": {
                "stealth": {
                    "description": "Minimal footprint scanning",
                    "reconnaissance": {
                        "enabled": True,
                        "whois": True,
                        "dns": True,
                        "ping": False,
                        "subdomain_enum": False,
                        "ssl_check": False
                    },
                    "port_scan": {
                        "enabled": True,
                        "scan_type": "top-ports",
                        "top_ports": 100,
                        "service_detection": False,
                        "os_detection": False,
                        "stealth_mode": True,
                        "timing": "T2"
                    },
                    "vulnerability_scan": {
                        "enabled": True,
                        "nikto": {
                            "enabled": False,
                            "plugins": ["@DEFAULT"],
                            "max_time": 60
                        },
                        "wpscan": {
                            "enabled": False,
                            "enumerate": "vp",
                            "stealthy": True
                        },
                        "custom_checks": {
                            "enabled": True,
                            "robots_txt": True,
                            "security_headers": True,
                            "admin_panels": False,
                            "backup_files": False
                        }
                    }
                },
                "report": {
                    "description": "Balanced scanning for reporting",
                    "reconnaissance": {
                        "enabled": True,
                        "whois": True,
                        "dns": True,
                        "ping": True,
                        "subdomain_enum": True,
                        "ssl_check": True
                    },
                    "port_scan": {
                        "enabled": True,
                        "scan_type": "tcp",
                        "top_ports": 1000,
                        "service_detection": True,
                        "os_detection": True,
                        "stealth_mode": False,
                        "timing": "T3"
                    },
                    "vulnerability_scan": {
                        "enabled": True,
                        "nikto": {
                            "enabled": True,
                            "plugins": ["@DEFAULT"],
                            "max_time": 300
                        },
                        "wpscan": {
                            "enabled": True,
                            "enumerate": "vp",
                            "stealthy": False
                        },
                        "custom_checks": {
                            "enabled": True,
                            "robots_txt": True,
                            "security_headers": True,
                            "admin_panels": True,
                            "backup_files": True
                        }
                    }
                },
                "full": {
                    "description": "Comprehensive scanning",
                    "reconnaissance": {
                        "enabled": True,
                        "whois": True,
                        "dns": True,
                        "ping": True,
                        "subdomain_enum": True,
                        "ssl_check": True,
                        "subdomain_wordlist": "subdomains.txt"
                    },
                    "port_scan": {
                        "enabled": True,
                        "scan_type": "tcp",
                        "ports": "1-65535",
                        "service_detection": True,
                        "os_detection": True,
                        "script_scan": True,
                        "stealth_mode": False,
                        "timing": "T4"
                    },
                    "vulnerability_scan": {
                        "enabled": True,
                        "nikto": {
                            "enabled": True,
                            "plugins": ["@ALL"],
                            "max_time": 1800
                        },
                        "wpscan": {
                            "enabled": True,
                            "enumerate": "vp,vt,tt,cb,dbe,u,m",
                            "stealthy": False,
                            "password_attack": True
                        },
                        "custom_checks": {
                            "enabled": True,
                            "robots_txt": True,
                            "security_headers": True,
                            "admin_panels": True,
                            "backup_files": True,
                            "directory_bruteforce": True
                        }
                    }
                },
                "quick": {
                    "description": "Fast preliminary scan",
                    "reconnaissance": {
                        "enabled": True,
                        "whois": False,
                        "dns": True,
                        "ping": True,
                        "subdomain_enum": False,
                        "ssl_check": True
                    },
                    "port_scan": {
                        "enabled": True,
                        "scan_type": "top-ports",
                        "top_ports": 50,
                        "service_detection": False,
                        "os_detection": False,
                        "timing": "T5"
                    },
                    "vulnerability_scan": {
                        "enabled": True,
                        "nikto": {
                            "enabled": False,
                            "max_time": 30
                        },
                        "wpscan": {
                            "enabled": False,
                            "stealthy": True
                        },
                        "custom_checks": {
                            "enabled": True,
                            "robots_txt": True,
                            "security_headers": True,
                            "admin_panels": False,
                            "backup_files": False
                        }
                    }
                }
            },
            "tools": {
                "nmap": {
                    "path": "nmap",
                    "args": ["-sV", "-O", "--script=default"]
                },
                "nikto": {
                    "path": "nikto",
                    "args": ["-Format", "json"]
                },
                "wpscan": {
                    "path": "wpscan",
                    "args": ["--format", "json"]
                },
                "whois": {
                    "path": "whois"
                },
                "dig": {
                    "path": "dig"
                }
            },
            "wordlists": {
                "subdomains": "wordlists/subdomains.txt",
                "directories": "wordlists/directories.txt",
                "passwords": "wordlists/passwords.txt"
            },
            "output": {
                "formats": ["json", "html", "csv"],
                "include_raw_data": False,
                "compress_reports": True
            }
        }
    
    def get_mode_config(self, mode: str) -> Dict[str, Any]:
        """Get configuration for specific scan mode"""
        if mode not in self.config["modes"]:
            print(f"[!] Unknown mode: {mode}, using 'report' mode")
            mode = "report"
        
        return self.config["modes"][mode]
    
    def get_general_config(self) -> Dict[str, Any]:
        """Get general configuration"""
        return self.config["general"]
    
    def get_tool_config(self, tool: str) -> Dict[str, Any]:
        """Get configuration for specific tool"""
        return self.config["tools"].get(tool, {})
    
    def get_wordlist_path(self, wordlist_type: str) -> str:
        """Get path to wordlist file"""
        return self.config["wordlists"].get(wordlist_type, f"wordlists/{wordlist_type}.txt")
    
    def update_mode_config(self, mode: str, config: Dict[str, Any]):
        """Update configuration for specific mode"""
        if mode in self.config["modes"]:
            self.config["modes"][mode].update(config)
            self.save_config()
        else:
            print(f"[!] Mode {mode} does not exist")
    
    def validate_config(self) -> bool:
        """Validate configuration integrity"""
        required_sections = ["general", "modes", "tools", "wordlists", "output"]
        
        for section in required_sections:
            if section not in self.config:
                print(f"[!] Missing configuration section: {section}")
                return False
        
        # Validate modes
        for mode_name, mode_config in self.config["modes"].items():
            required_keys = ["reconnaissance", "port_scan", "vulnerability_scan"]
            for key in required_keys:
                if key not in mode_config:
                    print(f"[!] Missing {key} in mode {mode_name}")
                    return False
        
        return True
    
    def print_mode_info(self, mode: str = None):
        """Print information about available modes"""
        if mode:
            if mode in self.config["modes"]:
                config = self.config["modes"][mode]
                print(f"\n[+] Mode: {mode.upper()}")
                print(f"Description: {config['description']}")
                print(f"Reconnaissance: {'Enabled' if config['reconnaissance']['enabled'] else 'Disabled'}")
                print(f"Port Scan: {'Enabled' if config['port_scan']['enabled'] else 'Disabled'}")
                print(f"Vulnerability Scan: {'Enabled' if config['vulnerability_scan']['enabled'] else 'Disabled'}")
            else:
                print(f"[!] Mode {mode} not found")
        else:
            print("\n[+] Available scan modes:")
            for mode_name, config in self.config["modes"].items():
                print(f"  {mode_name.upper()}: {config['description']}")
    
    def create_config_template(self):
        """Create a configuration template file"""
        template_file = "config_template.json"
        
        with open(template_file, 'w') as f:
            json.dump(self._get_default_config(), f, indent=2)
        
        print(f"[+] Configuration template created: {template_file}")
        return template_file


def get_config_for_mode(mode: str) -> Dict[str, Any]:
    """Convenience function to get mode configuration"""
    config_manager = ConfigManager()
    return config_manager.get_mode_config(mode)


def list_available_modes():
    """List all available scan modes"""
    config_manager = ConfigManager()
    config_manager.print_mode_info()


if __name__ == "__main__":
    import sys
    
    config = ConfigManager()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "list":
            config.print_mode_info()
        elif command == "validate":
            if config.validate_config():
                print("[+] Configuration is valid")
            else:
                print("[!] Configuration has issues")
        elif command == "template":
            config.create_config_template()
        elif command == "mode" and len(sys.argv) > 2:
            config.print_mode_info(sys.argv[2])
        else:
            print("Usage: python config.py [list|validate|template|mode <mode_name>]")
    else:
        config.print_mode_info()