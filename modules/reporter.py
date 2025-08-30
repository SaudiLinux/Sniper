#!/usr/bin/env python3
"""
SniperSayer Reporting Module
Author: SaudiLinux (https://github.com/SaudiLinux)
Email: SaudiLinux1@gmail.com

This module handles report generation and result categorization
with multiple output formats (JSON, HTML, CSV)
"""

import json
import csv
import os
from datetime import datetime
from collections import defaultdict
import xml.etree.ElementTree as ET


class ReportGenerator:
    """Main report generation class"""
    
    def __init__(self, target, output_dir="reports"):
        self.target = target
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize report structure
        self.report = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'summary': {},
            'reconnaissance': {},
            'port_scan': {},
            'vulnerabilities': {},
            'recommendations': []
        }
    
    def load_scan_results(self, results_dir="reports"):
        """Load all scan results from files"""
        results = {}
        
        # Load reconnaissance results
        recon_file = f"{results_dir}/recon_{self.target}.json"
        if os.path.exists(recon_file):
            with open(recon_file, 'r') as f:
                results['reconnaissance'] = json.load(f)
        
        # Load port scan results
        portscan_file = f"{results_dir}/portscan_{self.target}.json"
        if os.path.exists(portscan_file):
            with open(portscan_file, 'r') as f:
                results['port_scan'] = json.load(f)
        
        # Load vulnerability scan results
        vulnscan_file = f"{results_dir}/vulnscan_{self.target}.json"
        if os.path.exists(vulnscan_file):
            with open(vulnscan_file, 'r') as f:
                results['vulnerabilities'] = json.load(f)
        
        return results
    
    def categorize_results(self, results):
        """Categorize and organize scan results"""
        categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        # Categorize vulnerabilities
        if 'vulnerabilities' in results:
            vuln_data = results['vulnerabilities']
            
            # Nikto findings
            for vuln in vuln_data.get('nikto', []):
                severity = vuln.get('severity', 'info').lower()
                if severity in categorized:
                    categorized[severity].append({
                        'source': 'nikto',
                        'type': 'web_vulnerability',
                        'details': vuln
                    })
            
            # WPScan findings
            for vuln in vuln_data.get('wpscan', []):
                severity = vuln.get('severity', 'info').lower()
                if severity in categorized:
                    categorized[severity].append({
                        'source': 'wpscan',
                        'type': vuln.get('type', 'wordpress_vulnerability'),
                        'details': vuln
                    })
            
            # Custom checks
            for vuln in vuln_data.get('custom_checks', []):
                severity = vuln.get('severity', 'info').lower()
                if severity in categorized:
                    categorized[severity].append({
                        'source': 'custom',
                        'type': vuln.get('type', 'security_issue'),
                        'details': vuln
                    })
        
        # Categorize open ports
        if 'port_scan' in results:
            port_data = results['port_scan']
            for host in port_data.get('hosts', []):
                for port in host.get('ports', []):
                    if port.get('state') == 'open':
                        service = port.get('service', {})
                        
                        # Determine severity based on service
                        severity = 'info'
                        if service.get('name') in ['ftp', 'telnet', 'ssh']:
                            severity = 'medium'
                        elif service.get('name') in ['mysql', 'postgresql', 'mongodb']:
                            severity = 'high'
                        elif service.get('name') in ['ms-sql-s', 'oracle', 'redis']:
                            severity = 'critical'
                        
                        categorized[severity].append({
                            'source': 'nmap',
                            'type': 'open_port',
                            'details': {
                                'port': port.get('port'),
                                'service': service.get('name'),
                                'version': service.get('version'),
                                'banner': service.get('product')
                            }
                        })
        
        return categorized
    
    def generate_json_report(self, results, filename=None):
        """Generate comprehensive JSON report"""
        if not filename:
            filename = f"{self.output_dir}/report_{self.target}_{self.timestamp}.json"
        
        # Build report structure
        report = {
            'target': self.target,
            'scan_metadata': {
                'scan_date': datetime.now().isoformat(),
                'report_version': '1.0',
                'scanner': 'SniperSayer',
                'author': 'SaudiLinux'
            },
            'executive_summary': self._generate_executive_summary(results),
            'detailed_findings': self.categorize_results(results),
            'raw_results': results
        }
        
        # Save JSON report
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"[+] JSON report saved: {filename}")
        return filename
    
    def generate_html_report(self, results, filename=None):
        """Generate professional HTML report"""
        if not filename:
            filename = f"{self.output_dir}/report_{self.target}_{self.timestamp}.html"
        
        categorized = self.categorize_results(results)
        summary = self._generate_executive_summary(results)
        
        html_content = self._build_html_template(categorized, summary, results)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report saved: {filename}")
        return filename
    
    def generate_csv_report(self, results, filename=None):
        """Generate CSV report with findings"""
        if not filename:
            filename = f"{self.output_dir}/report_{self.target}_{self.timestamp}.csv"
        
        categorized = self.categorize_results(results)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['severity', 'source', 'type', 'description', 'details']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for severity, findings in categorized.items():
                for finding in findings:
                    writer.writerow({
                        'severity': severity.upper(),
                        'source': finding['source'],
                        'type': finding['type'],
                        'description': self._get_description(finding),
                        'details': json.dumps(finding['details'])
                    })
        
        print(f"[+] CSV report saved: {filename}")
        return filename
    
    def _generate_executive_summary(self, results):
        """Generate executive summary"""
        categorized = self.categorize_results(results)
        
        summary = {
            'total_findings': sum(len(findings) for findings in categorized.values()),
            'severity_breakdown': {
                'critical': len(categorized['critical']),
                'high': len(categorized['high']),
                'medium': len(categorized['medium']),
                'low': len(categorized['low']),
                'info': len(categorized['info'])
            },
            'risk_score': self._calculate_risk_score(categorized),
            'key_findings': self._extract_key_findings(categorized),
            'recommendations': self._generate_recommendations(categorized, results)
        }
        
        return summary
    
    def _calculate_risk_score(self, categorized):
        """Calculate overall risk score"""
        weights = {'critical': 10, 'high': 7, 'medium': 5, 'low': 2, 'info': 0}
        score = 0
        
        for severity, findings in categorized.items():
            score += len(findings) * weights.get(severity, 0)
        
        # Normalize to 0-100 scale
        max_possible = sum(weights.values()) * 20  # Assume max 20 findings per severity
        risk_score = min(int((score / max_possible) * 100), 100)
        
        return risk_score
    
    def _extract_key_findings(self, categorized):
        """Extract most important findings"""
        key_findings = []
        
        # Prioritize critical and high severity
        for severity in ['critical', 'high']:
            for finding in categorized.get(severity, []):
                key_findings.append({
                    'severity': severity.upper(),
                    'type': finding['type'],
                    'brief': self._get_brief_description(finding)
                })
        
        return key_findings[:5]  # Top 5 key findings
    
    def _generate_recommendations(self, categorized, results):
        """Generate actionable recommendations"""
        recommendations = []
        
        # Based on open ports
        port_findings = [f for findings in categorized.values() for f in findings if f['type'] == 'open_port']
        for finding in port_findings:
            service = finding['details'].get('service')
            port = finding['details'].get('port')
            
            if service == 'ftp' and port == 21:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Network Security',
                    'recommendation': f'Close FTP port {port} or secure with TLS/SSL'
                })
            elif service in ['mysql', 'postgresql']:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Database Security',
                    'recommendation': f'Restrict access to {service} port {port} to trusted IPs only'
                })
        
        # Based on web vulnerabilities
        web_vulns = [f for findings in categorized.values() for f in findings if f['source'] in ['nikto', 'wpscan']]
        if web_vulns:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Web Application Security',
                'recommendation': 'Update all web applications and plugins to latest versions'
            })
        
        # Based on missing security headers
        header_issues = [f for findings in categorized.values() for f in findings if f['type'] == 'missing_security_headers']
        if header_issues:
            recommendations.append({
                'priority': 'LOW',
                'category': 'HTTP Security',
                'recommendation': 'Implement security headers (CSP, HSTS, X-Frame-Options)'
            })
        
        return recommendations
    
    def _get_description(self, finding):
        """Get human-readable description for finding"""
        if finding['type'] == 'open_port':
            return f"Open port {finding['details'].get('port')} ({finding['details'].get('service')})"
        elif finding['type'] == 'web_vulnerability':
            return finding['details'].get('description', 'Web vulnerability detected')
        else:
            return finding['type'].replace('_', ' ').title()
    
    def _get_brief_description(self, finding):
        """Get brief description for key findings"""
        if finding['type'] == 'open_port':
            return f"Port {finding['details'].get('port')} open"
        elif finding['type'] == 'web_vulnerability':
            return finding['details'].get('description', 'Vulnerability')[:50] + "..."
        else:
            return finding['type']
    
    def _build_html_template(self, categorized, summary, results):
        """Build comprehensive HTML report template"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SniperSayer Security Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .severity-critical {{ color: #d32f2f; font-weight: bold; }}
        .severity-high {{ color: #f57c00; font-weight: bold; }}
        .severity-medium {{ color: #fbc02d; font-weight: bold; }}
        .severity-low {{ color: #388e3c; font-weight: bold; }}
        .severity-info {{ color: #1976d2; font-weight: bold; }}
        .summary-card {{ background: #f9f9f9; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ border-left: 4px solid #ddd; padding: 15px; margin: 10px 0; background: #fafafa; }}
        .recommendation {{ background: #e3f2fd; padding: 15px; margin: 10px 0; border-left: 4px solid #2196f3; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SniperSayer Security Report</h1>
            <h2>Target: {self.target}</h2>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>By: SaudiLinux (https://github.com/SaudiLinux)</p>
        </div>
        
        <div class="summary-card">
            <h3>📊 Executive Summary</h3>
            <p><strong>Risk Score:</strong> {summary['risk_score']}/100</p>
            <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
            <div style="display: flex; gap: 20px;">
                <span class="severity-critical">Critical: {summary['severity_breakdown']['critical']}</span>
                <span class="severity-high">High: {summary['severity_breakdown']['high']}</span>
                <span class="severity-medium">Medium: {summary['severity_breakdown']['medium']}</span>
                <span class="severity-low">Low: {summary['severity_breakdown']['low']}</span>
                <span class="severity-info">Info: {summary['severity_breakdown']['info']}</span>
            </div>
        </div>
        
        <h3>🔑 Key Findings</h3>
        <ul>
        """
        
        for finding in summary['key_findings']:
            html += f"<li><strong>[{finding['severity']}]</strong> {finding['brief']}</li>"
        
        html += "</ul>"
        
        # Add detailed findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = categorized.get(severity, [])
            if findings:
                html += f"<h3 class='severity-{severity}'>⚠️ {severity.upper()} Severity Findings ({len(findings)})</h3>"
                
                for finding in findings:
                    html += f"""
                    <div class="finding">
                        <strong>Source:</strong> {finding['source']}<br>
                        <strong>Type:</strong> {finding['type']}<br>
                        <strong>Description:</strong> {self._get_description(finding)}<br>
                        <strong>Details:</strong> <pre>{json.dumps(finding['details'], indent=2)}</pre>
                    </div>
                    """
        
        # Add recommendations
        html += "<h3>💡 Recommendations</h3>"
        for rec in summary['recommendations']:
            html += f"""
            <div class="recommendation">
                <strong>[{rec['priority']}] {rec['category']}:</strong><br>
                {rec['recommendation']}
            </div>
            """
        
        html += """
    </div>
</body>
</html>
        """
        
        return html
    
    def generate_all_reports(self, results_dir="reports"):
        """Generate all report formats"""
        results = self.load_scan_results(results_dir)
        
        if not any(results.values()):
            print("[!] No scan results found to generate reports")
            return
        
        # Generate all formats
        json_file = self.generate_json_report(results)
        html_file = self.generate_html_report(results)
        csv_file = self.generate_csv_report(results)
        
        print(f"[+] All reports generated successfully")
        print(f"    JSON: {json_file}")
        print(f"    HTML: {html_file}")
        print(f"    CSV: {csv_file}")
        
        return {
            'json': json_file,
            'html': html_file,
            'csv': csv_file
        }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python reporter.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    reporter = ReportGenerator(target)
    reports = reporter.generate_all_reports()
    
    print(f"Reports generated for {target}")
    for format_name, filepath in reports.items():
        print(f"  {format_name.upper()}: {filepath}")