#!/usr/bin/env python3
"""
Interactive XSS Vulnerability Scanner
Authorized for educational and penetration testing purposes only
USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST
"""

import requests
import json
import time
import re
import html
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional, Any
from datetime import datetime
import sys
import random
import string
import os

@dataclass
class ScanConfig:
    """Configuration for the XSS scanner"""
    target_url: str
    payload_file: str
    output_format: str = "html"
    max_depth: int = 3
    delay: float = 0.5
    user_agent: str = "XSS-Scanner/1.0 (Authorized Security Testing)"
    timeout: int = 10
    follow_redirects: bool = True

@dataclass
class InjectionPoint:
    """Represents a potential injection point"""
    url: str
    method: str
    parameter: str
    context: str
    value_type: str
    element_type: Optional[str] = None

@dataclass
class XSSVulnerability:
    """Represents a discovered XSS vulnerability"""
    target_url: str
    injection_point: InjectionPoint
    payload: str
    vulnerability_type: str
    context: str
    severity: str
    proof_of_concept: str
    confidence: str
    timestamp: str

class XSSScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
        })
        self.payloads = []
        self.vulnerabilities = []
        self.tested_urls = set()
        self.visited_urls = set()
        self.scope_domain = None
        
    def validate_scope(self, url: str) -> bool:
        """Ensure we only scan within authorized scope"""
        if not self.scope_domain:
            parsed = urlparse(self.config.target_url)
            self.scope_domain = parsed.netloc
        
        parsed_url = urlparse(url)
        return parsed_url.netloc == self.scope_domain
    
    def load_payloads(self) -> None:
        """Load XSS payloads from file"""
        try:
            with open(self.config.payload_file, 'r') as f:
                self.payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"[+] Loaded {len(self.payloads)} payloads from {self.config.payload_file}")
        except FileNotFoundError:
            print(f"[-] Payload file not found: {self.config.payload_file}")
            print("[*] Creating a sample payload file...")
            self.create_sample_payload_file()
            print("[+] Please restart the scan with the new payload file")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error loading payloads: {e}")
            sys.exit(1)
    
    def create_sample_payload_file(self):
        """Create a sample payload file"""
        payloads = [
            "# XSS Payload List for Testing",
            "# Use only on authorized systems",
            "",
            "# Basic payloads",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "",
            "# Attribute context",
            "\" onmouseover=\"alert('XSS')\"",
            "' onfocus='alert(\"XSS\")' autofocus ",
            "",
            "# JavaScript context",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "javascript:alert('XSS')",
            "",
            "# DOM-based indicators",
            "<script>document.write('<img src=x onerror=alert(1)>')</script>",
            "",
            "# Bypass attempts",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x oneonerrorrror=alert('XSS')>",
            "",
            "# Modern payloads",
            "<iframe srcdoc=\"<script>alert('XSS')</script>\">",
            "<details open ontoggle=alert('XSS')>",
            "",
            "# Polyglot payload",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert('XSS'))//",
        ]
        
        filename = "xss_payloads.txt"
        with open(filename, 'w') as f:
            for payload in payloads:
                f.write(f"{payload}\n")
        
        print(f"[+] Created sample payload file: {filename}")
        print("[+] Please edit this file to add your own payloads")
    
    def generate_marker(self, length: int = 8) -> str:
        """Generate unique marker for payload detection"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def detect_context(self, html_content: str, param_value: str) -> Tuple[str, Optional[str]]:
        """Detect the context where parameter value appears"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check if value appears in script tags
        scripts = soup.find_all('script')
        for script in scripts:
            if param_value in str(script):
                return "javascript", None
        
        # Check for attribute context
        for tag in soup.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and param_value in value:
                    return "attribute", tag.name
        
        # Check for HTML body context
        if param_value in soup.get_text():
            return "html", None
        
        # Check for URL context (in href/src attributes)
        for tag in soup.find_all(['a', 'img', 'iframe', 'script', 'link']):
            for attr in ['href', 'src', 'data', 'action']:
                if tag.get(attr) and param_value in tag.get(attr):
                    return "url", tag.name
        
        return "unknown", None
    
    def discover_injection_points(self, url: str, depth: int = 0) -> List[InjectionPoint]:
        """Discover potential injection points on the page"""
        if depth > self.config.max_depth or url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.config.timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"[-] Error fetching {url}: {e}")
            return []
        
        injection_points = []
        
        # Discover GET parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param in query_params:
            injection_points.append(InjectionPoint(
                url=url,
                method="GET",
                parameter=param,
                context="url",
                value_type="query"
            ))
        
        # Discover forms and POST parameters
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            form_url = urljoin(url, form_action) if form_action else url
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            params = [inp.get('name') for inp in inputs if inp.get('name')]
            
            for param in params:
                if param:
                    injection_points.append(InjectionPoint(
                        url=form_url,
                        method=form_method.upper(),
                        parameter=param,
                        context="form",
                        value_type="parameter"
                    ))
        
        # Discover links for further crawling
        if depth < self.config.max_depth:
            links = soup.find_all('a', href=True)
            for link in links:
                href = urljoin(url, link['href'])
                if self.validate_scope(href) and href not in self.visited_urls:
                    parsed_href = urlparse(href)
                    if parsed_href.scheme in ['http', 'https']:
                        print(f"  [*] Found link: {href}")
                        time.sleep(self.config.delay)
                        injection_points.extend(self.discover_injection_points(href, depth + 1))
        
        return injection_points
    
    def test_payload(self, injection_point: InjectionPoint, payload: str) -> Optional[Dict[str, Any]]:
        """Test a single payload on an injection point"""
        marker = self.generate_marker()
        tagged_payload = f"{payload}{marker}"
        
        try:
            if injection_point.method == "GET":
                parsed_url = urlparse(injection_point.url)
                query_params = parse_qs(parsed_url.query)
                
                # Replace all values of the parameter with our payload
                query_params[injection_point.parameter] = [tagged_payload]
                
                # Reconstruct URL
                new_query = urlencode(query_params, doseq=True)
                target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                response = self.session.get(target_url, timeout=self.config.timeout)
            
            else:  # POST
                # First get the form to understand all parameters
                response = self.session.get(injection_point.url, timeout=self.config.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                form = soup.find('form')
                
                if not form:
                    return None
                
                # Build form data with payload
                data = {}
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        if name == injection_point.parameter:
                            data[name] = tagged_payload
                        else:
                            # Use default values
                            if inp.get('type') == 'checkbox' or inp.get('type') == 'radio':
                                if inp.get('checked'):
                                    data[name] = inp.get('value', 'on')
                            elif inp.get('value'):
                                data[name] = inp.get('value')
                            else:
                                data[name] = 'test'
                
                response = self.session.post(injection_point.url, data=data, timeout=self.config.timeout)
            
            # Check for payload reflection
            response_text = response.text
            
            # Check if marker appears in response
            if marker in response_text:
                # Determine context and vulnerability type
                context, element_type = self.detect_context(response_text, marker)
                
                # Determine XSS type
                xss_type = "reflected"
                
                # Check if stored (would appear in subsequent requests)
                if injection_point.method == "POST":
                    time.sleep(1)
                    follow_up = self.session.get(injection_point.url, timeout=self.config.timeout)
                    if marker in follow_up.text:
                        xss_type = "stored"
                
                # Determine severity
                severity = self.calculate_severity(context, xss_type)
                confidence = self.calculate_confidence(marker, response_text)
                
                return {
                    'success': True,
                    'payload': payload,
                    'tagged_payload': tagged_payload,
                    'context': context,
                    'element_type': element_type,
                    'type': xss_type,
                    'severity': severity,
                    'confidence': confidence,
                    'response': response_text
                }
            
            # Check for DOM-based XSS (would require browser simulation)
            # This is a simplified check
            if self.check_dom_based_indicator(response_text, payload):
                return {
                    'success': True,
                    'payload': payload,
                    'context': 'javascript',
                    'type': 'dom',
                    'severity': 'medium',
                    'confidence': 'low',
                    'response': response_text
                }
            
        except requests.RequestException as e:
            print(f"[-] Request failed for {injection_point.url}: {e}")
        
        return None
    
    def calculate_severity(self, context: str, xss_type: str) -> str:
        """Calculate severity based on context and type"""
        if xss_type == "stored":
            return "high"
        elif context == "javascript":
            return "high"
        elif context == "attribute":
            return "medium"
        elif context == "html":
            return "medium"
        else:
            return "low"
    
    def calculate_confidence(self, marker: str, response: str) -> str:
        """Calculate confidence level based on payload reflection"""
        occurrences = response.count(marker)
        
        if occurrences > 3:
            return "high"
        elif occurrences > 1:
            return "medium"
        else:
            return "low"
    
    def check_dom_based_indicator(self, response: str, payload: str) -> bool:
        """Check for indicators of DOM-based XSS"""
        indicators = [
            'innerHTML',
            'document.write',
            'eval(',
            'setTimeout(',
            'setInterval(',
            'location.',
            'document.cookie',
            'window.name'
        ]
        
        soup = BeautifulSoup(response, 'html.parser')
        scripts = soup.find_all('script')
        
        for script in scripts:
            script_text = str(script)
            for indicator in indicators:
                if indicator in script_text:
                    # Check if any part of payload appears near indicator
                    payload_parts = payload.replace('<', '').replace('>', '').split()
                    for part in payload_parts:
                        if part and len(part) > 3 and part in script_text:
                            return True
        
        return False
    
    def scan(self) -> List[XSSVulnerability]:
        """Main scanning function"""
        print(f"\n{'='*60}")
        print(f"Starting XSS scan on: {self.config.target_url}")
        print(f"{'='*60}")
        
        # Load payloads
        self.load_payloads()
        
        # Discover injection points
        print("\n[*] Discovering injection points...")
        injection_points = self.discover_injection_points(self.config.target_url)
        print(f"[+] Found {len(injection_points)} potential injection points")
        
        # Test each injection point with each payload
        total_tests = len(injection_points) * len(self.payloads)
        test_count = 0
        
        print(f"[*] Starting payload testing...")
        print(f"[*] Total tests to perform: {total_tests}")
        
        for i, point in enumerate(injection_points):
            print(f"\n[*] Testing injection point {i+1}/{len(injection_points)}")
            print(f"    Parameter: {point.parameter}")
            print(f"    Method: {point.method}")
            print(f"    URL: {point.url}")
            
            for j, payload in enumerate(self.payloads):
                test_count += 1
                
                # Show progress every 5 tests
                if test_count % 5 == 0:
                    print(f"    [*] Progress: {test_count}/{total_tests} tests completed")
                
                result = self.test_payload(point, payload)
                
                if result and result['success']:
                    print(f"    [+] VULNERABILITY FOUND!")
                    print(f"        Type: {result['type']}")
                    print(f"        Severity: {result['severity']}")
                    print(f"        Context: {result['context']}")
                    print(f"        Payload: {payload[:50]}..." if len(payload) > 50 else f"        Payload: {payload}")
                    
                    vulnerability = XSSVulnerability(
                        target_url=self.config.target_url,
                        injection_point=point,
                        payload=payload,
                        vulnerability_type=result['type'],
                        context=result['context'],
                        severity=result['severity'],
                        proof_of_concept=self.generate_poc(point, payload, result['type']),
                        confidence=result['confidence'],
                        timestamp=datetime.now().isoformat()
                    )
                    
                    self.vulnerabilities.append(vulnerability)
                
                time.sleep(self.config.delay)
        
        return self.vulnerabilities
    
    def generate_poc(self, point: InjectionPoint, payload: str, vuln_type: str) -> str:
        """Generate proof of concept"""
        if point.method == "GET":
            parsed = urlparse(point.url)
            query_params = parse_qs(parsed.query)
            query_params[point.parameter] = [payload]
            new_query = urlencode(query_params, doseq=True)
            poc_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            return f"GET {poc_url}"
        else:
            return f"POST {point.url}\nParameter: {point.parameter}\nValue: {payload}"
    
    def generate_report(self, format_type: str = "html") -> str:
        """Generate vulnerability report"""
        if format_type.lower() == "json":
            return self.generate_json_report()
        else:
            return self.generate_html_report()
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            "scan_date": datetime.now().isoformat(),
            "target_url": self.config.target_url,
            "payload_file": self.config.payload_file,
            "vulnerabilities_found": len(self.vulnerabilities),
            "vulnerabilities": [
                {
                    "url": vuln.injection_point.url,
                    "parameter": vuln.injection_point.parameter,
                    "method": vuln.injection_point.method,
                    "payload": vuln.payload,
                    "type": vuln.vulnerability_type,
                    "context": vuln.context,
                    "severity": vuln.severity,
                    "confidence": vuln.confidence,
                    "proof_of_concept": vuln.proof_of_concept,
                    "timestamp": vuln.timestamp
                }
                for vuln in self.vulnerabilities
            ]
        }
        return json.dumps(report, indent=2)
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>XSS Vulnerability Scan Report</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
                .header { background: linear-gradient(135deg, #2c3e50, #4a6491); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
                .summary { background: #f8f9fa; padding: 25px; margin: 25px 0; border-radius: 10px; border-left: 5px solid #3498db; }
                .vulnerability { background: #fff; border: 1px solid #e0e0e0; margin: 25px 0; padding: 25px; border-radius: 10px; transition: transform 0.2s; }
                .vulnerability:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
                .high { border-left: 5px solid #e74c3c; }
                .medium { border-left: 5px solid #f39c12; }
                .low { border-left: 5px solid #f1c40f; }
                .severity { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin: 5px; }
                .severity-high { background: linear-gradient(135deg, #e74c3c, #c0392b); }
                .severity-medium { background: linear-gradient(135deg, #f39c12, #d35400); }
                .severity-low { background: linear-gradient(135deg, #f1c40f, #f39c12); }
                pre { background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; margin: 15px 0; }
                code { background: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
                table { width: 100%; border-collapse: collapse; margin: 15px 0; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }
                th { background: #f8f9fa; font-weight: 600; }
                h1 { margin: 0; font-size: 2.5em; }
                h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h3 { color: #34495e; }
                .poc { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 15px 0; }
                .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #7f8c8d; font-size: 0.9em; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
                .stat-value { font-size: 2.5em; font-weight: bold; color: #2c3e50; }
                .stat-label { color: #7f8c8d; font-size: 0.9em; }
                .scan-info { background: #e8f4fc; padding: 15px; border-radius: 5px; margin: 15px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 XSS Vulnerability Scan Report</h1>
                    <p><strong>Generated:</strong> {scan_date}</p>
                    <p><strong>Target URL:</strong> {target_url}</p>
                    <p><strong>Payload File:</strong> {payload_file}</p>
                </div>
                
                <div class="summary">
                    <h2>📊 Scan Summary</h2>
                    <div class="scan-info">
                        <p><strong>Scanner Version:</strong> XSS-Scanner v2.0</p>
                        <p><strong>Scan Duration:</strong> {scan_duration}</p>
                        <p><strong>Scope Domain:</strong> {scope_domain}</p>
                    </div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value">{vuln_count}</div>
                            <div class="stat-label">Total Vulnerabilities</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{high_count}</div>
                            <div class="stat-label">High Severity</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{medium_count}</div>
                            <div class="stat-label">Medium Severity</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{low_count}</div>
                            <div class="stat-label">Low Severity</div>
                        </div>
                    </div>
                </div>
                
                <h2>🎯 Discovered Vulnerabilities</h2>
                {vulnerabilities}
                
                <div class="summary">
                    <h2>🛡️ Remediation Recommendations</h2>
                    <table>
                        <tr>
                            <th>Context</th>
                            <th>Solution</th>
                        </tr>
                        <tr>
                            <td><strong>HTML Context</strong></td>
                            <td>Use HTML entity encoding: <code>&amp;lt;</code> for &lt;, <code>&amp;gt;</code> for &gt;</td>
                        </tr>
                        <tr>
                            <td><strong>Attribute Context</strong></td>
                            <td>Always quote attributes and use attribute encoding</td>
                        </tr>
                        <tr>
                            <td><strong>JavaScript Context</strong></td>
                            <td>Use JavaScript encoding and avoid <code>eval()</code>, <code>innerHTML</code></td>
                        </tr>
                        <tr>
                            <td><strong>URL Context</strong></td>
                            <td>Validate and encode URL parameters</td>
                        </tr>
                    </table>
                    
                    <h3>Best Practices:</h3>
                    <ul>
                        <li>Implement Content Security Policy (CSP) headers</li>
                        <li>Use frameworks with built-in XSS protection (React, Angular, Vue)</li>
                        <li>Enable HttpOnly flag for all cookies</li>
                        <li>Regular security testing and code reviews</li>
                        <li>Use Web Application Firewalls (WAF)</li>
                        <li>Implement input validation and output encoding libraries</li>
                    </ul>
                </div>
                
                <div class="footer">
                    <p><strong>⚠️ IMPORTANT:</strong> This report is for authorized security testing purposes only.</p>
                    <p>Unauthorized testing is illegal and unethical. Always obtain proper authorization.</p>
                    <p>Report generated by XSS Vulnerability Scanner v2.0 | {scan_date}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Calculate severity counts
        severity_counts = {"high": 0, "medium": 0, "low": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.lower()] += 1
        
        # Get scope domain
        parsed_url = urlparse(self.config.target_url)
        scope_domain = parsed_url.netloc
        
        # Generate vulnerability sections
        vuln_sections = ""
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                vuln_sections += f"""
                <div class="vulnerability {vuln.severity.lower()}">
                    <h3>Vulnerability #{i}: {vuln.injection_point.parameter} ({vuln.vulnerability_type.upper()} XSS)</h3>
                    <p><strong>Severity:</strong> <span class="severity severity-{vuln.severity.lower()}">{vuln.severity.upper()}</span></p>
                    <p><strong>Confidence:</strong> {vuln.confidence.upper()}</p>
                    <p><strong>Type:</strong> {vuln.vulnerability_type.upper()} XSS</p>
                    <p><strong>Context:</strong> {vuln.context.upper()}</p>
                    
                    <table>
                        <tr>
                            <th>URL</th>
                            <td>{vuln.injection_point.url}</td>
                        </tr>
                        <tr>
                            <th>Method</th>
                            <td>{vuln.injection_point.method}</td>
                        </tr>
                        <tr>
                            <th>Parameter</th>
                            <td><code>{vuln.injection_point.parameter}</code></td>
                        </tr>
                    </table>
                    
                    <p><strong>Successful Payload:</strong></p>
                    <pre>{html.escape(vuln.payload)}</pre>
                    
                    <p><strong>Proof of Concept:</strong></p>
                    <div class="poc">
                        <pre>{html.escape(vuln.proof_of_concept)}</pre>
                    </div>
                    
                    <p><strong>Timestamp:</strong> {vuln.timestamp}</p>
                </div>
                """
        else:
            vuln_sections = """
            <div class="summary" style="text-align: center; padding: 40px;">
                <h2 style="color: #27ae60;">✅ No Vulnerabilities Found</h2>
                <p>The scanner did not find any XSS vulnerabilities in the tested parameters.</p>
                <p><strong>Note:</strong> This doesn't guarantee the application is completely secure. 
                Continue regular security testing and follow security best practices.</p>
            </div>
            """
        
        return html_template.format(
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_url=self.config.target_url,
            payload_file=self.config.payload_file,
            vuln_count=len(self.vulnerabilities),
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            scope_domain=scope_domain,
            scan_duration="See scan log for details",
            vulnerabilities=vuln_sections
        )

def display_banner():
    """Display the tool banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║          🚀 INTERACTIVE XSS VULNERABILITY SCANNER            ║
    ║               v2.0 - For Authorized Testing Only             ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    """
    print(banner)

def get_user_input():
    """Get input from user interactively"""
    print("\n" + "="*70)
    print("SETUP INTERACTIVE SCAN")
    print("="*70)
    
    # Get target URL
    while True:
        target_url = input("\n🔗 ENTER THE TARGET URL: ").strip()
        if not target_url:
            print("[-] URL cannot be empty. Please try again.")
            continue
        
        # Validate URL format
        if not target_url.startswith(('http://', 'https://')):
            print("[-] URL must start with http:// or https://")
            continue
        
        print(f"[+] Target URL set to: {target_url}")
        break
    
    # Get payload file
    while True:
        payload_file = input("\n📄 ENTER YOUR PAYLOAD FILE (or press Enter for default 'xss_payloads.txt'): ").strip()
        
        if not payload_file:
            payload_file = "xss_payloads.txt"
            print(f"[+] Using default payload file: {payload_file}")
        
        # Check if file exists
        if not os.path.exists(payload_file):
            print(f"[-] Payload file not found: {payload_file}")
            
            create_new = input("[?] Would you like to create a sample payload file? (yes/no): ").strip().lower()
            if create_new == 'yes':
                scanner = XSSScanner(ScanConfig(target_url="", payload_file=""))
                scanner.create_sample_payload_file()
                print("[+] Please restart the scan")
                sys.exit(0)
            else:
                print("[-] Please provide a valid payload file path")
                continue
        
        print(f"[+] Payload file set to: {payload_file}")
        break
    
    # Get output format
    while True:
        output_format = input("\n📊 ENTER OUTPUT FORMAT (html/json, default: html): ").strip().lower()
        if not output_format:
            output_format = "html"
            print(f"[+] Using default output format: {output_format}")
            break
        elif output_format in ['html', 'json']:
            print(f"[+] Output format set to: {output_format}")
            break
        else:
            print("[-] Invalid format. Please enter 'html' or 'json'")
    
    # Get output file name
    while True:
        default_output = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{output_format}"
        output_file = input(f"\n💾 ENTER OUTPUT FILE NAME (or press Enter for '{default_output}'): ").strip()
        
        if not output_file:
            output_file = default_output
            print(f"[+] Output file set to: {output_file}")
            break
        
        # Ensure correct file extension
        if not output_file.endswith(f'.{output_format}'):
            output_file = f"{output_file}.{output_format}"
            print(f"[+] Adjusted output file name to: {output_file}")
        
        print(f"[+] Output file set to: {output_file}")
        break
    
    # Get request delay
    while True:
        delay_input = input("\n⏱️ ENTER REQUEST DELAY IN SECONDS (default: 0.5): ").strip()
        if not delay_input:
            delay = 0.5
            print(f"[+] Using default delay: {delay} seconds")
            break
        try:
            delay = float(delay_input)
            if delay < 0:
                print("[-] Delay cannot be negative")
                continue
            print(f"[+] Request delay set to: {delay} seconds")
            break
        except ValueError:
            print("[-] Please enter a valid number")
    
    return {
        'target_url': target_url,
        'payload_file': payload_file,
        'output_format': output_format,
        'output_file': output_file,
        'delay': delay
    }

def confirm_authorization():
    """Get user confirmation for authorized testing"""
    print("\n" + "="*70)
    print("⚠️  AUTHORIZATION CONFIRMATION REQUIRED ⚠️")
    print("="*70)
    print("\nBy using this tool, you CONFIRM that:")
    print("1. ✅ You have LEGAL AUTHORIZATION to test the target system")
    print("2. ✅ You have WRITTEN PERMISSION from the system owner")
    print("3. ✅ You understand UNAUTHORIZED testing is ILLEGAL")
    print("4. ✅ You will use this tool RESPONSIBLY and ETHICALLY")
    print("\n" + "-"*70)
    
    response = input("\n🔐 Do you confirm ALL of the above? (Type 'AUTHORIZE' to continue): ").strip()
    
    if response.upper() != "AUTHORIZE":
        print("\n" + "="*70)
        print("❌ SCAN CANCELLED")
        print("="*70)
        print("\nThis tool requires explicit authorization confirmation.")
        print("Only proceed if you have proper legal authorization.")
        print("\nExiting...")
        sys.exit(0)
    
    print("\n" + "="*70)
    print("✅ AUTHORIZATION CONFIRMED")
    print("="*70)
    print("\nStarting scan with authorized credentials...\n")

def main():
    """Main interactive function"""
    # Display banner
    display_banner()
    
    # Confirm authorization
    confirm_authorization()
    
    # Get user input interactively
    user_input = get_user_input()
    
    # Configure scanner
    config = ScanConfig(
        target_url=user_input['target_url'],
        payload_file=user_input['payload_file'],
        output_format=user_input['output_format'],
        delay=user_input['delay']
    )
    
    # Create scanner instance
    scanner = XSSScanner(config)
    
    # Record start time
    start_time = time.time()
    
    try:
        # Run scan
        vulnerabilities = scanner.scan()
        
        # Record end time
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Generate report
        print(f"\n{'='*60}")
        print("[*] Generating scan report...")
        report = scanner.generate_report(config.output_format)
        
        # Save report
        with open(user_input['output_file'], 'w') as f:
            f.write(report)
        
        # Display summary
        print(f"\n{'='*60}")
        print("📋 SCAN COMPLETE - SUMMARY")
        print("="*60)
        print(f"✅ Target: {config.target_url}")
        print(f"✅ Vulnerabilities Found: {len(vulnerabilities)}")
        print(f"✅ Scan Duration: {scan_duration:.2f} seconds")
        print(f"✅ Report Saved: {user_input['output_file']}")
        print(f"✅ Payloads Used: {len(scanner.payloads)}")
        
        if vulnerabilities:
            print(f"\n📊 Severity Breakdown:")
            severity_counts = {"high": 0, "medium": 0, "low": 0}
            for vuln in vulnerabilities:
                severity_counts[vuln.severity.lower()] += 1
            
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"   • {severity.upper()}: {count}")
            
            print(f"\n🔍 Top Vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                print(f"   {i}. {vuln.severity.upper()} - {vuln.vulnerability_type} XSS in {vuln.injection_point.parameter}")
            
            if len(vulnerabilities) > 5:
                print(f"   ... and {len(vulnerabilities) - 5} more")
        
        print(f"\n📁 Next Steps:")
        print(f"   1. Review the report: {user_input['output_file']}")
        print(f"   2. Validate findings manually")
        print(f"   3. Report vulnerabilities to development team")
        print(f"   4. Schedule retesting after fixes")
        
        print(f"\n{'='*60}")
        print("⚠️  REMINDER: This scan was for AUTHORIZED testing only")
        print("="*60)
        
    except KeyboardInterrupt:
        print(f"\n\n❌ Scan interrupted by user")
        print("[*] Partial results saved if available")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n[-] Scan failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()