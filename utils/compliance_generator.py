from typing import List, Dict
from datetime import datetime

class ComplianceGenerator:
    def __init__(self):
        self.frameworks = {
            'OWASP Top 10': self._owasp_top10_mapping,
            'PCI-DSS': self._pci_dss_mapping,
            'HIPAA': self._hipaa_mapping,
            'ISO27001': self._iso27001_mapping
        }
    
    def generate_compliance_report(self, vulnerabilities: List[Dict], framework: str) -> Dict:
        mapping_func = self.frameworks.get(framework, self._owasp_top10_mapping)
        compliance_issues = []
        for vuln in vulnerabilities:
            compliance_issues.append(mapping_func(vuln))
        return {
            'framework': framework,
            'generated_at': datetime.now().isoformat(),
            'total_issues': len(compliance_issues),
            'issues': compliance_issues
        }
    
    def _owasp_top10_mapping(self, vuln: Dict) -> Dict:
        mapping = {
            'Injection': 'A03:2021 - Injection',
            'Broken Authentication': 'A07:2021 - Identification and Authentication Failures',
            'Sensitive Data Exposure': 'A02:2021 - Cryptographic Failures',
            'XML External Entity': 'A03:2021 - Injection',
            'Broken Access Control': 'A01:2021 - Broken Access Control',
            'Security Misconfiguration': 'A05:2021 - Security Misconfiguration',
            'XSS': 'A03:2021 - Injection',
            'Insecure Deserialization': 'A08:2021 - Software and Data Integrity Failures',
            'Using Components with Known Vulnerabilities': 'A06:2021 - Vulnerable and Outdated Components',
            'Insufficient Logging': 'A09:2021 - Security Logging and Monitoring Failures'
        }
        return {
            'vulnerability_type': vuln.get('type', ''),
            'owasp_mapping': mapping.get(vuln.get('type', ''), 'Unknown'),
            'severity': vuln.get('severity', ''),
            'description': vuln.get('description', '')
        }
    
    def _pci_dss_mapping(self, vuln: Dict) -> Dict:
        return {
            'vulnerability_type': vuln.get('type', ''),
            'pci_requirement': '6.5.1',
            'description': f"PCI-DSS violation: {vuln.get('description', '')}"
        }
    
    def _hipaa_mapping(self, vuln: Dict) -> Dict:
        return {
            'vulnerability_type': vuln.get('type', ''),
            'hipaa_rule': 'Security Rule',
            'description': f"HIPAA violation: {vuln.get('description', '')}"
        }
    
    def _iso27001_mapping(self, vuln: Dict) -> Dict:
        return {
            'vulnerability_type': vuln.get('type', ''),
            'iso_control': 'A.14.2.1',
            'description': f"ISO27001 violation: {vuln.get('description', '')}"
        }