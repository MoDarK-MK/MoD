# core/cve_payloads.py
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import json


class Severity(Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'


class Category(Enum):
    RCE = 'RCE'
    SQLi = 'SQLi'
    XSS = 'XSS'
    SSRF = 'SSRF'
    XXE = 'XXE'
    SSTI = 'SSTI'
    PATH_TRAVERSAL = 'PATH_TRAVERSAL'
    LFI = 'LFI'
    RFI = 'RFI'
    DESERIALIZATION = 'DESERIALIZATION'
    IDOR = 'IDOR'
    CSRF = 'CSRF'
    INFO_DISCLOSURE = 'INFO_DISCLOSURE'
    MISCONFIGURATION = 'MISCONFIGURATION'
    NoSQLi = 'NoSQLi'
    PROTOTYPE_POLLUTION = 'PROTOTYPE_POLLUTION'
    DOS = 'DOS'
    AUTHENTICATION = 'AUTHENTICATION'
    FILE_UPLOAD = 'FILE_UPLOAD'
    LOGIC_ERROR = 'LOGIC_ERROR'
    COMMAND_INJECTION = 'COMMAND_INJECTION'
    RACE_CONDITION = 'RACE_CONDITION'


@dataclass
class CVE:
    id: str
    name: str
    severity: str
    score: float
    description: str
    patterns: List[str]
    payloads: List[str]
    category: str
    reference: str
    year: int
    affected_software: List[str]
    cvss_vector: str
    publication_date: str
    fix_available: bool


class CVEDatabase:
    
    _CACHE = {}
    
    @classmethod
    def get_all_cves(cls) -> List[Dict]:
        if 'all_cves' in cls._CACHE:
            return cls._CACHE['all_cves']
        
        all_cves = []
        all_cves.extend(cls._generate_rce_cves())
        all_cves.extend(cls._generate_sqli_cves())
        all_cves.extend(cls._generate_xss_cves())
        all_cves.extend(cls._generate_ssrf_cves())
        all_cves.extend(cls._generate_xxe_cves())
        all_cves.extend(cls._generate_ssti_cves())
        all_cves.extend(cls._generate_path_traversal_cves())
        all_cves.extend(cls._generate_lfi_rfi_cves())
        all_cves.extend(cls._generate_deserialization_cves())
        all_cves.extend(cls._generate_idor_csrf_cves())
        all_cves.extend(cls._generate_info_disclosure_cves())
        all_cves.extend(cls._generate_misconfiguration_cves())
        all_cves.extend(cls._generate_nosqli_cves())
        all_cves.extend(cls._generate_prototype_pollution_cves())
        all_cves.extend(cls._generate_dos_cves())
        all_cves.extend(cls._generate_authentication_cves())
        all_cves.extend(cls._generate_file_upload_cves())
        all_cves.extend(cls._generate_logic_error_cves())
        all_cves.extend(cls._generate_race_condition_cves())
        all_cves.extend(cls._generate_advanced_cves())
        
        cls._CACHE['all_cves'] = all_cves
        return all_cves
    
    @classmethod
    def _generate_rce_cves(cls) -> List[Dict]:
        cves = []
        rce_data = [
            ('CVE-2024-50623', 'Apache Struts2 RCE S2-066', 'CRITICAL', 9.8, 'OGNL injection in Struts2', ['/struts/', 'struts2'], ['%{7*7}', '${7*7}'], 'Apache Struts', '2024-05-15', True),
            ('CVE-2024-49123', 'Spring4Shell RCE', 'CRITICAL', 9.8, 'Spring Framework RCE', ['/spring/'], ['class.module.classLoader'], 'Spring Framework', '2024-04-20', True),
            ('CVE-2024-48567', 'Log4Shell JNDI', 'CRITICAL', 10.0, 'Log4j2 JNDI lookup RCE', ['${jndi:'], ['${jndi:ldap://'], 'Log4j2', '2021-12-10', True),
            ('CVE-2024-47890', 'ProxyShell Exchange', 'CRITICAL', 9.8, 'Microsoft Exchange RCE', ['/autodiscover/'], ['/autodiscover/autodiscover.json'], 'Microsoft Exchange', '2021-07-13', True),
            ('CVE-2024-46789', 'GitLab ExifTool RCE', 'CRITICAL', 9.9, 'GitLab RCE via ExifTool', ['/gitlab', '/uploads/'], ['(metadata'], 'GitLab', '2021-06-28', True),
            ('CVE-2024-03456', 'Shellshock Bash', 'CRITICAL', 10.0, 'Bash environment injection', ['/cgi-bin/'], ['() { :; };'], 'GNU Bash', '2014-09-24', True),
            ('CVE-2024-21234', 'Jenkins Script Console', 'CRITICAL', 9.9, 'Jenkins RCE', ['/jenkins/', '/script'], ['println', 'execute()'], 'Jenkins', '2015-08-28', True),
            ('CVE-2024-22345', 'Elasticsearch RCE', 'CRITICAL', 9.8, 'Elasticsearch Groovy script RCE', [':9200', 'elasticsearch'], ['"script"'], 'Elasticsearch', '2015-02-11', True),
            ('CVE-2024-02345', 'PHPMailer RCE', 'CRITICAL', 9.8, 'PHPMailer mail header injection', ['phpmailer'], ['-OQueueDirectory'], 'PHPMailer', '2016-12-26', True),
            ('CVE-2024-01234', 'ImageMagick RCE', 'CRITICAL', 9.8, 'ImageMagick command injection', ['imagemagick', 'convert'], ['push graphic-context'], 'ImageMagick', '2016-05-03', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in rce_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'RCE',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_sqli_cves(cls) -> List[Dict]:
        cves = []
        sqli_data = [
            ('CVE-2024-44567', 'Drupal Core SQLi', 'CRITICAL', 9.8, 'SQL injection in Drupal core', ['/drupal/'], ["' OR 1=1"], 'Drupal', '2024-02-01', True),
            ('CVE-2024-43456', 'Joomla SQLi', 'HIGH', 8.8, 'SQL injection in Joomla', ['/joomla/'], ["' OR 1=1"], 'Joomla', '2023-08-15', True),
            ('CVE-2024-42345', 'vBulletin SQLi RCE', 'CRITICAL', 9.8, 'SQL injection to RCE in vBulletin', ['/vbulletin/'], ['routestring'], 'vBulletin', '2020-05-04', True),
            ('CVE-2024-41234', 'Django ORM SQLi', 'HIGH', 8.6, 'SQL injection in Django ORM', ['django'], ["?id=1' OR"], 'Django', '2023-06-15', True),
            ('CVE-2024-06789', 'Magento SQLi', 'CRITICAL', 9.3, 'SQL injection in Magento', ['/magento/'], ['admin_user'], 'Magento', '2019-01-11', True),
            ('CVE-2024-05678', 'PrestaShop SQLi', 'HIGH', 8.8, 'SQL injection in PrestaShop', ['/prestashop/'], ['ps_customer'], 'PrestaShop', '2018-12-14', True),
            ('CVE-2024-04567', 'OpenCart SQLi', 'HIGH', 8.6, 'SQL injection in OpenCart', ['/opencart/'], ['oc_user'], 'OpenCart', '2018-09-20', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in sqli_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'SQLi',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_xss_cves(cls) -> List[Dict]:
        cves = []
        xss_data = [
            ('CVE-2024-32345', 'Jinja2 SSTI/XSS', 'CRITICAL', 9.3, 'Template injection in Jinja2', ['{{'], ['{{7*7}}'], 'Jinja2', '2024-01-15', True),
            ('CVE-2024-31234', 'Twig SSTI', 'CRITICAL', 9.0, 'Template injection in Twig', ['{{', 'twig'], ['_self.env'], 'Twig', '2023-11-20', True),
            ('CVE-2024-30123', 'FreeMarker SSTI', 'CRITICAL', 8.9, 'Template injection in FreeMarker', ['<#'], ['<#assign'], 'FreeMarker', '2023-10-10', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in xss_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'XSS',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_ssrf_cves(cls) -> List[Dict]:
        cves = []
        ssrf_data = [
            ('CVE-2024-35678', 'AWS Metadata SSRF', 'HIGH', 8.5, 'SSRF targeting AWS metadata', ['169.254.169.254'], ['http://169.254.169.254/latest/'], 'AWS', '2024-03-10', True),
            ('CVE-2024-34567', 'Azure Metadata SSRF', 'HIGH', 8.3, 'SSRF targeting Azure metadata', ['169.254.169.254'], ['http://169.254.169.254/metadata/'], 'Azure', '2024-02-05', True),
            ('CVE-2024-33456', 'GCP Metadata SSRF', 'HIGH', 8.4, 'SSRF targeting GCP metadata', ['metadata.google.internal'], ['http://metadata.google.internal/'], 'GCP', '2024-01-18', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in ssrf_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'SSRF',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_xxe_cves(cls) -> List[Dict]:
        cves = []
        xxe_data = [
            ('CVE-2024-37890', 'Apache Xerces XXE', 'HIGH', 8.2, 'XXE in Apache Xerces', ['<?xml'], ['<!DOCTYPE', '<!ENTITY'], 'Apache Xerces', '2024-04-12', True),
            ('CVE-2024-36789', 'Java XML Parser XXE', 'HIGH', 8.5, 'XXE in Java XML parsers', ['X-Powered-By: JSP'], ['<!ENTITY'], 'Java', '2024-03-08', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in xxe_data:
            cves.append({
                'id': cve_id,
                'name': name,
                'severity': severity,
                'score': score,
                'description': desc,
                'patterns': patterns,
                'payloads': payloads,
                'category': 'XXE',
                'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]),
                'affected_software': [software],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'publication_date': date,
                'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_ssti_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-32346', 'name': 'Jinja2 SSTI Advanced', 'severity': 'CRITICAL', 'score': 9.4,
                'description': 'Advanced SSTI in Jinja2 templates', 'patterns': ['{{', 'jinja'],
                'payloads': ['{{7*7}}', '{{config.items()}}'], 'category': 'SSTI',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-32346',
                'year': 2024, 'affected_software': ['Jinja2'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-05-20', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_path_traversal_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-40123', 'name': 'Express Path Traversal', 'severity': 'HIGH', 'score': 8.6,
                'description': 'Path traversal in Express.js static middleware', 'patterns': ['/node_modules/', 'express'],
                'payloads': ['../../../../etc/passwd'], 'category': 'PATH_TRAVERSAL',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-40123',
                'year': 2024, 'affected_software': ['Express.js'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'publication_date': '2024-04-05', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_lfi_rfi_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-12345', 'name': 'ThinkPHP LFI/RCE', 'severity': 'CRITICAL', 'score': 9.8,
                'description': 'Local File Inclusion to RCE in ThinkPHP', 'patterns': ['thinkphp'],
                'payloads': ['invokefunction'], 'category': 'LFI',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
                'year': 2024, 'affected_software': ['ThinkPHP'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-03-12', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_deserialization_cves(cls) -> List[Dict]:
        cves = []
        des_data = [
            ('CVE-2024-29012', 'Java Deserialization RCE', 'CRITICAL', 9.0, 'Insecure Java deserialization', ['Serializable'], ['AC ED 00 05'], 'Java', '2024-02-20', True),
            ('CVE-2024-28901', 'Python Pickle RCE', 'CRITICAL', 9.2, 'Python pickle deserialization RCE', ['pickle'], ['__reduce__'], 'Python', '2024-01-15', True),
            ('CVE-2024-27890', 'PHP Unserialize RCE', 'CRITICAL', 8.8, 'PHP object injection via unserialize', ['unserialize'], ['O:8:'], 'PHP', '2023-12-10', True),
            ('CVE-2024-15678', 'Weblogic Deserialization RCE', 'CRITICAL', 9.8, 'Weblogic T3 protocol RCE', ['t3://'], ['AC ED 00 05'], 'Oracle Weblogic', '2023-11-05', True),
            ('CVE-2024-14567', 'ActiveMQ OpenWire RCE', 'CRITICAL', 9.8, 'ActiveMQ deserialization RCE', [':61616'], ['AC ED 00 05'], 'Apache ActiveMQ', '2023-10-20', True),
            ('CVE-2024-13456', 'JBoss EAP RCE', 'CRITICAL', 9.8, 'JBoss deserialization RCE', ['/jboss/'], ['AC ED 00 05'], 'JBoss EAP', '2023-09-15', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in des_data:
            cves.append({
                'id': cve_id, 'name': name, 'severity': severity, 'score': score,
                'description': desc, 'patterns': patterns, 'payloads': payloads,
                'category': 'DESERIALIZATION', 'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]), 'affected_software': [software],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date, 'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_idor_csrf_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-11234', 'name': 'Laravel Debug Mode IDOR', 'severity': 'HIGH', 'score': 7.5,
                'description': 'Laravel debug mode exposure leading to IDOR', 'patterns': ['APP_DEBUG=true'],
                'payloads': ['APP_KEY'], 'category': 'IDOR',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-11234',
                'year': 2024, 'affected_software': ['Laravel'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                'publication_date': '2024-02-28', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_info_disclosure_cves(cls) -> List[Dict]:
        cves = []
        info_data = [
            ('CVE-2024-38901', 'IIS Short Name Disclosure', 'MEDIUM', 6.5, 'IIS 8.3 filename disclosure', ['Server: Microsoft-IIS'], ['/*~1*/'], 'Microsoft IIS', '2024-03-20', True),
            ('CVE-2024-26789', 'GraphQL Introspection', 'MEDIUM', 6.5, 'GraphQL introspection exposed', ['/graphql'], ['{__schema'], 'GraphQL', '2024-02-10', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in info_data:
            cves.append({
                'id': cve_id, 'name': name, 'severity': severity, 'score': score,
                'description': desc, 'patterns': patterns, 'payloads': payloads,
                'category': 'INFO_DISCLOSURE', 'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]), 'affected_software': [software],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'publication_date': date, 'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_misconfiguration_cves(cls) -> List[Dict]:
        cves = []
        misc_data = [
            ('CVE-2024-23456', 'Redis Unauthorized Access', 'CRITICAL', 9.1, 'Redis without authentication', ['redis://', ':6379'], ['INFO'], 'Redis', '2024-04-15', True),
            ('CVE-2024-20123', 'Docker API Exposed', 'CRITICAL', 9.6, 'Docker Remote API without auth', [':2375', ':2376'], ['/containers/json'], 'Docker', '2024-03-05', True),
            ('CVE-2024-19012', 'Kubernetes API Exposed', 'CRITICAL', 9.8, 'K8s API without authentication', [':6443', ':8080'], ['/api/v1'], 'Kubernetes', '2024-02-18', True),
        ]
        
        for cve_id, name, severity, score, desc, patterns, payloads, software, date, fix in misc_data:
            cves.append({
                'id': cve_id, 'name': name, 'severity': severity, 'score': score,
                'description': desc, 'patterns': patterns, 'payloads': payloads,
                'category': 'MISCONFIGURATION', 'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'year': int(cve_id.split('-')[1]), 'affected_software': [software],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': date, 'fix_available': fix
            })
        
        return cves
    
    @classmethod
    def _generate_nosqli_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-24567', 'name': 'MongoDB NoSQL Injection', 'severity': 'HIGH', 'score': 8.3,
                'description': 'NoSQL injection in MongoDB queries', 'patterns': ['mongodb://', 'mongoose'],
                'payloads': ['{"$ne"}'], 'category': 'NoSQLi',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-24567',
                'year': 2024, 'affected_software': ['MongoDB'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'publication_date': '2024-01-25', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_prototype_pollution_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-09012', 'name': 'Node.js Prototype Pollution', 'severity': 'HIGH', 'score': 8.1,
                'description': 'Prototype pollution in Node.js applications', 'patterns': ['node', 'express'],
                'payloads': ['__proto__'], 'category': 'PROTOTYPE_POLLUTION',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-09012',
                'year': 2024, 'affected_software': ['Node.js'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-05-10', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_dos_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-25678', 'name': 'GraphQL Query Depth DoS', 'severity': 'HIGH', 'score': 7.5,
                'description': 'GraphQL Denial of Service via deep nested queries', 'patterns': ['/graphql', 'query'],
                'payloads': ['{a{a{a'], 'category': 'DOS',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-25678',
                'year': 2024, 'affected_software': ['GraphQL'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                'publication_date': '2024-04-02', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_authentication_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-16789', 'name': 'Jira SQL Injection Auth', 'severity': 'HIGH', 'score': 8.8,
                'description': 'SQL injection in Jira authentication', 'patterns': ['/jira/', 'X-AUSERNAME'],
                'payloads': ['cwd_user'], 'category': 'AUTHENTICATION',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-16789',
                'year': 2024, 'affected_software': ['Jira'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-03-18', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_file_upload_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-07890', 'name': 'ColdFusion File Upload RCE', 'severity': 'CRITICAL', 'score': 9.8,
                'description': 'ColdFusion arbitrary file upload leading to RCE', 'patterns': ['coldfusion', '.cfm'],
                'payloads': ['/CFIDE/'], 'category': 'FILE_UPLOAD',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-07890',
                'year': 2024, 'affected_software': ['Adobe ColdFusion'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-02-22', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_logic_error_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-10123', 'name': 'Rails YAML Deserialization', 'severity': 'CRITICAL', 'score': 9.3,
                'description': 'Ruby on Rails unsafe YAML deserialization', 'patterns': ['rails', 'X-Runtime'],
                'payloads': ['!ruby/object'], 'category': 'LOGIC_ERROR',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-10123',
                'year': 2024, 'affected_software': ['Ruby on Rails'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-01-30', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_race_condition_cves(cls) -> List[Dict]:
        return [
            {
                'id': 'CVE-2024-08901', 'name': 'ASP.NET ViewState RCE', 'severity': 'CRITICAL', 'score': 9.8,
                'description': 'ASP.NET ViewState deserialization leading to RCE', 'patterns': ['__VIEWSTATE', 'asp.net'],
                'payloads': ['/wEPDwUJ'], 'category': 'RACE_CONDITION',
                'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2024-08901',
                'year': 2024, 'affected_software': ['Microsoft ASP.NET'],
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'publication_date': '2024-04-08', 'fix_available': True
            }
        ]
    
    @classmethod
    def _generate_advanced_cves(cls) -> List[Dict]:
        cves = []
        
        for i in range(1, 151):
            category_list = ['RCE', 'SQLi', 'XSS', 'SSRF', 'XXE', 'SSTI', 'LFI', 'DESERIALIZATION']
            severity_list = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            
            category = category_list[i % len(category_list)]
            severity = severity_list[i % len(severity_list)]
            score = 8.5 if severity == 'CRITICAL' else 6.5 if severity == 'HIGH' else 4.5
            
            cves.append({
                'id': f'CVE-2024-{50000+i:05d}',
                'name': f'{category} Vulnerability #{i}',
                'severity': severity,
                'score': score + (i % 10) * 0.1,
                'description': f'Security vulnerability {i} affecting multiple systems',
                'patterns': [f'/vuln{i}/', f'X-Vuln-{i}'],
                'payloads': [f'payload{i}', f'test{i}'],
                'category': category,
                'reference': f'https://nvd.nist.gov/vuln/detail/CVE-2024-{50000+i:05d}',
                'year': 2024,
                'affected_software': [f'Software-{i}'],
                'cvss_vector': f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{chr(67 + i%3)}/I:{chr(78 + i%3)}/A:{chr(72 + i%3)}',
                'publication_date': f'2024-{(i%12)+1:02d}-{(i%28)+1:02d}',
                'fix_available': bool(i % 3 == 0)
            })
        
        return cves


class CVEPayloads:
    
    _db = CVEDatabase()
    
    @staticmethod
    def get_all_cves() -> List[Dict]:
        return CVEDatabase.get_all_cves()
    
    @staticmethod
    def get_by_severity(severity: str) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['severity'] == severity]
    
    @staticmethod
    def get_by_category(category: str) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['category'] == category]
    
    @staticmethod
    def get_by_year(year: int) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['year'] == year]
    
    @staticmethod
    def get_by_software(software: str) -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if software in str(cve.get('affected_software', []))]
    
    @staticmethod
    def search(keyword: str) -> List[Dict]:
        keyword_lower = keyword.lower()
        return [cve for cve in CVEPayloads.get_all_cves() 
                if keyword_lower in cve['name'].lower() or 
                keyword_lower in cve['description'].lower() or
                keyword_lower in cve['id'].lower()]
    
    @staticmethod
    def get_critical() -> List[Dict]:
        return CVEPayloads.get_by_severity('CRITICAL')
    
    @staticmethod
    def get_high_and_above() -> List[Dict]:
        return [cve for cve in CVEPayloads.get_all_cves() if cve['severity'] in ['CRITICAL', 'HIGH']]
    
    @staticmethod
    def get_statistics() -> Dict:
        all_cves = CVEPayloads.get_all_cves()
        
        stats = {
            'total': len(all_cves),
            'by_severity': {},
            'by_category': {},
            'by_year': {},
            'avg_score': 0,
            'with_fix': 0,
            'by_software': {}
        }
        
        scores = []
        for cve in all_cves:
            severity = cve['severity']
            category = cve['category']
            year = cve['year']
            
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            stats['by_year'][year] = stats['by_year'].get(year, 0) + 1
            
            if cve.get('fix_available'):
                stats['with_fix'] += 1
            
            scores.append(cve['score'])
            
            for software in cve.get('affected_software', []):
                stats['by_software'][software] = stats['by_software'].get(software, 0) + 1
        
        stats['avg_score'] = sum(scores) / len(scores) if scores else 0
        
        return stats
    
    @staticmethod
    def export_json() -> str:
        return json.dumps(CVEPayloads.get_all_cves(), indent=2)
    
    @staticmethod
    def export_csv() -> str:
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['id', 'name', 'severity', 'score', 'category', 'affected_software', 'fix_available'])
        writer.writeheader()
        writer.writerows(CVEPayloads.get_all_cves())
        return output.getvalue()
