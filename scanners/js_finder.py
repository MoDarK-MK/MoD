"""
JavaScript Finder Scanner for MoD v4.0.0.5
Detects and extracts JavaScript files during crawling and sends results to webhook
"""

from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import re
import logging
import json
import hashlib
from datetime import datetime
from pathlib import Path
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from urllib.parse import urljoin, urlparse
from collections import defaultdict

logger = logging.getLogger("MoD.js_finder")
if not logger.handlers:
    log_dir = Path.home() / ".mod" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_dir / "js_finder.log")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)


class JSType(Enum):
    """JavaScript file types"""
    EXTERNAL = "external"
    INLINE = "inline"
    EVENT_HANDLER = "event_handler"
    EMBEDDED = "embedded"
    DYNAMIC = "dynamic"


class RiskLevel(Enum):
    """Risk levels for JavaScript patterns"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class JavaScriptFile:
    """Detected JavaScript file"""
    url: str
    file_type: JSType
    source_url: str
    detected_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    size: int = 0
    hash: str = ""
    line_number: Optional[int] = None
    content_preview: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    suspicious_patterns: List[str] = field(default_factory=list)
    sensitive_data: List[str] = field(default_factory=list)
    libraries_detected: List[str] = field(default_factory=list)
    is_minified: bool = False
    is_framework: bool = False
    framework_type: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'url': self.url,
            'type': self.file_type.value,
            'source_url': self.source_url,
            'detected_at': datetime.fromtimestamp(self.detected_timestamp).isoformat(),
            'size': self.size,
            'hash': self.hash,
            'line_number': self.line_number,
            'preview': self.content_preview[:100],
            'risk_level': self.risk_level.value,
            'suspicious_patterns': self.suspicious_patterns[:5],
            'libraries': self.libraries_detected,
            'minified': self.is_minified,
            'framework': self.framework_type
        }


@dataclass
class ScanResult:
    """JavaScript scan result"""
    url: str
    total_js_files: int = 0
    external_js: List[JavaScriptFile] = field(default_factory=list)
    inline_js: List[JavaScriptFile] = field(default_factory=list)
    event_handlers: List[JavaScriptFile] = field(default_factory=list)
    frameworks_detected: List[str] = field(default_factory=list)
    libraries_detected: List[str] = field(default_factory=list)
    critical_patterns: List[Dict] = field(default_factory=list)
    sensitive_data_found: List[str] = field(default_factory=list)
    scan_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    scan_duration: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'url': self.url,
            'total_js_files': self.total_js_files,
            'external_js_count': len(self.external_js),
            'inline_js_count': len(self.inline_js),
            'event_handlers_count': len(self.event_handlers),
            'external_js': [js.to_dict() for js in self.external_js[:10]],
            'frameworks': self.frameworks_detected,
            'libraries': self.libraries_detected,
            'critical_patterns': len(self.critical_patterns),
            'sensitive_data_found': len(self.sensitive_data_found),
            'scan_timestamp': datetime.fromtimestamp(self.scan_timestamp).isoformat(),
            'scan_duration_ms': int(self.scan_duration * 1000)
        }


class JSPatternDetector:
    """Detects suspicious patterns and sensitive data in JavaScript"""
    
    # Sensitive patterns
    SENSITIVE_PATTERNS = {
        'api_keys': [
            r"(?i)(?:api[-_]?key|apikey|api_secret|secret_key)[\s]*[=:]\s*['\"]([^'\"]{20,})['\"]",
            r"(?i)(?:x-api-key|authorization)[\s]*[=:]\s*['\"]Bearer\s+([a-zA-Z0-9\-_.]+)['\"]"
        ],
        'tokens': [
            r"(?i)(?:token|access_token|refresh_token)[\s]*[=:]\s*['\"]([a-zA-Z0-9\-_.]{20,})['\"]",
            r"(?i)jwt[\s]*[=:]\s*['\"]([a-zA-Z0-9\-_.]+)['\"]"
        ],
        'passwords': [
            r"(?i)(?:password|pwd|passwd)[\s]*[=:]\s*['\"]([^'\"]{8,})['\"]",
            r"(?i)(?:db_password|mysql_password)[\s]*[=:]\s*['\"]([^'\"]{8,})['\"]"
        ],
        'urls': [
            r"(?i)(?:database_url|db_url)[\s]*[=:]\s*['\"]([^'\"]+)['\"]",
            r"(?i)(?:webhook|callback_url)[\s]*[=:]\s*['\"]([^'\"]+)['\"]"
        ],
        'credentials': [
            r"(?i)(?:username|user|user_id)[\s]*[=:]\s*['\"]([^'\"]{3,})['\"]",
            r"(?i)(?:email)[\s]*[=:]\s*['\"]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})['\"]"
        ]
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'dom_manipulation': [
            r'document\.write\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'eval\(',
            r'Function\('
        ],
        'network_requests': [
            r'fetch\(',
            r'XMLHttpRequest',
            r'\.ajax\(',
            r'axios\.',
            r'WebSocket\('
        ],
        'storage_access': [
            r'localStorage',
            r'sessionStorage',
            r'document\.cookie',
            r'window\.name'
        ],
        'suspicious_calls': [
            r'document\.location',
            r'window\.location',
            r'new Worker\(',
            r'iframe',
            r'script\s+src'
        ]
    }
    
    # JavaScript frameworks and libraries
    FRAMEWORKS = {
        'react': [r'React\.', r'ReactDOM', r'jsx', r'from\s+[\'"]react[\'"]'],
        'vue': [r'new Vue\(', r'from\s+[\'"]vue[\'"]', r'v-bind', r'v-if'],
        'angular': [r'angular\.', r'@angular/', r'ng-app', r'ng-controller'],
        'jquery': [r'\$\(', r'jQuery', r'jquery\.', r'\.ajax\('],
        'lodash': [r'_\.', r'from\s+[\'"]lodash[\'"]'],
        'underscore': [r'_\.', r'underscore'],
        'typescript': [r'declare\s+', r'interface\s+', r':\s+\w+\s*[;,\)]'],
        'node': [r'require\(', r'module\.exports', r'process\.'],
    }
    
    @staticmethod
    def detect_sensitive_data(content: str) -> List[Tuple[str, str]]:
        """Detect sensitive data patterns in JavaScript content"""
        findings = []
        for category, patterns in JSPatternDetector.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append((category, match.group(0)[:80]))
        return findings
    
    @staticmethod
    def detect_suspicious_patterns(content: str) -> List[Tuple[str, str]]:
        """Detect suspicious JavaScript patterns"""
        findings = []
        for category, patterns in JSPatternDetector.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    findings.append((category, pattern))
        return findings
    
    @staticmethod
    def detect_frameworks(content: str) -> List[str]:
        """Detect JavaScript frameworks used"""
        detected = []
        for framework, patterns in JSPatternDetector.FRAMEWORKS.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    detected.append(framework)
                    break
        return list(set(detected))
    
    @staticmethod
    def is_minified(content: str) -> bool:
        """Check if JavaScript is minified"""
        # Heuristics for minified code
        lines = content.split('\n')
        avg_line_length = sum(len(line) for line in lines) / max(len(lines), 1)
        
        # Minified code typically has long lines
        if avg_line_length > 500:
            return True
        
        # Check for reduced whitespace
        if len(lines) < 5 and len(content) > 1000:
            return True
        
        # Check for minimal comments
        comment_ratio = len(re.findall(r'//|/\*', content)) / max(len(content) // 100, 1)
        if comment_ratio < 0.01:
            return True
        
        return False


class JSFinder:
    """Main JavaScript Finder scanner"""
    
    def __init__(self, webhook_url: Optional[str] = None, max_workers: int = 10):
        """Initialize JS Finder
        
        Args:
            webhook_url: Webhook URL for sending results
            max_workers: Maximum concurrent workers
        """
        self.webhook_url = webhook_url
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.timeout = 10
        self.detected_files: Set[str] = set()
        self.lock = threading.Lock()
        self.pattern_detector = JSPatternDetector()
        
    def find_external_js(self, html_content: str, base_url: str) -> List[JavaScriptFile]:
        """Find external JavaScript files in HTML"""
        js_files = []
        
        # Find script tags with src attribute
        pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            js_url = match.group(1)
            full_url = urljoin(base_url, js_url)
            
            with self.lock:
                if full_url not in self.detected_files:
                    self.detected_files.add(full_url)
                    
                    js_file = JavaScriptFile(
                        url=full_url,
                        file_type=JSType.EXTERNAL,
                        source_url=base_url,
                        content_preview=js_url
                    )
                    js_files.append(js_file)
                    logger.debug(f"Found external JS: {full_url}")
        
        return js_files
    
    def find_inline_js(self, html_content: str, base_url: str) -> List[JavaScriptFile]:
        """Find inline JavaScript in HTML"""
        js_blocks = []
        
        # Find script tags without src attribute
        pattern = r'<script[^>]*>([^<]+)</script>'
        matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for idx, match in enumerate(matches):
            js_content = match.group(1).strip()
            if js_content:
                js_hash = hashlib.md5(js_content.encode()).hexdigest()
                
                with self.lock:
                    if js_hash not in self.detected_files:
                        self.detected_files.add(js_hash)
                        
                        # Analyze content
                        sensitive_data = self.pattern_detector.detect_sensitive_data(js_content)
                        suspicious = self.pattern_detector.detect_suspicious_patterns(js_content)
                        frameworks = self.pattern_detector.detect_frameworks(js_content)
                        is_minified = self.pattern_detector.is_minified(js_content)
                        
                        # Determine risk level
                        risk_level = RiskLevel.INFO
                        if sensitive_data:
                            risk_level = RiskLevel.CRITICAL
                        elif suspicious and len(suspicious) > 3:
                            risk_level = RiskLevel.HIGH
                        elif suspicious:
                            risk_level = RiskLevel.MEDIUM
                        
                        js_file = JavaScriptFile(
                            url=f"{base_url}#inline-script-{idx}",
                            file_type=JSType.INLINE,
                            source_url=base_url,
                            size=len(js_content),
                            hash=js_hash,
                            line_number=idx,
                            content_preview=js_content[:100],
                            risk_level=risk_level,
                            suspicious_patterns=[p[1] for p in suspicious[:5]],
                            sensitive_data=[s[0] for s in sensitive_data[:5]],
                            libraries_detected=frameworks,
                            is_minified=is_minified
                        )
                        js_blocks.append(js_file)
                        logger.debug(f"Found inline JS (risk: {risk_level.value})")
        
        return js_blocks
    
    def find_event_handlers(self, html_content: str, base_url: str) -> List[JavaScriptFile]:
        """Find JavaScript in event handlers"""
        handlers = []
        
        # Find event handlers
        pattern = r'on\w+=["\']([^"\']+)["\']'
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        
        for idx, match in enumerate(matches):
            handler_code = match.group(1)
            js_hash = hashlib.md5(handler_code.encode()).hexdigest()
            
            with self.lock:
                if js_hash not in self.detected_files:
                    self.detected_files.add(js_hash)
                    
                    js_file = JavaScriptFile(
                        url=f"{base_url}#handler-{idx}",
                        file_type=JSType.EVENT_HANDLER,
                        source_url=base_url,
                        hash=js_hash,
                        content_preview=handler_code[:80],
                        risk_level=RiskLevel.MEDIUM
                    )
                    handlers.append(js_file)
                    logger.debug(f"Found event handler")
        
        return handlers
    
    def scan_page(self, url: str, html_content: str) -> ScanResult:
        """Scan a page for JavaScript"""
        import time
        start_time = time.time()
        
        result = ScanResult(url=url)
        
        # Find all types of JavaScript
        result.external_js = self.find_external_js(html_content, url)
        result.inline_js = self.find_inline_js(html_content, url)
        result.event_handlers = self.find_event_handlers(html_content, url)
        
        # Collect statistics
        result.total_js_files = len(result.external_js) + len(result.inline_js) + len(result.event_handlers)
        
        # Extract frameworks and libraries
        all_js_content = html_content
        result.frameworks_detected = self.pattern_detector.detect_frameworks(all_js_content)
        
        # Find critical patterns
        for js_file in result.inline_js + result.event_handlers:
            if js_file.risk_level == RiskLevel.CRITICAL:
                result.critical_patterns.append({
                    'type': js_file.file_type.value,
                    'preview': js_file.content_preview
                })
        
        result.scan_duration = time.time() - start_time
        
        logger.info(f"Scanned {url}: Found {result.total_js_files} JS resources")
        
        return result
    
    def send_to_webhook(self, result: ScanResult) -> bool:
        """Send scan result to webhook"""
        if not self.webhook_url:
            logger.warning("No webhook URL configured")
            return False
        
        try:
            payload = {
                'scanner': 'js_finder',
                'version': '4.0.0.5',
                'timestamp': datetime.now().isoformat(),
                'result': result.to_dict()
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook sent successfully for {result.url}")
                return True
            else:
                logger.error(f"Webhook returned status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
            return False
    
    def update_webhook(self, new_webhook_url: str) -> None:
        """Update webhook URL"""
        self.webhook_url = new_webhook_url
        logger.info(f"Webhook URL updated")
    
    def get_detected_files(self) -> Dict[str, List[Dict]]:
        """Get all detected JavaScript files"""
        return {
            'total_detected': len(self.detected_files),
            'files': list(self.detected_files)[:100]
        }


# Singleton instance
_js_finder_instance: Optional[JSFinder] = None
_js_finder_lock = threading.Lock()


def get_js_finder(webhook_url: Optional[str] = None) -> JSFinder:
    """Get or create JS Finder instance"""
    global _js_finder_instance
    
    if _js_finder_instance is None:
        with _js_finder_lock:
            if _js_finder_instance is None:
                _js_finder_instance = JSFinder(webhook_url=webhook_url)
    
    return _js_finder_instance
