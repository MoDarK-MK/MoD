"""CORS Misconfiguration Scanner with automated PoC generation."""

from typing import Dict, List, Any, Optional
import requests
from urllib.parse import urlparse


class CORSScanner:
    """Scanner for CORS misconfiguration vulnerabilities."""
    
    COMMON_ORIGINS = [
        'http://localhost',
        'http://localhost:3000',
        'http://localhost:8000',
        'http://127.0.0.1',
        'http://127.0.0.1:3000',
        'http://attacker.com',
        'http://localhost.attacker.com',
        'http://*.attacker.com',
        'null',
    ]
    
    def __init__(self, timeout: int = 10) -> None:
        """Initialize CORS scanner.
        
        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        self.results: List[Dict[str, Any]] = []
        self.session = requests.Session()
    
    def scan(self, target_url: str, custom_origins: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Scan target URL for CORS misconfiguration.
        
        Args:
            target_url: Target URL to scan.
            custom_origins: Custom origin list to test.
            
        Returns:
            List of CORS vulnerabilities found.
        """
        self.results = []
        origins_to_test = custom_origins or self.COMMON_ORIGINS
        
        for origin in origins_to_test:
            vulnerability = self._test_cors(target_url, origin)
            if vulnerability:
                self.results.append(vulnerability)
        
        return self.results
    
    def _test_cors(self, target_url: str, origin: str) -> Optional[Dict[str, Any]]:
        """Test specific origin for CORS misconfiguration.
        
        Args:
            target_url: Target URL.
            origin: Origin to test.
            
        Returns:
            Vulnerability dict if found, None otherwise.
        """
        try:
            headers = {
                'Origin': origin,
                'User-Agent': 'Mozilla/5.0 (CORS Scanner)',
                'Accept': '*/*',
            }
            
            response = self.session.options(
                target_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
            allow_methods = response.headers.get('Access-Control-Allow-Methods', '')
            allow_headers = response.headers.get('Access-Control-Allow-Headers', '')
            
            # Check for vulnerable CORS configuration
            if cors_header:
                severity = 'Low'
                is_vulnerable = False
                description = f'CORS header present: {cors_header}'
                
                # Check for wildcard origin with credentials
                if cors_header == '*' and allow_credentials.lower() == 'true':
                    severity = 'Critical'
                    is_vulnerable = True
                    description = 'Wildcard CORS origin with credentials enabled - Critical vulnerability'
                
                # Check for wildcard origin
                elif cors_header == '*':
                    severity = 'Medium'
                    is_vulnerable = True
                    description = 'Wildcard CORS origin allows any domain'
                
                # Check for specific origin that matches attacker origin
                elif 'attacker.com' in origin.lower() and origin in cors_header:
                    severity = 'High'
                    is_vulnerable = True
                    description = f'Application reflects attacker origin: {origin}'
                
                # Check for null origin
                elif origin == 'null' and 'null' in cors_header:
                    severity = 'High'
                    is_vulnerable = True
                    description = 'Application accepts null origin - can be exploited from file:// and data: URLs'
                
                if is_vulnerable or cors_header:
                    return {
                        'type': 'CORS Misconfiguration',
                        'origin_tested': origin,
                        'allowed_origin': cors_header,
                        'allow_credentials': allow_credentials,
                        'allow_methods': allow_methods or 'Not specified',
                        'allow_headers': allow_headers or 'Not specified',
                        'severity': severity,
                        'description': description,
                        'is_vulnerable': is_vulnerable,
                        'status_code': response.status_code,
                        'poc_url': self._generate_poc_url(target_url, origin, cors_header),
                    }
            
            return None
        
        except Exception as e:
            return {
                'type': 'CORS Misconfiguration',
                'origin_tested': origin,
                'severity': 'Error',
                'description': f'Error testing origin: {str(e)}',
                'is_vulnerable': False,
            }
    
    def _generate_poc_url(self, target_url: str, origin: str, allowed_origin: str) -> str:
        """Generate PoC URL for the vulnerability.
        
        Args:
            target_url: Target URL.
            origin: Origin tested.
            allowed_origin: Allowed origin from response.
            
        Returns:
            PoC URL string.
        """
        poc = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CORS PoC</title>
        </head>
        <body>
            <h1>CORS Misconfiguration PoC</h1>
            <p>Target: {target_url}</p>
            <p>Origin: {origin}</p>
            <p>Allowed: {allowed_origin}</p>
            <script>
                fetch('{target_url}', {{
                    method: 'GET',
                    credentials: 'include',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }})
                .then(response => response.text())
                .then(data => console.log('Response:', data))
                .catch(error => console.error('Error:', error));
            </script>
        </body>
        </html>
        """
        return poc.strip()
    
    def generate_poc_html(self, target_url: str, vulnerability: Dict[str, Any]) -> str:
        """Generate complete HTML PoC file.
        
        Args:
            target_url: Target URL.
            vulnerability: Vulnerability dictionary.
            
        Returns:
            HTML PoC code.
        """
        allowed_origin = vulnerability.get('allowed_origin', '')
        
        poc_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CORS Misconfiguration PoC</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        .info {{
            background: #f5f5f5;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .info p {{
            margin: 8px 0;
            color: #555;
        }}
        .info strong {{
            color: #333;
        }}
        button {{
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
            margin: 10px 5px 10px 0;
        }}
        button:hover {{
            background: #764ba2;
        }}
        #output {{
            background: #2d2d2d;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-family: 'Courier New', monospace;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .status {{
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .success {{
            background: #d4edda;
            color: #155724;
        }}
        .error {{
            background: #f8d7da;
            color: #721c24;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 CORS Misconfiguration PoC</h1>
        
        <div class="info">
            <p><strong>Target URL:</strong> {target_url}</p>
            <p><strong>Allowed Origin:</strong> {allowed_origin}</p>
            <p><strong>Vulnerability Type:</strong> {vulnerability.get('description', 'CORS Misconfiguration')}</p>
            <p><strong>Severity:</strong> <span style="color: #d32f2f;">{vulnerability.get('severity', 'Unknown')}</span></p>
        </div>
        
        <div>
            <button onclick="testCORS()">🧪 Test CORS</button>
            <button onclick="fetchData()">📥 Fetch with Credentials</button>
            <button onclick="clearOutput()">🗑️ Clear Output</button>
        </div>
        
        <div id="output"></div>
        
        <script>
            const targetUrl = '{target_url}';
            const allowedOrigin = '{allowed_origin}';
            
            function log(message) {{
                const output = document.getElementById('output');
                output.textContent += message + '\\n';
                output.scrollTop = output.scrollHeight;
            }}
            
            function clearOutput() {{
                document.getElementById('output').textContent = '';
            }}
            
            function testCORS() {{
                log('[*] Testing CORS Configuration...');
                log('[*] Target: ' + targetUrl);
                
                fetch(targetUrl, {{
                    method: 'OPTIONS',
                    headers: {{
                        'Origin': window.location.origin
                    }}
                }})
                .then(response => {{
                    log('[+] Status: ' + response.status);
                    log('[+] CORS Headers:');
                    
                    const corsOrigin = response.headers.get('Access-Control-Allow-Origin');
                    const corsCredentials = response.headers.get('Access-Control-Allow-Credentials');
                    const corsMethods = response.headers.get('Access-Control-Allow-Methods');
                    
                    log('    - Access-Control-Allow-Origin: ' + (corsOrigin || 'Not Set'));
                    log('    - Access-Control-Allow-Credentials: ' + (corsCredentials || 'Not Set'));
                    log('    - Access-Control-Allow-Methods: ' + (corsMethods || 'Not Set'));
                    
                    if (corsOrigin === '*' && corsCredentials === 'true') {{
                        log('[!] CRITICAL: Wildcard CORS with credentials enabled!');
                    }} else if (corsOrigin === '*') {{
                        log('[!] WARNING: Wildcard CORS enabled');
                    }}
                }})
                .catch(error => log('[!] Error: ' + error.message));
            }}
            
            function fetchData() {{
                log('[*] Attempting to fetch data with credentials...');
                
                fetch(targetUrl, {{
                    method: 'GET',
                    credentials: 'include',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }})
                .then(response => response.text())
                .then(data => {{
                    log('[+] Response received!');
                    log('[+] Data: ' + data.substring(0, 500));
                    if (data.length > 500) {{
                        log('... (truncated)');
                    }}
                }})
                .catch(error => log('[!] Error: ' + error.message));
            }}
            
            // Auto-run on load
            window.addEventListener('load', () => {{
                log('[+] CORS PoC Loaded');
                log('[+] Application Origin: ' + window.location.origin);
            }});
        </script>
    </div>
</body>
</html>
"""
        return poc_html
