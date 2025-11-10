from typing import Dict, Optional, Tuple
import base64
import jwt
from datetime import datetime, timedelta

class AuthManager:
    def __init__(self):
        self.auth_type = None
        self.credentials = {}
        
    def set_basic_auth(self, username: str, password: str):
        self.auth_type = "basic"
        self.credentials = {
            "username": username,
            "password": password
        }
    
    def set_bearer_token(self, token: str):
        self.auth_type = "bearer"
        self.credentials = {
            "token": token
        }
    
    def set_jwt_auth(self, token: str, secret: Optional[str] = None):
        self.auth_type = "jwt"
        self.credentials = {
            "token": token,
            "secret": secret
        }
    
    def set_oauth2(self, access_token: str, refresh_token: Optional[str] = None):
        self.auth_type = "oauth2"
        self.credentials = {
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    
    def get_auth_header(self) -> Dict[str, str]:
        if self.auth_type == "basic":
            username = self.credentials.get("username", "")
            password = self.credentials.get("password", "")
            credentials = f"{username}:{password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        
        elif self.auth_type == "bearer":
            token = self.credentials.get("token", "")
            return {"Authorization": f"Bearer {token}"}
        
        elif self.auth_type == "jwt":
            token = self.credentials.get("token", "")
            return {"Authorization": f"Bearer {token}"}
        
        elif self.auth_type == "oauth2":
            token = self.credentials.get("access_token", "")
            return {"Authorization": f"Bearer {token}"}
        
        return {}
    
    def validate_jwt(self) -> Tuple[bool, Dict]:
        if self.auth_type != "jwt":
            return False, {"error": "Not a JWT token"}
        
        token = self.credentials.get("token", "")
        secret = self.credentials.get("secret")
        
        try:
            if secret:
                decoded = jwt.decode(token, secret, algorithms=["HS256", "RS256"])
            else:
                decoded = jwt.decode(token, options={"verify_signature": False})
            
            return True, decoded
        except jwt.ExpiredSignatureError:
            return False, {"error": "Token expired"}
        except jwt.InvalidTokenError:
            return False, {"error": "Invalid token"}
        except Exception as e:
            return False, {"error": str(e)}
    
    def test_jwt_vulnerabilities(self, token: str) -> list:
        vulnerabilities = []
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            if decoded.get("alg") == "none":
                vulnerabilities.append({
                    "type": "JWT None Algorithm",
                    "severity": "Critical",
                    "description": "JWT uses 'none' algorithm which bypasses signature verification"
                })
            
            exp = decoded.get("exp")
            if exp:
                exp_date = datetime.fromtimestamp(exp)
                if exp_date > datetime.now() + timedelta(days=365):
                    vulnerabilities.append({
                        "type": "JWT Long Expiration",
                        "severity": "Medium",
                        "description": f"JWT expires in more than 1 year: {exp_date}"
                    })
            else:
                vulnerabilities.append({
                    "type": "JWT No Expiration",
                    "severity": "High",
                    "description": "JWT has no expiration time set"
                })
            
            if not decoded.get("iat"):
                vulnerabilities.append({
                    "type": "JWT No Issued At",
                    "severity": "Low",
                    "description": "JWT has no 'iat' (issued at) claim"
                })
            
        except Exception as e:
            vulnerabilities.append({
                "type": "JWT Parse Error",
                "severity": "Info",
                "description": f"Error parsing JWT: {str(e)}"
            })
        
        return vulnerabilities
    
    def clear_auth(self):
        self.auth_type = None
        self.credentials = {}