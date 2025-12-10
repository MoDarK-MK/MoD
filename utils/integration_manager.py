from typing import Dict, Optional, List, Any
import requests
import json
import os
from datetime import datetime

class AIProvider:
    """Base class for AI provider integrations"""
    def __init__(self, name: str, api_key: str = None, base_url: str = None):
        self.name = name
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = 30
        self.max_retries = 3
        
    def send_request(self, endpoint: str, data: Dict, method: str = 'POST') -> Dict:
        """Send API request with retry logic"""
        headers = self._get_headers()
        url = f"{self.base_url}{endpoint}" if self.base_url else endpoint
        
        for attempt in range(self.max_retries):
            try:
                if method == 'POST':
                    response = requests.post(url, json=data, headers=headers, timeout=self.timeout)
                else:
                    response = requests.get(url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:  # Rate limit
                    if attempt < self.max_retries - 1:
                        continue
                    return {'error': 'Rate limit exceeded', 'provider': self.name}
            except requests.exceptions.Timeout:
                if attempt < self.max_retries - 1:
                    continue
                return {'error': 'Request timeout', 'provider': self.name}
            except Exception as e:
                return {'error': str(e), 'provider': self.name}
        
        return {'error': 'Max retries exceeded', 'provider': self.name}
    
    def _get_headers(self) -> Dict:
        """Get headers for API request"""
        return {
            'Authorization': f'Bearer {self.api_key}' if self.api_key else '',
            'Content-Type': 'application/json',
            'User-Agent': 'MoD-SecurityScanner/4.0.0.4'
        }


class IntegrationManager:
    """Enhanced integration manager with support for 20+ AI providers and notification services"""
    
    def __init__(self):
        # Notification webhooks
        self.slack_webhook = None
        self.teams_webhook = None
        self.discord_webhook = None
        
        # API tokens
        self.github_token = None
        self.gitlab_token = None
        self.jira_url = None
        
        # AI Provider integrations
        self.ai_providers = {}
        self._init_ai_providers()
    
    def _init_ai_providers(self):
        """Initialize supported AI providers"""
        self.supported_providers = {
            # OpenAI
            'openai': {'url': 'https://api.openai.com/v1', 'name': 'OpenAI GPT-4/3.5'},
            
            # Anthropic
            'anthropic': {'url': 'https://api.anthropic.com', 'name': 'Anthropic Claude'},
            
            # Google
            'google_gemini': {'url': 'https://generativelanguage.googleapis.com', 'name': 'Google Gemini'},
            'google_palm': {'url': 'https://makersuite.google.com/api', 'name': 'Google PaLM'},
            
            # Meta
            'llama': {'url': 'https://api.llama.ai', 'name': 'Meta LLaMA'},
            'llama_cloud': {'url': 'https://llama.ai/api', 'name': 'LLaMA Cloud'},
            
            # Mistral
            'mistral': {'url': 'https://api.mistral.ai/v1', 'name': 'Mistral AI'},
            'mistral_cloud': {'url': 'https://mistral.cloud/api', 'name': 'Mistral Cloud'},
            
            # Cohere
            'cohere': {'url': 'https://api.cohere.ai', 'name': 'Cohere'},
            
            # HuggingFace
            'huggingface': {'url': 'https://api-inference.huggingface.co', 'name': 'HuggingFace'},
            'huggingface_inference': {'url': 'https://huggingface.co/api', 'name': 'HuggingFace Inference'},
            
            # Together AI
            'together_ai': {'url': 'https://api.together.xyz/v1', 'name': 'Together AI'},
            
            # Replicate
            'replicate': {'url': 'https://api.replicate.com/v1', 'name': 'Replicate'},
            
            # AI21
            'ai21': {'url': 'https://api.ai21.com/studio/v1', 'name': 'AI21 Labs'},
            
            # Aleph Alpha
            'aleph_alpha': {'url': 'https://api.aleph-alpha.com', 'name': 'Aleph Alpha'},
            
            # Stability AI
            'stability_ai': {'url': 'https://api.stability.ai', 'name': 'Stability AI'},
            
            # Perplexity
            'perplexity': {'url': 'https://api.perplexity.ai', 'name': 'Perplexity AI'},
            
            # LocalLLM (for self-hosted)
            'local_llm': {'url': 'http://localhost:8000', 'name': 'Local LLM Server'},
            
            # Ollama
            'ollama': {'url': 'http://localhost:11434', 'name': 'Ollama'},
        }
    
    def connect_ai_provider(self, provider_name: str, api_key: str = None, base_url: str = None) -> bool:
        """Connect to an AI provider"""
        if provider_name not in self.supported_providers:
            return False
        
        config = self.supported_providers[provider_name]
        provider_url = base_url or config['url']
        
        self.ai_providers[provider_name] = AIProvider(
            name=config['name'],
            api_key=api_key,
            base_url=provider_url
        )
        return True
    
    def disconnect_ai_provider(self, provider_name: str) -> bool:
        """Disconnect from an AI provider"""
        if provider_name in self.ai_providers:
            del self.ai_providers[provider_name]
            return True
        return False
    
    def get_available_providers(self) -> List[str]:
        """Get list of all available AI providers"""
        return list(self.supported_providers.keys())
    
    def get_connected_providers(self) -> List[str]:
        """Get list of currently connected AI providers"""
        return list(self.ai_providers.keys())
    
    def send_ai_request(self, provider_name: str, prompt: str, model: str = None, **kwargs) -> Dict:
        """Send request to an AI provider"""
        if provider_name not in self.ai_providers:
            return {'error': f'Provider {provider_name} not connected'}
        
        provider = self.ai_providers[provider_name]
        
        # Provider-specific request formatting
        if provider_name in ['openai']:
            data = {
                'model': model or 'gpt-4',
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': kwargs.get('temperature', 0.7),
                'max_tokens': kwargs.get('max_tokens', 2000)
            }
            return provider.send_request('/chat/completions', data)
        
        elif provider_name in ['anthropic']:
            data = {
                'model': model or 'claude-3-sonnet-20240229',
                'messages': [{'role': 'user', 'content': prompt}],
                'max_tokens': kwargs.get('max_tokens', 2000)
            }
            return provider.send_request('/messages', data)
        
        elif provider_name in ['google_gemini']:
            data = {
                'contents': [{'parts': [{'text': prompt}]}],
                'generationConfig': {
                    'temperature': kwargs.get('temperature', 0.7),
                    'maxOutputTokens': kwargs.get('max_tokens', 2000)
                }
            }
            return provider.send_request('/generateContent', data)
        
        elif provider_name in ['mistral', 'mistral_cloud']:
            data = {
                'model': model or 'mistral-large-latest',
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': kwargs.get('temperature', 0.7)
            }
            return provider.send_request('/chat/completions', data)
        
        elif provider_name in ['cohere']:
            data = {
                'prompt': prompt,
                'model': model or 'command',
                'max_tokens': kwargs.get('max_tokens', 2000)
            }
            return provider.send_request('/generate', data)
        
        elif provider_name in ['huggingface', 'huggingface_inference']:
            data = {'inputs': prompt}
            return provider.send_request('/models', data)
        
        elif provider_name in ['together_ai']:
            data = {
                'model': model or 'togethercomputer/llama-2-70b-chat',
                'prompt': prompt,
                'max_tokens': kwargs.get('max_tokens', 2000)
            }
            return provider.send_request('/completions', data)
        
        elif provider_name in ['replicate']:
            data = {
                'model': model or 'mistral-7b',
                'input': {'prompt': prompt}
            }
            return provider.send_request('/predictions', data)
        
        elif provider_name in ['local_llm', 'ollama']:
            data = {
                'prompt': prompt,
                'model': model or 'llama2',
                'stream': False
            }
            return provider.send_request('/api/generate', data)
        
        else:
            # Generic request
            data = {'prompt': prompt, **kwargs}
            return provider.send_request('/generate', data)
    
    def set_slack_webhook(self, webhook_url: str):
        self.slack_webhook = webhook_url
    
    def set_teams_webhook(self, webhook_url: str):
        self.teams_webhook = webhook_url
    
    def set_discord_webhook(self, webhook_url: str):
        self.discord_webhook = webhook_url
    
    def get_discord_webhook(self) -> Optional[str]:
        """Get current Discord webhook URL"""
        return self.discord_webhook
    
    def send_discord_message(self, message: str, severity: str = 'info') -> bool:
        """Send message to Discord webhook"""
        return self.send_discord_notification(message, severity)
    
    def send_slack_notification(self, message: str, severity: str = 'info'):
        if not self.slack_webhook:
            return False
        try:
            payload = {
                'text': message,
                'attachments': [{
                    'color': self._get_color_by_severity(severity),
                    'text': message,
                    'ts': int(datetime.now().timestamp())
                }]
            }
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def send_teams_notification(self, message: str, severity: str = 'info'):
        if not self.teams_webhook:
            return False
        try:
            payload = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                'summary': message,
                'themeColor': self._get_color_by_severity(severity),
                'sections': [{
                    'activityTitle': 'MoD Security Alert',
                    'text': message,
                    'activitySubtitle': f'Timestamp: {datetime.now().isoformat()}'
                }]
            }
            response = requests.post(self.teams_webhook, json=payload, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def send_discord_notification(self, message: str, severity: str = 'info'):
        """Send notification to Discord webhook"""
        if not self.discord_webhook:
            return False
        try:
            payload = {
                'content': message,
                'embeds': [{
                    'title': 'MoD Security Alert',
                    'description': message,
                    'color': self._get_color_by_severity_int(severity),
                    'timestamp': datetime.now().isoformat()
                }]
            }
            response = requests.post(self.discord_webhook, json=payload, timeout=10)
            return response.status_code in [200, 204]
        except Exception:
            return False
    
    def _get_color_by_severity(self, severity: str) -> str:
        """Get hex color for severity level (for Slack/Teams)"""
        colors = {
            'Critical': 'ff0000',
            'High': 'ff6600',
            'Medium': 'ffff00',
            'Low': '00ff00',
            'Info': '0099ff'
        }
        return colors.get(severity, '0099ff')
    
    def _get_color_by_severity_int(self, severity: str) -> int:
        """Get integer color for severity level (for Discord)"""
        colors = {
            'Critical': 16711680,  # Red
            'High': 16744448,      # Orange
            'Medium': 16776960,    # Yellow
            'Low': 65280,          # Green
            'Info': 39423          # Blue
        }
        return colors.get(severity, 39423)