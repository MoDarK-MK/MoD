from typing import Dict, Optional
import requests
import json

class IntegrationManager:
    def __init__(self):
        self.slack_webhook = None
        self.teams_webhook = None
        self.github_token = None
        self.jira_url = None
    
    def set_slack_webhook(self, webhook_url: str):
        self.slack_webhook = webhook_url
    
    def set_teams_webhook(self, webhook_url: str):
        self.teams_webhook = webhook_url
    
    def send_slack_notification(self, message: str, severity: str = 'info'):
        if not self.slack_webhook:
            return False
        try:
            payload = {
                'text': message,
                'attachments': [{
                    'color': self._get_color_by_severity(severity),
                    'text': message
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
                    'text': message
                }]
            }
            response = requests.post(self.teams_webhook, json=payload, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def _get_color_by_severity(self, severity: str) -> str:
        colors = {
            'Critical': 'ff0000',
            'High': 'ff6600',
            'Medium': 'ffff00',
            'Low': '00ff00',
            'Info': '0099ff'
        }
        return colors.get(severity, '0099ff')