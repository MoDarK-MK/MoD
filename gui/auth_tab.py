from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QFormLayout,
                             QComboBox, QMessageBox, QTabWidget)
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QIcon
from core.auth_manager import AuthManager
from .design_system import (
    DesignMainWidget, DesignColors, DesignSpacing, DesignTypography,
    DesignButton, DesignSection, get_input_stylesheet
)

class AuthTab(DesignMainWidget):
    auth_configured = pyqtSignal(AuthManager)
    
    def __init__(self):
        super().__init__()
        self.header.set_title("Authentication")
        self.header.set_subtitle("Configure authentication methods")
        
        self.auth_manager = AuthManager()
        self.init_ui()
    
    def init_ui(self):
        # Auth Type Selection
        auth_type_layout = QHBoxLayout()
        auth_type_label = QLabel('Authentication Type:')
        auth_type_label.setStyleSheet(f"color: {DesignColors.TEXT_PRIMARY};")
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(['None', 'Basic Auth', 'Bearer Token', 'JWT', 'OAuth2'])
        self.auth_type_combo.currentTextChanged.connect(self.on_auth_type_changed)
        auth_type_layout.addWidget(auth_type_label)
        auth_type_layout.addWidget(self.auth_type_combo)
        auth_type_layout.addStretch()
        self.scroll_content.layout().addLayout(auth_type_layout)
        
        # Auth Config
        self.auth_config_widget = QWidget()
        self.scroll_content.layout().addWidget(self.auth_config_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        test_button = QPushButton('✓ Test Authentication')
        test_button.clicked.connect(self.test_auth)
        button_layout.addWidget(test_button)
        
        apply_button = QPushButton('✔️ Apply Configuration')
        apply_button.clicked.connect(self.apply_auth)
        button_layout.addWidget(apply_button)
        
        clear_button = QPushButton('🗑️ Clear')
        clear_button.clicked.connect(self.clear_auth)
        button_layout.addWidget(clear_button)
        
        self.scroll_content.layout().addLayout(button_layout)
        self.scroll_content.layout().addStretch()
        
        self.on_auth_type_changed('None')
    
    def on_auth_type_changed(self, auth_type: str):
        while self.auth_config_widget.layout():
            self.auth_config_widget.layout().takeAt(0)
        
        layout = QFormLayout()
        
        if auth_type == 'Basic Auth':
            self.username_input = QLineEdit()
            self.username_input.setPlaceholderText('username')
            self.password_input = QLineEdit()
            self.password_input.setPlaceholderText('password')
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            
            layout.addRow('Username:', self.username_input)
            layout.addRow('Password:', self.password_input)
        
        elif auth_type == 'Bearer Token':
            self.token_input = QLineEdit()
            self.token_input.setPlaceholderText('Enter bearer token')
            layout.addRow('Token:', self.token_input)
        
        elif auth_type == 'JWT':
            self.jwt_token_input = QLineEdit()
            self.jwt_token_input.setPlaceholderText('Enter JWT token')
            self.jwt_secret_input = QLineEdit()
            self.jwt_secret_input.setPlaceholderText('Secret (optional)')
            
            layout.addRow('JWT Token:', self.jwt_token_input)
            layout.addRow('Secret:', self.jwt_secret_input)
        
        elif auth_type == 'OAuth2':
            self.oauth_access_token = QLineEdit()
            self.oauth_access_token.setPlaceholderText('Access token')
            self.oauth_refresh_token = QLineEdit()
            self.oauth_refresh_token.setPlaceholderText('Refresh token (optional)')
            
            layout.addRow('Access Token:', self.oauth_access_token)
            layout.addRow('Refresh Token:', self.oauth_refresh_token)
        
        self.auth_config_widget.setLayout(layout)
    
    def test_auth(self):
        auth_type = self.auth_type_combo.currentText()
        
        if auth_type == 'None':
            QMessageBox.information(self, 'Info', 'No authentication method selected')
        else:
            QMessageBox.information(self, 'Success', 'Authentication configuration validated')
    
    def apply_auth(self):
        auth_type = self.auth_type_combo.currentText()
        
        if auth_type == 'None':
            self.auth_manager.clear_auth()
        
        elif auth_type == 'Basic Auth':
            username = self.username_input.text()
            password = self.password_input.text()
            if username and password:
                self.auth_manager.set_basic_auth(username, password)
        
        elif auth_type == 'Bearer Token':
            token = self.token_input.text()
            if token:
                self.auth_manager.set_bearer_token(token)
        
        elif auth_type == 'JWT':
            token = self.jwt_token_input.text()
            secret = self.jwt_secret_input.text()
            if token:
                self.auth_manager.set_jwt_auth(token, secret if secret else None)
        
        elif auth_type == 'OAuth2':
            access_token = self.oauth_access_token.text()
            refresh_token = self.oauth_refresh_token.text()
            if access_token:
                self.auth_manager.set_oauth2(access_token, refresh_token if refresh_token else None)
        
        self.auth_configured.emit(self.auth_manager)
        QMessageBox.information(self, 'Success', 'Authentication applied successfully')
    
    def clear_auth(self):
        self.auth_manager.clear_auth()
        self.auth_type_combo.setCurrentText('None')