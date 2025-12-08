#!/usr/bin/env python3
"""
Script to update all remaining tab files with professional design system
"""
import os
import re

TAB_FILES = [
    'gui/auth_tab.py',
    'gui/subdomain_tab.py',
    'gui/wayback_tab.py',
    'gui/advanced_settings_tab.py',
    'gui/request_monitor_tab.py',
    'gui/cve_scanner_tab.py',
    'gui/waf_bypass_tab.py',
    'gui/cors_tab.py',
    'gui/discord_tab.py',
    'gui/help_tab.py',
    'gui/graphql_tab.py',
    'gui/websocket_tab.py',
]

def update_imports(content):
    """Update imports to include design_system"""
    # Check if already has design_system import
    if 'from .design_system import' in content:
        return content
    
    # Remove QWidget from imports
    content = content.replace('from PyQt6.QtWidgets import (QWidget, ', 'from PyQt6.QtWidgets import (')
    content = content.replace('QWidget, ', '')
    
    # Find the last import line and add design_system import after it
    lines = content.split('\n')
    last_import_idx = 0
    for i, line in enumerate(lines):
        if line.startswith('from ') or line.startswith('import '):
            last_import_idx = i
    
    if last_import_idx > 0:
        insert_pos = last_import_idx + 1
        design_import = """from .design_system import (
    DesignMainWidget, DesignColors, DesignSpacing, DesignTypography,
    DesignButton, DesignSection, get_input_stylesheet, get_table_stylesheet
)"""
        lines.insert(insert_pos, design_import)
        content = '\n'.join(lines)
    
    return content

def update_class_definition(content):
    """Change class from QWidget to DesignMainWidget"""
    # Find class definition
    pattern = r'class\s+(\w+Tab)\(QWidget\):'
    match = re.search(pattern, content)
    if match:
        class_name = match.group(1)
        content = re.sub(
            rf'class\s+{class_name}\(QWidget\):',
            f'class {class_name}(DesignMainWidget):',
            content
        )
    
    return content

def update_init_method(content):
    """Update __init__ to add header setup"""
    # Find __init__ method and add header setup after super().__init__()
    pattern = r'(def __init__\(.*?\):.*?super\(\)\.__init__\(\))'
    match = re.search(pattern, content, re.DOTALL)
    
    if match:
        init_section = match.group(1)
        if 'self.header.set_title' not in content:
            # Add header setup
            tab_name = re.search(r'class\s+(\w+)Tab\(', content)
            if tab_name:
                # Convert class name to title (e.g., AuthTab -> Authentication)
                class_base = tab_name.group(1)
                title_map = {
                    'Auth': 'Authentication',
                    'Subdomain': 'Subdomain Scanner',
                    'Wayback': 'Wayback Machine',
                    'AdvancedSettings': 'Advanced Settings',
                    'RequestMonitor': 'Request Monitor',
                    'CVEScanner': 'CVE Scanner',
                    'WAFBypass': 'WAF Bypass',
                    'CORS': 'CORS Testing',
                    'Discord': 'Discord Integration',
                    'Help': 'Help & Support',
                    'GraphQL': 'GraphQL Testing',
                    'WebSocket': 'WebSocket Security',
                }
                title = title_map.get(class_base, class_base)
                
                # Find where to insert header setup (after super().__init__())
                super_pattern = r'(super\(\)\.__init__\(\))'
                replacement = f'\\1\n        self.header.set_title("{title}")\n        self.header.set_subtitle("Testing and configuration")'
                content = re.sub(super_pattern, replacement, content, count=1)
    
    return content

def update_setlayout_calls(content):
    """Replace self.setLayout(main_layout) with scroll_content approach"""
    # Replace direct setLayout calls
    content = re.sub(
        r'self\.setLayout\((\w+)\)',
        r'self.scroll_content.layout().addLayout(\1)\n        self.scroll_content.layout().addStretch()',
        content
    )
    
    return content

def process_file(filepath):
    """Process a single tab file"""
    print(f"Processing {filepath}...", end=" ")
    
    if not os.path.exists(filepath):
        print("❌ NOT FOUND")
        return False
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Skip if already updated
        if 'DesignMainWidget' in content:
            print("✓ Already updated")
            return True
        
        # Apply updates
        content = update_imports(content)
        content = update_class_definition(content)
        content = update_init_method(content)
        content = update_setlayout_calls(content)
        
        # Write back
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✓ Updated")
        return True
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Main function"""
    print("=" * 60)
    print("Updating tab files with professional design system")
    print("=" * 60)
    
    updated = 0
    for filepath in TAB_FILES:
        if process_file(filepath):
            updated += 1
    
    print("=" * 60)
    print(f"✓ Updated {updated}/{len(TAB_FILES)} files")
    print("=" * 60)

if __name__ == '__main__':
    main()
