#!/usr/bin/env python3
"""
Code cleanup and project organization script
"""

import os
import sys
from pathlib import Path
from typing import List

class ProjectCleaner:
    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self.issues = []
        self.fixed = []
    
    def fix_unicode_issues(self):
        """Fix unicode character issues in Python files"""
        py_files = list(self.root.rglob('*.py'))
        
        for file_path in py_files:
            try:
                content = file_path.read_text(encoding='utf-8')
                
                # Replace fancy box characters with ASCII equivalents
                replacements = {
                    '[': '[',
                    ']': ']',
                    '[': '[',
                    ']': ']',
                    '|': '|',
                    '=': '=',
                    '>': '>',
                    '[OK]': '[OK]',
                    '[FAIL]': '[FAIL]',
                    '[WARN]': '[WARN]',
                }
                
                updated = False
                for old, new in replacements.items():
                    if old in content:
                        content = content.replace(old, new)
                        updated = True
                
                if updated:
                    file_path.write_text(content, encoding='utf-8')
                    self.fixed.append(str(file_path))
                    print(f"Fixed: {file_path.name}")
                    
            except Exception as e:
                self.issues.append((str(file_path), str(e)))
                print(f"Error in {file_path.name}: {e}")
    
    def remove_temp_files(self):
        """Remove temporary test files"""
        temp_files = [
            'test_zero_day_enhancement.py',
            'optimization_report.json',
            'test_results.json',
            'fix_syntax.py'
        ]
        
        for temp_file in temp_files:
            path = self.root / temp_file
            if path.exists():
                path.unlink()
                print(f"Removed: {temp_file}")
    
    def organize_imports(self):
        """Ensure imports are in correct order"""
        # Key files to check
        key_files = [
            'core/mod_ai.py',
            'core/zero_day_engine.py',
            'scanners/zero_day_scanner.py',
            'gui/main_window.py'
        ]
        
        for file_path in key_files:
            full_path = self.root / file_path
            if full_path.exists():
                try:
                    content = full_path.read_text(encoding='utf-8')
                    if '__future__' in content:
                        lines = content.split('\n')
                        if 'from __future__' not in '\n'.join(lines[:5]):
                            print(f"[WARN] {file_path}: __future__ import not at start")
                except Exception as e:
                    print(f"Error checking {file_path}: {e}")
    
    def report(self):
        """Print cleanup report"""
        print("\n" + "="*60)
        print("PROJECT CLEANUP REPORT")
        print("="*60)
        print(f"Fixed files: {len(self.fixed)}")
        for f in self.fixed:
            print(f"  - {f}")
        
        if self.issues:
            print(f"\nIssues found: {len(self.issues)}")
            for path, issue in self.issues:
                print(f"  - {path}: {issue}")
        
        print("="*60)

if __name__ == '__main__':
    os.chdir('c:\\Users\\modark\\Desktop\\MoD')
    
    cleaner = ProjectCleaner('.')
    print("Cleaning up project...\n")
    
    print("1. Fixing unicode characters...")
    cleaner.fix_unicode_issues()
    
    print("\n2. Removing temporary files...")
    cleaner.remove_temp_files()
    
    print("\n3. Checking import organization...")
    cleaner.organize_imports()
    
    cleaner.report()
    print("\n✓ Cleanup complete!")
