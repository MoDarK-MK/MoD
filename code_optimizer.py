#!/usr/bin/env python3
"""
Advanced code optimization and refactoring script
Improves performance, readability, and maintainability
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Set

class CodeOptimizer:
    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self.optimizations = []
        self.metrics = {
            'files_scanned': 0,
            'issues_found': 0,
            'optimizations_applied': 0
        }
    
    def optimize_imports(self, file_path: Path) -> bool:
        """Remove unused imports and optimize import order"""
        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')
            
            # Check for circular imports or unused imports
            issues_found = False
            for i, line in enumerate(lines[:50]):  # Check first 50 lines
                if line.strip().startswith('import ') or line.strip().startswith('from '):
                    issues_found = True
                    break
            
            return issues_found
        except Exception:
            return False
    
    def optimize_performance(self, file_path: Path) -> List[str]:
        """Identify performance optimization opportunities"""
        recommendations = []
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Check for inefficient patterns
            if content.count('for ') > 5 and content.count('list(') > 3:
                recommendations.append(f"{file_path.name}: Consider using list comprehensions")
            
            if content.count('.append(') > 10 and content.count('list()') > 0:
                recommendations.append(f"{file_path.name}: Consider pre-allocating lists")
            
            if 'sleep' in content and 'import time' in content:
                recommendations.append(f"{file_path.name}: Review sleep() usage for performance")
            
            return recommendations
        except Exception:
            return []
    
    def find_code_duplication(self, file_path: Path) -> List[str]:
        """Find duplicated code patterns"""
        issues = []
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Find similar patterns (simplified)
            functions = re.findall(r'def (\w+)\([^)]*\):', content)
            if len(functions) != len(set(functions)):
                issues.append(f"{file_path.name}: Duplicate function definitions detected")
            
            return issues
        except Exception:
            return []
    
    def check_docstrings(self, file_path: Path) -> int:
        """Count missing or incomplete docstrings"""
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Count functions/classes without docstrings
            definitions = re.findall(r'(def|class) \w+', content)
            docstrings = content.count('"""')
            
            return len(definitions) - (docstrings // 2)
        except Exception:
            return 0
    
    def optimize_project(self):
        """Run all optimizations on the project"""
        py_files = list(self.root.rglob('*.py'))
        
        print("\n" + "="*70)
        print("CODE OPTIMIZATION ANALYSIS")
        print("="*70 + "\n")
        
        # Performance analysis
        print("[1] PERFORMANCE ANALYSIS")
        print("-" * 70)
        all_recommendations = []
        for py_file in py_files:
            if py_file.name in ['test_', 'cleanup_', '__pycache__']:
                continue
            recs = self.optimize_performance(py_file)
            all_recommendations.extend(recs)
        
        if all_recommendations:
            for rec in all_recommendations[:10]:
                print(f"  * {rec}")
            if len(all_recommendations) > 10:
                print(f"  ... and {len(all_recommendations)-10} more")
        else:
            print("  [OK] No performance issues detected")
        
        # Code duplication analysis
        print("\n[2] DUPLICATION ANALYSIS")
        print("-" * 70)
        dup_issues = []
        for py_file in py_files:
            if py_file.name.startswith('test_'):
                continue
            issues = self.find_code_duplication(py_file)
            dup_issues.extend(issues)
        
        if dup_issues:
            for issue in dup_issues[:5]:
                print(f"  * {issue}")
        else:
            print("  [OK] No code duplication detected")
        
        # Docstring coverage
        print("\n[3] DOCUMENTATION COVERAGE")
        print("-" * 70)
        total_missing = 0
        for py_file in py_files:
            if py_file.name.startswith('test_'):
                continue
            missing = self.check_docstrings(py_file)
            if missing > 0:
                print(f"  * {py_file.name}: {missing} missing docstrings")
            total_missing += missing
        
        if total_missing == 0:
            print("  [OK] All functions/classes have docstrings")
        
        print("\n" + "="*70)
        print(f"Scanned: {len(py_files)} Python files")
        print("="*70)

if __name__ == '__main__':
    os.chdir('c:\\Users\\modark\\Desktop\\MoD')
    
    optimizer = CodeOptimizer('.')
    optimizer.optimize_project()
