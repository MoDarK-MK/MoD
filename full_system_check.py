#!/usr/bin/env python3
import sys
import os
os.environ['PYTHONIOENCODING'] = 'utf-8'

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QSize

app = QApplication(sys.argv)

print("\n" + "="*70)
print("COMPREHENSIVE APPLICATION CHECK")
print("="*70)

tests_passed = 0
tests_failed = 0

# Test 1: All imports
print("\n1. Testing all module imports...")
try:
    from gui.main_window import MainWindow
    from gui.help_tab import HelpTab
    from gui.cors_tab import CORSTab
    from gui.scan_tab import ScanTab
    from gui.results_tab import ResultsTab
    from utils.update_checker import UpdateChecker
    print("   [PASS] All GUI modules imported successfully")
    tests_passed += 1
except Exception as e:
    print(f"   [FAIL] Import error: {e}")
    tests_failed += 1

# Test 2: Scanner imports
print("\n2. Testing scanner imports...")
try:
    from scanners.xss_scanner import XSSScanner
    from scanners.sql_scanner import SQLScanner
    from scanners.rce_scanner import RCEScanner
    from scanners.command_injection_scanner import CommandInjectionScanner
    from scanners.xxe_scanner import XXEScanner
    from scanners.cors_scanner import CORSScanner
    print("   [PASS] All scanner modules imported successfully")
    tests_passed += 1
except Exception as e:
    print(f"   [FAIL] Scanner import error: {e}")
    tests_failed += 1

# Test 3: Core module imports
print("\n3. Testing core module imports...")
try:
    from core.vulnerability_detector import VulnerabilityDetector
    from core.scanner_engine import ScannerEngine
    from core.response_analyzer import ResponseAnalyzer
    print("   [PASS] All core modules imported successfully")
    tests_passed += 1
except Exception as e:
    print(f"   [FAIL] Core module error: {e}")
    tests_failed += 1

# Test 4: Main window sizing
print("\n4. Checking main window sizing...")
try:
    main_window = MainWindow()
    size = main_window.minimumSize()
    print(f"   [INFO] Main window minimum size: {size.width()}x{size.height()}")
    if size.width() >= 1600 and size.height() >= 1000:
        print("   [PASS] Window size is adequate (>= 1600x1000)")
        tests_passed += 1
    else:
        print("   [FAIL] Window size is too small")
        tests_failed += 1
except Exception as e:
    print(f"   [FAIL] Main window error: {e}")
    tests_failed += 1

# Test 5: Update checker
print("\n5. Testing update checker...")
try:
    checker = UpdateChecker()
    version = checker.current_version
    print(f"   [INFO] Current version: {version}")
    print("   [PASS] Update checker initialized successfully")
    tests_passed += 1
except Exception as e:
    print(f"   [FAIL] Update checker error: {e}")
    tests_failed += 1

# Test 6: Version file
print("\n6. Checking version.txt...")
try:
    from pathlib import Path
    version_file = Path(__file__).parent / "version.txt"
    if version_file.exists():
        version = version_file.read_text().strip()
        print(f"   [INFO] Version file found: {version}")
        print("   [PASS] Version file is present and readable")
        tests_passed += 1
    else:
        print("   [FAIL] Version file not found")
        tests_failed += 1
except Exception as e:
    print(f"   [FAIL] Version file error: {e}")
    tests_failed += 1

# Test 7: File syntax check
print("\n7. Checking Python syntax of all files...")
try:
    import py_compile
    from pathlib import Path
    
    py_files = list(Path(__file__).parent.glob('**/*.py'))
    syntax_errors = 0
    
    for py_file in py_files:
        if '__pycache__' in str(py_file):
            continue
        try:
            py_compile.compile(str(py_file), doraise=True)
        except py_compile.PyCompileError:
            syntax_errors += 1
    
    if syntax_errors == 0:
        print(f"   [INFO] Checked {len(py_files)} Python files")
        print("   [PASS] No syntax errors found")
        tests_passed += 1
    else:
        print(f"   [FAIL] Found {syntax_errors} syntax errors")
        tests_failed += 1
except Exception as e:
    print(f"   [FAIL] Syntax check error: {e}")
    tests_failed += 1

print("\n" + "="*70)
print(f"RESULTS: {tests_passed} passed, {tests_failed} failed")
print("="*70)

if tests_failed == 0:
    print("\n[SUCCESS] ALL CHECKS PASSED - APPLICATION IS READY FOR USE")
    sys.exit(0)
else:
    print(f"\n[ERROR] {tests_failed} CHECKS FAILED - PLEASE FIX ISSUES")
    sys.exit(1)
