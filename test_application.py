#!/usr/bin/env python3
"""Comprehensive application test suite"""

import sys
import os

def test_imports():
    """Test all module imports"""
    print("\n" + "="*70)
    print("TESTING MODULE IMPORTS")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    imports_to_test = [
        ('utils.logger', 'Logger'),
        ('utils.integration_manager', 'IntegrationManager'),
        ('utils.config', 'Config'),
        ('utils.update_checker', 'UpdateChecker'),
        ('core.scanner_engine', 'ScannerEngine'),
    ]
    
    for module_name, class_name in imports_to_test:
        try:
            module = __import__(module_name, fromlist=[class_name])
            getattr(module, class_name)
            print(f"✓ {module_name}.{class_name}")
            tests_passed += 1
        except Exception as e:
            print(f"✗ {module_name}.{class_name}: {str(e)}")
            tests_failed += 1
    
    return tests_passed, tests_failed

def test_logger():
    """Test Logger functionality"""
    print("\n" + "="*70)
    print("TESTING LOGGER FUNCTIONALITY")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    try:
        from utils.logger import Logger, DiscordHandler
        
        # Test Logger initialization
        logger = Logger('TestLogger')
        print("✓ Logger initialization")
        tests_passed += 1
        
        # Test logging methods
        try:
            logger.debug("Test debug message")
            logger.info("Test info message")
            logger.warning("Test warning message")
            logger.error("Test error message")
            logger.critical("Test critical message")
            print("✓ All logging methods work")
            tests_passed += 1
        except Exception as e:
            print(f"✗ Logging methods failed: {str(e)}")
            tests_failed += 1
        
        # Test Discord logging enable/disable
        try:
            # Test enable (without actual webhook)
            result = logger.enable_discord_logging("https://invalid-webhook-url.invalid")
            print("✓ Discord logging enable/disable")
            tests_passed += 1
        except Exception as e:
            print(f"✗ Discord logging methods: {str(e)}")
            tests_failed += 1
        
    except Exception as e:
        print(f"✗ Logger initialization: {str(e)}")
        tests_failed += 1
    
    return tests_passed, tests_failed

def test_integration_manager():
    """Test IntegrationManager functionality"""
    print("\n" + "="*70)
    print("TESTING INTEGRATION MANAGER")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    try:
        from utils.integration_manager import IntegrationManager
        
        manager = IntegrationManager()
        print("✓ IntegrationManager initialization")
        tests_passed += 1
        
        # Test provider methods
        try:
            providers = manager.get_available_providers()
            print(f"✓ get_available_providers ({len(providers)} providers)")
            tests_passed += 1
        except Exception as e:
            print(f"✗ get_available_providers: {str(e)}")
            tests_failed += 1
        
        # Test Discord webhook
        try:
            manager.set_discord_webhook("https://invalid-webhook.invalid")
            print("✓ set_discord_webhook")
            tests_passed += 1
        except Exception as e:
            print(f"✗ set_discord_webhook: {str(e)}")
            tests_failed += 1
        
        # Test provider connection
        try:
            result = manager.connect_ai_provider('openai', api_key='test-key')
            if result:
                print("✓ connect_ai_provider")
                tests_passed += 1
            else:
                print("✗ connect_ai_provider failed")
                tests_failed += 1
        except Exception as e:
            print(f"✗ connect_ai_provider: {str(e)}")
            tests_failed += 1
        
        # Test get connected providers
        try:
            connected = manager.get_connected_providers()
            print(f"✓ get_connected_providers ({len(connected)} connected)")
            tests_passed += 1
        except Exception as e:
            print(f"✗ get_connected_providers: {str(e)}")
            tests_failed += 1
        
    except Exception as e:
        print(f"✗ IntegrationManager initialization: {str(e)}")
        tests_failed += 1
    
    return tests_passed, tests_failed

def test_core_modules():
    """Test core scanning modules"""
    print("\n" + "="*70)
    print("TESTING CORE MODULES")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    core_modules = [
        'auth_manager',
        'cache_manager',
        'distributed_scanner',
        'intelligent_scanner',
        'payload_generator',
        'request_handler',
        'response_analyzer',
        'scanner_engine',
        'vulnerability_detector',
    ]
    
    for module_name in core_modules:
        try:
            module = __import__(f'core.{module_name}', fromlist=[module_name])
            print(f"✓ core.{module_name}")
            tests_passed += 1
        except Exception as e:
            print(f"✗ core.{module_name}: {str(e)}")
            tests_failed += 1
    
    return tests_passed, tests_failed

def test_scanners():
    """Test scanner modules"""
    print("\n" + "="*70)
    print("TESTING SCANNER MODULES")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    scanner_modules = [
        'api_scanner',
        'command_injection_scanner',
        'cors_scanner',
        'csrf_scanner',
        'cve_scanner',
        'file_upload_scanner',
        'graphql_scanner',
        'ldap_scanner',
        'oauth_saml_scanner',
        'rce_scanner',
        'sql_scanner',
        'ssrf_scanner',
        'ssti_scanner',
        'subdomain_scanner',
        'waf_bypass_engine',
        'wayback_scanner',
        'websocket_scanner',
        'xss_scanner',
        'xxe_scanner',
    ]
    
    for module_name in scanner_modules:
        try:
            module = __import__(f'scanners.{module_name}', fromlist=[module_name])
            print(f"✓ scanners.{module_name}")
            tests_passed += 1
        except Exception as e:
            print(f"✗ scanners.{module_name}: {str(e)}")
            tests_failed += 1
    
    return tests_passed, tests_failed

def test_utils():
    """Test utility modules"""
    print("\n" + "="*70)
    print("TESTING UTILITY MODULES")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    util_modules = [
        'cache',
        'compliance_generator',
        'config',
        'database',
        'integration_manager',
        'logger',
        'proxy_manager',
        'report_generator',
        'update_checker',
        'wayback_client',
    ]
    
    for module_name in util_modules:
        try:
            module = __import__(f'utils.{module_name}', fromlist=[module_name])
            print(f"✓ utils.{module_name}")
            tests_passed += 1
        except Exception as e:
            print(f"✗ utils.{module_name}: {str(e)}")
            tests_failed += 1
    
    return tests_passed, tests_failed

def main():
    """Run all tests"""
    print("\n")
    print("█" * 70)
    print("█" + " " * 68 + "█")
    print("█" + "  COMPREHENSIVE APPLICATION TEST SUITE".center(68) + "█")
    print("█" + " " * 68 + "█")
    print("█" * 70)
    
    total_passed = 0
    total_failed = 0
    
    # Run test suites
    passed, failed = test_imports()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_logger()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_integration_manager()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_core_modules()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_scanners()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_utils()
    total_passed += passed
    total_failed += failed
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total Tests Passed: {total_passed} ✓")
    print(f"Total Tests Failed: {total_failed} ✗")
    print(f"Success Rate: {(total_passed / (total_passed + total_failed) * 100):.1f}%")
    print("="*70 + "\n")
    
    return 0 if total_failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
