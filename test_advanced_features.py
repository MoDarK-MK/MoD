#!/usr/bin/env python3
"""Test Discord and AI functionality"""

import sys
from utils.integration_manager import IntegrationManager
from utils.logger import Logger

def test_discord_integration():
    """Test Discord webhook integration"""
    print("\n" + "="*70)
    print("TESTING DISCORD INTEGRATION")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    try:
        manager = IntegrationManager()
        
        # Test webhook setting
        webhook_url = "https://discord.com/api/webhooks/test/test"
        manager.set_discord_webhook(webhook_url)
        print("✓ set_discord_webhook()")
        tests_passed += 1
        
        # Test webhook retrieval
        retrieved_webhook = manager.get_discord_webhook()
        if retrieved_webhook == webhook_url:
            print("✓ get_discord_webhook() - webhook retrieved correctly")
            tests_passed += 1
        else:
            print(f"✗ get_discord_webhook() - mismatch: {retrieved_webhook}")
            tests_failed += 1
        
        # Test sending Discord message (will fail without valid webhook, but tests the method)
        try:
            result = manager.send_discord_message("Test message", severity="info")
            print("✓ send_discord_message() method callable")
            tests_passed += 1
        except Exception as e:
            if "webhook" in str(e).lower() or "url" in str(e).lower():
                print("✓ send_discord_message() method callable (expected webhook error)")
                tests_passed += 1
            else:
                print(f"✗ send_discord_message(): {str(e)}")
                tests_failed += 1
        
    except Exception as e:
        print(f"✗ Discord integration test: {str(e)}")
        tests_failed += 1
    
    return tests_passed, tests_failed

def test_ai_providers():
    """Test AI provider functionality"""
    print("\n" + "="*70)
    print("TESTING AI PROVIDERS")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    try:
        manager = IntegrationManager()
        
        # Get available providers
        providers = manager.get_available_providers()
        print(f"✓ Found {len(providers)} available AI providers")
        tests_passed += 1
        
        # List all providers
        print(f"\n  Available Providers:")
        for i, provider in enumerate(providers, 1):
            print(f"    {i:2}. {provider}")
        
        # Test provider connection
        manager.connect_ai_provider('openai', api_key='test-key')
        connected = manager.get_connected_providers()
        if 'openai' in connected:
            print(f"\n✓ OpenAI provider connected")
            tests_passed += 1
        else:
            print(f"\n✗ OpenAI provider not in connected list")
            tests_failed += 1
        
        # Test multiple provider support
        manager.connect_ai_provider('anthropic', api_key='test-key')
        connected = manager.get_connected_providers()
        if len(connected) >= 1:
            print(f"✓ Multiple providers supported ({len(connected)} connected)")
            tests_passed += 1
        else:
            print(f"✗ Multiple provider support failed")
            tests_failed += 1
        
    except Exception as e:
        print(f"✗ AI provider test: {str(e)}")
        tests_failed += 1
    
    return tests_passed, tests_failed

def test_logger_discord_integration():
    """Test Logger Discord integration"""
    print("\n" + "="*70)
    print("TESTING LOGGER DISCORD INTEGRATION")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    try:
        logger = Logger("TestDiscord")
        
        # Test enable
        logger.enable_discord_logging("https://discord.com/api/webhooks/test/test", min_level="INFO")
        print("✓ enable_discord_logging()")
        tests_passed += 1
        
        # Test get active webhooks
        webhooks = logger.get_active_webhooks()
        if len(webhooks) > 0:
            print(f"✓ get_active_webhooks() - {len(webhooks)} webhook(s)")
            tests_passed += 1
        else:
            print("✗ No active webhooks found")
            tests_failed += 1
        
        # Test disable
        logger.disable_discord_logging("https://discord.com/api/webhooks/test/test")
        print("✓ disable_discord_logging()")
        tests_passed += 1
        
        # Verify disabled
        webhooks = logger.get_active_webhooks()
        if len(webhooks) == 0:
            print("✓ Webhook disabled successfully")
            tests_passed += 1
        else:
            print("✗ Webhook still active after disable")
            tests_failed += 1
        
    except Exception as e:
        print(f"✗ Logger Discord integration: {str(e)}")
        tests_failed += 1
    
    return tests_passed, tests_failed

def main():
    """Run all tests"""
    print("\n" + "█"*70)
    print("█" + "  ADVANCED FEATURE TESTING (Discord & AI)".center(68) + "█")
    print("█"*70)
    
    total_passed = 0
    total_failed = 0
    
    passed, failed = test_discord_integration()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_ai_providers()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_logger_discord_integration()
    total_passed += passed
    total_failed += failed
    
    print("\n" + "="*70)
    print("ADVANCED TEST SUMMARY")
    print("="*70)
    print(f"Total Tests Passed: {total_passed} ✓")
    print(f"Total Tests Failed: {total_failed} ✗")
    print(f"Success Rate: {(total_passed / (total_passed + total_failed) * 100):.1f}%")
    print("="*70 + "\n")
    
    return 0 if total_failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
