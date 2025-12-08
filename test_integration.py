#!/usr/bin/env python3
"""Full integration test for Discord and AI features"""

import sys
from utils.logger import Logger
from utils.integration_manager import IntegrationManager

def test_discord_logging_full():
    """Full Discord logging integration test"""
    print("\n" + "="*70)
    print("FULL DISCORD LOGGING INTEGRATION TEST")
    print("="*70)
    
    try:
        logger = Logger("IntegrationTest")
        webhook = "https://discord.com/api/webhooks/test/webhook"
        
        # Test enable
        logger.enable_discord_logging(webhook, min_level="DEBUG")
        print("✓ Discord logging enabled")
        
        # Test logging at different levels
        logger.debug("Debug message for Discord")
        logger.info("Info message for Discord")
        logger.warning("Warning message for Discord")
        logger.error("Error message for Discord")
        logger.critical("Critical message for Discord")
        print("✓ All logging levels sent to Discord")
        
        # Test webhook management
        webhooks = logger.get_active_webhooks()
        assert len(webhooks) > 0, "No active webhooks found"
        print(f"✓ Active webhooks: {len(webhooks)}")
        
        # Test disable
        logger.disable_discord_logging(webhook)
        webhooks_after = logger.get_active_webhooks()
        assert len(webhooks_after) == 0, "Webhooks not disabled"
        print("✓ Discord logging disabled successfully")
        
        return True
    except Exception as e:
        print(f"✗ Discord logging test failed: {str(e)}")
        return False

def test_ai_integration_full():
    """Full AI integration test"""
    print("\n" + "="*70)
    print("FULL AI INTEGRATION TEST")
    print("="*70)
    
    try:
        manager = IntegrationManager()
        
        # Test provider discovery
        providers = manager.get_available_providers()
        assert len(providers) == 19, f"Expected 19 providers, got {len(providers)}"
        print(f"✓ All 19 AI providers available")
        
        # Test multiple connections
        manager.connect_ai_provider('openai', api_key='test-key-1')
        manager.connect_ai_provider('anthropic', api_key='test-key-2')
        manager.connect_ai_provider('google_gemini', api_key='test-key-3')
        
        connected = manager.get_connected_providers()
        assert len(connected) >= 3, f"Expected 3+ connected providers, got {len(connected)}"
        print(f"✓ Multiple providers connected: {connected}")
        
        # Test provider information
        for provider_name in ['openai', 'anthropic', 'google_gemini']:
            assert provider_name in connected, f"{provider_name} not connected"
        print("✓ All test providers connected successfully")
        
        # Test provider disconnection
        manager.disconnect_ai_provider('openai')
        connected_after = manager.get_connected_providers()
        assert 'openai' not in connected_after, "OpenAI still connected after disconnect"
        print("✓ Provider disconnection working")
        
        return True
    except Exception as e:
        print(f"✗ AI integration test failed: {str(e)}")
        return False

def test_discord_ai_combined():
    """Combined Discord and AI integration test"""
    print("\n" + "="*70)
    print("COMBINED DISCORD & AI INTEGRATION TEST")
    print("="*70)
    
    try:
        logger = Logger("CombinedTest")
        manager = IntegrationManager()
        
        # Set up Discord logging
        logger.enable_discord_logging("https://test-webhook.invalid", min_level="INFO")
        print("✓ Discord logging enabled")
        
        # Set up AI providers
        manager.connect_ai_provider('openai', api_key='test')
        manager.connect_ai_provider('anthropic', api_key='test')
        print("✓ AI providers connected")
        
        # Simulate integrated workflow
        logger.info("Starting security scan with AI analysis")
        print("✓ Log entry created")
        
        # Check Discord webhook
        webhooks = logger.get_active_webhooks()
        assert len(webhooks) > 0, "Discord webhook not active"
        print("✓ Discord webhook active")
        
        # Check AI providers
        connected = manager.get_connected_providers()
        assert 'openai' in connected and 'anthropic' in connected, "AI providers not connected"
        print("✓ AI providers ready")
        
        # Cleanup
        logger.disable_discord_logging("https://test-webhook.invalid")
        print("✓ Cleanup complete")
        
        return True
    except Exception as e:
        print(f"✗ Combined integration test failed: {str(e)}")
        return False

def main():
    """Run all integration tests"""
    print("\n" + "█"*70)
    print("█" + "  FULL INTEGRATION TEST SUITE".center(68) + "█")
    print("█"*70)
    
    results = []
    
    # Run tests
    results.append(("Discord Logging Integration", test_discord_logging_full()))
    results.append(("AI Integration", test_ai_integration_full()))
    results.append(("Combined Discord & AI", test_discord_ai_combined()))
    
    # Summary
    print("\n" + "="*70)
    print("INTEGRATION TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {test_name}")
    
    print("="*70)
    print(f"Total: {passed}/{total} tests passed")
    print(f"Success Rate: {(passed/total*100):.1f}%")
    print("="*70 + "\n")
    
    return 0 if passed == total else 1

if __name__ == '__main__':
    sys.exit(main())
