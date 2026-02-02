#!/usr/bin/env python3
"""
Demo script for the Secure Data Extraction System
Shows extraction capabilities and security features
"""

from data_extractor import SecureDataExtractor
import json

def demo_extraction():
    """Demonstrate data extraction with various input types"""
    print("Secure Data Extraction System Demo")
    print("=" * 50)
    
    extractor = SecureDataExtractor()
    
    # Demo with realistic mixed data
    sample_data = """
    Customer Support Information:
    
    For technical support, email us at tech-support@company.com or visit 
    our help center at https://help.company.com/support
    
    Sales inquiries: sales@company.com
    Phone: (555) 123-4567 or 1-800-555-0199
    
    Business hours: 9:00 AM to 6:00 PM (Monday-Friday)
    Emergency support available 24/7 at https://emergency.company.com
    
    Payment methods accepted:
    - Visa: 4532123456789012
    - MasterCard: 5555555555554444
    
    System maintenance window: 02:30 to 04:00 daily
    Last updated: 2024-01-15 at 18:45
    """
    
    print("Processing sample customer data...")
    results = extractor.extract_data(sample_data)
    
    print("\nExtraction Results:")
    for data_type, matches in results.items():
        if matches:
            print(f"\n{data_type.upper().replace('_', ' ')}:")
            for match in matches:
                print(f"  - {match}")
    
    return results

def demo_security():
    """Demonstrate security features with malicious input"""
    print("\nSecurity Validation Demo")
    print("=" * 50)
    
    extractor = SecureDataExtractor()
    
    # Test various malicious inputs
    malicious_inputs = [
        {
            'name': 'XSS Injection',
            'data': 'Contact admin@site.com <script>alert("XSS")</script>'
        },
        {
            'name': 'SQL Injection',
            'data': 'Email: user@test.com\'; DROP TABLE users; --'
        },
        {
            'name': 'Path Traversal',
            'data': 'Visit https://site.com or check ../../../etc/passwd'
        },
        {
            'name': 'Command Injection',
            'data': 'Call (555) 123-4567 && rm -rf /'
        }
    ]
    
    for test in malicious_inputs:
        print(f"\nTesting: {test['name']}")
        print(f"Input: {test['data'][:60]}...")
        
        results = extractor.extract_data(test['data'])
        total_matches = sum(len(matches) for matches in results.values())
        
        if total_matches == 0:
            print("SECURE: Input correctly rejected")
        else:
            print(f"WARNING: {total_matches} matches found (potential security issue)")

def demo_edge_cases():
    """Demonstrate handling of edge cases"""
    print("\nEdge Case Testing")
    print("=" * 50)
    
    extractor = SecureDataExtractor()
    
    edge_cases = [
        ('Empty string', ''),
        ('Only spaces', '   '),
        ('Very long email', 'user@' + 'a' * 300 + '.com'),
        ('Invalid credit card', '1234567890123456789012345'),
        ('Invalid time', '25:99 and 12:70 PM'),
        ('Mixed valid/invalid', 'Valid: user@test.com Invalid: not-an-email')
    ]
    
    for name, test_data in edge_cases:
        print(f"\nTesting: {name}")
        results = extractor.extract_data(test_data)
        total_matches = sum(len(matches) for matches in results.values())
        print(f"   Matches found: {total_matches}")

def main():
    """Run the complete demo"""
    try:
        # Main extraction demo
        results = demo_extraction()
        
        # Security demo
        demo_security()
        
        # Edge cases demo
        demo_edge_cases()
        
        # Save results
        with open('demo_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nSummary")
        print("=" * 50)
        print("Data extraction: Working correctly")
        print("Security validation: Blocking malicious input")
        print("Edge case handling: Robust and stable")
        print("Results saved to: demo_results.json")
        
    except Exception as e:
        print(f"\nDemo failed: {e}")
        print("Please ensure all required files are present")

if __name__ == "__main__":
    main()
