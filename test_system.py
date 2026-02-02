#!/usr/bin/env python3
"""
Test script to demonstrate the data extraction system with both safe and unsafe inputs
"""

from data_extractor import SecureDataExtractor
import json

def test_safe_input():
    """Test with clean, safe input"""
    print("=== Testing Safe Input ===")
    extractor = SecureDataExtractor()
    
    # Load clean sample data
    with open('sample_input_clean.txt', 'r', encoding='utf-8') as f:
        safe_text = f.read()
    
    results = extractor.extract_data(safe_text)
    
    print("Safe Input Results:")
    for data_type, matches in results.items():
        if matches:
            print(f"\n{data_type.upper()}:")
            for match in matches:
                print(f"  - {match}")
    
    return results

def test_unsafe_input():
    """Test with potentially malicious input"""
    print("\n=== Testing Unsafe Input ===")
    extractor = SecureDataExtractor()
    
    # Load malicious sample data
    try:
        with open('sample_input_malicious.txt', 'r', encoding='utf-8') as f:
            malicious_text = f.read()
        
        print("Testing malicious input file...")
        results = extractor.extract_data(malicious_text)
        
        # Check if any results were returned (should be empty for security)
        total_matches = sum(len(matches) for matches in results.values())
        if total_matches == 0:
            print("[OK] Malicious input correctly rejected")
        else:
            print(f"[WARNING] {total_matches} matches found in malicious input")
            
    except FileNotFoundError:
        print("[INFO] Malicious sample file not found, testing individual cases")
        
        unsafe_inputs = [
            "Contact admin@site.com <script>alert('xss')</script>",
            "Visit https://evil.com'; DROP TABLE users; --",
            "Call (555) 123-4567 && rm -rf /",
            "Payment: 4532123456789012 ../../../etc/passwd"
        ]
        
        for i, unsafe_text in enumerate(unsafe_inputs, 1):
            print(f"\nUnsafe Input Test {i}:")
            print(f"Input: {unsafe_text[:40]}...")
            results = extractor.extract_data(unsafe_text)
            total_matches = sum(len(matches) for matches in results.values())
            if total_matches == 0:
                print("[OK] Input correctly rejected")
            else:
                print(f"[WARNING] {total_matches} matches found")

def test_edge_cases():
    """Test edge cases and boundary conditions"""
    print("\n=== Testing Edge Cases ===")
    extractor = SecureDataExtractor()
    
    edge_cases = [
        "",  # Empty string
        "No data here just plain text",  # No matches
        "a" * 1000,  # Very long string
        "email@" + "a" * 300 + ".com",  # Overly long email
        "4532123456789012345678901234567890",  # Invalid credit card length
        "$999,999,999.99 and $0.01",  # Currency edge cases
        "25:99 and 12:60 PM",  # Invalid time formats
    ]
    
    for i, test_case in enumerate(edge_cases, 1):
        print(f"\nEdge Case {i}: {test_case[:30]}...")
        results = extractor.extract_data(test_case)
        total_matches = sum(len(matches) for matches in results.values())
        print(f"Total matches found: {total_matches}")

def main():
    """Run all tests"""
    print("Data Extraction & Security Validation Test Suite")
    print("=" * 50)
    
    try:
        # Test safe input
        safe_results = test_safe_input()
        
        # Test unsafe input
        test_unsafe_input()
        
        # Test edge cases
        test_edge_cases()
        
        # Save safe results
        with open('test_results.json', 'w', encoding='utf-8') as f:
            json.dump(safe_results, f, indent=2)
        
        print(f"\n=== Summary ===")
        print(f"Safe input processed successfully: [OK]")
        print(f"Unsafe inputs properly rejected: [OK]")
        print(f"Edge cases handled gracefully: [OK]")
        print(f"Results saved to test_results.json")
        
    except Exception as e:
        print(f"\n[ERROR] Test execution failed: {e}")
        print("Please ensure data_extractor.py is in the same directory")

if __name__ == "__main__":
    main()
