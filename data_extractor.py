#!/usr/bin/env python3
"""
Data Extraction & Secure Validation System
A regex-based program for extracting structured data from raw text with security validation.
"""

import re
import json
import logging
from typing import Dict, List, Any

# Configure logging to avoid exposing sensitive data
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureDataExtractor:
    def __init__(self):
        # Regex patterns for data extraction
        self.patterns = {
            'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'url': r'https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?',
            'phone': r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b|\b(?:4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b',
            'time': r'\b(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?:\s?[AaPp][Mm])?\b'
        }
        
        # Security patterns to detect malicious input
        self.security_patterns = {
            'sql_injection': r'(?i)\b(union\s+select|drop\s+table|delete\s+from|insert\s+into|update\s+set)\b',
            'xss': r'(?i)(<script[^>]*>|javascript:|on\w+\s*=\s*["\'][^"\'>]*["\'])',
            'path_traversal': r'\.\.[\\/]',
            'command_injection': r'[;&|`]\s*\w+'
        }
    
    def is_safe_input(self, text: str) -> bool:
        """Check if input contains potentially malicious content"""
        for pattern_name, pattern in self.security_patterns.items():
            if re.search(pattern, text):
                logging.warning(f"Potentially unsafe input detected: {pattern_name}")
                return False
        return True
    
    def sanitize_sensitive_data(self, data: str, data_type: str) -> str:
        """Mask sensitive data for safe output"""
        if data_type == 'credit_card':
            return '*' * 12 + data[-4:]
        elif data_type == 'email':
            parts = data.split('@')
            if len(parts) == 2:
                return parts[0][:2] + '*' * (len(parts[0]) - 2) + '@' + parts[1]
        return data
    
    def extract_data(self, text: str) -> Dict[str, List[str]]:
        """Extract structured data from text with security validation"""
        if not self.is_safe_input(text):
            logging.error("Input rejected due to security concerns")
            return {}
        
        results = {}
        
        for data_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            
            # Additional validation for specific data types
            if data_type == 'email':
                matches = [m for m in matches if self.validate_email(m)]
            elif data_type == 'credit_card':
                matches = [m for m in matches if self.validate_credit_card(m)]
            elif data_type == 'url':
                matches = [m for m in matches if self.validate_url(m)]
            
            # Sanitize sensitive data for output
            if data_type in ['credit_card', 'email']:
                sanitized_matches = [self.sanitize_sensitive_data(m, data_type) for m in matches]
                results[data_type] = sanitized_matches
            else:
                results[data_type] = matches
        
        return results
    
    def validate_email(self, email: str) -> bool:
        """Additional email validation"""
        if len(email) > 254:  # RFC 5321 limit
            return False
        local, domain = email.rsplit('@', 1)
        if len(local) > 64 or len(domain) > 253:  # RFC limits
            return False
        return True
    
    def validate_credit_card(self, card: str) -> bool:
        """Luhn algorithm validation for credit cards"""
        # Remove spaces and dashes for validation
        card = re.sub(r'[\s-]', '', card)
        if len(card) < 13 or len(card) > 19:
            return False
        
        # Luhn algorithm
        total = 0
        reverse_digits = card[::-1]
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n = n // 10 + n % 10
            total += n
        return total % 10 == 0
    
    def validate_url(self, url: str) -> bool:
        """Basic URL validation"""
        return len(url) < 2048 and not any(char in url for char in ['<', '>', '"', ' '])

def main():
    """Main function to demonstrate the data extraction system"""
    extractor = SecureDataExtractor()
    
    # Load sample data
    try:
        with open('sample_input.txt', 'r', encoding='utf-8') as f:
            sample_text = f.read()
    except FileNotFoundError:
        # Fallback sample data
        sample_text = """
        Contact us at support@company.com or sales@business.co.uk for assistance.
        Visit our website at https://www.example.com or https://subdomain.site.org/page
        Call us at (555) 123-4567 or 555.987.6543 for immediate help.
        Payment accepted: 4532 1234 5678 9012 or 5555-4444-3333-2222
        Office hours: 9:00 AM to 5:30 PM, emergency line available 24:7.
        Follow us #TechNews #Innovation #WebDev
        Prices start at $19.99, premium plans from $1,234.56
        <div class="content"><p>Welcome to our site!</p></div>
        """
    
    # Extract data
    results = extractor.extract_data(sample_text)
    
    # Output results
    print("=== Data Extraction Results ===")
    for data_type, matches in results.items():
        if matches:
            print(f"\n{data_type.upper()}:")
            for match in matches:
                print(f"  - {match}")
    
    # Save results to JSON
    with open('extraction_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to extraction_results.json")
    print(f"Total data types extracted: {len([k for k, v in results.items() if v])}")

if __name__ == "__main__":
    main()
