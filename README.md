# School Regex Data Extraction System

A secure, regex-based data extraction system designed to process raw text data from external APIs while maintaining security awareness and handling realistic data variations.

## Features

- **Data Extraction**: Extracts 8 different data types using robust regex patterns
- **Security Validation**: Detects and rejects potentially malicious input
- **Sensitive Data Protection**: Masks sensitive information in outputs
- **Real-world Compatibility**: Handles realistic formatting variations
- **Comprehensive Validation**: Additional validation beyond regex matching

## Supported Data Types

1. **Email Addresses**: `user@example.com`, `firstname.lastname@company.co.uk`
2. **URLs**: `https://www.example.com`, `https://subdomain.example.org/page`
3. **Phone Numbers**: `(123) 456-7890`, `123-456-7890`, `123.456.7890`
4. **Credit Card Numbers**: `1234 5678 9012 3456`, `1234-5678-9012-3456`
5. **Time Formats**: `14:30`, `2:30 PM`, `9:00 AM`

## Security Features

### Input Validation
- **SQL Injection Detection**: Identifies common SQL injection patterns
- **XSS Prevention**: Detects cross-site scripting attempts
- **Path Traversal Protection**: Prevents directory traversal attacks
- **Command Injection Detection**: Identifies shell command injection attempts

### Data Protection
- **Credit Card Masking**: Shows only last 4 digits (`****-****-****-1234`)
- **Email Masking**: Partially obscures email addresses (`jo***@example.com`)
- **Secure Logging**: Prevents sensitive data exposure in logs

## Usage

### Basic Usage
```python
from data_extractor import SecureDataExtractor

extractor = SecureDataExtractor()
text = "Contact us at support@company.com or call (555) 123-4567"
results = extractor.extract_data(text)
print(results)
```

### Command Line
```bash
python data_extractor.py
```

## File Structure

```
├── data_extractor.py      # Main extraction script
├── sample_input.txt       # Realistic sample data
├── extraction_results.json # Sample output
└── README.md             # This documentation
```

## Sample Input

The `sample_input.txt` file contains realistic data resembling:
- Customer support tickets
- API responses
- Mixed content with various data types
- Real-world formatting variations

## Sample Output

```json
{
  "email": [
    "jo***@techcorp.com",
    "j.***@gmail.co.uk"
  ],
  "phone": [
    "(555) 123-4567",
    "555.987.6543"
  ],
  "url": [
    "https://www.techcorp.com/checkout",
    "https://app.techcorp.com/dashboard"
  ],
  "credit_card": [
    "************9012",
    "************2222"
  ]
}
```

## Regex Patterns Explained

### Email Pattern
```regex
\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b
```
- Matches standard email formats with various special characters
- Validates domain extensions (minimum 2 characters)

### URL Pattern
```regex
https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?
```
- Supports HTTP and HTTPS protocols
- Handles subdomains, ports, paths, query parameters, and fragments

### Credit Card Pattern
```regex
\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b
```
- Validates major card types (Visa, MasterCard, American Express, Discover)
- Includes Luhn algorithm validation for additional security

## Security Considerations

1. **Input Sanitization**: All input is checked for malicious patterns before processing
2. **Data Masking**: Sensitive data is masked in outputs to prevent exposure
3. **Logging Safety**: Sensitive information is never logged in plain text
4. **Validation Layers**: Multiple validation steps beyond regex matching
5. **Length Limits**: Enforces realistic length limits to prevent buffer overflow attempts

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Installation

1. Clone the repository
2. Run the script: `python data_extractor.py`
3. Check `extraction_results.json` for output

## Testing

The system has been tested with:
- Valid data in various formats
- Malicious input attempts
- Edge cases and boundary conditions
- Real-world data variations

## License

