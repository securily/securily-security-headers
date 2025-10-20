# Security Headers Scanner by Securily
![Security Headers Scanner by Securily](securily-security-headers.png)

This tool has been developed by Securily to help developers troubleshoot and analyze the security headers in their web applications, mobile apps, and APIs. By checking the presence and configuration of security headers, this scanner aims to prevent potential security vulnerabilities and protect web applications from being compromised.

**✨ Now with comprehensive support for 26+ security headers including modern browser isolation features!**

## Features

- **Comprehensive Header Analysis**: Analyzes 12 web security headers, 6 app headers, and 11 API headers including modern Cross-Origin isolation policies
- **Expert Security Guidance**: Pre-configured with detailed explanations and remediation steps for each security header
- **Multi-Platform Support**: Separate scanning profiles for web applications, mobile/desktop apps, and RESTful APIs
- **Detailed Configuration**: Each header includes severity ratings, reasoning, remediation steps, and valid values
- **Verbose Output**: Detailed information and feedback during the scanning process for troubleshooting
- **JSON Reports**: Generates comprehensive JSON reports with header status, severity, reasoning, and remediation steps
- **A+ Site Compatible**: Comprehensive coverage of modern security headers for A+ rated sites
- **Works Offline**: Pre-built security header knowledge base
- **Optional AI Insights**: Get smart, contextual security recommendations with Gemini AI

## Quickstart

```bash
git clone https://github.com/securily/security-headers-scanner.git
cd security-headers-scanner
pip install -r requirements.txt
./securily-headers.sh -u https://securily.com
```

## Security Headers Supported

### Web Applications (12 headers)
- ✅ Strict-Transport-Security (HSTS)
- ✅ Content-Security-Policy (CSP)
- ✅ X-Content-Type-Options
- ✅ X-Frame-Options
- ✅ X-XSS-Protection
- ✅ Referrer-Policy
- ✅ Permissions-Policy
- ✅ Cross-Origin-Embedder-Policy
- ✅ Cross-Origin-Opener-Policy
- ✅ Cross-Origin-Resource-Policy
- ✅ Expect-CT
- ✅ Feature-Policy

### API Applications (11 headers)
- ✅ All CORS headers (Access-Control-*)
- ✅ Core security headers (HSTS, CSP, X-Frame-Options)
- ✅ Cross-Origin-Resource-Policy

### Mobile/Desktop Apps (15 headers)
- ✅ All web headers + caching headers
- ✅ Content-Encoding, ETag, Vary, Cache-Control

See [HEADERS_COVERAGE.md](HEADERS_COVERAGE.md) for complete details.

## Installation & Setup

### Prerequisites
- Python 3.7 or higher

### Step 1: Clone the Repository
```bash
git clone https://github.com/securily/security-headers-scanner.git
cd security-headers-scanner
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

## Usage

### Basic Web Scan
```bash
./securily-headers.sh -u https://example.com
```

### Verbose Output (Recommended)
```bash
./securily-headers.sh -u https://example.com -v
```

### API Scan with Authorization
```bash
./securily-headers.sh -u https://api.example.com -a <BEARER_TOKEN>
```

### Command-Line Options
- `-u, --url-to-scan` (required): Target URL to scan
- `-v, --verbose`: Enable detailed output for troubleshooting
- `-a, --authorization-for-api`: Bearer token for API authentication
- `-ai, --ai-insights` (optional): Enable AI-powered insights with Gemini API key

## Output

Results are saved to `results.json` in the current directory.

### Standard Output (without AI):

```json
[
  {
    "url": "https://example.com",
    "name": "Strict-Transport-Security",
    "value": "max-age=31536000; includeSubDomains",
    "severity": "High",
    "reason": "This header helps protect users from man-in-the-middle attacks...",
    "remediation": "To enable this header, add the following...",
    "values": "max-age, includeSubDomains, preload",
    "status": "PASS",
    "status_code": 200
  }
]
```

### Enhanced Output (with AI insights):
```json
{
  "scan_results": [...],
  "ai_insights": {
    "grade": "D",
    "priority_actions": [
      "1. Implement Strict-Transport-Security immediately",
      "2. Add Content-Security-Policy to prevent XSS",
      "3. Configure X-Frame-Options to prevent clickjacking"
    ],
    "risk_assessment": "High risk of MITM attacks, XSS vulnerabilities...",
    "quick_wins": ["Add X-Content-Type-Options: nosniff", "Set X-Frame-Options: DENY"],
    "industry_context": "This site lacks basic security headers that 90% of secure sites implement..."
  },
  "scan_metadata": {
    "url": "https://example.com",
    "timestamp": "2025-10-17T18:30:00",
    "headers_scanned": 12,
    "headers_passed": 0,
    "headers_failed": 12
  }
}
```

## Examples

### Scan a Website with Verbose Output
```bash
./securily-headers.sh -u https://example.com -v
```

### Scan an API Endpoint
```bash
# With authorization token
./securily-headers.sh -u https://api.example.com/v1/users -a "Bearer your-token-here"
```

### Scan with AI Insights (Optional)
```bash
# Get AI-powered security analysis
./securily-headers.sh -u https://example.com -ai YOUR_GEMINI_API_KEY

# Combine with verbose output
./securily-headers.sh -u https://example.com -ai YOUR_GEMINI_API_KEY -v
```

## How It Works

1. **URL Analysis**: Determines if scanning a web app, mobile app, or API
2. **Configuration Loading**: Loads the pre-built security header knowledge base
3. **HTTP Request**: Fetches headers from the target URL (follows redirects)
4. **Comparison**: Analyzes headers against security best practices
5. **Reporting**: Generates detailed JSON report with PASS/FAIL status

The scanner includes comprehensive information about each security header:
- Clear explanations of security risks
- Step-by-step remediation instructions
- Valid header values and directives
- Severity ratings (High, Medium, Low)

## Configuration

The scanner uses a comprehensive `configuration.json` file that contains detailed information about all 26 security headers. This includes severity ratings, explanations, remediation steps, and valid values for each header.

## Documentation

- **configuration.json** - Complete definitions for all 26 security headers
- **example_scan.sh** - Interactive examples and usage demonstrations
- **AI_INSIGHTS.md** - Guide to using the optional AI insights feature

## Troubleshooting

### Configuration File Missing
If the configuration.json file is missing:
```bash
# The scanner requires configuration.json to be present
# Make sure it exists in the same directory as the script
ls -la configuration.json
```

### SSL Certificate Errors
The scanner follows redirects and may disable SSL verification for external content. For production use, review the SSL handling in the code.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements:

1. Read the [Contributor License Agreement](CLA.md)
2. Fork the repository
3. Create a feature branch
4. Submit a pull request
5. Open an issue for bug reports

Please ensure all contributions:
- Include appropriate tests
- Follow existing code style
- Update documentation as needed
- Sign the CLA

## Security

This is a security scanning tool. Please use responsibly:
- Only scan websites you own or have permission to test
- Do not abuse API rate limits
- Keep your API keys secure
- Report security vulnerabilities privately

## License

This tool is open source and licensed under the [GNU General Public License v3.0](LICENSE).

## Acknowledgments

- Developed by [Securily](https://securily.com)
- Inspired by [SecurityHeaders.com](https://securityheaders.com)
- Security header definitions from OWASP

## Version

**Version 2.1** (October 2025)
- 26 security headers supported
- 100% coverage of A+ rated sites
- Multi-platform support (web/app/API)
- Works offline with static configuration
- Optional AI insights with Gemini integration
