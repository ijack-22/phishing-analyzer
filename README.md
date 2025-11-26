
# 🛡️ Phishing Link Analyzer

A Python-based cybersecurity tool to detect and analyze potential phishing URLs through multiple detection methods.

## 🔍 Features

- **Domain Age Analysis** - Flags newly registered domains (<6 months)
- **SSL Certificate Verification** - Checks SSL validity and issuer
- **URL Heuristic Analysis** - Detects suspicious patterns and keywords
- **VirusTotal Integration** - Real-time threat intelligence
- **Risk Scoring** - Comprehensive risk assessment with clear indicators
- **Interactive CLI** - Easy-to-use command line interface

## Detection Methods

    Domain Analysis: WHOIS lookup, creation date, TLD reputation

    SSL Analysis: Certificate validity, expiration, issuer trust

    URL Patterns: Suspicious keywords, shorteners, special characters

    Threat Intelligence: VirusTotal multi-engine scanning
    
    Risk Scoring

    🟢 0-2: Low risk - Legitimate website

    🟡 2-5: Medium risk - Suspicious indicators

    🔴 5+: High risk - Likely phishing/malicious


    Contributing

Contributions welcome! Please feel free to submit issues, feature requests, or pull requests.

 ##Disclaimer

This tool is for educational and defensive security purposes only. Always use responsibly and in compliance with applicable laws.


### Prerequisites
- Python 3.7+
- VirusTotal API key (free tier available)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/phishing-analyzer.git
cd phishing-analyzer
