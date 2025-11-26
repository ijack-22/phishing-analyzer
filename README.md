
cat > README.md << 'EOF'
# 🛡️ Phishing Link Analyzer

A Python-based cybersecurity tool to detect and analyze potential phishing URLs through multiple detection methods.

## 🔍 Features

- **Domain Age Analysis** - Flags newly registered domains (<6 months)
- **SSL Certificate Verification** - Checks SSL validity and issuer
- **URL Heuristic Analysis** - Detects suspicious patterns and keywords
- **VirusTotal Integration** - Real-time threat intelligence
- **Risk Scoring** - Comprehensive risk assessment with clear indicators
- **Interactive CLI** - Easy-to-use command line interface

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- VirusTotal API key (free tier available)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/phishing-analyzer.git
cd phishing-analyzer
