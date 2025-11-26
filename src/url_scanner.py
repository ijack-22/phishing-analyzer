# src/url_scanner.py
import re
from urllib.parse import urlparse

# Common phishing keywords in URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'banking', 'authenticate',
    'confirm', 'validation', 'signin', 'password', 'credential', 'recovery',
    'facebook', 'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix',
    'wallet', 'crypto', 'coinbase', 'binance', 'trust', 'security', 'auth',
    'oauth', 'sso', 'identity', 'passkey', 'credential', 'token', 'session'
]

# Common URL shorteners
SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'click.me', 'shorte.st', 'bc.vc', 'pub.dev', 'cutt.ly', 'rb.gy',
    'tiny.cc', 'shrink.me', 'shorturl.at', 'ulvis.net', 'x.co', 'cli.gs'
]

# Suspicious TLDs (Top Level Domains)
SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.site', '.online', '.webcam', 
                   '.work', '.bid', '.win', '.loan', '.date', '.racing']

def analyze_url_heuristics(url):
    """Analyze URL for suspicious patterns and keywords"""
    print(f"🔍 Analyzing URL patterns for: {url}")
    
    results = {
        'suspicious_keywords': [],
        'is_shortened': False,
        'has_ip_address': False,
        'suspicious_tld': False,
        'special_chars_count': 0,
        'risk_score': 0
    }
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    path = parsed_url.path.lower()
    full_url_lower = url.lower()
    
    # Check for IP address instead of domain
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    if re.search(ip_pattern, domain):
        results['has_ip_address'] = True
        results['risk_score'] += 3
        print("🚨 URL contains IP address instead of domain name")
    
    # Check for URL shorteners
    for shortener in SHORTENERS:
        if shortener in domain:
            results['is_shortened'] = True
            results['risk_score'] += 2
            print(f"🚨 URL uses shortening service: {shortener}")
            break
    
    # Check for suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            results['suspicious_tld'] = True
            results['risk_score'] += 1
            print(f"🚨 Suspicious TLD detected: {tld}")
            break
    
    # Check for suspicious keywords in domain and path
    for keyword in SUSPICIOUS_KEYWORDS:
        # Check if keyword is in domain or path (more suspicious)
        if keyword in domain or keyword in path:
            results['suspicious_keywords'].append(keyword)
            results['risk_score'] += 1  # Higher risk if in domain/path
            print(f"🚨 Suspicious keyword in domain/path: '{keyword}'")
        # Less risk if only in query parameters
        elif keyword in full_url_lower:
            results['suspicious_keywords'].append(keyword)
            results['risk_score'] += 0.3
            print(f"⚠️  Suspicious keyword in URL: '{keyword}'")
    
    # Check for random-looking subdomains or paths (like sexhfr.xyz)
    if re.search(r'^[a-z]{4,10}\.[a-z]{2,4}$', domain.replace('www.', '')):
        results['risk_score'] += 1
        print("🚨 Domain name appears random/gibberish")
    
    # Check for excessive numbers in URL (like tracking IDs)
    number_count = len(re.findall(r'\d+', url))
    if number_count > 3:
        results['risk_score'] += 1
        print(f"🚨 Excessive numbers in URL ({number_count} found)")
    
    # Check for special characters (potential obfuscation)
    special_chars = len(re.findall(r'[^\w\s./:-]', url))
    results['special_chars_count'] = special_chars
    if special_chars > 3:
        results['risk_score'] += 1
        print(f"🚨 High number of special characters: {special_chars}")
    
    # Overall URL length (very long URLs can be suspicious)
    if len(url) > 75:
        results['risk_score'] += 1
        print(f"🚨 Very long URL ({len(url)} characters)")
    
    # Check for @ symbol (userinfo in URL - can be used for deception)
    if '@' in url:
        results['risk_score'] += 2
        print("🚨 URL contains '@' symbol (potential deception)")
    
    print(f"✅ URL heuristic analysis complete. Risk score: {results['risk_score']:.1f}")
    return results
