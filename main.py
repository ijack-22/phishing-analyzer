# main.py
from src.domain_checker import extract_domain_from_url, check_domain_age, check_ssl_certificate
from src.url_scanner import analyze_url_heuristics
from src.vt_integration import check_virustotal_url, check_virustotal_domain, get_virustotal_api_key
import sys

def analyze_phishing_url(url):
    """Main function to analyze a URL for phishing indicators"""
    print(f"\n🎯 PHISHING ANALYSIS REPORT")
    print("=" * 50)
    print(f"🔗 URL: {url}")
    print("=" * 50)
    
    # Extract domain
    domain = extract_domain_from_url(url)
    if not domain:
        print("❌ Failed to analyze URL")
        return
    
    results = {}
    
    # URL Heuristic analysis
    print("\n🔍 URL PATTERN ANALYSIS:")
    url_analysis = analyze_url_heuristics(url)
    results['url_analysis'] = url_analysis
    
    # Domain age analysis
    print("\n📅 DOMAIN AGE ANALYSIS:")
    age_info = check_domain_age(domain)
    results['domain_age'] = age_info
    
    # SSL analysis (only for HTTPS)
    if url.startswith('https://'):
        print("\n🔐 SSL CERTIFICATE ANALYSIS:")
        ssl_info = check_ssl_certificate(domain)
        results['ssl_info'] = ssl_info
    else:
        results['ssl_info'] = {'valid': False, 'reason': 'HTTP only'}
        print("\n🔐 SSL CERTIFICATE: Not applicable (HTTP)")
    
    # VirusTotal analysis (if API key available)
    print("\n🌐 THREAT INTELLIGENCE:")
    vt_api_key = get_virustotal_api_key()
    if vt_api_key:
        # Check URL reputation
        vt_url_result = check_virustotal_url(url, vt_api_key)
        results['virustotal_url'] = vt_url_result
        
        # Check domain reputation
        vt_domain_result = check_virustotal_domain(domain, vt_api_key)
        results['virustotal_domain'] = vt_domain_result
    else:
        print("ℹ️  VirusTotal: No API key configured")
        results['virustotal_url'] = {'error': 'No API key'}
        results['virustotal_domain'] = {'error': 'No API key'}
    
    # Generate final risk assessment
    print("\n⚠️  RISK ASSESSMENT:")
    print("-" * 30)
    
    risk_factors = []
    total_risk_score = 0
    
    # Check domain age risk
    if age_info.get('is_suspicious'):
        risk_factors.append("🚨 Domain is very new (<6 months)")
        total_risk_score += 2
    else:
        risk_factors.append("✅ Domain is established")
    
    # Check SSL risk
    if url.startswith('https://'):
        if results['ssl_info'].get('valid'):
            risk_factors.append("✅ SSL Certificate is valid")
        else:
            risk_factors.append("🚨 SSL Certificate is invalid")
            total_risk_score += 2
    else:
        risk_factors.append("🚨 No SSL encryption (HTTP)")
        total_risk_score += 1
    
    # Add URL heuristic risks
    total_risk_score += url_analysis['risk_score']
    
    # Add VirusTotal risks
    if vt_api_key and 'virustotal_url' in results:
        vt_url = results['virustotal_url']
        if vt_url.get('positives', 0) > 0:
            total_risk_score += 3
            risk_factors.append(f"🚨 VirusTotal: {vt_url['positives']} engines detected threats")
        elif 'error' not in vt_url:
            risk_factors.append("✅ VirusTotal: No threats detected")
    
    # Print all risk factors
    for factor in risk_factors:
        print(factor)
    
    # Print URL-specific risks
    if url_analysis['has_ip_address']:
        print("🚨 URL uses IP address instead of domain")
    if url_analysis['is_shortened']:
        print("🚨 URL uses shortening service")
    if url_analysis['suspicious_tld']:
        print("🚨 Suspicious top-level domain (.xyz, .top, etc.)")
    if url_analysis['suspicious_keywords']:
        print(f"🚨 Suspicious keywords: {', '.join(url_analysis['suspicious_keywords'])}")
    if url_analysis['special_chars_count'] > 3:
        print(f"🚨 Many special characters: {url_analysis['special_chars_count']}")
    
    # Overall risk level
    print(f"\n📊 TOTAL RISK SCORE: {total_risk_score:.1f}/10")
    if total_risk_score >= 5:
        print("🔴 HIGH RISK: Multiple suspicious factors detected!")
    elif total_risk_score >= 2:
        print("🟡 MEDIUM RISK: Suspicious factors detected")
    else:
        print("🟢 LOW RISK: No obvious phishing indicators")
    
    return results

def main():
    """Main function to run the phishing analyzer"""
    print("🛡️  PHISHING LINK ANALYZER")
    print("Type 'quit' to exit")
    print("-" * 40)
    
    while True:
        url = input("\n🔗 Enter URL to analyze: ").strip()
        
        if url.lower() in ['quit', 'exit', 'q']:
            print("👋 Stay safe out there!")
            break
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        analyze_phishing_url(url)

if __name__ == "__main__":
    main()
