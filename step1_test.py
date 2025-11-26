# step1_test.py
from src.domain_checker import extract_domain_from_url, check_domain_age, check_ssl_certificate

# Test our domain extraction, age checking, AND SSL
test_urls = [
    "https://google.com",
    "https://www.github.com", 
    "http://example.com/path?query=test"
]

print("🧪 Testing Domain Extraction, Age Check & SSL Verification...")
print("=" * 60)

for url in test_urls:
    print(f"\n🔗 Analyzing: {url}")
    
    # Step 1: Extract domain
    domain = extract_domain_from_url(url)
    
    if domain:
        # Step 2: Check domain age
        age_info = check_domain_age(domain)
        print(f"📅 Domain Age: {age_info['age_days']} days")
        print(f"📅 Created: {age_info['creation_date']}")
        print(f"🚨 Suspiciously new: {age_info['is_suspicious']}")
        
        # Step 3: Check SSL certificate (only for HTTPS URLs)
        if url.startswith('https://'):
            ssl_info = check_ssl_certificate(domain)
            print(f"🔐 SSL Valid: {ssl_info.get('valid', False)}")
            if ssl_info.get('valid'):
                print(f"📅 SSL Expires in: {ssl_info.get('days_until_expiry')} days")
                print(f"🏢 SSL Issuer: {ssl_info.get('issuer')}")
        else:
            print("🔓 No SSL (HTTP only)")
    else:
        print("❌ Failed to extract domain")
    
    print("─" * 60)
