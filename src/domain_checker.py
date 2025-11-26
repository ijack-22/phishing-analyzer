# src/domain_checker.py
from urllib.parse import urlparse
import whois
from datetime import datetime
import pytz
import ssl
import socket

def extract_domain_from_url(url):
    """Extract domain from full URL - STEP 1"""
    try:
        print(f"🔄 Extracting domain from: {url}")
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        print(f"✅ Extracted domain: {domain}")
        return domain
    except Exception as e:
        print(f"❌ Error extracting domain: {e}")
        return None

def check_domain_age(domain):
    """Check how old the domain is (new domains are suspicious) - STEP 2"""
    try:
        print(f"🔍 Checking domain age for: {domain}")
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        # Handle multiple creation dates (some WHOIS returns list)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # FIX: Handle timezone-aware datetime comparison
            if creation_date.tzinfo is not None:
                # Make creation_date timezone-aware to match datetime.now()
                now_aware = datetime.now(pytz.UTC)
                domain_age_days = (now_aware - creation_date).days
            else:
                # Creation date is naive, make both naive
                now_naive = datetime.now()
                domain_age_days = (now_naive - creation_date).days
            
            print(f"✅ Domain age: {domain_age_days} days (created: {creation_date})")
            
            return {
                'age_days': domain_age_days,
                'creation_date': str(creation_date),
                'is_suspicious': domain_age_days < 180  # Less than 6 months = suspicious
            }
        else:
            print("❌ Could not find creation date")
            return {'age_days': 'Unknown', 'creation_date': 'Unknown', 'is_suspicious': True}
            
    except Exception as e:
        print(f"❌ Domain age check failed: {e}")
        return {'age_days': 'Unknown', 'creation_date': 'Unknown', 'is_suspicious': True}

def check_ssl_certificate(domain):
    """Check SSL certificate validity - STEP 3"""
    try:
        print(f"🔐 Checking SSL certificate for: {domain}")
        context = ssl.create_default_context()
        
        # Try HTTPS first
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check expiration
                expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expires - datetime.now()).days
                
                issuer = dict(x[0] for x in cert['issuer'])['organizationName']
                
                print(f"✅ SSL Valid: {days_until_expiry} days until expiry (Issuer: {issuer})")
                
                return {
                    'valid': True,
                    'days_until_expiry': days_until_expiry,
                    'issuer': issuer,
                    'expires': str(expires)
                }
    except Exception as e:
        print(f"❌ SSL check failed: {e}")
        return {'valid': False, 'error': str(e)}
