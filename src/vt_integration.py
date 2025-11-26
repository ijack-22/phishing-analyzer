# src/vt_integration.py
import requests
import time
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_virustotal_api_key():
    """Get VirusTotal API key from environment variable"""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        print("❌ VirusTotal API key not found. Please set VIRUSTOTAL_API_KEY in .env file")
        print("💡 Get free API key from: https://www.virustotal.com/gui/join-us")
        return None
    return api_key

def check_virustotal_url(url, api_key):
    """Check URL reputation with VirusTotal"""
    print(f"🔍 Checking VirusTotal for: {url}")
    
    # VirusTotal API endpoint
    url_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    url_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    
    headers = {
        'User-Agent': 'PhishingAnalyzer/1.0'
    }
    
    try:
        # First, submit URL for scanning
        scan_params = {
            'apikey': api_key,
            'url': url
        }
        
        print("📡 Submitting URL to VirusTotal...")
        scan_response = requests.post(url_scan_url, data=scan_params, headers=headers)
        
        if scan_response.status_code == 204:
            print("⏳ API quota exceeded. Waiting 60 seconds...")
            time.sleep(60)
            return {'error': 'API quota exceeded, try again later'}
        
        scan_data = scan_response.json()
        
        # Wait a moment for analysis to complete
        time.sleep(2)
        
        # Get the report
        report_params = {
            'apikey': api_key,
            'resource': url,
            'scan': 1
        }
        
        report_response = requests.get(url_report_url, params=report_params, headers=headers)
        report_data = report_response.json()
        
        if report_data['response_code'] == 1:
            # Analysis successful
            positives = report_data.get('positives', 0)
            total = report_data.get('total', 0)
            
            print(f"✅ VirusTotal: {positives}/{total} engines detected threats")
            
            return {
                'positives': positives,
                'total': total,
                'scan_date': report_data.get('scan_date'),
                'permalink': report_data.get('permalink')
            }
        else:
            print("❌ VirusTotal: No report available")
            return {'error': 'No report available'}
            
    except Exception as e:
        print(f"❌ VirusTotal check failed: {e}")
        return {'error': str(e)}

def check_virustotal_domain(domain, api_key):
    """Check domain reputation with VirusTotal"""
    print(f"🔍 Checking VirusTotal domain reputation: {domain}")
    
    domain_report_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    
    headers = {
        'User-Agent': 'PhishingAnalyzer/1.0'
    }
    
    try:
        params = {
            'apikey': api_key,
            'domain': domain
        }
        
        response = requests.get(domain_report_url, params=params, headers=headers)
        
        if response.status_code == 204:
            print("⏳ API quota exceeded. Waiting 60 seconds...")
            time.sleep(60)
            return {'error': 'API quota exceeded, try again later'}
        
        data = response.json()
        
        if data.get('response_code') == 1:
            # Get detection ratios from various services
            detections = data.get('detected_urls', [])
            positive_detections = sum(item.get('positives', 0) for item in detections[:5])  # Last 5 detections
            
            print(f"✅ VirusTotal Domain: {positive_detections} recent threat detections")
            
            return {
                'detected_urls': len(detections),
                'positive_detections': positive_detections,
                'categories': data.get('categories', {}),
                'whois': data.get('whois', 'Not available')
            }
        else:
            print("❌ VirusTotal: No domain report available")
            return {'error': 'No domain report available'}
            
    except Exception as e:
        print(f"❌ VirusTotal domain check failed: {e}")
        return {'error': str(e)}
