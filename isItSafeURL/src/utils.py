import csv
from datetime import datetime
import tldextract
import os
from urllib.parse import urlparse


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_FILE = os.path.join(DATA_DIR, "scan_log.csv")

def extract_url_features(url):
    """Extracts subdomain, domain, and TLD from a URL."""
    try:
        ext = tldextract.extract(url)
        return ext.subdomain, ext.domain, ext.suffix
    except Exception:
        return "N/A", "N/A", "N/A"

def log_result(url, score, result, features):
    """
    Logs the detection result to a CSV file.
    Writes a header if the file does not exist.
    """
    
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        
    file_exists = os.path.exists(LOG_FILE)
    
   
    subdomain, domain, tld = features

    with open(LOG_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        
        if not file_exists:
            writer.writerow([
                "Timestamp", "URL", "Risk Score", "Result", 
                "Subdomain", "Domain", "TLD"
            ])
            
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
            url, 
            score, 
            result, 
            subdomain, 
            domain, 
            tld
        ])

def validate_url(url):
    """
    Checks if the URL is properly formatted and doesn't contain
    suspiciously prohibited characters (e.g., spaces).
    """
    if not url or not isinstance(url, str):
        return False
        
    url = url.strip()
    if " " in url:
        return False

    try:
        parsed = urlparse(url)
        if not parsed.scheme in ('http', 'https'):
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False


