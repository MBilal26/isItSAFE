import re
import math
from urllib.parse import urlparse


def calculate_entropy(s):
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0
    probabilities = [s.count(c) / len(s) for c in set(s)]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return entropy

def is_homograph_attack(url):
    """Check for non-ASCII characters (potential homograph attack)."""
    try:
        url.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True


def check_fake_url(url):
    """
    Analyzes a URL based on a set of heuristic rules and returns a risk score.
    A score of 5 or higher is considered FAKE/PHISHING.
    """
    risk_score = 0
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc
    path_query = parsed_url.path + parsed_url.query

   
    if is_homograph_attack(url):
        risk_score += 5
        
   
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, hostname):
        risk_score += 4

  
    if "@" in url:
        risk_score += 3

   
    entropy = calculate_entropy(hostname)
    if entropy > 3.5:
        risk_score += 2

   
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update', 'webscr', 'signin']
    for word in suspicious_words:
        if word in path_query.lower():
            risk_score += 2
            break


    if parsed_url.scheme == "http":
        risk_score += 1
    
  
    if len(url) > 100:
        risk_score += 1

    return risk_score

if __name__ == "__main__":
    
    print("🔍 Fake URL Detector (Console Version)")
    
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "https://www.paypal.com@secure-login.net/verify",
        "http://a8d3j2k4l9.com/account/update",
        "https://apple.com/secure/login.php?user=test",
        "https://xn--pple-43d.com" 
    ]
    
    for url in test_urls:
        score = check_fake_url(url)
        result = "FAKE / PHISHING" if score >= 5 else "LEGITIMATE"
        print(f"\nURL: {url}")
        print(f"Risk Score: {score}")
        print(f"Result: {result}")
