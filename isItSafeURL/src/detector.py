import re
import math
from urllib.parse import urlparse
import tldextract

# High-value targets for brand spoofing checks
PROTECTED_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 
    'netflix', 'bankofamerica', 'chase', 'wellsfargo', 'bofa', 
    'instagram', 'twitter', 'linkedin', 'outlook', 'office', 'adobe'
]

# TLDs frequently abused in phishing campaigns
RISKY_TLDS = [
    'zip', 'mov', 'top', 'xyz', 'icu', 'wang', 'work', 
    'online', 'click', 'account', 'security', 'verify'
]

# Common URL shorteners used to hide destinations
SHORTENERS = [
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly'
]

def levenshtein_distance(s1, s2):
    """Calculates the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def canonicalize_domain(domain):
    """
    Unmasks common visual substitutions to find underlying brands.
    e.g., 'rn' -> 'm', '0' -> 'o', '1' -> 'l'
    """
    subs = {
        'rn': 'm',
        'vv': 'w',
        'cl': 'd',
        '0': 'o',
        '1': 'i',
        '|': 'l',
        '8': 'b',
        '5': 's',
        'q': 'g'
    }
    canon = domain.lower()
    for old, new in subs.items():
        canon = canon.replace(old, new)
    return canon

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
    High-fidelity heuristic engine with typosquatting detection.
    Returns a risk score 0-10.
    """
    risk_score = 0
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.lower()
    path_query = (parsed_url.path + parsed_url.query).lower()
    
    # Use tldextract for accurate domain analysis
    ext = tldextract.extract(url)
    subdomain = ext.subdomain.lower()
    domain = ext.domain.lower()
    tld = ext.suffix.lower()

    # 1. Homograph Attack (Punycode / IDN)
    if is_homograph_attack(url) or "xn--" in hostname:
        risk_score += 5

    # 2. IP Address as Hostname
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, hostname):
        risk_score += 4

    # 3. Credential/Authority Obfuscation
    if "@" in url:
        risk_score += 4

    # 4. Deep Typosquatting & Brand Spoofing Logic
    canon_domain = canonicalize_domain(domain)
    
    for brand in PROTECTED_BRANDS:
        # Exact match in non-official domain (e.g., paypal-secure.com)
        if brand in domain and domain != brand:
            risk_score += 5
            break
            
        # Homoglyph Attack (e.g., rnicrosoft.com, g00gle.com)
        if canon_domain == brand and domain != brand:
            risk_score += 6
            break

        # Fuzzy Match (Levenshtein) - Catch bit-squatting or subtle typos
        # Score increases for very close matches (distance 1-2)
        dist = levenshtein_distance(domain, brand)
        if dist == 1 and len(brand) > 3:
            risk_score += 5
            break
        elif dist == 2 and len(brand) > 5:
            risk_score += 3
            break

        # Brand in subdomain
        if brand in subdomain:
            risk_score += 3
            break

    # 5. Risky TLDs
    if tld in RISKY_TLDS:
        risk_score += 3

    # 6. URL Shorteners
    if hostname in SHORTENERS:
        risk_score += 2

    # 7. Suspicious Keywords in Path/Subdomain
    keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'signin', 'confirm']
    for kw in keywords:
        if kw in path_query or kw in subdomain:
            risk_score += 2
            break

    # 8. Hostname Entropy (Random-looking domains)
    entropy = calculate_entropy(domain)
    if entropy > 3.9:
        risk_score += 2

    # 9. Excessive Dashes/Subdomains (Obfuscation)
    if domain.count("-") > 2:
        risk_score += 2
    if subdomain.count(".") > 2:
        risk_score += 2

    # 10. Non-HTTPS
    if parsed_url.scheme == "http":
        risk_score += 1

    # Cap result at 10
    return min(risk_score, 10)

if __name__ == "__main__":
    test_urls = [
        "https://www.microsoft.com",                    # Safe
        "https://rnicrosoft.com/login",                 # Typo (rn -> m)
        "https://g00gle.com",                           # Typo (0 -> o)
        "https://paypa1.com/verify",                    # Typo (1 -> l)
        "https://paypal-security-update.net/login",     # Identity (Brand in name)
        "https://xn--pple-43d.com",                     # Homograph
        "https://bit.ly/3xY8zD",                        # Shortener
        "http://chase.online-verify.top/secure",        # Complex Phish
        "https://microsft.com"                          # Fuzzy (Missing letter)
    ]
    
    print("--- Testing 'Super Realistic' URL Detection Engine\n" + "="*50)
    for url in test_urls:
        score = check_fake_url(url)
        verdict = "PHISHING" if score >= 6 else "SUSPICIOUS" if score >= 3 else "SAFE"
        print(f"URL: {url}")
        print(f"Score: {score}/10 | Verdict: {verdict}\n")
