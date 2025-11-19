# File: src/rule_based/detector.py

import re
from urllib.parse import urlparse

# --- RULE-BASED CHECKS ---

def check_url_length(url):
    """
    Check if the URL length is suspicious (often > 75 characters).
    Returns 1 if suspicious (Phishing), 0 if safe.
    """
    if len(url) >= 75:
        return 1
    return 0

def check_at_symbol(url):
    """
    Check for the '@' symbol, often used to embed credentials or mislead.
    Returns 1 if present (Phishing), 0 if safe.
    """
    if '@' in url:
        return 1
    return 0

def check_multiple_subdomains(url):
    """
    Check if the URL has an excessive number of subdomains (e.g., > 3).
    Returns 1 if excessive (Phishing), 0 if safe.
    """
    try:
        # urlparse breaks the URL into components
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        
        # Count the number of dots in the host (excluding the TLD dot)
        # Example: www.sub.example.com -> ['www', 'sub', 'example', 'com'] -> 3 dots.
        # We check if the count of parts is greater than 4 (www.sub.dom.tld)
        parts = host.split('.')
        
        if len(parts) > 4:
            return 1
    except Exception:
        # Handle cases where urlparse might fail
        return 0
    return 0

def check_double_slash(url):
    """
    Check for the presence of '//' other than in the protocol part (http://).
    Returns 1 if found (Phishing), 0 if safe.
    """
    # Find the position of the first occurrence of '//'
    protocol_end = url.find('//')
    
    # If a second '//' is found after the protocol part, it's suspicious
    if protocol_end > -1 and url.rfind('//', protocol_end + 2) > -1:
        return 1
    return 0

# --- MAIN RULE-BASED DETECTOR FUNCTION ---

def rule_based_detector(url):
    """
    Aggregates all rule-based checks.
    If ANY check returns 1 (Phishing), the overall result is Phishing.
    """
    
    # List of all rule functions
    rules = [
        check_url_length,
        check_at_symbol,
        check_multiple_subdomains,
        check_double_slash
    ]

    for rule_func in rules:
        if rule_func(url) == 1:
            return {
                'is_phishing': True,
                'reason': f'Flagged by Rule: {rule_func.__name__}'
            }
            
    return {
        'is_phishing': False,
        'reason': 'Passed all rule-based checks.'
    }

# --- EXAMPLE USAGE (for testing the module) ---
if __name__ == "__main__":
    # Example Phishing URLs
    phish_url_1 = "http://www.bank-of-america.security-login.com/long-form/sign-in?sessionid=123456789012345678901234567890" # Long length
    phish_url_2 = "http://secure.login@fakebank.com/signin" # @ symbol

    # Example Safe URL
    safe_url = "https://www.google.com/search?q=cybersecurity+github"

    print(f"Testing URL: {phish_url_1}")
    print(f"Result: {rule_based_detector(phish_url_1)}")
    
    print("-" * 20)
    
    print(f"Testing URL: {phish_url_2}")
    print(f"Result: {rule_based_detector(phish_url_2)}")
    
    print("-" * 20)

    print(f"Testing URL: {safe_url}")
    print(f"Result: {rule_based_detector(safe_url)}")
