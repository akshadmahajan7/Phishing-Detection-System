# File: src/ml_model/feature_extractor.py

import requests
import re
import datetime
from urllib.parse import urlparse
import socket # Used for simple DNS/IP check
import whois # Package: python-whois
import pandas as pd
import numpy as np
from datetime import date

# --- 1. LEXICAL FEATURES ---

def url_length(url):
    """Length of the URL."""
    return len(url)

def hostname_length(url):
    """Length of the hostname."""
    return len(urlparse(url).netloc)

def count_dots(url):
    """Count of dots in the hostname."""
    return urlparse(url).netloc.count('.')

def count_special_chars(url):
    """Count of non-alphanumeric/standard chars (e.g., - and _)."""
    # Exclude protocol and known safe punctuation (., /, :)
    parsed = urlparse(url)
    string = parsed.netloc + parsed.path + parsed.params + parsed.query
    
    # Count special characters that are NOT letters, digits, or basic punctuation
    # (Excludes common URL parts like . / : -)
    return len(re.findall(r"[^a-zA-Z0-9./:-]", string))

def has_ip_address(url):
    """Check if the hostname is an IP address."""
    host = urlparse(url).netloc
    # Simple regex check for IPv4
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_pattern, host):
        return 1
    return 0

# --- 2. DOMAIN/EXTERNAL FEATURES (Requires WHOIS/Requests) ---

def check_ssl_status(url):
    """
    Attempts a simple check if the URL uses HTTPS (often a positive indicator, but not guaranteed).
    Returns 1 if HTTPS is used, 0 otherwise.
    """
    if url.startswith('https://'):
        return 1
    return 0
    
def get_domain_age(url):
    """
    Fetches WHOIS data to determine the domain registration age in days.
    Returns the age (days) or 0 if data is unavailable or an error occurs.
    """
    try:
        domain = urlparse(url).netloc
        if has_ip_address(url):
            return 0 # Cannot WHOIS query IP addresses
            
        w = whois.whois(domain)
        
        # WHOIS response can be tricky. Try 'creation_date'.
        creation_date = w.creation_date
        
        # Handle lists if multiple dates are returned
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # Calculate age from today
            if isinstance(creation_date, datetime.datetime):
                age = (date.today() - creation_date.date()).days
            elif isinstance(creation_date, datetime.date):
                 age = (date.today() - creation_date).days
            
            # Phishing sites are often < 180 days old. Return a large number if old.
            return age if age > 0 else 0
            
    except Exception as e:
        # print(f"WHOIS error for {url}: {e}") # Uncomment for debugging
        return 0 # Return 0 if WHOIS fails (treat as unknown/new for modeling purposes)
        
    return 0 # Default return

# --- 3. AGGREGATOR FUNCTION ---

def extract_features(url):
    """
    Extracts a set of machine learning features from a single URL.
    Returns a dictionary of features.
    """
    features = {}
    
    # 1. Lexical Features
    features['f_url_len'] = url_length(url)
    features['f_hostname_len'] = hostname_length(url)
    features['f_num_dots'] = count_dots(url)
    features['f_num_special_chars'] = count_special_chars(url)
    features['f_has_ip'] = has_ip_address(url)
    
    # 2. Domain/External Features
    features['f_ssl_status'] = check_ssl_status(url)
    
    # WARNING: WHOIS lookups are slow and should be cached in production/training!
    # Removing WHOIS check from the example usage below as it requires external network access
    # features['f_domain_age'] = get_domain_age(url) 
    
    return features

def extract_all_features(X):
    """
    Applies the feature extraction to a DataFrame of URLs.
    X is a DataFrame with a column named 'URL'.
    Returns a new DataFrame with all extracted features.
    """
    feature_list = []
    
    # Iterate through each URL in the input DataFrame
    for index, row in X.iterrows():
        url = row['URL']
        
        # Extract features for the current URL
        extracted_data = extract_features(url)
        
        # Manually add domain age (WHOIS is slow, so we skip it for quick local demo)
        extracted_data['f_domain_age'] = 1000 if extracted_data['f_has_ip'] == 0 else 0 
        
        feature_list.append(extracted_data)
        
    return pd.DataFrame(feature_list)

# --- EXAMPLE USAGE ---
if __name__ == "__main__":
    
    # Sample URLs for testing the feature extraction logic
    test_urls = pd.DataFrame({
        'URL': [
            'https://www.google.com/search',
            'http://10.0.0.1/login.php', 
            'https://tinyurl.com/a-suspicious-long-string-of-chars-that-is-phishing'
        ]
    })
    
    print("Testing Feature Extraction (WHOIS check is skipped for speed):")
    feature_df = extract_all_features(test_urls)
    
    print("\nExtracted Features DataFrame:")
    print(feature_df)
