# File: src/utils/data_loader.py

import pandas as pd
import numpy as np

def load_phishing_dataset():
    """
    Simulates loading a structured Phishing dataset (like the UCI Phishing Websites Data Set).
    
    In a real scenario, this function would:
    1. Download the CSV/JSON file.
    2. Load it into a Pandas DataFrame.
    3. Perform initial cleaning (if necessary).
    
    For demonstration, we create a small synthetic DataFrame 
    where 'URL' is the feature column and 'Label' is the target.
    
    Returns: X (features DataFrame), y (labels Series)
    """
    print("Loading and preparing synthetic dataset...")
    
    # Synthetic data resembling real Phishing features
    data = {
        'URL': [
            'https://www.google.com/search?q=safe',
            'http://login.paypal.com@192.168.1.1/', # Phishing (IP/ @)
            'https://very-long-domain-name-to-hide-truth.com/login-new', # Phishing (Length)
            'https://secure.facebook.com/home',
            'http://www.bad-site.info/wp-admin.php', # Phishing (TLD/Keywords)
            'https://www.amazon.com/gp/prime',
            'http://secure.login.bank.com.cn/auth' # Phishing (Multiple subdomains)
        ],
        'Label': [0, 1, 1, 0, 1, 0, 1] # 0 = Safe, 1 = Phishing
    }
    
    df = pd.DataFrame(data)
    
    X = df[['URL']]
    y = df['Label']
    
    print(f"Dataset loaded. Shape: {df.shape}")
    return X, y

if __name__ == '__main__':
    X, y = load_phishing_dataset()
    print("\nSample Features (X):")
    print(X.head())
    print("\nSample Labels (y):")
    print(y.head())
