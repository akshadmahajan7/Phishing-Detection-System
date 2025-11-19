# File: src/ml_model/trainer.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import sys

# Ensure the parent directory (src) is in the Python path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Import modules from other project directories
from src.utils.data_loader import load_phishing_dataset
from src.ml_model.feature_extractor import extract_all_features

# Define the path to save the model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')

def train_and_save_model():
    """
    1. Loads the data.
    2. Extracts ML features.
    3. Trains a Random Forest Classifier.
    4. Evaluates the model.
    5. Saves the trained model to disk.
    """
    print("--- Starting Model Training Pipeline ---")
    
    # 1. Load Data
    X_url, y = load_phishing_dataset()
    
    # 2. Feature Extraction
    print("Extracting features from URLs...")
    # NOTE: In a real-world scenario, the WHOIS lookups in extract_all_features 
    # would be executed here, which is the most time-consuming step.
    X_features = extract_all_features(X_url)
    
    # Check for NaNs and replace (Crucial step for ML robustness)
    X_features = X_features.fillna(0)
    
    # 3. Split Data
    X_train, X_test, y_train, y_test = train_test_split(
        X_features, y, test_size=0.2, random_state=42
    )
    
    print(f"Training on {len(X_train)} samples, Testing on {len(X_test)} samples.")
    
    # 4. Train Classifier (Random Forest is robust and effective for this task)
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    
    # 5. Evaluate Model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print("\n--- Model Evaluation ---")
    print(f"Accuracy: {accuracy:.4f}")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe (0)', 'Phishing (1)']))
    
    # 6. Save Model
    joblib.dump(model, MODEL_PATH)
    print(f"\nModel successfully trained and saved to: {MODEL_PATH}")
    
    # Also save the feature names (important for prediction consistency)
    feature_names_path = os.path.join(os.path.dirname(__file__), 'feature_names.pkl')
    joblib.dump(X_features.columns.tolist(), feature_names_path)
    print(f"Feature names saved to: {feature_names_path}")
    
    print("--- Training Pipeline Complete ---")

if __name__ == '__main__':
    train_and_save_model()
