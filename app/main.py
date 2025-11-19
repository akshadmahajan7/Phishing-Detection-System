# File: app/main.py (UPDATED)

from flask import Flask, render_template, request, redirect, url_for
import sys
import os
import joblib
import pandas as pd
import numpy as np

# Adjust Python path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import detection components
from src.rule_based.detector import rule_based_detector
from src.ml_model.feature_extractor import extract_features # We use the single URL feature extractor

app = Flask(__name__)

# --- ML Model Loading ---
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'src', 'ml_model', 'model.pkl')
FEATURE_NAMES_PATH = os.path.join(os.path.dirname(__file__), '..', 'src', 'ml_model', 'feature_names.pkl')

ML_MODEL = None
FEATURE_NAMES = None

def load_ml_model():
    """Loads the trained ML model and feature names from disk."""
    global ML_MODEL, FEATURE_NAMES
    try:
        ML_MODEL = joblib.load(MODEL_PATH)
        FEATURE_NAMES = joblib.load(FEATURE_NAMES_PATH)
        print("ML Model and feature names loaded successfully.")
    except Exception as e:
        print(f"Error loading ML Model: {e}")
        print("Please run 'python src/ml_model/trainer.py' first.")

load_ml_model() # Load the model when the application starts

# --- Prediction Logic ---
def ml_predict(url):
    """Extracts features and makes a prediction using the loaded ML model."""
    if ML_MODEL is None:
        return {'is_phishing': False, 'reason': 'ML Model not loaded.'}
    
    # 1. Extract features for the single URL
    raw_features = extract_features(url)
    
    # Temporarily add the domain age feature (simulate external lookup)
    # In a real setup, get_domain_age(url) would be called here.
    raw_features['f_domain_age'] = 1000 if raw_features['f_has_ip'] == 0 else 0 
    
    # Convert features to a DataFrame row
    feature_row = pd.DataFrame([raw_features], columns=FEATURE_NAMES)
    
    # 2. Make prediction
    prediction = ML_MODEL.predict(feature_row)[0]
    
    if prediction == 1:
        return {'is_phishing': True, 'reason': 'Flagged by Machine Learning Classifier (Random Forest)'}
    else:
        # Get probability (for richer output, optional)
        proba = ML_MODEL.predict_proba(feature_row)[0][0] * 100 # Safe probability
        return {'is_phishing': False, 'reason': f'Predicted Safe by ML Classifier ({proba:.2f}% confidence)'}

@app.route('/', methods=['GET'])
def index():
    """Renders the main input form."""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """
    Handles submission and runs sequential detection: Rule-Based then ML.
    """
    if request.method == 'POST':
        url_input = request.form.get('url_input', '').strip()
        
        if not url_input:
            return redirect(url_for('index'))

        # 1. RUN RULE-BASED CHECK
        rule_result = rule_based_detector(url_input)
        
        if rule_result['is_phishing']:
            # If flagged by rule, return result immediately
            final_result = rule_result
        else:
            # 2. IF SAFE, RUN ML CHECK
            print("Rule-Based Passed. Proceeding to ML Analysis...")
            final_result = ml_predict(url_input)
            
        return render_template('result.html', url=url_input, result=final_result)

    return redirect(url_for('index'))

if __name__ == '__main__':
    # You must have installed dependencies and run the trainer.py before running this!
    print("Starting Flask app at http://127.0.0.1:5000/")
    app.run(debug=True)
