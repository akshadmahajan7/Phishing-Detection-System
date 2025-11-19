# 🎣 Phishing Detection System

---

## 🌟 Project Overview
This project is a robust, multi-layered solution designed to combat phishing attacks by accurately detecting malicious URLs. It achieves high performance by combining Rule-Based Heuristics for rapid, high-confidence detection with advanced Machine Learning techniques for sophisticated analysis of complex, zero-day threats.
The goal is to provide a reliable, real-time assessment of any URL, classifying it as Safe or Phishing.

---

## ✨ Features and Technology Stack
| **Component** |	**Technology** | **Description** |
| --- | --- | --- |
| **Primary Language** | $\text{Python}$ | The core development language. |
| **Machine Learning** | $\text{Scikit-learn}$ ($\text{Random Forest}$), $\text{Pandas}$ | Used for data preprocessing, feature engineering, and classifier training. |
| **Data Sources** | $\text{UCI ML Phishing Dataset}$, $\text{PhishTank API}$ | High-quality, real-world data sources for model training and dynamic checks. |
| **Rule Engine** | Custom Python implementation | Executes checks for URL length, misleading characters ($\text{@}$), and non-standard encoding ($\text{Punycode}$). |
| **User Interface** | $\text{Flask}$ Web Application | Provides a simple, interactive interface for URL submission and prediction display. | 

---

## 🛡️ The Dual-Layered Detection Strategy
The system's strength lies in its ability to deploy two distinct detection layers sequentially:
**Layer 1: Rule-Based Heuristics (Speed)**
This layer acts as a rapid filter, catching low-effort or obvious phishing attempts based on predefined criteria.
* **URL Anomalies**: Checking for unusual length, excessive use of special characters ($\text{-}$, $\text{/}$), and the presence of the `@` symbol.
* **Domain Age & SSL**: Quickly querying basic $\text{WHOIS}$ data to verify if the domain is newly registered (a common phishing indicator) and checking for a valid $\text{HTTPS/TLS}$ certificate.

**Layer 2: Machine Learning Classification (Sophistication)**
URLs that pass the rule-based check are subjected to detailed analysis by the trained classifier.
1. Feature Extraction: Over 30 features are extracted, covering:
   * Lexical Features: Analyzing the spelling and structure of the hostname.
   * Host-Based Features: Detailed $\text{WHOIS}$ and DNS records.
   * Traffic Features: (Potential future integration) Checking $\text{Alexa}$ rank or site popularity.
2. Prediction: The Random Forest model utilizes these features to calculate the probability of the URL being malicious, providing a final, robust classification.

---

## 🚀 Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites
$\text{Python 3.8+}$
$\text{pip}$ (Python package installer)

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/your-username/Phishing-Detection-System.git
cd Phishing-Detection-System
```
2. **Create and activate a virtual environmen**t:
```bash
python3 -m venv venv
source venv/bin/activate 
```
3. **Install dependencies**:
```bash
pip install -r requirements.txt
```
**Running the Application**
1. **Train the model** (required to generate the necessary `model.pkl` file):
```bash
python src/ml_model/trainer.py
```
2. **Start** **the** **$\text{Flask}$ web server**:
```bash
python app/main.py
```
Access the application in your browser at `http://127.0.0.1:5000/`.

---

## 🤝 Contributing
We highly value contributions! By tackling one of the points below, you can help make this detection system more effective. Please fork the repository and submit a Pull Request.
**Contribution Points**
* **Refinement**: Enhance the `src/rule_based/detector.py` by adding checks for specific high-profile brand names in the URL (e.g., typosquatting).
* **Model Improvement**: Experiment with a different classifier (e.g., $\text{Gradient Boosting}$ or $\text{Neural Network}$) in `src/ml_model/trainer.py` and compare its performance metrics ($\text{F1-score}$, $\text{Recall}$) to the existing $\text{Random Forest}$ model.
* **UI/UX**: Improve the user interface design in the $\text{Flask}$ templates to provide a clearer, more aesthetically pleasing results page.
* **Feature Engineering**: Integrate a function into `src/ml_model/feature_extractor.py` to check the domain's $\text{Google Safe Browsing API}$ status.

---

## 📝 License
This project is open-source and available under the MIT License.<br>
You can find the full license text here: [LICENSE](LICENSE)
