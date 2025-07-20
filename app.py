#!/usr/bin/env python3
"""
Python ML Microservice for Malicious URL Detection
Simple Flask service with ML-like behavior for local testing
"""

from flask import Flask, request, jsonify
import logging
import os
import re
import random
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ML-like patterns for URL analysis
ML_PATTERNS = {
    'high_risk': [
        r'(?i)(malware|virus|trojan|spyware|phishing|scam|fake|hack|crack|warez|keygen|nulled)',
        r'(?i)\.(exe|bat|cmd|com|pif|scr|vbs|js|jar|msi|dmg|app|deb|rpm|apk|ipa)$',
        r'(?i)(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|169\.254\.)'
    ],
    'medium_risk': [
        r'(?i)(bit\.ly|goo\.gl|tinyurl|is\.gd|t\.co|fb\.me|ow\.ly|su\.pr|twurl|snipurl)',
        r'(?i)(download|free|cracked|hack|cheat|bot|exploit)',
        r'(?i)(admin|login|signin|banking|payment|verify|update|account)'
    ],
    'low_risk': [
        r'(?i)(google|facebook|twitter|linkedin|github|stackoverflow)',
        r'(?i)\.(com|org|net|edu|gov)$'
    ]
}

def extract_features(url):
    """Extract features from URL for ML-like analysis"""
    features = {
        'length': len(url),
        'special_chars': len(re.findall(r'[^a-zA-Z0-9.]', url)),
        'suspicious_keywords': 0,
        'entropy': 0,
        'complexity': 0
    }
    
    # Count suspicious keywords
    suspicious_words = ['malware', 'virus', 'trojan', 'spyware', 'phishing', 'scam', 'fake', 'hack']
    for word in suspicious_words:
        if word.lower() in url.lower():
            features['suspicious_keywords'] += 1
    
    # Calculate entropy (simplified)
    char_counts = {}
    for char in url.lower():
        char_counts[char] = char_counts.get(char, 0) + 1
    
    total_chars = len(url)
    entropy = 0
    for count in char_counts.values():
        p = count / total_chars
        if p > 0:
            entropy -= p * (p ** 0.5)  # Simplified entropy
    
    features['entropy'] = round(entropy, 2)
    
    # Calculate complexity (ratio of special chars to total length)
    features['complexity'] = round(features['special_chars'] / max(features['length'], 1), 2)
    
    return features

def ml_predict(url):
    """ML-like prediction function"""
    features = extract_features(url)
    
    # Base confidence calculation
    confidence = 0.0
    
    # High risk patterns
    for pattern in ML_PATTERNS['high_risk']:
        if re.search(pattern, url):
            confidence += 0.3
    
    # Medium risk patterns
    for pattern in ML_PATTERNS['medium_risk']:
        if re.search(pattern, url):
            confidence += 0.15
    
    # Feature-based scoring
    if features['suspicious_keywords'] > 0:
        confidence += features['suspicious_keywords'] * 0.1
    
    if features['complexity'] > 0.3:
        confidence += 0.1
    
    if features['entropy'] < -0.5:
        confidence += 0.05
    
    # Add some randomness to simulate ML uncertainty
    confidence += random.uniform(-0.05, 0.05)
    
    # Ensure confidence is between 0 and 1
    confidence = max(0.0, min(1.0, confidence))
    
    # Determine label
    if confidence > 0.6:
        label = 'malicious'
    elif confidence > 0.3:
        label = 'suspicious'
    else:
        label = 'safe'
    
    return label, confidence, features

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'python-ml-microservice',
        'model': 'rule-based-ml-simulator',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    """ML prediction endpoint"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Get ML prediction
        label, confidence, features = ml_predict(url)
        
        result = {
            'url': url,
            'prediction': label,
            'confidence': round(confidence, 3),
            'features': features,
            'model': 'rule-based-ml-simulator',
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"ML prediction for {url}: {label} (confidence: {confidence:.3f})")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in ML prediction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/info', methods=['GET'])
def model_info():
    """Model information endpoint"""
    return jsonify({
        'service': 'python-ml-microservice',
        'model': 'rule-based-ml-simulator',
        'version': '1.0.0',
        'description': 'Rule-based ML simulator for local testing',
        'features': ['url_length', 'special_chars', 'suspicious_keywords', 'entropy', 'complexity'],
        'patterns': {
            'high_risk': len(ML_PATTERNS['high_risk']),
            'medium_risk': len(ML_PATTERNS['medium_risk']),
            'low_risk': len(ML_PATTERNS['low_risk'])
        }
    })

@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        'service': 'Python ML Microservice',
        'version': '1.0.0',
        'endpoints': {
            'health': '/health',
            'predict': '/predict',
            'info': '/info'
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Starting Python ML Microservice on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False) 