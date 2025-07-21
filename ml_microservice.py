#!/usr/bin/env python3
"""
AI-Powered ML Microservice for Malicious URL Detection
Uses advanced AI models and threat intelligence for dynamic detection
"""

from flask import Flask, request, jsonify
import os
import logging
from typing import Dict, Any
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pickle
from model_config import get_model_config, is_whitelisted_domain, get_suspicious_score, CONFIDENCE_THRESHOLDS
from ai_detector import detect_malicious_url, AIMalwareDetector
from datetime import datetime
import sys

# Configure enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log')
    ]
)

# Create logger
logger = logging.getLogger(__name__)

# Log startup information
logger.info("=== Python ML Microservice Starting ===")
logger.info("Service: AI-powered URL malware detection")
logger.info("Version: 1.0.0")
logger.info("Environment: Production")
logger.info("AI Detector: Lightweight NLTK-based analysis")
logger.info("========================================")

app = Flask(__name__)

# Configuration
DEVICE = "cpu"  # Always use CPU for scikit-learn

# Initialize AI-powered detection system
logger.info("Initializing AI-Powered ML microservice")

# Initialize AI detector
ai_detector = AIMalwareDetector()

# Fallback to simple model for compatibility
vectorizer = TfidfVectorizer(
    max_features=1000,
    ngram_range=(1, 3),
    stop_words='english'
)

classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    
# Initialize with dummy data to avoid training issues
dummy_urls = [
    "google.com",
    "facebook.com", 
    "amazon.com",
    "malicious-site.com",
    "phishing-example.com"
]
dummy_labels = [0, 0, 0, 1, 1]  # 0 = safe, 1 = malicious

try:
    # Fit the vectorizer and classifier with dummy data
    X_dummy = vectorizer.fit_transform(dummy_urls)
    classifier.fit(X_dummy, dummy_labels)
    logger.info("Fallback model initialized with dummy data")
except Exception as e:
    logger.error(f"Error initializing fallback model: {e}")

def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent processing
    """
    if not url:
        return url
    
    # Convert to lowercase and trim
    normalized = url.lower().strip()
    
    # Remove protocol if present
    normalized = re.sub(r'^https?://', '', normalized)
    
    # Remove www. prefix for consistency
    if normalized.startswith('www.'):
        normalized = normalized[4:]
    
    return normalized

def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract features from URL for better classification
    """
    features = {}
    
    # Normalize URL for feature extraction
    normalized_url = normalize_url(url)
    
    # Basic URL features
    features['length'] = len(normalized_url)
    features['has_https'] = url.startswith('https://')
    features['has_www'] = 'www.' in url.lower()
    features['has_subdomain'] = normalized_url.count('.') > 1
    
    # Get suspicious score using the configuration
    suspicious_data = get_suspicious_score(normalized_url)
    features['suspicious_patterns'] = suspicious_data['score']
    features['suspicious_ratio'] = suspicious_data['ratio']
    features['detected_patterns'] = suspicious_data['patterns']
    
    # Check if domain is whitelisted
    features['is_whitelisted'] = is_whitelisted_domain(normalized_url)
    
    return features

def preprocess_url(url: str, content: str = "") -> str:
    """
    Preprocess URL and content for ML model input
    """
    # Normalize URL for consistent processing
    normalized_url = normalize_url(url)
    
    # Extract domain and path
    parts = normalized_url.split('/', 1)
    domain = parts[0]
    path = '/' + parts[1] if len(parts) > 1 else ''
    
    # Extract features
    features = extract_url_features(url)
    
    # Create feature string
    feature_str = f"len:{features['length']} https:{features['has_https']} www:{features['has_www']} sub:{features['has_subdomain']} sus:{features['suspicious_patterns']}"
    
    # Combine URL with features and content
    if content:
        # Extract text content (remove HTML tags)
        content_text = re.sub(r'<[^>]+>', ' ', content)
        content_text = re.sub(r'\s+', ' ', content_text).strip()
        
        # Combine URL with features and content
        combined = f"{normalized_url} {feature_str} {content_text[:300]}"  # Limit content length
    else:
        combined = f"{normalized_url} {feature_str}"
    
    return combined

def predict_malicious(text: str) -> Dict[str, Any]:
    """
    Predict if the given text (URL + content) is malicious using AI-powered detection
    """
    try:
        # Use AI-powered detection as primary method
        ai_result = ai_detector.detect_malicious(text)
        
        # Map AI result to expected format
        label = "malicious" if ai_result["is_malicious"] else "safe"
        confidence = ai_result["confidence"]
        
        # Prepare detailed reasoning
        reason = ai_result.get("reasoning", [])
        
        # Add threat intelligence details
        threat_intel = ai_result.get("threat_intelligence", {})
        if threat_intel.get("phish_tank", {}).get("is_phishing"):
            reason.append("PhishTank: URL found in phishing database")
        
        if threat_intel.get("url_void", {}).get("detections", 0) > 0:
            detections = threat_intel["url_void"]["detections"]
            engines = threat_intel["url_void"]["engines"]
            reason.append(f"URLVoid: {detections}/{engines} engines detected as malicious")
        
        # Add AI analysis details
        ai_analysis = ai_result.get("ai_analysis", {})
        if ai_analysis.get("semantic_score", 0) > 0.6:
            reason.append(f"Semantic analysis: High suspicious language score ({ai_analysis['semantic_score']:.3f})")
        
        if ai_analysis.get("behavioral_score", 0) > 0.6:
            reason.append(f"Behavioral analysis: Suspicious patterns detected ({ai_analysis['behavioral_score']:.3f})")
        
        # Fallback to rule-based if AI fails
        if confidence == 0.0 or not reason:
            logger.warning("AI detection failed, falling back to rule-based detection")
            return fallback_rule_based_detection(text)
        
        logger.info(f"AI-powered decision: label={label}, confidence={confidence}, risk_level={ai_result['risk_level']}")
        
        return {
            "label": label,
            "probability": confidence,
            "confidence": confidence,
            "processed_text": text[:100] + "..." if len(text) > 100 else text,
            "features": {
                "ai_model": "ai-powered",
                "risk_level": ai_result["risk_level"],
                "threat_intelligence": threat_intel,
                "ai_analysis": ai_analysis
            },
            "reason": reason
        }
        
    except Exception as e:
        logger.error(f"Error in AI prediction: {e}")
        logger.info("Falling back to rule-based detection")
        return fallback_rule_based_detection(text)

def fallback_rule_based_detection(text: str) -> Dict[str, Any]:
    """
    Fallback to rule-based detection if AI fails
    """
    try:
        # Preprocess input
        processed_text = preprocess_url(text)
        
        # Extract features for rule-based classification
        features = extract_url_features(text)
        
        # Rule-based classification with better logic
        label = "safe"
        confidence = 0.8  # Default high confidence for safe
        reason = []
        
        # Whitelist override logic - should be checked FIRST
        if features['is_whitelisted']:
            label = "safe"
            confidence = 0.95
            reason.append("whitelisted domain override")
            return {
                "label": label,
                "probability": confidence,
                "confidence": confidence,
                "processed_text": processed_text[:100] + "..." if len(processed_text) > 100 else processed_text,
                "features": features,
                "reason": reason
            }
        
        # More conservative high-risk indicators - only flag if very suspicious
        if features['suspicious_patterns'] >= 4:
            label = "malicious"
            confidence = 0.85
            reason.append(f"suspicious_patterns >= 4 ({features['suspicious_patterns']})")
        elif features['suspicious_patterns'] == 3:
            label = "malicious"
            confidence = 0.75
            reason.append(f"suspicious_patterns == 3")
        elif features['suspicious_ratio'] > 0.5:  # Increased threshold
            label = "malicious"
            confidence = 0.7
            reason.append(f"suspicious_ratio > 0.5 ({features['suspicious_ratio']:.2f})")
        
        # More specific suspicious keywords (only high-risk ones)
        suspicious_keywords = [
            'login', 'signin', 'secure', 'verify', 'account', 'bank', 'paypal', 'ebay',
            'update', 'confirm', 'reset', 'password', 'credential', 'invoice', 'payment', 'alert',
            'wallet', 'crypto', 'bitcoin', 'blockchain', 'auth', 'session', 'token',
            'wp-admin', 'wp-content', 'verify', 'validate'
        ]
        normalized_text = text.lower()
        keyword_count = 0
        for keyword in suspicious_keywords:
            if keyword in normalized_text:
                keyword_count += 1
        
        # Only flag as malicious if multiple suspicious keywords are found AND not whitelisted
        if keyword_count >= 3:  # Increased threshold
            label = "malicious"
            confidence = max(confidence, 0.75)
            reason.append(f"multiple suspicious keywords detected ({keyword_count})")
        
        # Additional whitelist for common legitimate domains
        legitimate_domains = [
            'bopsecrets.org', 'wikipedia.org', 'github.com', 'stackoverflow.com',
            'reddit.com', 'medium.com', 'dev.to', 'hashnode.com', 'blogspot.com',
            'wordpress.com', 'tumblr.com', 'livejournal.com', 'blogger.com'
        ]
        # Extract domain robustly
        import re
        url_for_domain = text
        if not url_for_domain.startswith('http://') and not url_for_domain.startswith('https://'):
            url_for_domain = 'http://' + url_for_domain
        domain_match = re.search(r'^(?:https?://)?(?:www\.)?([^/:]+)', url_for_domain.lower())
        if domain_match:
            domain = domain_match.group(1)
            if any(legit_domain in domain for legit_domain in legitimate_domains):
                label = "safe"
                confidence = max(confidence, 0.8)
                reason.append("legitimate domain detected")
        
        # High-risk pattern detection - only for very high scores
        if features['suspicious_patterns'] > 5:
            label = "malicious"
            confidence = max(confidence, 0.9)
            reason.append(f"suspicious_patterns > 5 ({features['suspicious_patterns']})")
        
        # Log the reason for debugging
        logger.info(f"Fallback rule-based decision: label={label}, confidence={confidence}, reasons={reason}")
        
        return {
            "label": label,
            "probability": confidence,
            "confidence": confidence,
            "processed_text": processed_text[:100] + "..." if len(processed_text) > 100 else processed_text,
            "features": features,
            "reason": reason
        }
        
    except Exception as e:
        logger.error(f"Error in fallback prediction: {e}")
        return {
            "label": "unknown",
            "probability": 0.5,
            "confidence": 0.0,
            "error": str(e)
        }

@app.route("/predict", methods=["POST"])
def predict():
    """
    Main prediction endpoint
    Expects JSON: {"url": "http://example.com", "content": "<optional page content>"}
    Returns: {"label": "malicious", "probability": 0.98, "confidence": 0.98}
    """
    try:
        data = request.get_json(force=True)
        
        if not data or "url" not in data:
            return jsonify({
                "error": "Missing 'url' parameter",
                "label": "unknown",
                "probability": 0.0
            }), 400
        
        url = data.get("url", "")
        content = data.get("content", "")
        
        if not url:
            return jsonify({
                "error": "Empty URL provided",
                "label": "unknown", 
                "probability": 0.0
            }), 400
        
        # Normalize URL for consistent processing
        normalized_url = normalize_url(url)
        
        # Make prediction
        result = predict_malicious(normalized_url)
        
        # Add metadata
        result.update({
            "model": "scikit-learn", # Indicate it's a lightweight model
            "device": DEVICE,
            "url": url,
            "normalized_url": normalized_url,
            "has_content": bool(content)
        })
        
        logger.info(f"Prediction for {url} (normalized: {normalized_url}): {result['label']} (confidence: {result['confidence']:.3f})")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in /predict endpoint: {e}")
        return jsonify({
            "error": str(e),
            "label": "unknown",
            "probability": 0.0
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check if AI detector is working
        test_result = ai_detector.detect_malicious("https://example.com")
        
        health_status = {
            "status": "UP",
            "service": "Python ML Microservice",
            "version": "1.0.0",
            "ai_detector": "working",
            "timestamp": datetime.now().isoformat(),
            "endpoints": {
                "/predict": "POST - URL prediction endpoint",
                "/health": "GET - Health check endpoint"
            }
        }
        
        app.logger.info("Health check passed - AI detector is working")
        return jsonify(health_status), 200
        
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        health_status = {
            "status": "DOWN",
            "service": "Python ML Microservice",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        return jsonify(health_status), 503

@app.route("/info", methods=["GET"])
def info():
    """Model information endpoint"""
    return jsonify({
        "model_name": "scikit-learn", # Indicate it's a lightweight model
        "device": DEVICE,
        "model_type": type(classifier).__name__,
        "tokenizer_type": type(vectorizer).__name__,
        "max_length": 512,
        "endpoints": {
            "/predict": "POST - Predict malicious URLs",
            "/health": "GET - Health check",
            "/info": "GET - Model information"
        }
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info(f"Starting ML microservice on {host}:{port}")
    logger.info(f"Model: scikit-learn")
    logger.info(f"Device: {DEVICE}")
    
    app.run(host=host, port=port, debug=False) 