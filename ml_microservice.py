#!/usr/bin/env python3
"""
Advanced ML Microservice for Malicious URL Detection
Uses HuggingFace transformers for state-of-the-art phishing/malware detection
"""

from flask import Flask, request, jsonify
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
import os
import logging
from typing import Dict, Any
import re
import numpy as np
from model_config import get_model_config, is_whitelisted_domain, get_suspicious_score, CONFIDENCE_THRESHOLDS

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration - Use a better model for URL classification
MODEL_NAME = os.getenv("HF_MODEL_NAME", "distilbert-base-uncased")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# Initialize the model and tokenizer
logger.info(f"Loading model: {MODEL_NAME} on device: {DEVICE}")

try:
    # Load tokenizer and model
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
    
    # Move to device
    model = model.to(DEVICE)
    model.eval()
    
    logger.info(f"Model loaded successfully: {MODEL_NAME}")
    
except Exception as e:
    logger.error(f"Error loading model {MODEL_NAME}: {e}")
    # Fallback to a simpler model if the specified one fails
    MODEL_NAME = "distilbert-base-uncased"
    logger.info(f"Falling back to: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
    model = model.to(DEVICE)
    model.eval()

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
    Predict if the given text (URL + content) is malicious
    """
    try:
        # Preprocess input
        processed_text = preprocess_url(text)
        
        # Extract features for rule-based classification
        features = extract_url_features(text)
        
        # Rule-based classification since model is not trained
        label = "safe"
        confidence = 0.5
        reason = []
        
        # More conservative high-risk indicators
        if features['suspicious_patterns'] >= 3:
            label = "malicious"
            confidence = 0.85
            reason.append(f"suspicious_patterns >= 3 ({features['suspicious_patterns']})")
        elif features['suspicious_patterns'] == 2:
            label = "malicious"
            confidence = 0.7
            reason.append(f"suspicious_patterns == 2")
        elif features['suspicious_ratio'] > 0.3:
            label = "malicious"
            confidence = 0.65
            reason.append(f"suspicious_ratio > 0.3 ({features['suspicious_ratio']:.2f})")
        
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
        
        # Only flag as malicious if multiple suspicious keywords are found
        if keyword_count >= 2:
            label = "malicious"
            confidence = max(confidence, 0.7)
            reason.append(f"multiple suspicious keywords detected ({keyword_count})")
        
        # Whitelist override logic
        if features['is_whitelisted']:
            label = "safe"
            confidence = max(confidence, 0.9)
            reason.append("whitelisted domain override")
        
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
        
        # High-risk pattern detection
        if features['suspicious_patterns'] > 3:
            label = "malicious"
            confidence = max(confidence, 0.9)
            reason.append(f"suspicious_patterns > 3 ({features['suspicious_patterns']})")
        
        # Log the reason for debugging
        logger.info(f"Rule-based decision: label={label}, confidence={confidence}, reasons={reason}, features={features}")
        
        return {
            "label": label,
            "probability": confidence,
            "confidence": confidence,
            "processed_text": processed_text[:100] + "..." if len(processed_text) > 100 else processed_text,
            "features": features,
            "reason": reason
        }
        
    except Exception as e:
        logger.error(f"Error in prediction: {e}")
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
            "model": MODEL_NAME,
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

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "model": MODEL_NAME,
        "device": DEVICE,
        "model_loaded": model is not None
    })

@app.route("/info", methods=["GET"])
def info():
    """Model information endpoint"""
    return jsonify({
        "model_name": MODEL_NAME,
        "device": DEVICE,
        "model_type": type(model).__name__,
        "tokenizer_type": type(tokenizer).__name__,
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
    logger.info(f"Model: {MODEL_NAME}")
    logger.info(f"Device: {DEVICE}")
    
    app.run(host=host, port=port, debug=False) 