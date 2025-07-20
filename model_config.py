"""
Model configuration and utility functions for ML microservice
"""

import re
from typing import Dict, Any, List

# Confidence thresholds for different detection methods
CONFIDENCE_THRESHOLDS = {
    'high': 0.8,
    'medium': 0.6,
    'low': 0.4
}

# Whitelisted domains that are known to be safe
WHITELISTED_DOMAINS = [
    'google.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com',
    'reddit.com', 'medium.com', 'dev.to', 'hashnode.com',
    'wordpress.com', 'blogspot.com', 'tumblr.com'
]

# Suspicious patterns for URL analysis - more conservative
SUSPICIOUS_PATTERNS = [
    r'\b(?:login|signin|secure|verify|account|bank|paypal|ebay)\b',
    r'\b(?:update|confirm|reset|password|credential|invoice|payment|alert)\b',
    r'\b(?:wallet|crypto|bitcoin|blockchain|auth|session|token)\b',
    r'\b(?:wp-admin|wp-content|verify|validate)\b',
    r'\b(?:free|download|click|here|now|urgent|limited|offer)\b',
    r'\b(?:winner|prize|lottery|claim|reward|bonus|cash)\b',
    r'\b(?:virus|malware|scan|clean|remove|fix|repair)\b',
    r'\b(?:suspended|locked|banned|restricted|verify|confirm)\b',
    # High-risk patterns that are more specific
    r'\b(?:bitcoin.*wallet|wallet.*bitcoin)\b',
    r'\b(?:paypal.*verify|verify.*paypal)\b',
    r'\b(?:bank.*login|login.*bank)\b',
    r'\b(?:password.*reset|reset.*password)\b',
    r'\b(?:account.*suspended|suspended.*account)\b'
]

def get_model_config() -> Dict[str, Any]:
    """
    Get model configuration
    """
    return {
        'model_name': 'distilbert-base-uncased',
        'max_length': 512,
        'confidence_thresholds': CONFIDENCE_THRESHOLDS,
        'suspicious_patterns': SUSPICIOUS_PATTERNS,
        'whitelisted_domains': WHITELISTED_DOMAINS
    }

def is_whitelisted_domain(url: str) -> bool:
    """
    Check if the domain is in the whitelist
    """
    if not url:
        return False
    
    # Extract domain from URL
    domain_match = re.search(r'^(?:https?://)?(?:www\.)?([^/:]+)', url.lower())
    if not domain_match:
        return False
    
    domain = domain_match.group(1)
    
    # Check if domain is whitelisted (exact match or subdomain)
    for whitelisted in WHITELISTED_DOMAINS:
        if domain == whitelisted or domain.endswith('.' + whitelisted):
            return True
    
    # Additional check for common legitimate domains
    legitimate_domains = [
        'bopsecrets.org', 'wikipedia.org', 'github.com', 'stackoverflow.com',
        'reddit.com', 'medium.com', 'dev.to', 'hashnode.com', 'blogspot.com',
        'wordpress.com', 'tumblr.com', 'livejournal.com', 'blogger.com',
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'netflix.com', 'youtube.com', 'twitter.com', 'linkedin.com'
    ]
    
    for legit_domain in legitimate_domains:
        if domain == legit_domain or domain.endswith('.' + legit_domain):
            return True
    
    return False

def get_suspicious_score(url: str) -> Dict[str, Any]:
    """
    Calculate suspicious score based on patterns in the URL
    """
    if not url:
        return {'score': 0, 'ratio': 0.0, 'patterns': []}
    
    url_lower = url.lower()
    detected_patterns = []
    total_matches = 0
    
    # Check each suspicious pattern
    for pattern in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, url_lower)
        if matches:
            detected_patterns.extend(matches)
            total_matches += len(matches)
    
    # Calculate ratio of suspicious words to total words
    words = re.findall(r'\b\w+\b', url_lower)
    ratio = total_matches / len(words) if words else 0.0
    
    return {
        'score': total_matches,
        'ratio': ratio,
        'patterns': list(set(detected_patterns))  # Remove duplicates
    }

def extract_domain_features(url: str) -> Dict[str, Any]:
    """
    Extract domain-specific features
    """
    if not url:
        return {}
    
    # Extract domain
    domain_match = re.search(r'^(?:https?://)?(?:www\.)?([^/:]+)', url.lower())
    if not domain_match:
        return {}
    
    domain = domain_match.group(1)
    
    features = {
        'domain_length': len(domain),
        'subdomain_count': domain.count('.'),
        'has_numbers': bool(re.search(r'\d', domain)),
        'has_hyphens': '-' in domain,
        'has_underscores': '_' in domain,
        'is_whitelisted': is_whitelisted_domain(domain)
    }
    
    return features 