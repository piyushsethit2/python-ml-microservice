#!/usr/bin/env python3
"""
AI-Powered Malicious URL Detection
Leverages free AI/ML resources and threat intelligence APIs
"""

import requests
import json
import time
import hashlib
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
import logging
from transformers import pipeline, AutoTokenizer, AutoModel
from sentence_transformers import SentenceTransformer
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    """Stores threat intelligence data from multiple sources"""
    virus_total: Dict[str, Any] = None
    phish_tank: Dict[str, Any] = None
    url_void: Dict[str, Any] = None
    google_safe: Dict[str, Any] = None
    whois_data: Dict[str, Any] = None
    dns_data: Dict[str, Any] = None
    ssl_data: Dict[str, Any] = None

@dataclass
class AIAnalysis:
    """Stores AI analysis results"""
    semantic_score: float = 0.0
    behavioral_score: float = 0.0
    threat_correlation: float = 0.0
    confidence: float = 0.0
    reasoning: List[str] = None
    risk_level: str = "unknown"

class ThreatIntelligenceCollector:
    """Collects threat intelligence from free APIs"""
    
    def __init__(self):
        # Free API endpoints (no authentication required for basic usage)
        self.apis = {
            "phish_tank": "https://checkurl.phishtank.com/checkurl/",
            "url_void": "https://api.urlvoid.com/v1/path/",
            "google_safe": "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        }
        
        # Rate limiting
        self.rate_limits = {
            "phish_tank": {"requests": 0, "limit": 100, "window": 3600},
            "url_void": {"requests": 0, "limit": 100, "window": 86400},
            "google_safe": {"requests": 0, "limit": 10000, "window": 86400}
        }
    
    def collect_all(self, url: str) -> ThreatIntelligence:
        """Collect threat intelligence from all available sources"""
        logger.info(f"Collecting threat intelligence for: {url}")
        
        intel = ThreatIntelligence()
        
        try:
            # PhishTank check (free, no API key required)
            intel.phish_tank = self.check_phishtank(url)
            
            # URLVoid check (free tier)
            intel.url_void = self.check_urlvoid(url)
            
            # WHOIS data (free)
            intel.whois_data = self.get_whois_data(url)
            
            # DNS reputation (free)
            intel.dns_data = self.get_dns_reputation(url)
            
            # SSL certificate analysis (free)
            intel.ssl_data = self.analyze_ssl_certificate(url)
            
        except Exception as e:
            logger.error(f"Error collecting threat intelligence: {e}")
        
        return intel
    
    def check_phishtank(self, url: str) -> Dict[str, Any]:
        """Check URL against PhishTank database"""
        try:
            # Hash the URL for PhishTank API
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            
            response = requests.get(f"{self.apis['phish_tank']}{url_hash}")
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "is_phishing": data.get("in_database", False),
                    "verified": data.get("verified", False),
                    "verified_at": data.get("verified_at"),
                    "details": data.get("details", {})
                }
        except Exception as e:
            logger.warning(f"PhishTank check failed: {e}")
        
        return {"is_phishing": False, "verified": False}
    
    def check_urlvoid(self, url: str) -> Dict[str, Any]:
        """Check URL against URLVoid database"""
        try:
            # URLVoid requires domain only
            domain = urlparse(url).netloc
            
            response = requests.get(f"{self.apis['url_void']}{domain}")
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "detections": data.get("detections", 0),
                    "engines": data.get("engines", 0),
                    "scan_date": data.get("scan_date"),
                    "details": data.get("details", {})
                }
        except Exception as e:
            logger.warning(f"URLVoid check failed: {e}")
        
        return {"detections": 0, "engines": 0}
    
    def get_whois_data(self, url: str) -> Dict[str, Any]:
        """Get WHOIS data for domain"""
        try:
            domain = urlparse(url).netloc
            
            # Use free WHOIS service
            response = requests.get(f"https://whois.whoisxmlapi.com/api/v1?apiKey=at_demo&domainName={domain}")
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "registrar": data.get("registrar", {}),
                    "creation_date": data.get("creationDate"),
                    "expiration_date": data.get("expirationDate"),
                    "domain_age_days": self.calculate_domain_age(data.get("creationDate")),
                    "country": data.get("registrant", {}).get("country")
                }
        except Exception as e:
            logger.warning(f"WHOIS check failed: {e}")
        
        return {}
    
    def get_dns_reputation(self, url: str) -> Dict[str, Any]:
        """Analyze DNS reputation"""
        try:
            domain = urlparse(url).netloc
            
            # Check for suspicious DNS patterns
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            suspicious_subdomains = ['www', 'secure', 'login', 'signin']
            
            return {
                "suspicious_tld": any(domain.endswith(tld) for tld in suspicious_tlds),
                "suspicious_subdomain": any(sub in domain.lower() for sub in suspicious_subdomains),
                "domain_length": len(domain),
                "subdomain_count": domain.count('.')
            }
        except Exception as e:
            logger.warning(f"DNS analysis failed: {e}")
        
        return {}
    
    def analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        try:
            import ssl
            import socket
            
            domain = urlparse(url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "valid": True,
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject']),
                        "expires": cert['notAfter'],
                        "san": cert.get('subjectAltName', [])
                    }
        except Exception as e:
            logger.warning(f"SSL analysis failed: {e}")
            return {"valid": False, "error": str(e)}
    
    def calculate_domain_age(self, creation_date: str) -> int:
        """Calculate domain age in days"""
        try:
            from datetime import datetime
            if creation_date:
                created = datetime.strptime(creation_date, "%Y-%m-%d")
                now = datetime.now()
                return (now - created).days
        except:
            pass
        return 0

class AIAnalyzer:
    """Performs AI-powered analysis using free models"""
    
    def __init__(self):
        logger.info("Initializing AI Analyzer...")
        
        try:
            # Load pre-trained models (free from Hugging Face)
            self.sentiment_analyzer = pipeline("sentiment-analysis", model="distilbert-base-uncased")
            self.text_classifier = pipeline("text-classification", model="microsoft/DialoGPT-medium")
            self.similarity_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            logger.info("AI models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load AI models: {e}")
            # Fallback to rule-based analysis
    
    def analyze_url(self, url: str, content: str = "", intel: ThreatIntelligence = None) -> AIAnalysis:
        """Perform comprehensive AI analysis"""
        logger.info(f"Performing AI analysis for: {url}")
        
        analysis = AIAnalysis()
        reasoning = []
        
        try:
            # 1. Semantic Analysis
            semantic_score = self.analyze_semantics(url, content)
            analysis.semantic_score = semantic_score
            reasoning.append(f"Semantic analysis score: {semantic_score:.3f}")
            
            # 2. Behavioral Analysis
            behavioral_score = self.analyze_behavioral_patterns(url, content)
            analysis.behavioral_score = behavioral_score
            reasoning.append(f"Behavioral analysis score: {behavioral_score:.3f}")
            
            # 3. Threat Correlation
            if intel:
                threat_correlation = self.correlate_threat_indicators(intel)
                analysis.threat_correlation = threat_correlation
                reasoning.append(f"Threat correlation score: {threat_correlation:.3f}")
            
            # 4. Calculate overall confidence
            scores = [semantic_score, behavioral_score]
            if intel:
                scores.append(analysis.threat_correlation)
            
            analysis.confidence = np.mean(scores)
            analysis.reasoning = reasoning
            
            # 5. Determine risk level
            analysis.risk_level = self.determine_risk_level(analysis.confidence, intel)
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            analysis.confidence = 0.5
            analysis.risk_level = "unknown"
            analysis.reasoning = [f"Analysis error: {str(e)}"]
        
        return analysis
    
    def analyze_semantics(self, url: str, content: str) -> float:
        """Analyze semantic meaning of URL and content"""
        try:
            # Combine URL and content for analysis
            text = f"{url} {content[:500]}"  # Limit content length
            
            # Sentiment analysis
            sentiment_result = self.sentiment_analyzer(text)
            sentiment_score = sentiment_result[0]['score']
            
            # Detect suspicious language patterns
            suspicious_patterns = [
                r'\b(?:urgent|immediate|now|limited|offer|free|winner|prize)\b',
                r'\b(?:verify|confirm|update|secure|login|password)\b',
                r'\b(?:account|bank|paypal|credit.*card)\b',
                r'\b(?:suspended|locked|banned|restricted)\b'
            ]
            
            pattern_score = 0
            for pattern in suspicious_patterns:
                matches = len(re.findall(pattern, text.lower()))
                pattern_score += matches * 0.1
            
            # Combine scores
            semantic_score = min(1.0, sentiment_score + pattern_score)
            
            return semantic_score
            
        except Exception as e:
            logger.warning(f"Semantic analysis failed: {e}")
            return 0.5
    
    def analyze_behavioral_patterns(self, url: str, content: str) -> float:
        """Analyze behavioral patterns that indicate malicious intent"""
        try:
            score = 0.0
            
            # URL-based behavioral analysis
            url_lower = url.lower()
            
            # Suspicious URL patterns
            suspicious_url_patterns = [
                r'bitcoin.*wallet|wallet.*bitcoin',
                r'paypal.*verify|verify.*paypal',
                r'bank.*login|login.*bank',
                r'password.*reset|reset.*password',
                r'account.*suspended|suspended.*account'
            ]
            
            for pattern in suspicious_url_patterns:
                if re.search(pattern, url_lower):
                    score += 0.3
            
            # Content-based behavioral analysis
            if content:
                content_lower = content.lower()
                
                # Form analysis
                if 'form' in content_lower and ('password' in content_lower or 'credit' in content_lower):
                    score += 0.2
                
                # Redirect analysis
                if 'redirect' in content_lower or 'location.href' in content_lower:
                    score += 0.15
                
                # Urgency indicators
                urgency_words = ['urgent', 'immediate', 'now', 'limited', 'expires']
                urgency_count = sum(1 for word in urgency_words if word in content_lower)
                score += urgency_count * 0.1
            
            return min(1.0, score)
            
        except Exception as e:
            logger.warning(f"Behavioral analysis failed: {e}")
            return 0.5
    
    def correlate_threat_indicators(self, intel: ThreatIntelligence) -> float:
        """Correlate multiple threat intelligence indicators"""
        try:
            score = 0.0
            indicators = 0
            
            # PhishTank correlation
            if intel.phish_tank and intel.phish_tank.get("is_phishing"):
                score += 0.8
                indicators += 1
            
            # URLVoid correlation
            if intel.url_void:
                detections = intel.url_void.get("detections", 0)
                engines = intel.url_void.get("engines", 0)
                if detections > 0 and engines > 0:
                    detection_ratio = detections / engines
                    score += detection_ratio * 0.6
                    indicators += 1
            
            # WHOIS correlation
            if intel.whois_data:
                domain_age = intel.whois_data.get("domain_age_days", 0)
                if domain_age < 30:  # Very new domain
                    score += 0.4
                    indicators += 1
            
            # DNS correlation
            if intel.dns_data:
                if intel.dns_data.get("suspicious_tld"):
                    score += 0.3
                    indicators += 1
                if intel.dns_data.get("suspicious_subdomain"):
                    score += 0.2
                    indicators += 1
            
            # SSL correlation
            if intel.ssl_data and not intel.ssl_data.get("valid"):
                score += 0.5
                indicators += 1
            
            # Normalize score
            if indicators > 0:
                return min(1.0, score / indicators)
            
            return 0.0
            
        except Exception as e:
            logger.warning(f"Threat correlation failed: {e}")
            return 0.0
    
    def determine_risk_level(self, confidence: float, intel: ThreatIntelligence = None) -> str:
        """Determine risk level based on confidence and intelligence"""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        elif confidence >= 0.4:
            return "low"
        else:
            return "safe"

class AIMalwareDetector:
    """Main AI-powered malware detector"""
    
    def __init__(self):
        self.intel_collector = ThreatIntelligenceCollector()
        self.ai_analyzer = AIAnalyzer()
        logger.info("AI Malware Detector initialized")
    
    def detect_malicious(self, url: str, content: str = "") -> Dict[str, Any]:
        """Main detection method"""
        logger.info(f"AI detection started for: {url}")
        
        try:
            # 1. Collect threat intelligence
            intel = self.intel_collector.collect_all(url)
            
            # 2. Perform AI analysis
            analysis = self.ai_analyzer.analyze_url(url, content, intel)
            
            # 3. Generate prediction
            is_malicious = analysis.confidence > 0.6 or analysis.risk_level in ["high", "medium"]
            
            # 4. Prepare result
            result = {
                "url": url,
                "is_malicious": is_malicious,
                "confidence": analysis.confidence,
                "risk_level": analysis.risk_level,
                "reasoning": analysis.reasoning,
                "threat_intelligence": {
                    "phish_tank": intel.phish_tank,
                    "url_void": intel.url_void,
                    "whois": intel.whois_data,
                    "dns": intel.dns_data,
                    "ssl": intel.ssl_data
                },
                "ai_analysis": {
                    "semantic_score": analysis.semantic_score,
                    "behavioral_score": analysis.behavioral_score,
                    "threat_correlation": analysis.threat_correlation
                },
                "model": "ai-powered",
                "version": "1.0"
            }
            
            logger.info(f"AI detection completed: {result['risk_level']} risk, {result['confidence']:.3f} confidence")
            return result
            
        except Exception as e:
            logger.error(f"AI detection failed: {e}")
            return {
                "url": url,
                "is_malicious": False,
                "confidence": 0.0,
                "risk_level": "unknown",
                "reasoning": [f"Detection error: {str(e)}"],
                "model": "ai-powered",
                "version": "1.0"
            }

# Global instance
ai_detector = AIMalwareDetector()

def detect_malicious_url(url: str, content: str = "") -> Dict[str, Any]:
    """Convenience function for external use"""
    return ai_detector.detect_malicious(url, content)

if __name__ == "__main__":
    # Test the AI detector
    test_urls = [
        "https://google.com",
        "https://facebook.com",
        "https://malicious-test-site.com/login/verify",
        "https://bitcoin-wallet-verify.com"
    ]
    
    for url in test_urls:
        result = detect_malicious_url(url)
        print(f"\nURL: {url}")
        print(f"Risk: {result['risk_level']}")
        print(f"Confidence: {result['confidence']:.3f}")
        print(f"Malicious: {result['is_malicious']}")
        print(f"Reasoning: {result['reasoning']}") 