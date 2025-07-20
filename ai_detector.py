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
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lightweight imports - no heavy transformers
try:
    import nltk
    from nltk.sentiment import SentimentIntensityAnalyzer
    # Download required NLTK data
    nltk.download('vader_lexicon', quiet=True)
    nltk.download('punkt', quiet=True)
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    logger.warning("NLTK not available, using fallback sentiment analysis")

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
            'phish_tank': 'https://checkurl.phishtank.com/checkurl/',
            'url_void': 'https://api.urlvoid.com/v1/path/',
            'whois': 'https://api.domainsdb.info/v1/domains/search'
        }
        logger.info("Threat Intelligence Collector initialized")
    
    def collect_all(self, url: str) -> ThreatIntelligence:
        """Collect all available threat intelligence"""
        logger.info(f"Collecting threat intelligence for: {url}")
        
        intel = ThreatIntelligence()
        
        try:
            # Collect in parallel (simplified for memory efficiency)
            intel.phish_tank = self.check_phishtank(url)
            intel.url_void = self.check_urlvoid(url)
            intel.whois_data = self.get_whois_data(url)
            intel.dns_data = self.get_dns_reputation(url)
            intel.ssl_data = self.analyze_ssl_certificate(url)
            
        except Exception as e:
            logger.error(f"Error collecting threat intelligence: {e}")
        
        return intel
    
    def check_phishtank(self, url: str) -> Dict[str, Any]:
        """Check URL against PhishTank database"""
        try:
            # Use PhishTank's public API with better error handling
            api_url = "https://checkurl.phishtank.com/checkurl/"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {'url': url}
            
            response = requests.post(api_url, data=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "is_phishing": result.get("in_database", False),
                    "verified": result.get("verified", False),
                    "verified_at": result.get("verified_at"),
                    "details": result.get("details", {})
                }
            else:
                logger.warning(f"PhishTank API returned {response.status_code}")
                # Fallback: try alternative method
                return self._fallback_phishtank_check(url)
                
        except Exception as e:
            logger.warning(f"PhishTank check failed: {e}")
            return self._fallback_phishtank_check(url)
    
    def _fallback_phishtank_check(self, url: str) -> Dict[str, Any]:
        """Fallback PhishTank check using different method"""
        try:
            # Try using the search API instead
            search_url = f"https://phishtank.org/phish_search.php?q={requests.utils.quote(url)}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(search_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Simple pattern matching for phishing indicators
                content = response.text.lower()
                phishing_indicators = [
                    'phish', 'malicious', 'suspicious', 'reported', 'verified'
                ]
                
                indicator_count = sum(1 for indicator in phishing_indicators if indicator in content)
                
                return {
                    "is_phishing": indicator_count > 2,
                    "verified": False,
                    "confidence": min(indicator_count / len(phishing_indicators), 1.0),
                    "method": "fallback_search"
                }
            else:
                return {"is_phishing": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            logger.warning(f"Fallback PhishTank check failed: {e}")
            return {"is_phishing": False, "error": str(e)}
    
    def check_urlvoid(self, url: str) -> Dict[str, Any]:
        """Check URL against URLVoid database"""
        try:
            # Simple URLVoid check (no API key required for basic usage)
            domain = urlparse(url).netloc
            
            # Use a free URL reputation service
            reputation_url = f"https://api.urlvoid.com/v1/path/{domain}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(reputation_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "detections": data.get("detections", 0),
                    "engines": data.get("engines", 0),
                    "details": data.get("details", {})
                }
            else:
                return {"detections": 0, "engines": 0, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            logger.warning(f"URLVoid check failed: {e}")
            return {"detections": 0, "engines": 0, "error": str(e)}
    
    def get_whois_data(self, url: str) -> Dict[str, Any]:
        """Get WHOIS data for domain"""
        try:
            domain = urlparse(url).netloc
            
            # Use a free WHOIS service
            whois_url = f"https://api.domainsdb.info/v1/domains/search?domain={domain}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(whois_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("domains"):
                    domain_info = data["domains"][0]
                    creation_date = domain_info.get("create_date")
                    return {
                        "domain": domain,
                        "creation_date": creation_date,
                        "domain_age_days": self.calculate_domain_age(creation_date),
                        "registrar": domain_info.get("registrar"),
                        "country": domain_info.get("country")
                    }
            
            return {"domain": domain, "domain_age_days": 999, "error": "No data"}
            
        except Exception as e:
            logger.warning(f"WHOIS check failed: {e}")
            return {"domain": urlparse(url).netloc, "domain_age_days": 999, "error": str(e)}
    
    def get_dns_reputation(self, url: str) -> Dict[str, Any]:
        """Get DNS reputation data"""
        try:
            domain = urlparse(url).netloc
            
            # Simple DNS analysis
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']
            suspicious_subdomains = ['www1', 'www2', 'www3', 'secure', 'login', 'verify']
            
            tld = '.' + domain.split('.')[-1]
            subdomain = domain.split('.')[0] if len(domain.split('.')) > 2 else None
            
            return {
                "domain": domain,
                "suspicious_tld": tld in suspicious_tlds,
                "suspicious_subdomain": subdomain in suspicious_subdomains if subdomain else False,
                "subdomain_count": len(domain.split('.')) - 2
            }
            
        except Exception as e:
            logger.warning(f"DNS reputation check failed: {e}")
            return {"error": str(e)}
    
    def analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        try:
            if not url.startswith('https://'):
                return {"valid": False, "reason": "No HTTPS"}
            
            domain = urlparse(url).netloc
            
            # Simple SSL check
            response = requests.get(url, timeout=10, verify=True)
            
            return {
                "valid": True,
                "issuer": "Unknown",
                "expires": "Unknown"
            }
            
        except Exception as e:
            return {"valid": False, "reason": str(e)}
    
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
    """Performs AI-powered analysis using lightweight models"""
    
    def __init__(self):
        logger.info("Initializing Lightweight AI Analyzer...")
        
        # Use lightweight sentiment analysis
        if NLTK_AVAILABLE:
            self.sentiment_analyzer = SentimentIntensityAnalyzer()
            logger.info("NLTK sentiment analyzer loaded")
        else:
            self.sentiment_analyzer = None
            logger.warning("Using fallback sentiment analysis")
    
    def analyze_url(self, url: str, content: str = "", intel: ThreatIntelligence = None) -> AIAnalysis:
        """Perform comprehensive AI analysis"""
        logger.info(f"Performing lightweight AI analysis for: {url}")
        
        analysis = AIAnalysis()
        reasoning = []
        
        try:
            # 1. Semantic Analysis (lightweight)
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
        """Analyze semantic meaning of URL and content using lightweight methods"""
        try:
            # Combine URL and content for analysis
            text = f"{url} {content[:500]}"  # Limit content length
            
            # Lightweight sentiment analysis
            if self.sentiment_analyzer:
                sentiment_result = self.sentiment_analyzer.polarity_scores(text)
                sentiment_score = sentiment_result['compound']  # -1 to 1
                # Convert to 0-1 scale
                sentiment_score = (sentiment_score + 1) / 2
            else:
                # Fallback sentiment analysis
                sentiment_score = self._fallback_sentiment(text)
            
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
    
    def _fallback_sentiment(self, text: str) -> float:
        """Fallback sentiment analysis without NLTK"""
        try:
            # Simple keyword-based sentiment
            positive_words = ['good', 'safe', 'secure', 'trusted', 'verified', 'official']
            negative_words = ['urgent', 'suspended', 'locked', 'verify', 'confirm', 'update', 'secure']
            
            text_lower = text.lower()
            positive_count = sum(1 for word in positive_words if word in text_lower)
            negative_count = sum(1 for word in negative_words if word in text_lower)
            
            if positive_count == 0 and negative_count == 0:
                return 0.5
            
            return max(0.0, min(1.0, positive_count / (positive_count + negative_count)))
            
        except Exception as e:
            logger.warning(f"Fallback sentiment failed: {e}")
            return 0.5
    
    def analyze_behavioral_patterns(self, url: str, content: str) -> float:
        """Analyze behavioral patterns that indicate malicious intent"""
        try:
            score = 0.0
            
            # URL-based behavioral analysis
            url_lower = url.lower()
            
            # Enhanced suspicious URL patterns for phishing detection
            suspicious_url_patterns = [
                r'bitcoin.*wallet|wallet.*bitcoin',
                r'paypal.*verify|verify.*paypal',
                r'bank.*login|login.*bank',
                r'password.*reset|reset.*password',
                r'account.*suspended|suspended.*account',
                r'secure.*login|login.*secure',
                r'verify.*account|account.*verify',
                r'update.*information|information.*update',
                r'confirm.*details|details.*confirm',
                r'validate.*account|account.*validate',
                r'security.*check|check.*security',
                r'login.*required|required.*login',
                r'access.*denied|denied.*access',
                r'account.*locked|locked.*account',
                r'verify.*identity|identity.*verify',
                r'update.*profile|profile.*update',
                r'confirm.*email|email.*confirm',
                r'verify.*phone|phone.*verify',
                r'secure.*access|access.*secure',
                r'login.*portal|portal.*login'
            ]
            
            for pattern in suspicious_url_patterns:
                if re.search(pattern, url_lower):
                    score += 0.3
            
            # Domain-based analysis
            domain = urlparse(url).netloc.lower()
            
            # Suspicious domain patterns
            suspicious_domain_patterns = [
                r'secure.*login|login.*secure',
                r'verify.*account|account.*verify',
                r'bank.*online|online.*bank',
                r'paypal.*secure|secure.*paypal',
                r'ebay.*verify|verify.*ebay',
                r'amazon.*secure|secure.*amazon',
                r'apple.*verify|verify.*apple',
                r'google.*secure|secure.*google',
                r'facebook.*verify|verify.*facebook',
                r'twitter.*verify|verify.*twitter',
                r'linkedin.*verify|verify.*linkedin',
                r'netflix.*verify|verify.*netflix',
                r'spotify.*verify|verify.*spotify',
                r'uber.*verify|verify.*uber',
                r'lyft.*verify|verify.*lyft',
                r'airbnb.*verify|verify.*airbnb',
                r'booking.*verify|verify.*booking',
                r'expedia.*verify|verify.*expedia',
                r'hotels.*verify|verify.*hotels'
            ]
            
            for pattern in suspicious_domain_patterns:
                if re.search(pattern, domain):
                    score += 0.4  # Higher score for domain-level patterns
            
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
                urgency_words = ['urgent', 'immediate', 'now', 'limited', 'expires', 'soon', 'quickly', 'hurry']
                urgency_count = sum(1 for word in urgency_words if word in content_lower)
                score += urgency_count * 0.1
                
                # Suspicious form fields
                suspicious_fields = ['ssn', 'social', 'security', 'number', 'credit', 'card', 'cvv', 'cvc', 'pin', 'password']
                field_count = sum(1 for field in suspicious_fields if field in content_lower)
                score += field_count * 0.1
            
            # Additional phishing indicators
            if 'consultancy' in domain or 'consulting' in domain:
                # Many phishing sites use generic business terms
                score += 0.2
            
            if len(domain.split('.')) > 2:
                # Subdomains can be suspicious
                score += 0.1
            
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
        # More aggressive thresholds for better phishing detection
        if confidence >= 0.6:  # Lowered from 0.8
            return "high"
        elif confidence >= 0.4:  # Lowered from 0.6
            return "medium"
        elif confidence >= 0.2:  # Lowered from 0.4
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
            
            # 3. Enhanced decision logic with multiple indicators
            is_malicious = self._enhanced_decision_logic(url, analysis, intel)
            
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
                "version": "1.1"
            }
            
            logger.info(f"AI detection completed: {result['risk_level']} risk, {result['confidence']:.3f} confidence, malicious: {is_malicious}")
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
                "version": "1.1"
            }
    
    def _enhanced_decision_logic(self, url: str, analysis: AIAnalysis, intel: ThreatIntelligence) -> bool:
        """Enhanced decision logic with multiple indicators"""
        malicious_indicators = 0
        total_indicators = 0
        
        # 1. AI Analysis confidence
        if analysis.confidence > 0.5:
            malicious_indicators += 1
        total_indicators += 1
        
        # 2. Risk level
        if analysis.risk_level in ["high", "medium"]:
            malicious_indicators += 1
        total_indicators += 1
        
        # 3. PhishTank check (if available)
        if intel.phish_tank and intel.phish_tank.get("is_phishing"):
            malicious_indicators += 2  # Higher weight for confirmed phishing
            total_indicators += 1
        
        # 4. URLVoid detections
        if intel.url_void and intel.url_void.get("detections", 0) > 0:
            malicious_indicators += 1
            total_indicators += 1
        
        # 5. Domain age (new domains are suspicious)
        if intel.whois_data and intel.whois_data.get("domain_age_days", 999) < 30:
            malicious_indicators += 1
            total_indicators += 1
        
        # 6. SSL certificate issues
        if intel.ssl_data and not intel.ssl_data.get("valid", True):
            malicious_indicators += 1
            total_indicators += 1
        
        # 7. DNS reputation issues
        if intel.dns_data and (intel.dns_data.get("suspicious_tld") or intel.dns_data.get("suspicious_subdomain")):
            malicious_indicators += 1
            total_indicators += 1
        
        # 8. URL pattern analysis
        suspicious_patterns = [
            r'bitcoin.*wallet|wallet.*bitcoin',
            r'paypal.*verify|verify.*paypal',
            r'bank.*login|login.*bank',
            r'password.*reset|reset.*password',
            r'account.*suspended|suspended.*account',
            r'secure.*login|login.*secure',
            r'verify.*account|account.*verify',
            r'update.*information|information.*update'
        ]
        
        url_lower = url.lower()
        pattern_matches = sum(1 for pattern in suspicious_patterns if re.search(pattern, url_lower))
        if pattern_matches > 0:
            malicious_indicators += min(pattern_matches, 2)  # Cap at 2
            total_indicators += 1
        
        # 9. Content accessibility (404 errors are suspicious for phishing)
        if "404" in str(intel.dns_data) or "error" in str(intel.dns_data):
            malicious_indicators += 1
            total_indicators += 1
        
        # Decision logic: More aggressive threshold
        if total_indicators > 0:
            malicious_ratio = malicious_indicators / total_indicators
            return malicious_ratio >= 0.3  # Lowered threshold from 0.6
        
        # Fallback to AI confidence
        return analysis.confidence > 0.5

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