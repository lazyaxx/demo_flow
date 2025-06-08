from crewai.tools import BaseTool
import requests
import re
from typing import Dict, List, Any
import os
import json
import hashlib
import time
from urllib.parse import urlparse
import uuid
import random

class URLAnalyzerTool(BaseTool):
    name: str = "url_analyzer"
    description: str = "Analyzes URLs for potential security threats and provides confidence scores"
    
    def _run(self, url: str) -> str:
        """Analyze a URL for security threats"""
        try:
            # Multiple unique identifiers to ensure no caching
            unique_id = f"{uuid.uuid4().hex[:8]}_{int(time.time())}_{random.randint(1000,9999)}"
            
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return json.dumps({
                    "analysis_id": unique_id,
                    "url": url,
                    "confidence_score": 0.9,
                    "threat_indicators": ["Invalid URL format"],
                    "assessment": "malicious",
                    "details": "URL format is invalid",
                    "timestamp": time.time()
                })
            
            # Rest of your analysis logic...
            threat_indicators = []
            confidence_score = 0.0
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'\.exe$', r'\.scr$', r'\.bat$', r'\.com$',
                r'phishing', r'malware', r'virus', r'hack'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    threat_indicators.append(f"Suspicious pattern: {pattern}")
                    confidence_score += 0.2
            
            # Check domain reputation
            domain = parsed_url.netloc.lower()
            malicious_domains = ['malware.com', 'phishing-site.net', 'suspicious-download.org']
            
            if any(bad_domain in domain for bad_domain in malicious_domains):
                threat_indicators.append("Known malicious domain")
                confidence_score += 0.5
            
            confidence_score = min(confidence_score, 1.0)
            
            if confidence_score > 0.7:
                assessment = "malicious"
            elif confidence_score > 0.3:
                assessment = "suspicious"
            else:
                assessment = "benign"
            
            result = {
                "analysis_id": unique_id,
                "url": url,
                "confidence_score": confidence_score,
                "threat_indicators": threat_indicators,
                "assessment": assessment,
                "details": f"Analysis completed with {len(threat_indicators)} indicators",
                "timestamp": time.time()
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            return json.dumps({
                "analysis_id": f"error_{uuid.uuid4().hex[:8]}",
                "url": url,
                "error": str(e),
                "timestamp": time.time()
            })

class SOCCommunicationTool(BaseTool):
    name: str = "soc_communicator"
    description: str = "Communicates with SOC admin server for severity assessment"
    
    def _run(self, analysis_data: str) -> str:  # Return string
        """Send analysis to SOC admin and get severity assessment"""

        import json
        try:
            data = json.loads(analysis_data)
            # Add unique identifier to avoid caching
            comm_id = hashlib.md5(f"{data}_{time.time()}".encode()).hexdigest()[:8]
            
            # Parse analysis data
            if "malicious" in data.lower():
                confidence_score = 0.8
                assessment = "malicious"
            elif "suspicious" in data.lower():
                confidence_score = 0.5
                assessment = "suspicious"
            else:
                confidence_score = 0.2
                assessment = "benign"
            
            # Simulate SOC response
            if confidence_score > 0.7:
                result = {
                    "communication_id": comm_id,
                    "soc_severity": "high",
                    "soc_action": "block",
                    "soc_reason": "High threat confidence detected",
                    "communication_status": "success"
                }
            elif confidence_score > 0.3:
                result = {
                    "communication_id": comm_id,
                    "soc_severity": "medium", 
                    "soc_action": "review",
                    "soc_reason": "Medium threat requires review",
                    "communication_status": "success"
                }
            else:
                result = {
                    "communication_id": comm_id,
                    "soc_severity": "low",
                    "soc_action": "allow",
                    "soc_reason": "Low threat confidence",
                    "communication_status": "success"
                }
                
            return json.dumps(result, indent=2)
                
        except Exception as e:
            return json.dumps({
                "communication_id": "error",
                "soc_severity": "unknown",
                "soc_action": "review", 
                "soc_reason": f"SOC communication error: {str(e)}",
                "communication_status": "error"
            })

class GatekeeperTool(BaseTool):
    name: str = "gatekeeper_monitor"
    description: str = "Makes final security decisions based on analysis and SOC input"
    
    def _run(self, context: str) -> str:
        """Make final security decision - single call only"""
        try:
            decision_id = hashlib.md5(f"{context}_{time.time()}".encode()).hexdigest()[:8]
            context_lower = context.lower()
            
            # Rule 1: Block exe downloads marked as benign
            if ".exe" in context_lower and "benign" in context_lower:
                return f"""
GATEKEEPER DECISION [{decision_id}]:
🚫 OVERRIDE: Executable download blocked despite benign classification
📋 REASON: Security policy violation - executable files require strict scrutiny
✅ FINAL ACTION: BLOCK
"""
            
            # Rule 2: Block malicious content marked as allow
            if ("malicious" in context_lower or "high" in context_lower) and "allow" in context_lower:
                return f"""
GATEKEEPER DECISION [{decision_id}]:
🚫 OVERRIDE: High-risk content blocked despite allow recommendation
📋 REASON: Threat level conflicts with permissive action
✅ FINAL ACTION: BLOCK
"""
            
            # Rule 3: Approve blocking decisions
            if "block" in context_lower:
                return f"""
GATEKEEPER DECISION [{decision_id}]:
✅ APPROVED: Blocking decision confirmed
📋 REASON: Security assessment and action are aligned
✅ FINAL ACTION: BLOCK CONFIRMED
"""
            
            # Default: Follow SOC recommendation
            return f"""
GATEKEEPER DECISION [{decision_id}]:
✅ APPROVED: No policy violations detected
📋 REASON: Security analysis is consistent with recommendations
✅ FINAL ACTION: PROCEED AS RECOMMENDED
"""
            
        except Exception as e:
            return f"""
GATEKEEPER ERROR [{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}]:
❌ ERROR: {str(e)}
✅ FALLBACK ACTION: MANUAL REVIEW REQUIRED
"""
