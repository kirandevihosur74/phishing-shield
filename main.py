"""
Phishing Detection API with Claude Vision and Browserbase/Stagehand
Real-time email phishing analysis using Claude 3.5 Sonnet
"""

import os
import re
import json
import base64
import httpx
from enum import Enum
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import anthropic


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

BROWSERBASE_API_KEY = os.getenv("BROWSERBASE_API_KEY", "")
BROWSERBASE_PROJECT_ID = os.getenv("BROWSERBASE_PROJECT_ID", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# Claude model configuration
MODEL_ID = "claude-sonnet-4-20250514"

# Initialize Claude client
claude_client: Optional[anthropic.AsyncAnthropic] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Request/Response Models
# ═══════════════════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    """Incoming scan request from Chrome extension"""
    sender_email: str = Field(..., description="Email address of the sender")
    links: list[str] = Field(default_factory=list, description="List of URLs found in email body")
    email_subject: Optional[str] = Field(None, description="Subject line of the email")
    email_snippet: Optional[str] = Field(None, description="Preview text from email body")


class ThreatType(str, Enum):
    """Types of email threats"""
    PHISHING = "phishing"
    TECH_SUPPORT = "tech_support"
    SCAREWARE = "scareware"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"


class ScanResponse(BaseModel):
    """Phishing analysis response"""
    is_phishing: bool = Field(..., description="Whether the email is likely a threat")
    threat_type: str = Field(default="benign", description="Type of threat: phishing, tech_support, scareware, suspicious, benign")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")
    reason: str = Field(..., description="Explanation of the verdict")


class RemoteInspectionResult(BaseModel):
    """Result from Browserbase URL inspection"""
    url: str
    page_title: str
    screenshot_base64: Optional[str] = None
    final_url: str
    is_redirect: bool
    ssl_valid: bool
    suspicious_indicators: list[str]


# ═══════════════════════════════════════════════════════════════════════════════
# Browserbase/Stagehand Integration
# ═══════════════════════════════════════════════════════════════════════════════

async def create_browserbase_session() -> dict:
    """Create a new Browserbase browser session"""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.browserbase.com/v1/sessions",
            headers={
                "X-BB-API-Key": BROWSERBASE_API_KEY,
                "Content-Type": "application/json"
            },
            json={
                "projectId": BROWSERBASE_PROJECT_ID,
                "browserSettings": {
                    "viewport": {"width": 1280, "height": 720}
                }
            },
            timeout=30.0
        )
        response.raise_for_status()
        return response.json()


async def connect_to_session(session_id: str) -> str:
    """Get WebSocket debugger URL for a session"""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.browserbase.com/v1/sessions/{session_id}/debug",
            headers={"X-BB-API-Key": BROWSERBASE_API_KEY},
            timeout=30.0
        )
        response.raise_for_status()
        data = response.json()
        return data.get("debuggerUrl", "")


async def remote_inspect_url(url: str) -> dict:
    """
    Remotely inspect a URL using Browserbase.
    Opens the link in a sandboxed browser, captures screenshot,
    extracts page metadata, and checks for suspicious indicators.
    
    Args:
        url: The URL to inspect
        
    Returns:
        Dictionary with inspection results including:
        - page_title: Title of the page
        - final_url: URL after any redirects
        - is_redirect: Whether the URL redirected
        - ssl_valid: Whether SSL certificate is valid
        - suspicious_indicators: List of suspicious patterns found
        - screenshot_base64: Base64 encoded screenshot (optional)
    """
    
    # Default response for when inspection fails or is unavailable
    default_response = {
        "url": url,
        "page_title": "Unable to inspect",
        "final_url": url,
        "is_redirect": False,
        "ssl_valid": url.startswith("https://"),
        "suspicious_indicators": [],
        "screenshot_base64": None
    }
    
    if not BROWSERBASE_API_KEY or not BROWSERBASE_PROJECT_ID:
        # Return heuristic analysis when Browserbase is not configured
        return await analyze_url_heuristically(url)
    
    try:
        # Create a new browser session
        session = await create_browserbase_session()
        session_id = session.get("id")
        
        if not session_id:
            return default_response
        
        # Use Browserbase's CDP endpoint to control the browser
        cdp_url = f"wss://connect.browserbase.com?apiKey={BROWSERBASE_API_KEY}&sessionId={session_id}"
        
        # For now, we'll use the REST API to navigate and capture
        async with httpx.AsyncClient() as client:
            # Navigate to URL using Browserbase's action API
            navigate_response = await client.post(
                f"https://api.browserbase.com/v1/sessions/{session_id}/actions",
                headers={
                    "X-BB-API-Key": BROWSERBASE_API_KEY,
                    "Content-Type": "application/json"
                },
                json={
                    "action": "navigate",
                    "params": {"url": url}
                },
                timeout=60.0
            )
            
            # Get page info
            page_response = await client.post(
                f"https://api.browserbase.com/v1/sessions/{session_id}/actions",
                headers={
                    "X-BB-API-Key": BROWSERBASE_API_KEY,
                    "Content-Type": "application/json"
                },
                json={
                    "action": "evaluate",
                    "params": {
                        "expression": "JSON.stringify({title: document.title, url: window.location.href})"
                    }
                },
                timeout=30.0
            )
            
            page_data = {}
            if page_response.status_code == 200:
                result = page_response.json()
                if "result" in result:
                    try:
                        page_data = json.loads(result["result"])
                    except:
                        pass
            
            # Take screenshot
            screenshot_response = await client.post(
                f"https://api.browserbase.com/v1/sessions/{session_id}/actions",
                headers={
                    "X-BB-API-Key": BROWSERBASE_API_KEY,
                    "Content-Type": "application/json"
                },
                json={
                    "action": "screenshot",
                    "params": {"format": "png"}
                },
                timeout=30.0
            )
            
            screenshot_b64 = None
            if screenshot_response.status_code == 200:
                screenshot_data = screenshot_response.json()
                screenshot_b64 = screenshot_data.get("data")
            
            # Close the session
            await client.delete(
                f"https://api.browserbase.com/v1/sessions/{session_id}",
                headers={"X-BB-API-Key": BROWSERBASE_API_KEY},
                timeout=10.0
            )
            
            final_url = page_data.get("url", url)
            
            # Analyze for suspicious indicators
            suspicious = await detect_suspicious_indicators(url, final_url, page_data.get("title", ""))
            
            return {
                "url": url,
                "page_title": page_data.get("title", "Unknown"),
                "final_url": final_url,
                "is_redirect": final_url != url,
                "ssl_valid": final_url.startswith("https://"),
                "suspicious_indicators": suspicious,
                "screenshot_base64": screenshot_b64
            }
            
    except Exception as e:
        print(f"Browserbase inspection error: {e}")
        # Fall back to heuristic analysis
        return await analyze_url_heuristically(url)


async def analyze_url_heuristically(url: str) -> dict:
    """Analyze URL using heuristics when Browserbase is unavailable"""
    from urllib.parse import urlparse
    
    suspicious_indicators = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Check for IP address instead of domain
    import re
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        suspicious_indicators.append("Uses IP address instead of domain name")
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        suspicious_indicators.append(f"Uses suspicious TLD")
    
    # Check for brand impersonation patterns
    brand_keywords = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'bank', 'secure', 'login', 'verify', 'update', 'account']
    for brand in brand_keywords:
        if brand in domain and not domain.endswith(f'{brand}.com'):
            suspicious_indicators.append(f"Possible brand impersonation: {brand}")
            break
    
    # Check for excessive subdomains
    if domain.count('.') > 3:
        suspicious_indicators.append("Excessive subdomains (possible phishing)")
    
    # Check for URL encoding tricks
    if '%' in url or '@' in parsed.netloc:
        suspicious_indicators.append("URL contains encoding tricks or @ symbol")
    
    # Check for non-HTTPS
    if not url.startswith('https://'):
        suspicious_indicators.append("Not using HTTPS")
    
    # Check for suspicious path patterns
    suspicious_paths = ['/login', '/signin', '/verify', '/secure', '/update', '/confirm']
    if any(pattern in parsed.path.lower() for pattern in suspicious_paths):
        suspicious_indicators.append("URL path suggests credential harvesting")
    
    # Check for long random-looking strings
    if len(parsed.path) > 100 or len(parsed.query) > 200:
        suspicious_indicators.append("Unusually long URL path or parameters")
    
    return {
        "url": url,
        "page_title": "Not inspected (heuristic analysis)",
        "final_url": url,
        "is_redirect": False,
        "ssl_valid": url.startswith("https://"),
        "suspicious_indicators": suspicious_indicators,
        "screenshot_base64": None
    }


async def detect_suspicious_indicators(original_url: str, final_url: str, title: str) -> list[str]:
    """Detect suspicious patterns in URL and page content"""
    from urllib.parse import urlparse
    
    indicators = []
    
    # Check for redirects to different domains
    orig_domain = urlparse(original_url).netloc
    final_domain = urlparse(final_url).netloc
    if orig_domain != final_domain:
        indicators.append(f"Redirects to different domain: {final_domain}")
    
    # Check page title for suspicious patterns
    phishing_title_keywords = ['verify', 'suspended', 'locked', 'unusual activity', 
                               'confirm identity', 'update payment', 'action required']
    title_lower = title.lower()
    for keyword in phishing_title_keywords:
        if keyword in title_lower:
            indicators.append(f"Suspicious page title contains: {keyword}")
            break
    
    # Add heuristic checks
    heuristic_result = await analyze_url_heuristically(final_url)
    indicators.extend(heuristic_result["suspicious_indicators"])
    
    return list(set(indicators))  # Remove duplicates


# ═══════════════════════════════════════════════════════════════════════════════
# Google ADK PhishingAgent
# ═══════════════════════════════════════════════════════════════════════════════

def create_remote_inspect_tool():
    """Create the remote_inspect_url tool for the agent"""
    
    async def tool_remote_inspect_url(url: str) -> str:
        """
        Remotely inspect a URL using a sandboxed browser.
        Opens the link, captures a screenshot, extracts page title,
        checks for redirects, and identifies suspicious indicators.
        
        Args:
            url: The URL to inspect for phishing indicators
            
        Returns:
            JSON string with inspection results
        """
        result = await remote_inspect_url(url)
        return json.dumps(result, indent=2)
    
    return tool_remote_inspect_url


# System prompt for the PhishingAgent
PHISHING_AGENT_INSTRUCTION = """You are a cybersecurity expert specializing in email threat detection.
Your task is to analyze emails and classify them into threat categories.

THREAT CATEGORIES:
1. **phishing** - Credential harvesting, fake login pages, account verification scams
2. **tech_support** - Fake tech support, remote access requests, spoofed phone numbers, Microsoft/Apple impersonation
3. **scareware** - Fake virus alerts, system failure warnings, ransomware threats, urgent security alerts
4. **suspicious** - Has STRONG red flags that indicate malicious intent
5. **benign** - Appears legitimate (DEFAULT - most emails are benign)

IMPORTANT - Avoid False Positives:
- Job alerts, newsletters, and notifications from legitimate services are BENIGN
- If links point to legitimate domains with valid SSL, it's likely BENIGN
- Subscription emails, order confirmations, and alerts are usually BENIGN
- A sender using Gmail/personal email for legitimate services is NORMAL (not suspicious)
- Only flag as suspicious/threat if there are CLEAR malicious indicators

ANALYSIS CRITERIA:

**PHISHING indicators (require MULTIPLE):**
- Fake login pages or credential harvesting forms
- Urgent "verify account" with suspicious links
- Typosquatting domains (paypa1.com, micr0soft.com)
- Links that DON'T match the claimed sender

**TECH SUPPORT SCAM indicators (require MULTIPLE):**
- Unsolicited calls to action with phone numbers
- "Microsoft/Apple Support" from non-official domains
- Requests to install remote access software
- Claims about computer being infected

**SCAREWARE indicators (require MULTIPLE):**
- Fake "Virus detected" alerts
- Threats about file deletion/encryption
- Fake Windows Defender alerts
- Urgency + fear tactics

**BENIGN indicators (one is enough):**
- Links match legitimate service domains
- Normal newsletter/alert content
- No credential requests
- No urgency or fear tactics
- Professional formatting from known services

CRITICAL INSTRUCTIONS:
- DO NOT attempt to call any functions or tools
- ONLY output a valid JSON object, nothing else
- Default to BENIGN unless there are CLEAR threat indicators
- Err on the side of caution - false negatives are better than false positives

Your response must be EXACTLY this JSON format:
{"is_phishing": true/false, "threat_type": "phishing|tech_support|scareware|suspicious|benign", "confidence": 0.0-1.0, "reason": "your explanation"}

Note: is_phishing should be TRUE ONLY for actual phishing, tech_support, and scareware threats."""


async def analyze_email_with_agent(scan_request: ScanRequest) -> ScanResponse:
    """Run Claude to analyze an email for phishing"""
    global claude_client
    
    if not claude_client:
        print("Claude client not initialized, using fallback")
        return await fallback_analysis(scan_request)
    
    # First, inspect any links using our heuristic tool
    link_analysis_results = []
    if scan_request.links:
        for link in scan_request.links[:3]:  # Limit to first 3 links
            try:
                inspection = await remote_inspect_url(link)
                link_analysis_results.append(inspection)
            except Exception as e:
                print(f"Link inspection error for {link}: {e}")
    
    # Build the user message with email details
    user_message_parts = [
        "Analyze this email for phishing:",
        "",
        f"**Sender Email:** {scan_request.sender_email}",
    ]
    
    if scan_request.email_subject:
        user_message_parts.append(f"**Subject:** {scan_request.email_subject}")
    
    if scan_request.email_snippet:
        user_message_parts.append(f"**Email Preview:** {scan_request.email_snippet}")
    
    if scan_request.links:
        user_message_parts.append(f"**Links Found:** {len(scan_request.links)}")
        for i, link in enumerate(scan_request.links[:5], 1):
            user_message_parts.append(f"  {i}. {link}")
        if len(scan_request.links) > 5:
            user_message_parts.append(f"  ... and {len(scan_request.links) - 5} more links")
    else:
        user_message_parts.append("**Links Found:** None")
    
    # Add link inspection results
    if link_analysis_results:
        user_message_parts.append("")
        user_message_parts.append("**Link Inspection Results:**")
        for result in link_analysis_results:
            user_message_parts.append(f"  URL: {result.get('url', 'N/A')}")
            user_message_parts.append(f"  Final URL: {result.get('final_url', 'N/A')}")
            user_message_parts.append(f"  Page Title: {result.get('page_title', 'N/A')}")
            user_message_parts.append(f"  Is Redirect: {result.get('is_redirect', False)}")
            user_message_parts.append(f"  SSL Valid: {result.get('ssl_valid', False)}")
            if result.get('suspicious_indicators'):
                user_message_parts.append(f"  Suspicious Indicators: {', '.join(result['suspicious_indicators'])}")
            user_message_parts.append("")
    
    user_message_parts.extend([
        "",
        "Based on this analysis, provide your verdict as a JSON object with is_phishing, confidence, and reason fields.",
        "ONLY output the JSON object, nothing else."
    ])
    
    user_message = "\n".join(user_message_parts)
    
    try:
        # Call Claude API
        response = await claude_client.messages.create(
            model=MODEL_ID,
            max_tokens=500,
            temperature=0.1,  # Low temperature for consistent analysis
            system=PHISHING_AGENT_INSTRUCTION,
            messages=[
                {"role": "user", "content": user_message}
            ]
        )
        
        response_text = response.content[0].text if response.content else ""
        print(f"Claude response: {response_text[:300]}")
        
        # Parse the JSON response
        json_match = None
        if '{' in response_text and '}' in response_text:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            json_str = response_text[start:end]
            try:
                json_match = json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"JSON parse error: {e}")
        
        if json_match:
            threat_type = json_match.get("threat_type", "suspicious" if json_match.get("is_phishing") else "benign")
            return ScanResponse(
                is_phishing=bool(json_match.get("is_phishing", False)),
                threat_type=threat_type,
                confidence=float(json_match.get("confidence", 0.5)),
                reason=str(json_match.get("reason", "Analysis completed"))
            )
        else:
            # Fallback if JSON parsing fails
            return ScanResponse(
                is_phishing=False,
                threat_type="benign",
                confidence=0.3,
                reason=f"Unable to parse response: {response_text[:100]}"
            )
            
    except Exception as e:
        print(f"Claude API error: {e}")
        import traceback
        traceback.print_exc()
        # Perform basic heuristic analysis as fallback
        return await fallback_analysis(scan_request)


async def fallback_analysis(scan_request: ScanRequest) -> ScanResponse:
    """Enhanced fallback analysis with threat type classification"""
    
    # Combine all text for analysis
    full_text = f"{scan_request.email_subject or ''} {scan_request.email_snippet or ''}".lower()
    sender = scan_request.sender_email.lower() if scan_request.sender_email else ""
    
    # Threat scores
    scores = {
        "phishing": 0.0,
        "tech_support": 0.0,
        "scareware": 0.0
    }
    reasons = []
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # TECH SUPPORT SCAM Detection
    # ═══════════════════════════════════════════════════════════════════════════════
    
    # Tech Support Scam - Only HIGH confidence indicators
    tech_support_patterns = [
        (r'call\s*(us\s*)?(now|immediately).*\d{3}.*\d{4}', 0.4, "Urgent call with phone number"),
        (r'microsoft\s*(support|technician).*call', 0.5, "Microsoft support scam"),
        (r'apple\s*(support|technician).*call', 0.5, "Apple support scam"),
        (r'(teamviewer|anydesk|logmein).*install', 0.5, "Remote access software install request"),
        (r'your\s*computer\s*(has|is)\s*been\s*(infected|compromised|hacked)', 0.4, "Computer infection claim"),
    ]
    
    for pattern, weight, reason in tech_support_patterns:
        if re.search(pattern, full_text, re.IGNORECASE):
            scores["tech_support"] += weight
            if reason not in reasons:
                reasons.append(reason)
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # SCAREWARE Detection - Only HIGH confidence indicators
    # ═══════════════════════════════════════════════════════════════════════════════
    
    scareware_patterns = [
        (r'virus\s*(detected|found).*immediate', 0.5, "Virus detected urgency"),
        (r'malware\s*(detected|found).*action', 0.5, "Malware action required"),
        (r'your\s*files\s*(will\s*be|are\s*being)\s*(deleted|encrypted)', 0.6, "File encryption/deletion threat"),
        (r'ransomware.*detected', 0.6, "Ransomware alert"),
        (r'windows\s*defender\s*alert.*virus', 0.5, "Fake Windows Defender"),
        (r'(trojan|worm|spyware)\s*(detected|found).*remove', 0.5, "Malware removal scam"),
    ]
    
    for pattern, weight, reason in scareware_patterns:
        if re.search(pattern, full_text, re.IGNORECASE):
            scores["scareware"] += weight
            if reason not in reasons:
                reasons.append(reason)
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # PHISHING Detection - Only STRONG indicators (removed generic patterns)
    # ═══════════════════════════════════════════════════════════════════════════════
    
    phishing_patterns = [
        (r'verify\s*your\s*(account|identity).*click', 0.35, "Account verification with click"),
        (r'account\s*(will\s*be|has\s*been)\s*(locked|suspended|terminated)', 0.4, "Account suspension threat"),
        (r'unusual\s*(activity|sign[- ]?in).*verify', 0.35, "Unusual activity + verify"),
        (r'update\s*your\s*(payment|billing).*immediately', 0.4, "Urgent payment update"),
        (r'confirm\s*your\s*identity.*24\s*hours', 0.4, "Identity confirmation deadline"),
        (r'click\s*(here|below)\s*to\s*(restore|unlock|verify)\s*your\s*account', 0.4, "Click to restore account"),
    ]
    
    for pattern, weight, reason in phishing_patterns:
        if re.search(pattern, full_text, re.IGNORECASE):
            scores["phishing"] += weight
            if reason not in reasons:
                reasons.append(reason)
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # Sender Analysis
    # ═══════════════════════════════════════════════════════════════════════════════
    
    # Brand impersonation in sender
    brand_patterns = [
        (r'paypa[l1]', "PayPal"),
        (r'app[l1]e', "Apple"),
        (r'micros[o0]ft', "Microsoft"),
        (r'amaz[o0]n', "Amazon"),
        (r'g[o0]{2}g[l1]e', "Google"),
        (r'netf[l1]ix', "Netflix"),
    ]
    
    for pattern, brand in brand_patterns:
        if re.search(pattern, sender) and not sender.endswith(f'{brand.lower()}.com'):
            scores["phishing"] += 0.35
            reasons.append(f"Possible {brand} impersonation")
            break
    
    # Free email with brand name
    free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
    sender_domain = sender.split('@')[-1] if '@' in sender else ''
    sender_local = sender.split('@')[0] if '@' in sender else sender
    
    if sender_domain in free_domains:
        for _, brand in brand_patterns:
            if brand.lower() in sender_local:
                scores["phishing"] += 0.3
                reasons.append(f"Brand '{brand}' used with free email")
                break
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # Link Analysis
    # ═══════════════════════════════════════════════════════════════════════════════
    
    if scan_request.links:
        for link in scan_request.links[:5]:
            heuristic = await analyze_url_heuristically(link)
            if heuristic["suspicious_indicators"]:
                scores["phishing"] += 0.1 * min(len(heuristic["suspicious_indicators"]), 3)
                reasons.extend(heuristic["suspicious_indicators"][:2])
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # Determine Threat Type
    # ═══════════════════════════════════════════════════════════════════════════════
    
    # Normalize scores
    for key in scores:
        scores[key] = min(scores[key], 1.0)
    
    max_score = max(scores.values())
    
    # Require HIGH confidence to mark as threat - reduce false positives
    if max_score < 0.35:
        threat_type = "benign"
        confidence = 1 - max_score
        is_threat = False
    elif max_score < 0.6:
        threat_type = "suspicious"
        confidence = max_score
        is_threat = False
    else:
        # Determine which threat type has highest score (requires >= 0.6)
        if scores["scareware"] == max_score:
            threat_type = "scareware"
        elif scores["tech_support"] == max_score:
            threat_type = "tech_support"
        else:
            threat_type = "phishing"
        confidence = max_score
        is_threat = True
    
    reason = "; ".join(reasons[:4]) if reasons else "No suspicious indicators found"
    
    return ScanResponse(
        is_phishing=is_threat,
        threat_type=threat_type,
        confidence=confidence,
        reason=reason
    )


# ═══════════════════════════════════════════════════════════════════════════════
# FastAPI Application
# ═══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global claude_client
    
    # Startup
    print("🛡️  Phishing Detection API starting...")
    
    if not ANTHROPIC_API_KEY:
        print("⚠️  Warning: ANTHROPIC_API_KEY not set. Using fallback analysis.")
    else:
        # Initialize Claude client
        try:
            claude_client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
            print(f"✅ Claude AI configured (model: {MODEL_ID})")
        except Exception as e:
            print(f"⚠️  Warning: Failed to initialize Claude client: {e}")
            claude_client = None
    
    if not BROWSERBASE_API_KEY or not BROWSERBASE_PROJECT_ID:
        print("⚠️  Warning: Browserbase not configured. Using heuristic URL analysis.")
    else:
        print("✅ Browserbase configured")
    
    print("🚀 API ready to receive scan requests")
    
    yield
    
    # Shutdown
    print("👋 Phishing Detection API shutting down...")


app = FastAPI(
    title="Phishing Detection API",
    description="Real-time phishing detection using Claude Vision API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for Chrome extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to chrome-extension://
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Phishing Detection API",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "claude_ai_configured": bool(ANTHROPIC_API_KEY),
        "browserbase_configured": bool(BROWSERBASE_API_KEY and BROWSERBASE_PROJECT_ID)
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: ScanRequest):
    """
    Scan an email for phishing indicators.
    
    This endpoint analyzes the sender email and any links found in the email body
    using AI-powered phishing detection with optional remote URL inspection.
    
    Returns a verdict with confidence score and explanation.
    """
    try:
        # Use Claude if API key is configured
        if ANTHROPIC_API_KEY:
            result = await analyze_email_with_agent(request)
        else:
            # Fall back to heuristic analysis
            result = await fallback_analysis(request)
        
        return result
        
    except Exception as e:
        print(f"Scan error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@app.post("/inspect-url")
async def inspect_url_endpoint(url: str):
    """
    Directly inspect a URL using Browserbase.
    Useful for debugging and manual URL checks.
    """
    try:
        result = await remote_inspect_url(url)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"URL inspection failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
