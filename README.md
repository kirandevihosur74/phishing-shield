# 🛡️ Phishing Shield v2.0

Real-time AI-powered threat detection for Gmail & Outlook using Claude Vision API and Browserbase.

**Now detects: Phishing | Tech Support Scams | Scareware**

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Chrome Extension (Manifest V3)                     │
│  ┌─────────────────┐    ┌─────────────────┐    ┌────────────────┐   │
│  │ MutationObserver│───▶│  Extract Email  │───▶│  Toast UI      │   │
│  │ (Auto-Detect)   │    │  Sender + Links │    │  (Color-coded) │   │
│  └─────────────────┘    └────────┬────────┘    └────────────────┘   │
│                                  │                                   │
│  ┌─────────────────┐             │                                   │
│  │ Service Worker  │◀────────────┘                                   │
│  │ (Background)    │─────── API Request ─────────────────────┐      │
│  └─────────────────┘                                         │      │
│           │                                                  │      │
│           ▼ (if API fails)                                   │      │
│  ┌─────────────────┐                                         │      │
│  │ Local Heuristics│                                         │      │
│  │ (Fallback)      │                                         │      │
│  └─────────────────┘                                         │      │
└──────────────────────────────────────────────────────────────│──────┘
                                                               │
                                                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         FastAPI Backend                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌────────────────┐   │
│  │   /scan API     │───▶│ Threat Analyzer │───▶│ Claude Sonnet  │   │
│  │   Endpoint      │    │ (Classification)│    │ (Anthropic)    │   │
│  └─────────────────┘    └────────┬────────┘    └────────────────┘   │
│                                  │                                   │
│                                  ▼                                   │
│                    ┌─────────────────────────┐                       │
│                    │  URL Inspector          │                       │
│                    │  (Browserbase/Heuristic)│                       │
│                    └─────────────────────────┘                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Features

### 🔍 Real-Time Detection
- **Auto-Detection**: MutationObserver watches for new emails without page reloads
- **Gmail & Outlook Support**: Works on both major email platforms
- **Non-Blocking**: Background Service Worker handles API calls

### 🎯 Threat Classification
| Threat Type | Color | Indicators |
|-------------|-------|------------|
| 🎣 **Phishing** | Red | Fake logins, credential harvesting, account verification scams |
| 📞 **Tech Support** | Yellow | Fake support numbers, remote access requests, Microsoft/Apple impersonation |
| 💀 **Scareware** | Purple | Virus alerts, system failure warnings, ransomware threats |
| ⚠️ **Suspicious** | Orange | Some red flags but not clearly malicious |
| ✅ **Benign** | Green | Appears legitimate |

### 🛡️ Reliability
- **Triage Layer**: AI analysis with heuristic fallback
- **Offline Mode**: Local pattern matching when API unavailable
- **Caching**: Background worker caches results to reduce API calls

### 🎨 Modern UI
- **Toast Notifications**: Material UI-style floating alerts
- **Color-Coded**: Instant visual threat identification
- **Non-Intrusive**: Dismissible notifications that don't block email

## Quick Start

### Prerequisites

- Python 3.10+
- Google Chrome
- Anthropic API Key (for Claude)
- Browserbase API Key (optional)

### 1. Backend Setup

```bash
cd spam_detector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export ANTHROPIC_API_KEY="your-anthropic-api-key"
export BROWSERBASE_API_KEY="your-browserbase-api-key"       # Optional
export BROWSERBASE_PROJECT_ID="your-browserbase-project-id"  # Optional

# Run the server
python main.py
```

### 2. Chrome Extension Setup

1. Go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → Select `extension` folder
4. Pin the extension for easy access

### 3. Test It!

1. Open Gmail or Outlook
2. Open any email
3. Watch for the scanning toast and result

## API Reference

### POST /scan

```json
// Request
{
  "sender_email": "support@paypa1.com",
  "links": ["http://paypa1-verify.tk/login"],
  "email_subject": "URGENT: Verify Your Account",
  "email_snippet": "Your account will be suspended unless you verify..."
}

// Response
{
  "is_phishing": true,
  "threat_type": "phishing",
  "confidence": 0.87,
  "reason": "Possible PayPal impersonation; Account suspension threat; Suspicious TLD"
}
```

### Threat Types
- `phishing` - Credential harvesting attempts
- `tech_support` - Fake tech support scams
- `scareware` - Fake virus/malware alerts
- `suspicious` - Potentially harmful
- `benign` - Appears safe

### GET /health

```json
{
  "status": "healthy",
  "claude_ai_configured": true,
  "browserbase_configured": false
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key for Claude |
| `BROWSERBASE_API_KEY` | No | Browserbase for URL inspection |
| `BROWSERBASE_PROJECT_ID` | No | Browserbase project ID |

## Detection Patterns

### Tech Support Scam Indicators
- Phone numbers (especially 1-8XX toll-free)
- "Microsoft Support" or "Apple Support" impersonation
- Remote access software mentions (TeamViewer, AnyDesk)
- "Your computer is infected/hacked" claims

### Scareware Indicators
- "Virus detected" or "Malware found" alerts
- "Your system is at risk" warnings
- "Files will be deleted/encrypted" threats
- Fake Windows Defender alerts

### Phishing Indicators
- "Verify your account" requests
- Account suspension threats
- Payment update requests
- Typosquatting domains (paypa1.com, micros0ft.com)

## Development

### Testing the API

```bash
# Test phishing
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "sender_email": "security@paypa1.com",
    "links": ["http://paypa1-verify.tk/login"],
    "email_subject": "Verify Your Account Now"
  }'

# Test tech support scam
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "sender_email": "support@microsoft-help.tk",
    "email_subject": "Your Computer Has Been Infected - Call 1-800-123-4567",
    "email_snippet": "Call Microsoft Support immediately. Our technician will use TeamViewer to fix your computer."
  }'

# Test scareware
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "sender_email": "alert@security-warning.com",
    "email_subject": "CRITICAL: Virus Detected on Your System",
    "email_snippet": "Windows Defender has detected a trojan. Your files will be encrypted in 24 hours. Immediate action required!"
  }'
```

### Extension Debugging

1. Open Gmail/Outlook in Chrome
2. Press F12 → Console tab
3. Filter by `[Phishing Shield]`
4. Check Network tab for API calls

## Tech Stack

- **Backend**: Python FastAPI
- **AI**: Claude Sonnet (Anthropic)
- **URL Inspection**: Browserbase API / Heuristics
- **Frontend**: Chrome Extension (Manifest V3)
- **Background**: Service Worker
- **Email Support**: Gmail, Outlook Web

## What's New in v2.0

- ✅ Auto-detection with MutationObserver (no reload needed)
- ✅ Tech Support Scam detection
- ✅ Scareware detection
- ✅ Background Service Worker (non-blocking)
- ✅ Local heuristic fallback
- ✅ Material UI toast notifications
- ✅ Color-coded threat levels
- ✅ Outlook Web support
- ✅ Result caching

## License

MIT License

## Disclaimer

This tool assists in identifying potential threats but should not be solely relied upon. Always exercise caution with suspicious emails.
