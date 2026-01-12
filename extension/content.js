/**
 * Phishing Shield - Gmail/Outlook Content Script (Enhanced)
 * 
 * Features:
 * - Improved MutationObserver for real-time detection
 * - Background Service Worker communication for non-blocking API calls
 * - Local heuristic fallback when API unavailable
 * - Dynamic threat-specific toast notifications
 * - Support for Gmail and Outlook Web
 */

(function() {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════════════════
  // Configuration
  // ═══════════════════════════════════════════════════════════════════════════════
  
  const CONFIG = {
    API_URL: 'http://localhost:8000',
    SCAN_ENDPOINT: '/scan',
    DEBOUNCE_MS: 500,  // Wait 500ms after email opens before scanning
    MAX_LINKS_TO_SEND: 10,
    TOAST_CONTAINER_ID: 'phishing-shield-toast-container',
    TOAST_DURATION: 10000,
    DEBUG: true,
    // Threat type colors
    THREAT_COLORS: {
      phishing: { bg: '#dc2626', icon: '🎣', label: 'Phishing' },
      tech_support: { bg: '#eab308', icon: '📞', label: 'Tech Support Scam' },
      scareware: { bg: '#9333ea', icon: '💀', label: 'Scareware' },
      suspicious: { bg: '#f97316', icon: '⚠️', label: 'Suspicious' },
      benign: { bg: '#22c55e', icon: '✅', label: 'Safe' }
    }
  };

  // Track analyzed emails to prevent re-scanning
  const analyzedEmails = new Map(); // emailId -> result
  
  // Debounce timer
  let debounceTimer = null;
  
  // Observer instance
  let mainObserver = null;
  let emailContentObserver = null;

  // ═══════════════════════════════════════════════════════════════════════════════
  // Logging Utility
  // ═══════════════════════════════════════════════════════════════════════════════
  
  function log(...args) {
    if (CONFIG.DEBUG) {
      console.log('%c[Phishing Shield]', 'color: #3b82f6; font-weight: bold;', ...args);
    }
  }

  function logError(...args) {
    console.error('%c[Phishing Shield Error]', 'color: #ef4444; font-weight: bold;', ...args);
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  // Local Heuristic Triage (Fallback)
  // ═══════════════════════════════════════════════════════════════════════════════

  const SCAM_PATTERNS = {
    // Tech Support Scam patterns - HIGH confidence indicators only
    tech_support: {
      keywords: [
        /call\s*(us\s*)?(now|immediately)\s*.*\d{3}.*\d{4}/i, // Call now with phone number
        /microsoft\s*(support|technician).*call/i,
        /apple\s*(support|technician).*call/i,
        /remote\s*access.*install/i,
        /(teamviewer|anydesk|logmein).*install/i,
        /your\s*computer\s*(has|is)\s*been\s*(infected|compromised|hacked)/i,
      ],
      weight: 0.4
    },
    // Scareware patterns - HIGH confidence indicators only
    scareware: {
      keywords: [
        /virus\s*(detected|found).*immediate/i,
        /malware\s*(detected|found).*action/i,
        /your\s*files\s*(will\s*be|are\s*being)\s*(deleted|encrypted)/i,
        /ransomware.*detected/i,
        /windows\s*defender\s*alert.*virus/i,
        /trojan.*detected.*remove/i,
      ],
      weight: 0.45
    },
    // Phishing patterns - Only strong indicators
    phishing: {
      keywords: [
        /verify\s*your\s*(account|identity).*click/i,
        /account\s*(will\s*be|has\s*been)\s*(locked|suspended|terminated)/i,
        /unusual\s*(activity|sign[- ]?in).*verify/i,
        /update\s*your\s*(payment|billing).*immediately/i,
        /confirm\s*your\s*identity.*24\s*hours/i,
      ],
      weight: 0.35
    }
  };

  const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.loan', '.date'];
  
  const DOMAIN_BLACKLIST = [
    /paypa[l1](?!\.com)/i,
    /app[l1]e(?!\.com)/i,
    /micros[o0]ft(?!\.com)/i,
    /amaz[o0]n(?!\.com)/i,
    /g[o0]{2}g[l1]e(?!\.com)/i,
    /faceb[o0]{2}k(?!\.com)/i,
    /netf[l1]ix(?!\.com)/i,
    /bank.*secure/i,
    /secure.*login/i,
    /verify.*account/i,
  ];

  /**
   * Local heuristic analysis when API is unavailable
   */
  function localHeuristicAnalysis(emailData) {
    const { sender_email, links, email_subject, email_snippet } = emailData;
    const fullText = `${email_subject || ''} ${email_snippet || ''}`.toLowerCase();
    
    let scores = {
      phishing: 0,
      tech_support: 0,
      scareware: 0
    };
    
    const reasons = [];
    
    // Check patterns for each threat type
    for (const [threatType, config] of Object.entries(SCAM_PATTERNS)) {
      for (const pattern of config.keywords) {
        if (pattern.test(fullText)) {
          scores[threatType] += config.weight;
          if (scores[threatType] <= config.weight) {
            reasons.push(`${threatType.replace('_', ' ')} indicator: "${fullText.match(pattern)?.[0] || 'pattern match'}"`);
          }
        }
      }
    }
    
    // Check sender domain
    if (sender_email) {
      const senderLower = sender_email.toLowerCase();
      
      // Check for brand impersonation in sender
      for (const pattern of DOMAIN_BLACKLIST) {
        if (pattern.test(senderLower)) {
          scores.phishing += 0.4;
          reasons.push(`Suspicious sender domain: ${sender_email}`);
          break;
        }
      }
      
      // Free email + brand name = suspicious
      const freeEmails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
      const brands = ['paypal', 'apple', 'amazon', 'microsoft', 'netflix', 'bank'];
      const domain = senderLower.split('@')[1] || '';
      const localPart = senderLower.split('@')[0] || '';
      
      if (freeEmails.some(d => domain.includes(d))) {
        for (const brand of brands) {
          if (localPart.includes(brand)) {
            scores.phishing += 0.3;
            reasons.push(`Brand "${brand}" used with free email provider`);
            break;
          }
        }
      }
    }
    
    // Check links
    if (links && links.length > 0) {
      for (const link of links) {
        const linkLower = link.toLowerCase();
        
        // Suspicious TLDs
        if (SUSPICIOUS_TLDS.some(tld => linkLower.includes(tld))) {
          scores.phishing += 0.2;
          reasons.push(`Suspicious TLD in link`);
        }
        
        // IP address in URL
        if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) {
          scores.phishing += 0.3;
          reasons.push(`IP address used instead of domain`);
        }
        
        // Brand impersonation in link
        for (const pattern of DOMAIN_BLACKLIST) {
          if (pattern.test(linkLower)) {
            scores.phishing += 0.3;
            reasons.push(`Possible brand impersonation in link`);
            break;
          }
        }
      }
    }
    
    // Determine threat type - require HIGH confidence for threats
    const maxScore = Math.max(scores.phishing, scores.tech_support, scores.scareware);
    let threat_type = 'benign';
    let confidence = 0;
    
    // Require score >= 0.65 to classify as actual threat
    if (maxScore >= 0.65) {
      if (scores.scareware === maxScore) {
        threat_type = 'scareware';
      } else if (scores.tech_support === maxScore) {
        threat_type = 'tech_support';
      } else {
        threat_type = 'phishing';
      }
      confidence = Math.min(maxScore, 0.95);
    } else if (maxScore >= 0.45) {
      // Only mark as suspicious if moderately high score
      threat_type = 'suspicious';
      confidence = maxScore;
    } else {
      // Default to benign
      threat_type = 'benign';
      confidence = 1 - maxScore;
    }
    
    return {
      is_phishing: threat_type !== 'benign' && threat_type !== 'suspicious',
      threat_type,
      confidence,
      reason: reasons.length > 0 ? reasons.slice(0, 3).join('; ') : 'No suspicious indicators found',
      source: 'heuristic'
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  // Email Extraction (Gmail & Outlook)
  // ═══════════════════════════════════════════════════════════════════════════════

  function isGmail() {
    return window.location.hostname.includes('mail.google.com');
  }

  function isOutlook() {
    return window.location.hostname.includes('outlook.live.com') || 
           window.location.hostname.includes('outlook.office.com');
  }

  function extractSenderEmail() {
    if (isGmail()) {
      // Gmail sender is in the "From" header - look specifically in the email header area
      // The sender element has class 'gD' with email attribute, inside the header
      const senderSelectors = [
        // Primary: sender name/email in header (class gD)
        '.gD[email]',
        // From row sender
        '.go[email]',
        // Expanded email header
        'table.cf.gJ span[email]',
        // Sender in collapsed view
        '.yP[email]',
        '.zF[email]',
        // Generic with email attribute (but NOT in profile area)
        '.adn span[email]',
      ];

      for (const selector of senderSelectors) {
        const element = document.querySelector(selector);
        if (element) {
          const email = element.getAttribute('email');
          if (email && email.includes('@')) {
            log('Found sender via selector:', selector, email);
            return email.trim();
          }
        }
      }
      
      // Try data-hovercard-id on sender elements
      const hovercardEl = document.querySelector('.gD[data-hovercard-id]');
      if (hovercardEl) {
        const email = hovercardEl.getAttribute('data-hovercard-id');
        if (email && email.includes('@')) {
          log('Found sender via hovercard:', email);
          return email.trim();
        }
      }

    } else if (isOutlook()) {
      const senderEl = document.querySelector('[data-testid="SenderPersona"] span[title*="@"]');
      if (senderEl) {
        return senderEl.getAttribute('title') || senderEl.textContent;
      }
    }

    // NO fallback regex - too unreliable, picks up wrong emails
    log('Could not find sender email with specific selectors');
    return null;
  }

  function extractEmailSubject() {
    if (isGmail()) {
      const selectors = ['h2.hP', '[data-thread-perm-id] h2', '.ha h2', 'h2[data-legacy-thread-id]'];
      for (const selector of selectors) {
        const el = document.querySelector(selector);
        if (el?.textContent) return el.textContent.trim();
      }
    } else if (isOutlook()) {
      const subjectEl = document.querySelector('[data-testid="SubjectLine"]');
      if (subjectEl?.textContent) return subjectEl.textContent.trim();
    }
    return null;
  }

  function extractEmailSnippet() {
    if (isGmail()) {
      const bodySelectors = ['.a3s.aiL', '.a3s', '[data-message-id] .a3s', '.ii.gt'];
      for (const selector of bodySelectors) {
        const el = document.querySelector(selector);
        if (el?.textContent) return el.textContent.trim().substring(0, 1000);
      }
    } else if (isOutlook()) {
      const bodyEl = document.querySelector('[data-testid="ReadingPaneContainerId"]');
      if (bodyEl?.textContent) return bodyEl.textContent.trim().substring(0, 1000);
    }
    return null;
  }

  function extractEmailLinks() {
    const links = new Set();
    let bodyElement = null;

    if (isGmail()) {
      const bodySelectors = ['.a3s.aiL', '.a3s', '.ii.gt', '[data-message-id]'];
      for (const selector of bodySelectors) {
        bodyElement = document.querySelector(selector);
        if (bodyElement) break;
      }
    } else if (isOutlook()) {
      bodyElement = document.querySelector('[data-testid="ReadingPaneContainerId"]');
    }

    if (!bodyElement) {
      log('Could not find email body');
      return [];
    }

    const anchors = bodyElement.querySelectorAll('a[href]');
    
    anchors.forEach(anchor => {
      let href = anchor.getAttribute('href');
      if (!href) return;
      
      // Unwrap Google redirect URLs
      if (href.includes('google.com/url?')) {
        try {
          const url = new URL(href);
          const actualUrl = url.searchParams.get('q') || url.searchParams.get('url');
          if (actualUrl) href = actualUrl;
        } catch (e) {}
      }
      
      // Unwrap Outlook safelinks
      if (href.includes('safelinks.protection.outlook.com')) {
        try {
          const url = new URL(href);
          const actualUrl = url.searchParams.get('url');
          if (actualUrl) href = decodeURIComponent(actualUrl);
        } catch (e) {}
      }

      // Filter out internal/mail links
      if (href.startsWith('mailto:')) return;
      if (href.startsWith('#')) return;
      if (href.includes('mail.google.com')) return;
      if (href.includes('outlook.live.com')) return;
      if (href.includes('accounts.google.com')) return;
      
      if (href.startsWith('http://') || href.startsWith('https://')) {
        links.add(href);
      }
    });

    return Array.from(links).slice(0, CONFIG.MAX_LINKS_TO_SEND);
  }

  function getEmailId() {
    const subject = extractEmailSubject() || 'unknown';
    const sender = extractSenderEmail() || 'unknown';
    const str = `${subject}-${sender}-${window.location.hash}-${Date.now()}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return `email-${Math.abs(hash)}`;
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  // Toast Notification System (Material UI Style)
  // ═══════════════════════════════════════════════════════════════════════════════

  function createToastContainer() {
    let container = document.getElementById(CONFIG.TOAST_CONTAINER_ID);
    if (!container) {
      container = document.createElement('div');
      container.id = CONFIG.TOAST_CONTAINER_ID;
      container.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 999999;
        display: flex;
        flex-direction: column;
        gap: 12px;
        pointer-events: none;
        font-family: 'Google Sans', 'Segoe UI', Roboto, sans-serif;
      `;
      document.body.appendChild(container);
    }
    return container;
  }

  function showToast(result, emailId) {
    const container = createToastContainer();
    
    // Remove existing toast for this email
    const existingToast = document.getElementById(`toast-${emailId}`);
    if (existingToast) existingToast.remove();
    
    const threatType = result.threat_type || (result.is_phishing ? 'phishing' : 'benign');
    const threatConfig = CONFIG.THREAT_COLORS[threatType] || CONFIG.THREAT_COLORS.suspicious;
    
    // For benign emails, always show a "safe" toast
    if (threatType === 'benign') {
      showSafeToast(emailId);
      return;
    }
    
    if (threatType === 'suspicious' && result.confidence < 0.6) {
      log('Low confidence suspicious, skipping toast');
      return;
    }
    
    // For actual threats, require at least 50% confidence
    if (result.is_phishing && result.confidence < 0.5) {
      log('Threat confidence too low, skipping toast:', result.confidence);
      return;
    }
    
    const confidencePercent = Math.round(result.confidence * 100);
    const sourceLabel = result.source === 'heuristic' ? ' (Offline)' : '';
    
    const toast = document.createElement('div');
    toast.id = `toast-${emailId}`;
    toast.style.cssText = `
      background: ${threatConfig.bg};
      color: white;
      padding: 16px 20px;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      min-width: 320px;
      max-width: 420px;
      pointer-events: auto;
      animation: slideIn 0.3s ease-out;
      position: relative;
      backdrop-filter: blur(10px);
    `;
    
    toast.innerHTML = `
      <style>
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100%); opacity: 0; }
        }
        .toast-progress {
          position: absolute;
          bottom: 0;
          left: 0;
          height: 4px;
          background: rgba(255,255,255,0.5);
          border-radius: 0 0 12px 12px;
          animation: progress ${CONFIG.TOAST_DURATION}ms linear;
        }
        @keyframes progress {
          from { width: 100%; }
          to { width: 0%; }
        }
      </style>
      <div style="display: flex; align-items: flex-start; gap: 12px;">
        <span style="font-size: 28px;">${threatConfig.icon}</span>
        <div style="flex: 1;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <strong style="font-size: 15px;">${threatConfig.label}${sourceLabel}</strong>
            <span style="font-size: 12px; opacity: 0.9; background: rgba(255,255,255,0.2); padding: 2px 8px; border-radius: 10px;">
              ${confidencePercent}%
            </span>
          </div>
          <p style="margin: 0; font-size: 13px; opacity: 0.95; line-height: 1.4;">
            ${escapeHtml(result.reason || 'Analysis complete')}
          </p>
        </div>
        <button onclick="this.parentElement.parentElement.remove()" style="
          background: rgba(255,255,255,0.2);
          border: none;
          color: white;
          width: 24px;
          height: 24px;
          border-radius: 50%;
          cursor: pointer;
          font-size: 14px;
          display: flex;
          align-items: center;
          justify-content: center;
        ">×</button>
      </div>
      <div class="toast-progress"></div>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after duration
    setTimeout(() => {
      if (toast.parentElement) {
        toast.style.animation = 'slideOut 0.3s ease-in forwards';
        setTimeout(() => toast.remove(), 300);
      }
    }, CONFIG.TOAST_DURATION);
    
    log('Toast shown:', threatConfig.label, result);
  }

  function showScanningToast() {
    const container = createToastContainer();
    
    // Remove existing scanning toast
    const existingScanning = document.getElementById('toast-scanning');
    if (existingScanning) existingScanning.remove();
    
    const toast = document.createElement('div');
    toast.id = 'toast-scanning';
    toast.style.cssText = `
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: white;
      padding: 14px 20px;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(59, 130, 246, 0.4);
      min-width: 280px;
      pointer-events: auto;
      animation: slideIn 0.3s ease-out;
      display: flex;
      align-items: center;
      gap: 12px;
    `;
    
    toast.innerHTML = `
      <style>
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      </style>
      <div style="
        width: 20px;
        height: 20px;
        border: 2px solid rgba(255,255,255,0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
      "></div>
      <span style="font-size: 14px;">🛡️ Analyzing email for threats...</span>
    `;
    
    container.appendChild(toast);
  }

  function hideScanningToast() {
    const scanningToast = document.getElementById('toast-scanning');
    if (scanningToast) {
      scanningToast.style.animation = 'slideOut 0.3s ease-in forwards';
      setTimeout(() => scanningToast.remove(), 300);
    }
  }

  function showSafeToast(emailId) {
    const container = createToastContainer();
    
    // Remove existing toast for this email
    const existingToast = document.getElementById(`toast-${emailId}`);
    if (existingToast) existingToast.remove();
    
    const toast = document.createElement('div');
    toast.id = `toast-${emailId}`;
    toast.style.cssText = `
      background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
      color: white;
      padding: 14px 20px;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(34, 197, 94, 0.4);
      min-width: 280px;
      pointer-events: auto;
      animation: slideIn 0.3s ease-out;
      display: flex;
      align-items: center;
      gap: 12px;
    `;
    
    toast.innerHTML = `
      <style>
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100%); opacity: 0; }
        }
      </style>
      <span style="font-size: 24px;">✅</span>
      <div style="flex: 1;">
        <strong style="font-size: 14px;">Email appears safe</strong>
        <p style="margin: 2px 0 0 0; font-size: 12px; opacity: 0.9;">No threats detected</p>
      </div>
      <button onclick="this.parentElement.remove()" style="
        background: rgba(255,255,255,0.2);
        border: none;
        color: white;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        cursor: pointer;
        font-size: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
      ">×</button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after 3 seconds (shorter than threat toasts)
    setTimeout(() => {
      if (toast.parentElement) {
        toast.style.animation = 'slideOut 0.3s ease-in forwards';
        setTimeout(() => toast.remove(), 300);
      }
    }, 3000);
    
    log('Safe toast shown for email:', emailId);
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  // API Communication with Service Worker
  // ═══════════════════════════════════════════════════════════════════════════════

  async function scanEmailViaAPI(emailData) {
    const url = `${CONFIG.API_URL}${CONFIG.SCAN_ENDPOINT}`;
    
    log('Sending scan request:', emailData);
    
    try {
      // Try to use service worker if available
      if (chrome?.runtime?.sendMessage) {
        return new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(
            { type: 'SCAN_EMAIL', data: emailData },
            (response) => {
              if (chrome.runtime.lastError) {
                log('Service worker unavailable, using direct fetch');
                // Fallback to direct fetch
                directFetch(url, emailData).then(resolve).catch(reject);
              } else if (response?.error) {
                reject(new Error(response.error));
              } else {
                resolve(response);
              }
            }
          );
        });
      } else {
        return await directFetch(url, emailData);
      }
    } catch (error) {
      logError('API request failed:', error);
      throw error;
    }
  }

  async function directFetch(url, emailData) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(emailData),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  // Main Analysis Flow
  // ═══════════════════════════════════════════════════════════════════════════════

  async function analyzeCurrentEmail() {
    const emailId = getEmailId();
    
    // Check cache
    if (analyzedEmails.has(emailId)) {
      const cachedResult = analyzedEmails.get(emailId);
      log('Using cached result for:', emailId);
      showToast(cachedResult, emailId);
      return;
    }

    // Extract email data
    const senderEmail = extractSenderEmail();
    const links = extractEmailLinks();
    const subject = extractEmailSubject();
    const snippet = extractEmailSnippet();

    if (!senderEmail && !subject && !snippet) {
      log('Could not extract email data, skipping analysis');
      return;
    }

    const emailData = {
      sender_email: senderEmail || 'unknown@unknown.com',
      links: links,
      email_subject: subject,
      email_snippet: snippet
    };

    log('Analyzing email:', { emailId, senderEmail, links: links.length, subject });

    // Small delay before showing scanning toast
    await sleep(300);
    showScanningToast();
    
    const scanStartTime = Date.now();

    try {
      // Try API first
      const result = await scanEmailViaAPI(emailData);
      
      // Cache result
      analyzedEmails.set(emailId, result);
      
      // Ensure scanning toast is visible for at least 1 second
      const elapsed = Date.now() - scanStartTime;
      if (elapsed < 1000) {
        await sleep(1000 - elapsed);
      }
      
      hideScanningToast();
      
      // Small delay before showing result toast
      await sleep(400);
      showToast(result, emailId);
      
    } catch (error) {
      logError('API analysis failed, using heuristic fallback:', error);
      
      // Fallback to local heuristics
      const heuristicResult = localHeuristicAnalysis(emailData);
      
      // Cache result
      analyzedEmails.set(emailId, heuristicResult);
      
      // Ensure scanning toast is visible for at least 1 second
      const elapsed = Date.now() - scanStartTime;
      if (elapsed < 1000) {
        await sleep(1000 - elapsed);
      }
      
      hideScanningToast();
      
      // Small delay before showing result toast
      await sleep(400);
      showToast(heuristicResult, emailId);
    }
  }
  
  // Helper function for delays
  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  function triggerAnalysis() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      analyzeCurrentEmail();
    }, CONFIG.DEBOUNCE_MS);
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  // Enhanced MutationObserver
  // ═══════════════════════════════════════════════════════════════════════════════

  function isViewingEmail() {
    if (isGmail()) {
      const hash = window.location.hash;
      if (hash.includes('/')) {
        const parts = hash.split('/');
        if (parts.length >= 2 && parts[1].length > 10) {
          return true;
        }
      }
      const emailBodySelectors = ['.a3s.aiL', '.a3s', '.ii.gt'];
      return emailBodySelectors.some(sel => document.querySelector(sel));
    } else if (isOutlook()) {
      return !!document.querySelector('[data-testid="ReadingPaneContainerId"]');
    }
    return false;
  }

  function getEmailContentContainer() {
    if (isGmail()) {
      return document.querySelector('.a3s.aiL') || 
             document.querySelector('.a3s') ||
             document.querySelector('.ii.gt');
    } else if (isOutlook()) {
      return document.querySelector('[data-testid="ReadingPaneContainerId"]');
    }
    return null;
  }

  function initObservers() {
    log('Initializing enhanced MutationObservers');

    // Main observer for detecting email opens
    const mainObserverConfig = {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['class', 'data-message-id', 'aria-expanded']
    };

    mainObserver = new MutationObserver((mutations) => {
      let shouldAnalyze = false;
      
      for (const mutation of mutations) {
        // Check for new nodes
        if (mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Gmail email body indicators
              if (node.matches?.('.a3s') || 
                  node.querySelector?.('.a3s') ||
                  node.matches?.('.ii.gt') ||
                  node.querySelector?.('.ii.gt') ||
                  node.matches?.('[data-message-id]') ||
                  node.querySelector?.('[data-message-id]')) {
                shouldAnalyze = true;
                break;
              }
              // Outlook reading pane
              if (node.matches?.('[data-testid="ReadingPaneContainerId"]') ||
                  node.querySelector?.('[data-testid="ReadingPaneContainerId"]')) {
                shouldAnalyze = true;
                break;
              }
            }
          }
        }
        
        // Check for attribute changes (email expansion in Gmail)
        if (mutation.type === 'attributes' && mutation.attributeName === 'aria-expanded') {
          if (mutation.target.getAttribute('aria-expanded') === 'true') {
            shouldAnalyze = true;
          }
        }
        
        if (shouldAnalyze) break;
      }

      if (shouldAnalyze && isViewingEmail()) {
        log('Email content change detected');
        triggerAnalysis();
      }
    });

    mainObserver.observe(document.body, mainObserverConfig);

    // Hash change listener for Gmail navigation
    window.addEventListener('hashchange', () => {
      log('Navigation detected:', window.location.hash);
      if (isViewingEmail()) {
        // Small delay to let content load
        setTimeout(triggerAnalysis, 200);
      }
    });

    // Popstate for Outlook navigation
    window.addEventListener('popstate', () => {
      log('Popstate navigation detected');
      if (isViewingEmail()) {
        setTimeout(triggerAnalysis, 200);
      }
    });

    log('Enhanced MutationObservers initialized');
  }

  // ═══════════════════════════════════════════════════════════════════════════════
  // Initialization
  // ═══════════════════════════════════════════════════════════════════════════════

  function init() {
    log('Phishing Shield v2.0 - Enhanced Real-Time Detection');
    log('Platform:', isGmail() ? 'Gmail' : isOutlook() ? 'Outlook' : 'Unknown');
    
    const checkReady = setInterval(() => {
      const mainContainer = document.querySelector('[role="main"]') || 
                           document.querySelector('[data-testid="MainModule"]');
      if (mainContainer) {
        clearInterval(checkReady);
        log('Email client loaded, starting observers');
        
        initObservers();
        
        if (isViewingEmail()) {
          log('Already viewing an email, triggering analysis');
          triggerAnalysis();
        }
      }
    }, 300);

    setTimeout(() => clearInterval(checkReady), 30000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
