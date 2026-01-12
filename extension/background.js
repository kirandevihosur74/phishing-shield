/**
 * Phishing Shield - Background Service Worker
 * 
 * Handles API requests in the background to prevent UI blocking.
 * Provides caching and retry logic for reliability.
 */

const CONFIG = {
  API_URL: 'http://localhost:8000',
  SCAN_ENDPOINT: '/scan',
  CACHE_DURATION: 5 * 60 * 1000, // 5 minutes
  MAX_RETRIES: 2,
  RETRY_DELAY: 1000,
};

// In-memory cache for scan results
const scanCache = new Map();

// Clean up old cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of scanCache.entries()) {
    if (now - value.timestamp > CONFIG.CACHE_DURATION) {
      scanCache.delete(key);
    }
  }
}, 60000);

/**
 * Generate cache key from email data
 */
function getCacheKey(emailData) {
  const str = JSON.stringify({
    sender: emailData.sender_email,
    subject: emailData.email_subject,
    links: emailData.links?.slice(0, 3)
  });
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return `scan-${Math.abs(hash)}`;
}

/**
 * Scan email via API with retry logic
 */
async function scanEmail(emailData, retryCount = 0) {
  const cacheKey = getCacheKey(emailData);
  
  // Check cache first
  const cached = scanCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
    console.log('[Phishing Shield BG] Cache hit:', cacheKey);
    return cached.result;
  }
  
  const url = `${CONFIG.API_URL}${CONFIG.SCAN_ENDPOINT}`;
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailData)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const result = await response.json();
    
    // Cache the result
    scanCache.set(cacheKey, {
      result,
      timestamp: Date.now()
    });
    
    console.log('[Phishing Shield BG] Scan complete:', result);
    return result;
    
  } catch (error) {
    console.error('[Phishing Shield BG] Scan error:', error);
    
    // Retry logic
    if (retryCount < CONFIG.MAX_RETRIES) {
      console.log(`[Phishing Shield BG] Retrying (${retryCount + 1}/${CONFIG.MAX_RETRIES})...`);
      await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY));
      return scanEmail(emailData, retryCount + 1);
    }
    
    throw error;
  }
}

/**
 * Message handler
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_EMAIL') {
    console.log('[Phishing Shield BG] Received scan request');
    
    scanEmail(message.data)
      .then(result => {
        sendResponse(result);
      })
      .catch(error => {
        sendResponse({ error: error.message });
      });
    
    // Return true to indicate async response
    return true;
  }
  
  if (message.type === 'CLEAR_CACHE') {
    scanCache.clear();
    console.log('[Phishing Shield BG] Cache cleared');
    sendResponse({ success: true });
    return true;
  }
  
  if (message.type === 'GET_STATS') {
    sendResponse({
      cacheSize: scanCache.size,
      uptime: Date.now()
    });
    return true;
  }
});

/**
 * Installation handler
 */
chrome.runtime.onInstalled.addListener((details) => {
  console.log('[Phishing Shield BG] Extension installed:', details.reason);
  
  if (details.reason === 'install') {
    // Open welcome page or instructions
    console.log('[Phishing Shield BG] First install - welcome!');
  }
});

/**
 * Startup handler
 */
chrome.runtime.onStartup.addListener(() => {
  console.log('[Phishing Shield BG] Browser started, service worker active');
});

console.log('[Phishing Shield BG] Service worker initialized');
