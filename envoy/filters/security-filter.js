// Advanced Security Filter for Envoy Proxy
// Implements threat detection, rate limiting, and security headers

class SecurityFilter extends RootContext {
  constructor() {
    super();
    this.suspiciousPatterns = [
      /\b(union|select|insert|delete|drop|create|alter)\b/i,
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/i,
      /vbscript:/i,
      /onload|onerror|onclick/i
    ];
    
    this.blockedUserAgents = [
      /sqlmap/i,
      /nikto/i,
      /nessus/i,
      /burp/i,
      /nmap/i,
      /masscan/i,
      /zap/i
    ];
    
    this.rateLimitCache = new Map();
    this.maxRequestsPerMinute = 100;
    this.blockDurationMs = 300000; // 5 minutes
  }
  
  onRequestHeaders(headers, endOfStream) {
    const method = headers[":method"];
    const path = headers[":path"];
    const userAgent = headers["user-agent"] || "";
    const xForwardedFor = headers["x-forwarded-for"] || "";
    const clientIp = this.getClientIp(xForwardedFor);
    
    // Security checks
    if (this.isBlockedUserAgent(userAgent)) {
      this.sendLocalResponse(403, "Forbidden", "Blocked user agent", []);
      return FilterHeadersStatus.StopIteration;
    }
    
    if (this.containsSqlInjection(path)) {
      this.sendLocalResponse(403, "Forbidden", "SQL injection attempt detected", []);
      this.logSecurityEvent("SQL_INJECTION", clientIp, path, userAgent);
      return FilterHeadersStatus.StopIteration;
    }
    
    if (this.containsXss(path)) {
      this.sendLocalResponse(403, "Forbidden", "XSS attempt detected", []);
      this.logSecurityEvent("XSS_ATTEMPT", clientIp, path, userAgent);
      return FilterHeadersStatus.StopIteration;
    }
    
    // Rate limiting
    if (this.isRateLimited(clientIp)) {
      this.sendLocalResponse(429, "Too Many Requests", "Rate limit exceeded", [
        ["retry-after", "300"]
      ]);
      return FilterHeadersStatus.StopIteration;
    }
    
    // Add security headers to request
    this.addRequestHeader("x-request-id", this.generateRequestId());
    this.addRequestHeader("x-client-ip", clientIp);
    this.addRequestHeader("x-timestamp", Date.now().toString());
    this.addRequestHeader("x-security-validated", "true");
    
    // Log legitimate request
    this.logRequest(method, path, clientIp, userAgent);
    
    return FilterHeadersStatus.Continue;
  }
  
  onResponseHeaders(headers, endOfStream) {
    // Add security response headers
    this.addResponseHeader("x-content-type-options", "nosniff");
    this.addResponseHeader("x-frame-options", "DENY");
    this.addResponseHeader("x-xss-protection", "1; mode=block");
    this.addResponseHeader("strict-transport-security", "max-age=31536000; includeSubDomains; preload");
    this.addResponseHeader("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    this.addResponseHeader("referrer-policy", "strict-origin-when-cross-origin");
    this.addResponseHeader("permissions-policy", "geolocation=(), microphone=(), camera=()");
    
    // Remove server information
    this.removeResponseHeader("server");
    this.removeResponseHeader("x-powered-by");
    
    return FilterHeadersStatus.Continue;
  }
  
  isBlockedUserAgent(userAgent) {
    return this.blockedUserAgents.some(pattern => pattern.test(userAgent));
  }
  
  containsSqlInjection(input) {
    return this.suspiciousPatterns.some(pattern => pattern.test(input));
  }
  
  containsXss(input) {
    const decodedInput = decodeURIComponent(input);
    return /<script|javascript:|vbscript:|onload|onerror|onclick/i.test(decodedInput);
  }
  
  isRateLimited(clientIp) {
    const now = Date.now();
    const windowStart = now - 60000; // 1 minute window
    
    if (!this.rateLimitCache.has(clientIp)) {
      this.rateLimitCache.set(clientIp, []);
    }
    
    const requests = this.rateLimitCache.get(clientIp);
    
    // Remove old requests outside the window
    const recentRequests = requests.filter(timestamp => timestamp > windowStart);
    
    // Check if client is currently blocked
    const lastRequest = recentRequests[recentRequests.length - 1];
    if (lastRequest && lastRequest.blocked && (now - lastRequest.timestamp) < this.blockDurationMs) {
      return true;
    }
    
    // Check rate limit
    if (recentRequests.length >= this.maxRequestsPerMinute) {
      recentRequests.push({ timestamp: now, blocked: true });
      this.rateLimitCache.set(clientIp, recentRequests);
      this.logSecurityEvent("RATE_LIMIT_EXCEEDED", clientIp, "", "");
      return true;
    }
    
    // Add current request
    recentRequests.push({ timestamp: now, blocked: false });
    this.rateLimitCache.set(clientIp, recentRequests);
    
    return false;
  }
  
  getClientIp(xForwardedFor) {
    if (xForwardedFor) {
      return xForwardedFor.split(',')[0].trim();
    }
    return "unknown";
  }
  
  generateRequestId() {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }
  
  logSecurityEvent(eventType, clientIp, path, userAgent) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event_type: eventType,
      client_ip: clientIp,
      path: path,
      user_agent: userAgent,
      severity: "HIGH",
      component: "envoy-security-filter"
    };
    
    console.log(JSON.stringify(logEntry));
  }
  
  logRequest(method, path, clientIp, userAgent) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event_type: "REQUEST",
      method: method,
      path: path,
      client_ip: clientIp,
      user_agent: userAgent,
      severity: "INFO",
      component: "envoy-security-filter"
    };
    
    console.log(JSON.stringify(logEntry));
  }
}

// Rate limiting configuration
class RateLimitFilter extends HttpFilter {
  constructor() {
    super();
    this.rateLimits = {
      "/api/v1/auth": { requests: 10, window: 60000 }, // 10 requests per minute
      "/api/v1/threats": { requests: 50, window: 60000 }, // 50 requests per minute
      "/api/v1/incidents": { requests: 20, window: 60000 }, // 20 requests per minute
      "default": { requests: 100, window: 60000 } // 100 requests per minute
    };
  }
  
  onRequestHeaders(headers, endOfStream) {
    const path = headers[":path"];
    const clientIp = this.getClientIp(headers["x-forwarded-for"] || "");
    
    const rateLimit = this.getRateLimitForPath(path);
    
    if (this.isRateLimited(clientIp, path, rateLimit)) {
      this.sendLocalResponse(429, "Too Many Requests", "Rate limit exceeded", [
        ["retry-after", Math.ceil(rateLimit.window / 1000).toString()],
        ["x-ratelimit-limit", rateLimit.requests.toString()],
        ["x-ratelimit-remaining", "0"],
        ["x-ratelimit-reset", Math.ceil((Date.now() + rateLimit.window) / 1000).toString()]
      ]);
      return FilterHeadersStatus.StopIteration;
    }
    
    return FilterHeadersStatus.Continue;
  }
  
  getRateLimitForPath(path) {
    for (const [pathPattern, limit] of Object.entries(this.rateLimits)) {
      if (pathPattern !== "default" && path.startsWith(pathPattern)) {
        return limit;
      }
    }
    return this.rateLimits.default;
  }
  
  isRateLimited(clientIp, path, rateLimit) {
    // Implementation would use a distributed cache like Redis
    // For now, using in-memory cache
    const key = `${clientIp}:${path}`;
    const now = Date.now();
    
    // This is a simplified implementation
    // In production, use Redis with sliding window
    return false; // Placeholder
  }
  
  getClientIp(xForwardedFor) {
    if (xForwardedFor) {
      return xForwardedFor.split(',')[0].trim();
    }
    return "unknown";
  }
}

// Export the filters
registerRootContext((rootContextId) => new SecurityFilter(rootContextId));
registerHttpFilter((rootContextId, contextId) => new RateLimitFilter(rootContextId, contextId));
