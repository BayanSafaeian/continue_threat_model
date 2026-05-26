# 🔒 Security Dependency Analysis: axios HTTP Client

**Package:** `axios` (v1.x)  
**Used In:** Multiple files across `core/`, `extensions/`, `packages/`  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟡 **MEDIUM-HIGH**

---

## 1. Dependency Purpose & Usage

### 1.1 Library Overview
```typescript
import axios from 'axios';

// Used for:
// - HTTP/HTTPS requests to external APIs
// - LLM provider API calls
// - Documentation fetching
// - Extension update checks
// - Telemetry export
```

### 1.2 Import Analysis
| Import | Type | Risk |
|--------|------|------|
| `axios` | Runtime HTTP client | 🟡 MEDIUM-HIGH |
| `@continuedev/fetch` | Custom fetch wrapper | 🟡 MEDIUM |
| `https`/`http` | Node.js built-in (via axios) | 🟢 LOW |

### 1.3 Authentication Methods
```typescript
// Bearer Token
axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// API Key
axios.get(url, { headers: { 'X-API-Key': apiKey } });

// Basic Auth
axios.get(url, { auth: { username, password } });
```

**Key Characteristics:**
- ✅ Supports multiple auth methods
- ✅ Interceptor chains for request/response modification
- ⚠️ Credentials stored in memory
- ⚠️ Can make requests to any URL (SSRF risk)

---

## 2. Data Flow Analysis

### 2.1 Input Data Flow
```
Application → axios Request Config → HTTP Client → Network → Remote API
```

| Data Type | Sensitivity | Encryption | Storage |
|-----------|-------------|------------|---------|
| API Keys | CRITICAL | TLS | Memory (session) |
| Bearer Tokens | CRITICAL | TLS | Memory (session) |
| Request Bodies | HIGH | TLS | Memory only |
| URLs/Endpoints | MEDIUM | TLS | Memory only |
| Custom Headers | MEDIUM | TLS | Memory only |

### 2.2 Output Data Flow
```
Remote API → HTTP Response → axios Response Parser → Application
```

| Data Type | Sensitivity | Validation |
|-----------|-------------|------------|
| Response Data | HIGH | JSON parsing, type checking |
| Status Codes | LOW | Numeric validation |
| Response Headers | MEDIUM | String validation |
| Error Objects | MEDIUM | Type checking |

### 2.3 Critical Data Transformations
```typescript
// Request configuration
axios.request({
  method: 'POST',
  url: apiUrl,
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  data: requestBody,
  timeout: 30000,
});

// Response interception
axios.interceptors.response.use(
  response => response.data,  // Extract data
  error => Promise.reject(error)  // Error handling
);
```

---

## 3. Threat Analysis

### 3.1 Primary Threat Vectors

| ID | Threat | CVSS | Severity |
|----|--------|------|----------|
| T1 | SSRF (Server-Side Request Forgery) | 8.6 | HIGH |
| T2 | Credential Leakage | 7.5 | HIGH |
| T3 | Request Smuggling | 7.2 | HIGH |
| T4 | DNS Rebinding | 7.5 | HIGH |
| T5 | MITM Attack | 6.8 | MEDIUM |
| T6 | Response Parsing Vulnerability | 6.5 | MEDIUM |
| T7 | Supply Chain Attack | 8.1 | HIGH |
| T8 | Header Injection (CRLF) | 6.5 | MEDIUM |

### 3.2 Detailed Threat Scenarios

#### T1: SSRF Attack
**Attack Vector:** Application Logic  
**CVSS:3.1 Score:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L)

```typescript
// ❌ VULNERABLE - User-controlled URL
app.get('/fetch', async (req, res) => {
  const url = req.query.url;  // User input
  const response = await axios.get(url);  // Direct use
  res.json(response.data);
});

// Attacker: http://internal-service/admin
```

**Attack Scenario:**
1. Attacker provides URL to internal service
2. axios makes request to internal network
3. Sensitive internal data exposed
4. Potential for internal service exploitation

**Impact:**
- Internal network reconnaissance
- Access to internal services
- Data exfiltration
- Potential RCE via internal services

**Mitigation:**
- Implement URL allowlist
- Block private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Validate URL scheme (https only)
- Use network segmentation

#### T2: Credential Leakage
**Attack Vector:** Configuration/Logging  
**CVSS:3.1 Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

```typescript
// ❌ VULNERABLE - Logging credentials
axios.interceptors.request.use(config => {
  console.log('Request:', config);  // Includes headers with auth
  return config;
});
```

**Attack Scenario:**
1. Credentials added to request headers
2. Interceptor logs full config object
3. Logs accessible to attacker (log aggregation, file access)
4. API keys/tokens extracted

**Impact:**
- Credential theft
- Unauthorized API access
- Account compromise

**Mitigation:**
- Never log full request config
- Redact sensitive headers before logging
- Use structured logging with field exclusion
- Implement log access controls

#### T3: Request Smuggling
**Attack Vector:** Network/Protocol  
**CVSS:3.1 Score:** 7.2 (AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)

```typescript
// ❌ VULNERABLE - User-controlled headers
app.post('/proxy', async (req, res) => {
  const customHeaders = req.body.headers;  // User input
  await axios.post(targetUrl, data, {
    headers: customHeaders  // Direct injection
  });
});
```

**Attack Scenario:**
1. Attacker injects CRLF characters in header value
2. Additional malicious headers added to request
3. Request interpreted differently by downstream servers
4. Cache poisoning, session hijacking, or XSS

**Impact:**
- Cache poisoning
- Session hijacking
- XSS attacks
- Request routing manipulation

**Mitigation:**
- Validate and sanitize all header values
- Reject CRLF characters (\r, \n)
- Use allowlist for header names
- Implement header value length limits

#### T4: DNS Rebinding
**Attack Vector:** Network  
**CVSS:3.1 Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Attack Scenario:**
1. Attacker controls domain with short TTL
2. Initial DNS resolution returns attacker's IP (allowed)
3. During request, DNS rebinding returns internal IP
4. axios connects to internal service

**Impact:**
- Bypass URL validation
- Access to internal services
- Data exfiltration

**Mitigation:**
- Implement DNS pinning
- Validate IP addresses after resolution
- Block private IP ranges
- Use IP allowlists instead of domain allowlists

#### T5: MITM Attack
**Attack Vector:** Network  
**CVSS:3.1 Score:** 6.8 (AV:A/AC:M/PR:N/UI:R/S:U/C:H/I:H/A:N)

```typescript
// ⚠️ Risk - No certificate pinning
axios.get('https://api.example.com/data');
```

**Attack Scenario:**
1. Attacker positions on network
2. Intercepts HTTPS traffic (certificate spoofing)
3. Captures credentials and data
4. Modifies requests/responses

**Impact:**
- Credential theft
- Data interception
- Request/response manipulation

**Mitigation:**
- Enforce HTTPS-only
- Implement certificate pinning
- Validate SSL certificates strictly
- Use HSTS headers

#### T6: Response Parsing Vulnerability
**Attack Vector:** Data Processing  
**CVSS:3.1 Score:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

```typescript
// ⚠️ Risk - Automatic JSON parsing
axios.get(url).then(response => {
  const data = response.data;  // Auto-parsed JSON
  // Potential for prototype pollution if JSON malicious
});
```

**Attack Scenario:**
1. Attacker controls API response
2. Malicious JSON with prototype pollution
3. Application processes polluted objects
4. Unexpected behavior or security bypass

**Impact:**
- Prototype pollution
- Application crashes
- Security bypass

**Mitigation:**
- Validate response structure
- Use JSON schema validation
- Implement response size limits
- Sanitize parsed objects

#### T7: Supply Chain Attack
**Attack Vector:** Supply Chain  
**CVSS:3.1 Score:** 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Dependency Tree:**
```
application
└── axios@1.x
    ├── follow-redirects
    ├── form-data
    ├── proxy-from-env
    └── [transitive dependencies]
```

**Attack Scenario:**
1. Attacker compromises axios or dependency
2. Malicious code added (credential harvesting, backdoor)
3. Application installs compromised package
4. Credentials and data exfiltrated

**Impact:**
- Credential theft
- Data exfiltration
- Remote code execution
- Supply chain propagation

**Mitigation:**
- Pin exact versions (use lockfile)
- Monitor npm security advisories
- Use npm audit regularly
- Consider package signature verification

#### T8: Header Injection (CRLF)
**Attack Vector:** Input Validation  
**CVSS:3.1 Score:** 6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

```typescript
// ❌ VULNERABLE - User input in header
const redirectUrl = req.query.redirect;
axios.get(url, {
  headers: {
    'X-Redirect': redirectUrl  // May contain \r\n
  }
});
```

**Attack Scenario:**
1. User input contains CRLF characters
2. Injected as new HTTP headers
3. Response splitting or header manipulation
4. XSS or cache poisoning

**Impact:**
- Response splitting
- Header manipulation
- XSS attacks
- Cache poisoning

**Mitigation:**
- Sanitize all user input in headers
- Reject CRLF characters
- Use header value allowlists
- Implement length limits

---

## 4. Entry Points (SDK Usage)

### 4.1 All Functions Using axios

| Function | Method | Data Sensitivity |
|----------|--------|------------------|
| `axios.create(config)` | Instance creation | Auth config |
| `axios.get(url, config)` | HTTP GET | URL, headers |
| `axios.post(url, data, config)` | HTTP POST | URL, data, auth |
| `axios.request(config)` | Generic request | Full config |
| `interceptors.request.use()` | Request interceptor | Headers, body |
| `interceptors.response.use()` | Response interceptor | Response data |
| `CancelToken` | Cancellation | Abort signals |

### 4.2 Request Configuration
```typescript
const instance = axios.create({
  baseURL: 'https://api.example.com',
  timeout: 30000,
  headers: {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  },
});
```

**Security Notes:**
- Credentials stored in instance memory
- Timeout enforcement prevents hanging requests
- Base URL can be overridden (SSRF risk)

### 4.3 Interceptor Usage
```typescript
// Request interceptor
axios.interceptors.request.use(config => {
  // Add auth token
  config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Response interceptor
axios.interceptors.response.use(
  response => response.data,
  error => {
    // Error handling
    return Promise.reject(error);
  }
);
```

**Security Notes:**
- Interceptors have access to all request/response data
- Potential for credential leakage in interceptor logic
- Error handlers may expose sensitive information

---

## 5. Assets & CIA Triad Assessment

### 5.1 Classified Assets

| Asset | Confidentiality | Integrity | Availability | Priority |
|-------|----------------|-----------|--------------|----------|
| API Keys | CRITICAL | HIGH | HIGH | CRITICAL |
| Bearer Tokens | CRITICAL | HIGH | HIGH | CRITICAL |
| Request Bodies | HIGH | MEDIUM | MEDIUM | HIGH |
| Response Data | HIGH | MEDIUM | MEDIUM | HIGH |
| URLs/Endpoints | MEDIUM | MEDIUM | LOW | MEDIUM |
| HTTP Headers | MEDIUM | MEDIUM | LOW | MEDIUM |
| Error Messages | LOW | LOW | LOW | LOW |

### 5.2 CIA Triad Analysis

#### Confidentiality
**Threats:**
- Credential interception (network, logs)
- Request/response data exposure
- MITM attacks
- Log file access

**Controls:**
- TLS encryption
- In-memory credential storage
- Log redaction

#### Integrity
**Threats:**
- Request/response manipulation
- Header injection
- Response parsing vulnerabilities

**Controls:**
- TLS integrity protection
- Response validation
- Header sanitization

#### Availability
**Threats:**
- Network timeouts
- DNS failures
- Remote API outages
- Resource exhaustion

**Controls:**
- Timeout enforcement
- Retry logic
- Circuit breakers

---

## 6. Trust Level Assessment

### 6.1 Component Trust Matrix

| Component | Trust Level | Justification |
|-----------|-------------|---------------|
| axios library | MEDIUM-HIGH | Widely-used, well-maintained, but large attack surface |
| Remote APIs | VARIABLE | Depends on endpoint (LLM providers = HIGH, unknown = LOW) |
| User-Provided URLs | LOW | Untrusted, potential for SSRF |
| Network Channel | MEDIUM | TLS-protected, but MITM possible |
| Interceptors | MEDIUM | Custom code, potential for injection |

### 6.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  TRUSTED ZONE (Local Application)                           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐    │
│  │ axios       │  │ Config Store │  │ Memory (Creds)  │    │
│  │ Instance    │  │              │  │                 │    │
│  └─────────────┘  └──────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ HTTPS (TLS 1.3)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  SEMI-TRUSTED ZONE (Network)                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Internet / Corporate Network / Public WiFi          │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ HTTP Request/Response
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  EXTERNAL ZONE (Remote APIs)                                │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐    │
│  │ LLM APIs    │  │ Auth System  │  │ Third-party     │    │
│  │             │  │              │  │ Services        │    │
│  └─────────────┘  └──────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 7. Architecture & Security Boundaries

### 7.1 Request Flow Architecture

```
┌──────────────┐
│   Application│
└──────┬───────┘
       │ 1. Request Config (URL, headers, body)
       ▼
┌─────────────────────────────────────┐
│         axios Instance              │
│  ┌───────────────────────────────┐  │
│  │ Request Interceptors          │  │
│  │ - Add auth headers            │  │
│  │ - Modify config               │  │
│  └───────────────────────────────┘  │
└──────┬──────────────────────────────┘
       │ 2. Final Request Config
       ▼
┌─────────────────────────────────────┐
│         HTTP Client                 │
│  ┌───────────────────────────────┐  │
│  │ DNS Resolution                │  │
│  │ TCP Connection                │  │
│  │ TLS Handshake                 │  │
│  └───────────────────────────────┘  │
└──────┬──────────────────────────────┘
       │ 3. HTTP Request (HTTPS)
       ▼
┌─────────────────────────────────────┐
│         Remote API                  │
│  ┌───────────────────────────────┐  │
│  │ Authentication                │  │
│  │ Request Processing            │  │
│  │ Response Generation           │  │
│  └───────────────────────────────┘  │
└──────┬──────────────────────────────┘
       │ 4. HTTP Response
       ▼
┌─────────────────────────────────────┐
│         axios Instance              │
│  ┌───────────────────────────────┐  │
│  │ Response Interceptors         │  │
│  │ - Parse data                  │  │
│  │ - Error handling              │  │
│  └───────────────────────────────┘  │
└──────┬──────────────────────────────┘
       │ 5. Response Data
       ▼
┌──────────────┐
│   Application│
└──────────────┘
```

### 7.2 Security Control Points

| Control Point | Current State | Recommendation |
|---------------|---------------|----------------|
| URL Validation | ❌ None | Implement allowlist |
| Header Sanitization | ⚠️ Basic | Add CRLF rejection |
| Authentication | ✅ Multiple methods | Add token rotation |
| Encryption | ✅ TLS | Add certificate pinning |
| Timeout | ✅ Configurable | Enforce global limits |
| Logging | ⚠️ Console | Add structured logging with redaction |
| Error Handling | ✅ Interceptors | Add error categorization |
| Response Validation | ❌ None | Add schema validation |

---

## 8. Security Recommendations

### 🔴 CRITICAL

#### 8.1 Implement URL Validation/Allowlist
**Priority:** CRITICAL  
**Effort:** MEDIUM

```typescript
const ALLOWED_HOSTS = [
  'api.anthropic.com',
  'api.openai.com',
  'bedrock-runtime.*.amazonaws.com',
];

function validateUrl(url: string): boolean {
  const parsed = new URL(url);
  
  // Check scheme
  if (parsed.protocol !== 'https:') {
    return false;
  }
  
  // Check host against allowlist
  if (!ALLOWED_HOSTS.some(host => parsed.hostname.endsWith(host))) {
    return false;
  }
  
  // Block private IP ranges
  const ip = dns.resolve(parsed.hostname);
  if (isPrivateIP(ip)) {
    return false;
  }
  
  return true;
}
```

#### 8.2 Never Expose Credentials in Logs
**Priority:** CRITICAL  
**Effort:** LOW

```typescript
// Secure logger
class SecureLogger {
  private static redactSensitiveData(config: any): any {
    const cloned = { ...config };
    
    // Redact authorization headers
    if (cloned.headers?.Authorization) {
      cloned.headers.Authorization = '[REDACTED]';
    }
    
    // Redact API keys
    if (cloned.headers?.['X-API-Key']) {
      cloned.headers['X-API-Key'] = '[REDACTED]';
    }
    
    return cloned;
  }
  
  static logRequest(config: any) {
    console.log('Request:', this.redactSensitiveData(config));
  }
}
```

### 🟠 HIGH

#### 8.3 Enforce HTTPS-Only
**Priority:** HIGH  
**Effort:** LOW

```typescript
const httpsOnlyAgent = new https.Agent({
  rejectUnauthorized: true,
  minVersion: 'TLSv1.3',
});

const instance = axios.create({
  httpsAgent: httpsOnlyAgent,
  maxRedirects: 0,  // Prevent redirect to HTTP
});
```

#### 8.4 Implement Request Timeouts
**Priority:** HIGH  
**Effort:** LOW

```typescript
const instance = axios.create({
  timeout: 30000,  // 30 seconds
  maxContentLength: 10 * 1024 * 1024,  // 10MB max
  maxBodyLength: 10 * 1024 * 1024,
});
```

#### 8.5 Add Response Validation
**Priority:** HIGH  
**Effort:** MEDIUM

```typescript
axios.interceptors.response.use(
  response => {
    // Validate response structure
    if (!response.data || typeof response.data !== 'object') {
      throw new Error('Invalid response format');
    }
    
    // Validate size
    if (JSON.stringify(response.data).length > MAX_RESPONSE_SIZE) {
      throw new Error('Response too large');
    }
    
    return response;
  },
  error => Promise.reject(error)
);
```

### 🟡 MEDIUM

#### 8.6 Implement Header Sanitization
**Priority:** MEDIUM  
**Effort:** LOW

```typescript
function sanitizeHeaderValue(value: string): string {
  // Remove CRLF characters
  return value.replace(/[\r\n]/g, '');
}

axios.interceptors.request.use(config => {
  if (config.headers) {
    for (const [key, value] of Object.entries(config.headers)) {
      if (typeof value === 'string') {
        config.headers[key] = sanitizeHeaderValue(value);
      }
    }
  }
  return config;
});
```

#### 8.7 Add Structured Logging
**Priority:** MEDIUM  
**Effort:** MEDIUM

```typescript
// Use structured logging with field exclusion
const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format((info) => {
      // Redact sensitive fields
      if (info.headers) {
        info.headers = redactSensitiveHeaders(info.headers);
      }
      return info;
    })(),
    winston.format.json()
  ),
});
```

### 🟢 LOW

#### 8.8 Implement Error Categorization
**Priority:** LOW  
**Effort:** LOW

```typescript
enum AxiosErrorType {
  NETWORK_ERROR = 'NETWORK_ERROR',
  TIMEOUT = 'TIMEOUT',
  AUTH_ERROR = 'AUTH_ERROR',
  NOT_FOUND = 'NOT_FOUND',
  SERVER_ERROR = 'SERVER_ERROR',
}

axios.interceptors.response.use(
  response => response,
  error => {
    if (error.code === 'ECONNABORTED') {
      error.category = AxiosErrorType.TIMEOUT;
    } else if (error.response?.status === 401) {
      error.category = AxiosErrorType.AUTH_ERROR;
    }
    return Promise.reject(error);
  }
);
```

---

## 9. Summary

### Risk Assessment Summary

| Category | Rating | Notes |
|----------|--------|-------|
| **Authentication** | 🟡 MEDIUM | Multiple methods, no rotation |
| **Data Protection** | 🟢 GOOD | TLS encryption |
| **Input Validation** | 🔴 POOR | No URL validation |
| **Output Validation** | 🔴 POOR | No response validation |
| **Supply Chain** | 🟡 MEDIUM | Widely-used, but many dependencies |
| **Network Security** | 🟢 GOOD | HTTPS enforced |
| **Error Handling** | 🟢 GOOD | Interceptor-based |
| **Logging** | 🟡 POOR | Potential credential leakage |

### Overall Risk: 🟡 **MEDIUM-HIGH**

**Primary Concerns:**
1. SSRF vulnerability via user-controlled URLs
2. Credential leakage in logs
3. No response validation
4. Supply chain attack surface
5. Header injection potential

**Strengths:**
1. Mature, well-maintained library
2. TLS encryption support
3. Flexible authentication
4. Interceptor system for customization

**Recommended Actions:**
1. Implement URL allowlist (CRITICAL)
2. Add credential redaction in logs (CRITICAL)
3. Enforce HTTPS-only (HIGH)
4. Add response validation (HIGH)
5. Implement request timeouts (HIGH)

---

*Generated with [Continue](https://continue.dev)*  
*Co-Authored-By: Continue <noreply@continue.dev>*
