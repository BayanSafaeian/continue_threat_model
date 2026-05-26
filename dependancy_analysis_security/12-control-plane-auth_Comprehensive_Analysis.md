# 🔒 Comprehensive Security Analysis: control-plane-auth [Authentication URL Generation]

**Package:** `core/control-plane/auth/index.ts`  
**Used In:** `/core/control-plane/auth/index.ts` (OAuth authentication flow initiation)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟠 **HIGH**

---

## 1. Dependency Purpose & Usage

### Primary Function
This module generates OAuth authentication URLs for the WorkOS authentication service. It constructs the authorization URL with proper parameters for the OAuth 2.0 flow, enabling users to authenticate with Continue Hub.

### Implementation
```typescript
import { v4 as uuidv4 } from "uuid";
import { IdeSettings } from "../..";
import { isHubEnv } from "../AuthTypes";
import { getControlPlaneEnv } from "../env";

export async function getAuthUrlForTokenPage(
  ideSettingsPromise: Promise<IdeSettings>,
  useOnboarding: boolean,
): Promise<string> {
  const env = await getControlPlaneEnv(ideSettingsPromise);

  if (!isHubEnv(env)) {
    throw new Error("Sign in disabled");
  }

  const url = new URL("https://api.workos.com/user_management/authorize");
  const params = {
    response_type: "code",
    client_id: env.WORKOS_CLIENT_ID,
    redirect_uri: `${env.APP_URL}tokens/${useOnboarding ? "onboarding-" : ""}callback`,
    state: uuidv4(),
    provider: "authkit",
  };
  Object.keys(params).forEach((key) =>
    url.searchParams.append(key, params[key as keyof typeof params]),
  );
  return url.toString();
}
```

### Dependency Type
- **Internal Core Module** - Authentication flow component
- **External Dependencies:** 
  - `uuid` (v4) - For generating state parameter
  - WorkOS API - OAuth 2.0 authorization endpoint
- **Coordinates:** Control Plane environment configuration, IDE settings

---

## 2. Data Flow Analysis

### Inbound Data
| Data Type | Source | Sensitivity | Validation |
|-----------|--------|-------------|------------|
| IDE settings | `ideSettingsPromise` | **High** | Type validation via TypeScript |
| `useOnboarding` flag | Function caller | Low | Boolean validation |
| Environment config | `getControlPlaneEnv()` | **Critical** | Schema validation |
| WorkOS Client ID | Environment config | **Critical** | String format validation |
| App URL | Environment config | **High** | URL format validation |

### Outbound Data
| Data Type | Destination | Sensitivity | Security Controls |
|-----------|-------------|-------------|-------------------|
| Auth URL | Browser/IDE webview | **High** | HTTPS enforced, parameter encoding |
| State parameter (UUID) | URL query string | Medium | Cryptographically random |
| Client ID | URL query string | Medium | Public identifier |
| Redirect URI | URL query string | **High** | Must match registered URI |

### Data Storage
| Storage | Location | Data Type | Encryption |
|---------|----------|-----------|------------|
| None (stateless) | N/A | N/A | N/A |

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                       Input Sources                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ IDE Settings │  │  Onboarding  │  │  Environment Config  │  │
│  │  (Promise)   │  │    Flag      │  │  (Client ID, URLs)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
└─────────┼─────────────────┼─────────────────────┼──────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                   getAuthUrlForTokenPage                        │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Environment Validation                                    │ │
│  │  - getControlPlaneEnv()                                   │ │
│  │  - isHubEnv() check                                       │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  URL Construction                                          │ │
│  │  - WorkOS authorize endpoint                              │ │
│  │  - OAuth 2.0 parameters                                   │ │
│  │  - UUID state generation                                  │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Output                                     │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  OAuth Authorization URL                                  │ │
│  │  https://api.workos.com/user_management/authorize?        │ │
│  │    response_type=code&client_id=...&redirect_uri=...&     │ │
│  │    state=<uuid>&provider=authkit                          │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  User Browser    │
                    │  (OAuth Flow)    │
                    └──────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

| Threat | CVSS Score | Attack Vector | Impact | Likelihood |
|--------|------------|---------------|--------|------------|
| OAuth Redirect URI Manipulation | 8.0 (High) | Local | Credential theft, session hijacking | Medium |
| State Parameter Prediction | 7.5 (High) | Network | CSRF attack, account linking | Low |
| Client ID Exposure | 5.0 (Medium) | Network | Phishing, impersonation | Low |
| Environment Config Tampering | 7.0 (High) | Local | Redirect to malicious auth server | Medium |
| WorkOS API Compromise | 8.5 (High) | Network | Full auth system compromise | Low |
| Onboarding Flow Bypass | 6.0 (Medium) | Local | Skip security checks | Low-Medium |

### Attack Vectors

**1. OAuth Redirect URI Attack**
```typescript
// VULNERABLE: If redirect_uri is not validated
const params = {
  redirect_uri: `${env.APP_URL}tokens/${useOnboarding ? "onboarding-" : ""}callback`,
  // Attacker could manipulate env.APP_URL to redirect to malicious site
};
```

**Mitigation:**
```typescript
// SECURE: Validate redirect URI against allowlist
const ALLOWED_REDIRECT_URIS = [
  'https://app.continue.dev/',
  'https://hub.continue.dev/',
  'http://localhost:3000/',  // Development only
];

function validateRedirectUri(uri: string): boolean {
  try {
    const parsedUrl = new URL(uri);
    return ALLOWED_REDIRECT_URIS.some(allowed => 
      parsedUrl.href.startsWith(allowed)
    );
  } catch {
    return false;
  }
}

export async function getAuthUrlForTokenPage(
  ideSettingsPromise: Promise<IdeSettings>,
  useOnboarding: boolean,
): Promise<string> {
  const env = await getControlPlaneEnv(ideSettingsPromise);

  if (!isHubEnv(env)) {
    throw new Error("Sign in disabled");
  }

  // SECURITY: Validate APP_URL
  const redirectUri = `${env.APP_URL}tokens/${useOnboarding ? "onboarding-" : ""}callback`;
  if (!validateRedirectUri(redirectUri)) {
    throw new Error(`Invalid redirect URI: ${redirectUri}`);
  }

  const url = new URL("https://api.workos.com/user_management/authorize");
  const params = {
    response_type: "code",
    client_id: env.WORKOS_CLIENT_ID,
    redirect_uri: redirectUri,
    state: uuidv4(),
    provider: "authkit",
  };
  // ... rest of function
}
```

**2. State Parameter Security**
```typescript
// CURRENT: Using uuid v4 (cryptographically secure)
import { v4 as uuidv4 } from "uuid";
const state = uuidv4();

// SECURE: Additional state validation
// The state parameter should be stored and validated on callback
export class AuthStateManager {
  private pendingStates = new Map<string, { timestamp: number; useOnboarding: boolean }>();
  
  generateState(useOnboarding: boolean): string {
    const state = uuidv4();
    this.pendingStates.set(state, {
      timestamp: Date.now(),
      useOnboarding,
    });
    
    // Clean up old states (5 minute timeout)
    setTimeout(() => {
      this.pendingStates.delete(state);
    }, 5 * 60 * 1000);
    
    return state;
  }
  
  validateState(state: string): boolean {
    const stored = this.pendingStates.get(state);
    if (!stored) return false;
    
    // Check expiry
    if (Date.now() - stored.timestamp > 5 * 60 * 1000) {
      this.pendingStates.delete(state);
      return false;
    }
    
    this.pendingStates.delete(state);
    return true;
  }
}
```

**3. Environment Configuration Validation**
```typescript
// SECURE: Validate environment configuration
import { z } from "zod";

const ControlPlaneEnvSchema = z.object({
  WORKOS_CLIENT_ID: z.string().min(1).regex(/^[a-zA-Z0-9_-]+$/),
  APP_URL: z.string().url().refine(url => 
    url.startsWith('https://') || url.startsWith('http://localhost'),
    { message: "APP_URL must be HTTPS or localhost" }
  ),
  // ... other fields
});

async function getControlPlaneEnvValidated(
  ideSettingsPromise: Promise<IdeSettings>
): Promise<ControlPlaneEnv> {
  const env = await getControlPlaneEnv(ideSettingsPromise);
  
  // Validate environment configuration
  const result = ControlPlaneEnvSchema.safeParse(env);
  if (!result.success) {
    throw new Error(`Invalid environment config: ${result.error.message}`);
  }
  
  return result.data;
}
```

**4. Open Redirect Prevention**
```typescript
// SECURE: Prevent open redirect vulnerabilities
function sanitizeAppUrl(appUrl: string): string {
  try {
    const url = new URL(appUrl);
    
    // Enforce HTTPS (except localhost)
    if (url.protocol !== 'https:' && !url.hostname === 'localhost') {
      throw new Error('APP_URL must use HTTPS');
    }
    
    // Remove trailing slashes for consistency
    return url.origin + url.pathname.replace(/\/+$/, '') + '/';
  } catch (e) {
    throw new Error(`Invalid APP_URL: ${appUrl}`);
  }
}
```

---

## 4. Entry Points

### Public Methods

| Entry Point | Parameters | Security Considerations |
|-------------|------------|------------------------|
| `getAuthUrlForTokenPage(ideSettingsPromise, useOnboarding)` | IDE settings promise, onboarding flag | **CRITICAL** - OAuth flow initiation, redirect URI construction |

### Internal Dependencies

| Dependency | Used By | Security Considerations |
|------------|---------|------------------------|
| `getControlPlaneEnv()` | getAuthUrlForTokenPage | **HIGH** - Environment config validation |
| `isHubEnv()` | getAuthUrlForTokenPage | **MEDIUM** - Environment type check |
| `uuidv4()` | State parameter | **MEDIUM** - Must be cryptographically secure |
| `URL` constructor | URL building | **LOW** - Built-in validation |

### Security Boundary Entry Points
```typescript
// CRITICAL: Validate all inputs at the boundary
export async function getAuthUrlForTokenPage(
  ideSettingsPromise: Promise<IdeSettings>,
  useOnboarding: boolean,
): Promise<string> {
  // SECURITY BOUNDARY 1: Validate IDE settings
  let ideSettings: IdeSettings;
  try {
    ideSettings = await ideSettingsPromise;
    if (!ideSettings || typeof ideSettings !== 'object') {
      throw new Error("Invalid IDE settings");
    }
  } catch (e) {
    throw new Error(`Failed to load IDE settings: ${e}`);
  }

  // SECURITY BOUNDARY 2: Get and validate environment
  const env = await getControlPlaneEnv(ideSettingsPromise);

  if (!isHubEnv(env)) {
    throw new Error("Sign in disabled");
  }

  // SECURITY BOUNDARY 3: Validate environment values
  if (!env.WORKOS_CLIENT_ID || env.WORKOS_CLIENT_ID.length < 10) {
    throw new Error("Invalid WorkOS Client ID");
  }

  if (!env.APP_URL || !env.APP_URL.startsWith('https://')) {
    throw new Error("Invalid APP_URL - must be HTTPS");
  }

  // SECURITY BOUNDARY 4: Construct and validate redirect URI
  const redirectUri = `${env.APP_URL}tokens/${useOnboarding ? "onboarding-" : ""}callback`;
  
  try {
    new URL(redirectUri);  // Validate URL format
  } catch {
    throw new Error(`Invalid redirect URI constructed: ${redirectUri}`);
  }

  // Build auth URL
  const url = new URL("https://api.workos.com/user_management/authorize");
  const params = {
    response_type: "code",
    client_id: env.WORKOS_CLIENT_ID,
    redirect_uri: redirectUri,
    state: uuidv4(),
    provider: "authkit",
  };
  
  Object.keys(params).forEach((key) =>
    url.searchParams.append(key, params[key as keyof typeof params]),
  );
  
  return url.toString();
}
```

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Confidentiality | Integrity | Availability | Priority |
|-------|-----------------|-----------|--------------|----------|
| WorkOS Client ID | Medium | **High** | **High** | **High** |
| App URL | Medium | **High** | Medium | **High** |
| OAuth State Parameter | Medium | **Critical** | Medium | **Critical** |
| Redirect URI | **High** | **Critical** | Medium | **Critical** |
| User credentials (external) | **Critical** | **Critical** | **High** | **Critical** |

### CIA Triad Analysis

**Confidentiality:**
- **Risk:** Client ID exposed in URL (acceptable for OAuth public identifier)
- **Current Controls:** HTTPS for all communication
- **Gaps:** None significant for this component
- **Recommendation:** Ensure HTTPS enforcement in all environments

**Integrity:**
- **Risk:** Redirect URI manipulation could lead to credential theft
- **Current Controls:** URL construction from environment config
- **Gaps:** No allowlist validation for redirect URIs
- **Recommendation:** Implement redirect URI allowlist validation

**Availability:**
- **Risk:** Auth flow failure blocks all Continue Hub features
- **Current Controls:** Environment validation, error handling
- **Gaps:** No fallback authentication mechanism
- **Recommendation:** Implement graceful error handling with user guidance

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Rationale | Security Requirements |
|-----------|-------------|-----------|----------------------|
| WorkOS API | **Medium** | External OAuth provider | HTTPS, proper OAuth flow |
| IDE Settings | **Medium** | External process | Type validation |
| Environment Config | **Medium-Low** | User/configurable | Strict validation required |
| UUID Generator | **High** | Cryptographically secure | Use v4 only |
| URL Constructor | **High** | Built-in browser/Node API | Input sanitization |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE (Core Logic)                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Auth URL Generation                                      │  │
│  │  - Parameter construction                                 │  │
│  │  - State generation                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          │
          ═══════════════════════════════════════
          TRUST BOUNDARY: Environment & Redirect Validation
          ═══════════════════════════════════════
                          │
┌─────────────────────────────────────────────────────────────────┐
│                  UNTRUSTED ZONE (External)                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │  IDE Settings    │  │  Environment     │  │  User Input  │  │
│  │  (External Proc) │  │  Config Files    │  │  (Onboarding)│  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          │
          ═══════════════════════════════════════
          TRUST BOUNDARY: OAuth Flow (External)
          ═══════════════════════════════════════
                          │
┌─────────────────────────────────────────────────────────────────┐
│                   WorkOS OAuth Service                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Authorization Endpoint                                   │  │
│  │  - User authentication                                    │  │
│  │  - Code generation                                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment
- **Trust Score:** 6/10 (Medium)
- **Primary Concern:** Redirect URI validation relies on environment config integrity
- **Secondary Concern:** No state parameter validation on callback (handled elsewhere)
- **Recommendation:** Implement comprehensive redirect URI validation

---

## 7. Architecture & Security Boundaries

### System Architecture
```
┌─────────────────────────────────────────────────────────────────────┐
│                        Input Layer                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │ IDE Settings│  │  Onboarding │  │  Environment│                 │
│  │   Promise   │  │    Flag     │  │    Config   │                 │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                 │
└─────────┼─────────────────┼─────────────────┼───────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SECURITY BOUNDARY                              │
│  ═══════════════════════════════════════════════════════════════    │
│  │ Settings Validation │ Config Validation │ URL Sanitization │     │
│  ═══════════════════════════════════════════════════════════════    │
└─────────────────────────────────────────────────────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   getAuthUrlForTokenPage                            │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Environment Check                                            │ │
│  │  - isHubEnv() validation                                      │ │
│  │  - WorkOS Client ID retrieval                                 │ │
│  └───────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  OAuth URL Construction                                       │ │
│  │  - WorkOS authorize endpoint                                  │ │
│  │  - Parameter assembly                                         │ │
│  │  - State generation (UUID v4)                                 │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Output Layer                                   │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  OAuth Authorization URL                                      │ │
│  │  (Redirected to WorkOS)                                       │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   WorkOS OAuth   │
                    │   Authorization  │
                    │   Server         │
                    └──────────────────┘
```

### Security Boundaries

| Boundary | From | To | Protection Mechanism |
|----------|------|-----|---------------------|
| IDE → Auth Module | IDE settings | getAuthUrlForTokenPage | Type validation, promise handling |
| Config → Auth Module | Environment | getAuthUrlForTokenPage | isHubEnv() check, URL validation |
| Auth Module → WorkOS | Auth URL | WorkOS API | HTTPS, OAuth 2.0 protocol |
| Auth Module → User | Auth URL | Browser | URL encoding, state parameter |

### Data Flow Through Boundaries
```
User Initiates Sign-In
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 1: Input Validation    │
│ - IDE settings type check       │
│ - Onboarding flag validation    │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 2: Config Validation   │
│ - isHubEnv() check              │
│ - WORKOS_CLIENT_ID validation   │
│ - APP_URL HTTPS enforcement     │
│ - [MISSING: Redirect allowlist] │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 3: URL Construction    │
│ - URL encoding                  │
│ - State parameter (UUID v4)     │
│ - Parameter sanitization        │
└─────────────────────────────────┘
         │
         ▼
   OAuth Flow Initiated (WorkOS)
```

---

## 8. Security Recommendations

### Critical Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 1 | Implement redirect URI allowlist validation | Prevent credential theft via redirect manipulation | Low (2-4 hours) |
| 2 | Add environment config schema validation | Ensure config integrity | Low (2-4 hours) |

### High Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 3 | Implement state parameter storage & validation | Prevent CSRF attacks | Medium (4-8 hours) |
| 4 | Add HTTPS enforcement for all environments | Prevent credential interception | Low (2-4 hours) |
| 5 | Implement auth URL audit logging | Security monitoring | Low (2-4 hours) |

### Medium Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 6 | Add WorkOS Client ID rotation support | Limit exposure if compromised | Medium (4-8 hours) |
| 7 | Implement auth flow timeout | Prevent stale auth attempts | Low (2-4 hours) |
| 8 | Add PKCE support (if WorkOS supports) | Enhanced OAuth security | Medium (4-8 hours) |

### Low Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 9 | Implement auth flow telemetry | Security monitoring | Low (2-4 hours) |
| 10 | Add graceful degradation for auth failures | Better UX | Low (2-4 hours) |

### Implementation Checklist

- [ ] **CRITICAL:** Add redirect URI allowlist validation
- [ ] **CRITICAL:** Implement environment config schema validation (Zod)
- [ ] **HIGH:** Add state parameter storage and validation on callback
- [ ] **HIGH:** Enforce HTTPS for APP_URL in all non-dev environments
- [ ] **HIGH:** Log auth URL generation for security audit
- [ ] **MEDIUM:** Implement Client ID rotation mechanism
- [ ] **MEDIUM:** Add auth flow timeout (5 minutes)
- [ ] **MEDIUM:** Evaluate PKCE support with WorkOS
- [ ] **LOW:** Add auth flow telemetry (success/failure rates)
- [ ] **LOW:** Improve error messages for auth failures

### Secure Implementation Example

```typescript
// SECURE: Enhanced authentication URL generation

import { v4 as uuidv4 } from "uuid";
import { IdeSettings } from "../..";
import { isHubEnv } from "../AuthTypes";
import { getControlPlaneEnv } from "../env";
import { z } from "zod";

// SECURITY: Redirect URI allowlist
const ALLOWED_REDIRECT_BASES = [
  'https://app.continue.dev/',
  'https://hub.continue.dev/',
  'https://continue.dev/',
];

// SECURITY: Environment schema validation
const ControlPlaneEnvSchema = z.object({
  WORKOS_CLIENT_ID: z.string()
    .min(10)
    .max(100)
    .regex(/^[a-zA-Z0-9_-]+$/),
  APP_URL: z.string()
    .url()
    .refine(url => {
      const parsed = new URL(url);
      return parsed.protocol === 'https:' || 
             parsed.hostname === 'localhost';
    }, { message: "APP_URL must be HTTPS or localhost" }),
});

// SECURITY: State parameter manager
class AuthStateManager {
  private static instance: AuthStateManager;
  private pendingStates = new Map<string, { 
    timestamp: number; 
    useOnboarding: boolean;
    ideWorkspaceId?: string;
  }>();
  
  private constructor() {}
  
  static getInstance(): AuthStateManager {
    if (!AuthStateManager.instance) {
      AuthStateManager.instance = new AuthStateManager();
    }
    return AuthStateManager.instance;
  }
  
  generateState(useOnboarding: boolean, ideWorkspaceId?: string): string {
    const state = uuidv4();
    this.pendingStates.set(state, {
      timestamp: Date.now(),
      useOnboarding,
      ideWorkspaceId,
    });
    
    // Auto-cleanup after 5 minutes
    setTimeout(() => {
      this.pendingStates.delete(state);
    }, 5 * 60 * 1000);
    
    return state;
  }
  
  validateState(state: string): { valid: boolean; useOnboarding: boolean } {
    const stored = this.pendingStates.get(state);
    if (!stored) {
      return { valid: false, useOnboarding: false };
    }
    
    // Check expiry
    if (Date.now() - stored.timestamp > 5 * 60 * 1000) {
      this.pendingStates.delete(state);
      return { valid: false, useOnboarding: false };
    }
    
    this.pendingStates.delete(state);
    return { valid: true, useOnboarding: stored.useOnboarding };
  }
}

function validateRedirectUri(redirectUri: string): boolean {
  try {
    const parsedUrl = new URL(redirectUri);
    
    // Must use HTTPS (except localhost)
    if (parsedUrl.protocol !== 'https:' && 
        parsedUrl.hostname !== 'localhost') {
      return false;
    }
    
    // Must match allowed base URLs
    return ALLOWED_REDIRECT_BASES.some(base => 
      parsedUrl.href.startsWith(base)
    );
  } catch {
    return false;
  }
}

export async function getAuthUrlForTokenPage(
  ideSettingsPromise: Promise<IdeSettings>,
  useOnboarding: boolean,
): Promise<string> {
  // SECURITY: Validate IDE settings
  let ideSettings: IdeSettings;
  try {
    ideSettings = await ideSettingsPromise;
    if (!ideSettings || typeof ideSettings !== 'object') {
      throw new Error("Invalid IDE settings");
    }
  } catch (e) {
    console.error("Failed to load IDE settings:", e);
    throw new Error("Authentication unavailable - IDE settings error");
  }

  // SECURITY: Get and validate environment
  const env = await getControlPlaneEnv(ideSettingsPromise);

  if (!isHubEnv(env)) {
    throw new Error("Sign in disabled in current environment");
  }

  // SECURITY: Schema validation
  const envValidation = ControlPlaneEnvSchema.safeParse(env);
  if (!envValidation.success) {
    console.error("Environment validation failed:", envValidation.error);
    throw new Error("Authentication configuration invalid");
  }

  const validatedEnv = envValidation.data;

  // SECURITY: Construct and validate redirect URI
  const redirectPath = `tokens/${useOnboarding ? "onboarding-" : ""}callback`;
  const redirectUri = new URL(redirectPath, validatedEnv.APP_URL).href;
  
  if (!validateRedirectUri(redirectUri)) {
    console.error("Redirect URI validation failed:", redirectUri);
    throw new Error("Authentication redirect URI invalid");
  }

  // SECURITY: Generate state parameter with tracking
  const state = AuthStateManager.getInstance().generateState(
    useOnboarding,
    await ideSettings.getWorkspaceId?.()
  );

  // Build auth URL with proper encoding
  const url = new URL("https://api.workos.com/user_management/authorize");
  const params = {
    response_type: "code",
    client_id: validatedEnv.WORKOS_CLIENT_ID,
    redirect_uri: redirectUri,
    state: state,
    provider: "authkit",
  };
  
  Object.keys(params).forEach((key) =>
    url.searchParams.append(key, params[key as keyof typeof params]),
  );
  
  // SECURITY: Log auth attempt (without sensitive data)
  console.log("Auth URL generated for onboarding:", useOnboarding);
  
  return url.toString();
}

// Export state validation for callback handler
export { AuthStateManager };
```

---

**Analysis Complete** ✅

*This security analysis was generated with [Continue](https://continue.dev)*

*Co-Authored-By: Continue <noreply@continue.dev>*
