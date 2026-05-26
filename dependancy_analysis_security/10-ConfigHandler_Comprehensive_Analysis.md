# 🔒 Comprehensive Security Analysis: ConfigHandler [Configuration Management]

**Package:** `core/config/ConfigHandler.ts`  
**Used In:** `/core/config/ConfigHandler.ts` (configuration loading, org/profile management)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟠 **HIGH**

---

## 1. Dependency Purpose & Usage

### Primary Function
ConfigHandler manages the entire configuration lifecycle for Continue, including organization selection, profile management, config loading/reloading, and coordination between local and cloud-based configurations. It serves as the central configuration orchestrator.

### Implementation
```typescript
export class ConfigHandler {
  controlPlaneClient: ControlPlaneClient;
  private readonly globalContext = new GlobalContext();
  private globalLocalProfileManager: ProfileLifecycleManager;

  private organizations: OrgWithProfiles[] = [];
  currentProfile: ProfileLifecycleManager | null;
  currentOrg: OrgWithProfiles | null;
  totalConfigReloads: number = 0;

  constructor(
    private readonly ide: IDE,
    private llmLogger: ILLMLogger,
    initialSessionInfoPromise: Promise<ControlPlaneSessionInfo | undefined>,
  ) {
    this.controlPlaneClient = new ControlPlaneClient(
      initialSessionInfoPromise,
      this.ide,
    );
    this.globalLocalProfileManager = new ProfileLifecycleManager(
      new LocalProfileLoader(this.ide, this.controlPlaneClient, this.llmLogger),
      this.ide,
    );
  }

  async loadConfig(): Promise<ConfigResult<ContinueConfig>> {
    await this.isInitialized;
    if (!this.currentProfile) {
      return { config: undefined, errors: undefined, configLoadInterrupted: true };
    }
    const config = await this.currentProfile.loadConfig(
      this.additionalContextProviders
    );
    return config;
  }

  async reloadConfig(reason: string, injectErrors?: ConfigValidationError[]) {
    const startTime = performance.now();
    this.totalConfigReloads += 1;
    
    const { config, errors = [], configLoadInterrupted } = 
      await this.currentProfile.reloadConfig(this.additionalContextProviders);
    
    this.notifyConfigListeners({ config, errors, configLoadInterrupted });
    // ... telemetry tracking
  }
}
```

### Dependency Type
- **Internal Core Module** - Central configuration management system
- **Coordinates:** ControlPlaneClient, ProfileLifecycleManager, LocalProfileLoader, PlatformProfileLoader
- **External:** Continue Hub API, Control Plane API
- **Storage:** GlobalContext (persistent settings), config YAML files

---

## 2. Data Flow Analysis

### Inbound Data
| Data Type | Source | Sensitivity | Validation |
|-----------|--------|-------------|------------|
| IDE settings | IDE.getIdeSettings() | Medium | IDE validation |
| Session info | ControlPlaneClient | **High** | Auth token validation |
| Organization list | Control Plane API | Medium | API response validation |
| Profile configs | Local FS / Hub API | **Critical** | YAML schema validation |
| User selections | GlobalContext | Medium | Key/value validation |
| Config YAML files | .continue/ directory | **Critical** | Schema validation via config-yaml |

### Outbound Data
| Data Type | Destination | Sensitivity | Security Controls |
|-----------|-------------|-------------|-------------------|
| Serialized config | GUI/Browser | **High** | Sanitization via getSerializedConfig |
| Config updates | Update listeners | **High** | Internal event system |
| Telemetry data | PostHog | Medium | Anonymized metrics |
| Org/Profile selections | GlobalContext | Medium | File system permissions |
| Policy data | PolicySingleton | **High** | In-memory only |

### Data Storage
| Storage | Location | Data Type | Encryption |
|---------|----------|-----------|------------|
| GlobalContext | Local file system | User preferences, selections | No (file system only) |
| Config YAML | `.continue/config.yaml` | Full configuration | No (file system only) |
| Session tokens | Memory/Secure storage | Auth tokens | Platform-dependent |
| Org/Profile cache | Memory | Organization/profile metadata | N/A |

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                      External Sources                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  IDE Settings│  │  Hub API     │  │  Local Config Files  │  │
│  │              │  │  (Orgs/Prof) │  │  (.continue/*.yaml)  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
└─────────┼─────────────────┼─────────────────────┼──────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ConfigHandler                              │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Authentication Layer                                      │ │
│  │  - ControlPlaneClient                                     │ │
│  │  - Session management                                     │ │
│  │  - Policy fetching                                        │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Organization & Profile Management                        │ │
│  │  - getOrgs()                                              │ │
│  │  - getHubProfiles()                                       │ │
│  │  - getLocalProfiles()                                     │ │
│  │  - rectifyProfilesForOrg()                                │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Configuration Loading                                    │ │
│  │  - reloadConfig()                                         │ │
│  │  - loadConfig()                                           │ │
│  │  - ProfileLifecycleManager coordination                   │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  State Persistence                                        │ │
│  │  - GlobalContext (selections)                             │ │
│  │  - Update listeners                                       │ │
│  │  - Telemetry                                              │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌──────────────────┐ ┌──────────────────┐ ┌─────────────────────┐
│   GlobalContext  │ │  Config Listeners│ │  Telemetry (PostHog)│
│   (Local FS)     │ │  (Internal)      │ │                     │
└──────────────────┘ └──────────────────┘ └─────────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

| Threat | CVSS Score | Attack Vector | Impact | Likelihood |
|--------|------------|---------------|--------|------------|
| Malicious Config Injection | 8.5 (High) | Local | Code execution, credential theft | Medium |
| Control Plane API Compromise | 7.5 (High) | Network | Malicious config distribution | Low-Medium |
| Session Token Theft | 7.0 (High) | Local | Account takeover, data access | Medium |
| YAML Deserialization Attack | 6.5 (Medium) | Local | Remote code execution | Medium |
| Configuration Tampering | 6.0 (Medium) | Local | Behavior modification | Medium |
| Policy Bypass | 5.5 (Medium) | Local | Security control circumvention | Low |

### Attack Vectors

**1. Malicious Config Injection**
```typescript
// VULNERABLE: Config loaded without sufficient validation
const { config, errors = [], configLoadInterrupted } = 
  await this.currentProfile.reloadConfig(this.additionalContextProviders);

// Attacker could inject malicious MCP servers, context providers, or LLM configs
```

**Mitigation:**
```typescript
// SECURE: Validate config against strict schema before use
import { validateConfigSecurity } from "../util/configSecurity";

async reloadConfig(reason: string, injectErrors?: ConfigValidationError[]) {
  const result = await this.currentProfile.reloadConfig(
    this.additionalContextProviders
  );
  
  // SECURITY: Validate loaded config
  const securityValidation = validateConfigSecurity(result.config);
  if (!securityValidation.valid) {
    Logger.error(`Config security validation failed: ${securityValidation.errors}`);
    return {
      ...result,
      errors: [...(result.errors || []), ...securityValidation.errors],
      configLoadInterrupted: true,
    };
  }
  
  this.notifyConfigListeners(result);
  return result;
}
```

**2. Control Plane API Response Validation**
```typescript
// SECURE: Validate API responses before trusting
private async getOrgs(): Promise<{ orgs: OrgWithProfiles[]; errors?: ConfigValidationError[] }> {
  const isSignedIn = await this.controlPlaneClient.isSignedIn();
  if (isSignedIn) {
    try {
      const policyResponse = await this.controlPlaneClient.getPolicy();
      
      // SECURITY: Validate policy response
      if (!this.validatePolicyResponse(policyResponse)) {
        throw new Error("Invalid policy response from control plane");
      }
      
      PolicySingleton.getInstance().policy = policyResponse;
      
      const orgDescriptions = await this.controlPlaneClient.listOrganizations();
      
      // SECURITY: Validate org list
      const validatedOrgs = orgDescriptions.filter(org => 
        this.validateOrganization(org)
      );
      
      // ... rest of processing
    } catch (e) {
      // Error handling
    }
  }
}

private validatePolicyResponse(policy: any): boolean {
  // Validate policy structure and values
  return policy && 
         typeof policy.allowOtherOrgs === 'boolean' &&
         !policy.__proto__ &&  // Prevent prototype pollution
         Object.keys(policy).length < 50;  // Reasonable size limit
}
```

**3. YAML Schema Validation**
```typescript
// SECURE: Strict YAML parsing with schema validation
import { loadYamlWithValidation } from "../util/yamlSecurity";

async getLocalProfiles(options: LoadAssistantFilesOptions) {
  const allFiles = await getAllDotContinueDefinitionFiles(...);
  
  const profiles = allFiles.map((assistant) => {
    try {
      // SECURITY: Safe YAML parsing with validation
      const config = loadYamlWithValidation(assistant.content, {
        maxDepth: 10,
        maxAliases: 100,
        allowedKeys: ALLOWED_CONFIG_KEYS,
        blockedPatterns: DANGEROUS_CONFIG_PATTERNS,
      });
      
      return new LocalProfileLoader(..., config);
    } catch (e) {
      Logger.error(`Invalid config file ${assistant.path}: ${e.message}`);
      return null;
    }
  }).filter(Boolean);
  
  // ... rest of processing
}
```

**4. Session Security**
```typescript
// SECURE: Enhanced session validation
async updateControlPlaneSessionInfo(
  sessionInfo: ControlPlaneSessionInfo | undefined,
) {
  // SECURITY: Validate session structure
  if (sessionInfo) {
    if (!this.validateSessionInfo(sessionInfo)) {
      Logger.error("Invalid session info detected");
      return false;
    }
    
    // SECURITY: Check session expiry
    if (sessionInfo.expiresAt && Date.now() > sessionInfo.expiresAt) {
      Logger.warn("Session expired, clearing");
      sessionInfo = undefined;
    }
  }
  
  // ... rest of session update logic
}

private validateSessionInfo(session: ControlPlaneSessionInfo): boolean {
  return session &&
         typeof session.account?.id === 'string' &&
         session.account.id.length > 0 &&
         session.account.id.length < 256 &&
         typeof session.AUTH_TYPE === 'string' &&
         ['oauth', 'onprem', 'api_key'].includes(session.AUTH_TYPE);
}
```

---

## 4. Entry Points

### Public Methods

| Entry Point | Parameters | Security Considerations |
|-------------|------------|------------------------|
| `loadConfig()` | None | **HIGH** - Returns full config with credentials |
| `reloadConfig(reason, injectErrors)` | Reason string, errors | **HIGH** - Triggers config reload |
| `setSelectedOrgId(orgId, profileId)` | Org ID, Profile ID | **HIGH** - Changes active org |
| `setSelectedProfileId(profileId)` | Profile ID | **HIGH** - Changes active profile |
| `updateControlPlaneSessionInfo(sessionInfo)` | Session info | **CRITICAL** - Auth state change |
| `refreshAll(reason)` | Reason string | **MEDIUM** - Full refresh trigger |
| `getSerializedConfig()` | None | **HIGH** - Config for GUI |
| `registerCustomContextProvider(provider)` | Provider | **HIGH** - Adds context provider |

### Internal Entry Points

| Entry Point | Called By | Security Considerations |
|-------------|-----------|------------------------|
| `cascadeInit(reason, isLogin)` | Constructor, updates | **HIGH** - Full initialization |
| `getOrgs()` | cascadeInit | **HIGH** - API calls, file loading |
| `getHubProfiles(orgScopeId)` | getNonPersonalHubOrg | **HIGH** - Hub config loading |
| `getLocalProfiles(options)` | getLocalOrg, getPersonalHubOrg | **HIGH** - Local file parsing |
| `rectifyProfilesForOrg(org, profiles)` | getHubOrg, getPersonalOrg | **MEDIUM** - Profile selection |
| `notifyConfigListeners(result)` | reloadConfig | **MEDIUM** - Event propagation |

### Security Boundary Entry Points
```typescript
// CRITICAL: Validate all external inputs
async updateControlPlaneSessionInfo(
  sessionInfo: ControlPlaneSessionInfo | undefined,
) {
  // SECURITY BOUNDARY 1: Validate session info structure
  if (sessionInfo && !this.validateSessionInfo(sessionInfo)) {
    Logger.error("Invalid session info - rejecting");
    return false;
  }
  
  // SECURITY BOUNDARY 2: Check for session hijacking
  const currentSession = await this.controlPlaneClient.sessionInfoPromise;
  if (currentSession && sessionInfo) {
    if (currentSession.account.id !== sessionInfo.account.id) {
      Logger.warn(`Account switch detected: ${currentSession.account.id} -> ${sessionInfo.account.id}`);
      // Could add additional verification here
    }
  }
  
  // ... proceed with update
}

async setSelectedOrgId(orgId: string, profileId?: string) {
  // SECURITY BOUNDARY: Validate org exists in loaded list
  const org = this.organizations.find((org) => org.id === orgId);
  if (!org) {
    Logger.error(`Attempted to select non-existent org: ${orgId}`);
    throw new Error(`Org ${orgId} not found`);
  }
  
  // ... proceed with selection
}
```

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Confidentiality | Integrity | Availability | Priority |
|-------|-----------------|-----------|--------------|----------|
| LLM API keys (in config) | **Critical** | **High** | Medium | **Critical** |
| Control plane tokens | **Critical** | **High** | Medium | **Critical** |
| Full configuration | **High** | **High** | **High** | **Critical** |
| Organization metadata | Medium | Medium | Medium | Medium |
| Profile selections | Low | Medium | Medium | Low |
| Policy data | Medium | **High** | Medium | High |

### CIA Triad Analysis

**Confidentiality:**
- **Risk:** Config contains API keys, tokens, and sensitive settings
- **Current Controls:** File system permissions, in-memory storage
- **Gaps:** No encryption at rest, config serialized to GUI
- **Recommendation:** Encrypt sensitive config values, minimize GUI exposure

**Integrity:**
- **Risk:** Malicious config modification could redirect API calls, add malicious MCP servers
- **Current Controls:** YAML schema validation via @continuedev/config-yaml
- **Gaps:** No config signing, no integrity verification
- **Recommendation:** Add config integrity checks, signature verification for Hub configs

**Availability:**
- **Risk:** Config loading failures block all functionality
- **Current Controls:** Error handling, fallback to local config, cascade reload
- **Gaps:** Single point of failure in config loading
- **Recommendation:** Implement config caching, graceful degradation

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Rationale | Security Requirements |
|-----------|-------------|-----------|----------------------|
| Control Plane API | **Medium** | External service, auth critical | HTTPS, token validation |
| Hub API (configs) | **Medium-Low** | External config source | Schema validation, signing |
| Local config files | **Low-Medium** | User-editable, tamperable | Strict validation |
| IDE interface | **Medium** | External process | Input validation |
| GlobalContext | **Medium** | Local storage | File permissions |
| ProfileLifecycleManager | **Medium** | Config loading | Validation passthrough |
| PolicySingleton | **Medium** | Security policy enforcement | Integrity protection |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE (Core Logic)                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  ConfigHandler Management                                 │  │
│  │  - Org/Profile selection                                  │  │
│  │  - Listener notification                                  │  │
│  │  - State persistence                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          │
          ═══════════════════════════════════════
          TRUST BOUNDARY 1: External APIs
          ═══════════════════════════════════════
                          │
┌─────────────────────────────────────────────────────────────────┐
│                  UNTRUSTED ZONE (External)                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │  Control Plane   │  │  Hub API         │  │  Local Files │  │
│  │  (Auth/Policy)   │  │  (Configs)       │  │  (YAML)      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment
- **Trust Score:** 5/10 (Medium-Low)
- **Primary Concern:** Config files can contain executable code (MCP servers, custom providers)
- **Secondary Concern:** No integrity verification for Hub configs
- **Recommendation:** Implement config signing, sandbox dangerous features

---

## 7. Architecture & Security Boundaries

### System Architecture
```
┌─────────────────────────────────────────────────────────────────────┐
│                       External Sources                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │  IDE        │  │  Control    │  │  Hub API    │  │  Local FS  │ │
│  │  Settings   │  │  Plane      │  │  (Orgs/    │  │  (.continue)│ │
│  │             │  │  (Auth)     │  │   Profiles) │  │             │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │
└─────────┼─────────────────┼─────────────────┼──────────────┼────────┘
          │                 │                 │              │
          ▼                 ▼                 ▼              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        SECURITY BOUNDARY                            │
│  ═══════════════════════════════════════════════════════════════    │
│  │ Session Validation │ Config Schema Check │ Integrity Verify │    │
│  ═══════════════════════════════════════════════════════════════    │
└─────────────────────────────────────────────────────────────────────┘
          │                 │                 │              │
          ▼                 ▼                 ▼              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         ConfigHandler                               │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Authentication & Session Management                          │ │
│  │  - ControlPlaneClient                                         │ │
│  │  - Session validation                                         │ │
│  │  - Policy enforcement                                         │ │
│  └───────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Organization Management                                      │ │
│  │  - getOrgs() (local + hub)                                    │ │
│  │  - Org selection & persistence                                │ │
│  │  - Policy application                                         │ │
│  └───────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Profile Management                                           │ │
│  │  - Profile loading (local/hub)                                │ │
│  │  - Profile selection                                          │ │
│  │  - Config caching                                             │ │
│  └───────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Configuration Loading                                        │ │
│  │  - reloadConfig()                                             │ │
│  │  - Schema validation                                          │ │
│  │  - Listener notification                                      │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
          │                         │                         │
          ▼                         ▼                         ▼
┌──────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   GlobalContext  │    │  Config Listeners│    │  Telemetry Service  │
│   (Selections)   │    │  (Internal)      │    │  (PostHog)          │
└──────────────────┘    └──────────────────┘    └─────────────────────┘
```

### Security Boundaries

| Boundary | From | To | Protection Mechanism |
|----------|------|-----|---------------------|
| IDE → ConfigHandler | IDE settings | ConfigHandler | IDE validation |
| Control Plane → ConfigHandler | API response | ConfigHandler | Token auth, response validation |
| Hub API → ConfigHandler | Config YAML | ConfigHandler | Schema validation |
| Local FS → ConfigHandler | Config files | ConfigHandler | YAML schema validation |
| ConfigHandler → Listeners | Config result | Internal components | Event system |

### Data Flow Through Boundaries
```
User Action / System Event
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 1: Auth Validation     │
│ - Session info validation       │
│ - Token verification            │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 2: Config Validation   │
│ - YAML schema check             │
│ - Security policy check         │
│ - [MISSING: Integrity verify]   │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 3: Listener Notification│
│ - Config distribution           │
│ - Error propagation             │
└─────────────────────────────────┘
         │
         ▼
   Config Applied System-wide
```

---

## 8. Security Recommendations

### Critical Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 1 | Implement config integrity verification | Detect tampered config files | Medium (4-8 hours) |
| 2 | Add sensitive value encryption | Protect API keys at rest | High (1-2 days) |

### High Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 3 | Validate Hub config signatures | Ensure config authenticity | High (1-2 days) |
| 4 | Add config security scanning | Detect malicious MCP servers, providers | Medium (4-8 hours) |
| 5 | Implement session validation hardening | Prevent session hijacking | Low (2-4 hours) |

### Medium Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 6 | Add config loading sandbox | Isolate dangerous config operations | High (2-3 days) |
| 7 | Implement config version pinning | Prevent unexpected config changes | Medium (4-8 hours) |
| 8 | Add audit logging for config changes | Security monitoring | Low (2-4 hours) |

### Low Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 9 | Implement config rollback | Recover from bad configs | Medium (4-8 hours) |
| 10 | Add per-config permissions | Granular access control | High (1-2 days) |

### Implementation Checklist

- [ ] **CRITICAL:** Add config integrity checksums for local configs
- [ ] **CRITICAL:** Encrypt sensitive config values (API keys, tokens)
- [ ] **HIGH:** Implement signature verification for Hub configs
- [ ] **HIGH:** Add security scanning for MCP server configs
- [ ] **HIGH:** Harden session validation (expiry, account switching)
- [ ] **MEDIUM:** Implement sandboxed config loading
- [ ] **MEDIUM:** Add config version pinning support
- [ ] **MEDIUM:** Log config changes for security audit
- [ ] **LOW:** Implement config rollback mechanism
- [ ] **LOW:** Add per-config access permissions

### Secure Implementation Example

```typescript
// SECURE: ConfigHandler with enhanced security controls

import { validateConfigSecurity } from "../util/configSecurity";
import { encryptSensitiveValues, decryptSensitiveValues } from "../util/configEncryption";
import { verifyConfigSignature } from "../util/configSigning";

export class ConfigHandler {
  async reloadConfig(reason: string, injectErrors?: ConfigValidationError[]) {
    const startTime = performance.now();
    this.totalConfigReloads += 1;
    
    if (!this.currentProfile) {
      const out = { config: undefined, errors: injectErrors, configLoadInterrupted: true };
      this.notifyConfigListeners(out);
      return out;
    }

    const result = await this.currentProfile.reloadConfig(this.additionalContextProviders);
    
    // SECURITY: Validate config integrity and safety
    if (result.config) {
      // Check for Hub config signature
      if (result.config.source === 'hub') {
        const signatureValid = await verifyConfigSignature(result.config);
        if (!signatureValid) {
          Logger.error("Hub config signature verification failed");
          result.errors = [...(result.errors || []), {
            fatal: true,
            message: "Config signature invalid - config may be tampered",
          }];
          result.configLoadInterrupted = true;
          this.notifyConfigListeners(result);
          return result;
        }
      }
      
      // Security scan for dangerous configurations
      const securityValidation = validateConfigSecurity(result.config);
      if (!securityValidation.valid) {
        Logger.error(`Config security validation failed: ${securityValidation.errors}`);
        result.errors = [...(result.errors || []), ...securityValidation.errors];
        result.configLoadInterrupted = true;
        this.notifyConfigListeners(result);
        return result;
      }
      
      // Decrypt sensitive values for use
      result.config = decryptSensitiveValues(result.config);
    }
    
    if (injectErrors) {
      result.errors = [...(result.errors || []), ...injectErrors];
    }

    this.notifyConfigListeners(result);
    this.initter.emit("init");
    
    // Telemetry (without sensitive data)
    const telemetryData = {
      duration: performance.now() - startTime,
      reason,
      configLoadInterrupted: result.configLoadInterrupted,
      errorCount: result.errors?.length || 0,
    };
    void Telemetry.capture("config_reload", telemetryData);
    
    return result;
  }
  
  async getSerializedConfig(): Promise<ConfigResult<BrowserSerializedContinueConfig>> {
    await this.isInitialized;
    if (!this.currentProfile) {
      return { config: undefined, errors: undefined, configLoadInterrupted: true };
    }
    
    const result = await this.currentProfile.getSerializedConfig(
      this.additionalContextProviders
    );
    
    // SECURITY: Remove sensitive values before serialization
    if (result.config) {
      result.config = this.sanitizeConfigForSerialization(result.config);
    }
    
    return result;
  }
  
  private sanitizeConfigForSerialization(config: BrowserSerializedContinueConfig) {
    // Remove or mask sensitive values
    const sanitized = { ...config };
    
    if (sanitized.models) {
      sanitized.models = sanitized.models.map(model => ({
        ...model,
        apiKey: model.apiKey ? '***REDACTED***' : undefined,
        apiSecret: model.apiSecret ? '***REDACTED***' : undefined,
      }));
    }
    
    return sanitized;
  }
}

// configSecurity.ts
export function validateConfigSecurity(config: ContinueConfig): { valid: boolean; errors: ConfigValidationError[] } {
  const errors: ConfigValidationError[] = [];
  
  // Check for dangerous MCP servers
  if (config.mcpServers) {
    for (const [name, server] of Object.entries(config.mcpServers)) {
      if (server.command && isDangerousCommand(server.command)) {
        errors.push({
          fatal: true,
          message: `MCP server "${name}" uses dangerous command: ${server.command}`,
        });
      }
      if (server.url && !isValidMcpUrl(server.url)) {
        errors.push({
          fatal: true,
          message: `MCP server "${name}" has invalid or unsafe URL: ${server.url}`,
        });
      }
    }
  }
  
  // Check for dangerous context providers
  if (config.contextProviders) {
    for (const provider of config.contextProviders) {
      if (isBlockedProvider(provider.name)) {
        errors.push({
          fatal: true,
          message: `Blocked context provider: ${provider.name}`,
        });
      }
    }
  }
  
  // Check for dangerous LLM configurations
  if (config.models) {
    for (const model of config.models) {
      if (model.apiBase && !isValidApiBase(model.apiBase)) {
        errors.push({
          fatal: false,
          message: `Model "${model.model}" has suspicious API base: ${model.apiBase}`,
        });
      }
    }
  }
  
  return { valid: errors.length === 0, errors };
}

function isDangerousCommand(command: string): boolean {
  const dangerousPatterns = [
    /rm\s+-rf\s+\//,
    /chmod\s+-R\s+777/,
    /curl.*\|.*(?:bash|sh)/,
    /wget.*\|.*(?:bash|sh)/,
    /eval\s*\(/,
    /exec\s*\(/,
  ];
  return dangerousPatterns.some(pattern => pattern.test(command));
}
```

---

**Analysis Complete** ✅

*This security analysis was generated with [Continue](https://continue.dev)*

*Co-Authored-By: Continue <noreply@continue.dev>*
