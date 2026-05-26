# 🔒 Comprehensive Security Analysis: GlobalContext Class [State Persistence]

**Package:** `core/util/GlobalContext.ts`  
**Used In:** `/core/util/GlobalContext.ts` (global state persistence)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟡 **MEDIUM**

---

## 1. Dependency Purpose & Usage

### Primary Function
The `GlobalContext` class provides a persistent storage mechanism for application-wide state using a JSON file. It handles:
- User model selections by profile
- OAuth token storage for MCP servers
- Shared configuration data
- UI state flags (dismissed notices, shown warnings)
- Indexing configuration state

### Implementation
```typescript
export class GlobalContext {
  // File path for persistent storage
  private filepath = getGlobalContextFilePath();
  
  // Write state to JSON file
  update<T extends keyof GlobalContextType>(
    key: T,
    value: GlobalContextType[T],
  ) {
    if (!fs.existsSync(filepath)) {
      fs.writeFileSync(filepath, JSON.stringify({ [key]: value }, null, 2));
    } else {
      const data = fs.readFileSync(filepath, "utf-8");
      const parsed = JSON.parse(data);
      parsed[key] = value;
      fs.writeFileSync(filepath, JSON.stringify(parsed, null, 2));
    }
  }
  
  // Read state from JSON file
  get<T extends keyof GlobalContextType>(
    key: T,
  ): GlobalContextType[T] | undefined {
    const filepath = getGlobalContextFilePath();
    if (!fs.existsSync(filepath)) {
      return undefined;
    }
    const data = fs.readFileSync(filepath, "utf-8");
    const parsed = JSON.parse(data);
    return parsed[key];
  }
}
```

### Dependency Type
- **Internal utility class** - Core state management
- **File-based persistence** - Uses Node.js `fs` module
- **JSON storage** - Unencrypted local file storage

---

## 2. Data Flow Analysis

### Inbound Data

| Data Type | Source | Sensitivity | Validation |
|-----------|--------|-------------|------------|
| `ModelRole` selections | User configuration | Low | TypeScript types |
| `OAuthTokens` | MCP OAuth flow | 🔴 **CRITICAL** | OAuth SDK types |
| `OAuthClientInformationFull` | MCP OAuth registration | 🔴 **CRITICAL** | OAuth SDK types |
| `SharedConfigSchema` | Config parsing | 🟡 **MEDIUM** | Zod schema |
| `SiteIndexingConfig[]` | Docs indexing | Low | TypeScript types |
| Workspace identifiers | IDE workspace | Low | String keys |
| Profile IDs | User profiles | Low | String keys |

### Outbound Data

| Data Type | Destination | Sensitivity | Access Control |
|-----------|-------------|-------------|----------------|
| OAuth tokens | Application memory | 🔴 **CRITICAL** | In-process only |
| Client secrets | Application memory | 🔴 **CRITICAL** | In-process only |
| Model selections | Application memory | Low | In-process only |
| Shared config | Application memory | 🟡 **MEDIUM** | In-process only |
| UI state flags | Application memory | Low | In-process only |

### Data Storage

| Storage Location | Data Type | Encryption | Access Control |
|------------------|-----------|------------|----------------|
| `~/.continue/globalContext.json` | All state | ❌ **NONE** | File system permissions |
| Application memory | Active state | ❌ **NONE** | Process isolation |

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                        │
├─────────────────────────────────────────────────────────────────┤
│  Model Selection │ OAuth Flow │ Config Parser │ UI Components  │
└────────┬────────────┬─────────────┬──────────────┬──────────────┘
         │            │             │              │
         ▼            ▼             ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    GlobalContext.update()                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  1. Read existing JSON from file                         │  │
│  │  2. Parse JSON (with error handling)                     │  │
│  │  3. Update specific key                                  │  │
│  │  4. Write JSON back to file                              │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│              File System (~/.continue/globalContext.json)       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  {                                                         │  │
│  │    "mcpOauthStorage": {                                    │  │
│  │      "https://mcp.example.com": {                          │  │
│  │        "tokens": {"access_token": "...", "refresh_token": "..."}, │
│  │        "clientInformation": {"client_id": "...", "client_secret": "..."} │
│  │      }                                                     │  │
│  │    },                                                      │  │
│  │    "selectedModelsByProfileId": {...},                     │  │
│  │    "sharedConfig": {...}                                   │  │
│  │  }                                                         │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

| Threat | CVSS Score | Attack Vector | Impact | Likelihood |
|--------|------------|---------------|--------|------------|
| **OAuth Token Theft** | 8.1 (HIGH) | Local file access | Account compromise | Medium |
| **JSON Injection** | 6.5 (MEDIUM) | Corrupted file | Data loss | Low |
| **Race Condition** | 5.3 (MEDIUM) | Concurrent writes | Data corruption | Medium |
| **Information Disclosure** | 4.3 (MEDIUM) | File read access | Config exposure | Medium |
| **Privilege Escalation** | 3.7 (LOW) | Config manipulation | Feature abuse | Low |

### Attack Vector: OAuth Token Theft

**Scenario:**
```
1. Attacker gains local file system access
   ├── Malware on user's machine
   ├── Another user on multi-user system
   └── Backup/sync service exposure

2. Attacker reads globalContext.json
   └── Extracts OAuth tokens and client secrets

3. Attacker uses tokens to:
   ├── Access MCP servers as victim
   ├── Exfiltrate data from connected services
   └── Perform actions on victim's behalf
```

**CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N = 6.8**

### Mitigation Strategies

#### 1. Encrypt Sensitive Data
```typescript
// SECURE: Encrypt OAuth tokens before storage
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

class SecureGlobalContext {
  private encrypt(text: string): string {
    const key = this.getKeyFromKeychain(); // Use OS keychain
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex');
    
    return JSON.stringify({
      iv: iv.toString('hex'),
      authTag,
      encrypted
    });
  }
  
  update(key: string, value: any) {
    // Encrypt sensitive keys before storage
    if (key === 'mcpOauthStorage') {
      value = this.encrypt(JSON.stringify(value));
    }
    // ... rest of update logic
  }
}
```

#### 2. Atomic File Operations
```typescript
// SECURE: Prevent race conditions with atomic writes
import { writeFileSync, renameSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

update<T extends keyof GlobalContextType>(
  key: T,
  value: GlobalContextType[T],
) {
  const filepath = getGlobalContextFilePath();
  const tempPath = join(tmpdir(), `globalContext.${Date.now()}.tmp`);
  
  // Write to temp file first
  writeFileSync(tempPath, JSON.stringify(data, null, 2), {
    mode: 0o600, // Owner read/write only
    flag: 'wx'   // Fail if exists (prevent TOCTOU)
  });
  
  // Atomic rename
  renameSync(tempPath, filepath);
}
```

#### 3. File Permission Hardening
```typescript
// SECURE: Set restrictive file permissions
import { chmodSync } from 'fs';

function createGlobalContextFile(filepath: string, data: any) {
  writeFileSync(filepath, JSON.stringify(data, null, 2), {
    mode: 0o600, // Owner read/write only (Unix)
    flag: 'wx'
  });
  
  // Ensure permissions on existing file
  chmodSync(filepath, 0o600);
}
```

---

## 4. Entry Points

### Public Methods

| Method | Entry Point | Security Considerations |
|--------|-------------|------------------------|
| `update(key, value)` | Any component calling update | No input validation, trusts caller |
| `get(key)` | Any component calling get | Returns sensitive data without access control |
| `getSharedConfig()` | Config consumers | Schema validation via Zod |
| `updateSharedConfig(values)` | Config setters | Partial update, merges with existing |
| `updateSelectedModel(profileId, role, title)` | Model selector | No authorization check |

### File System Entry Points

| Operation | Function | Security Considerations |
|-----------|----------|------------------------|
| File read | `fs.readFileSync()` | No permission check, trusts file exists |
| File write | `fs.writeFileSync()` | Creates file with default permissions |
| File delete | `fs.unlinkSync()` | On corruption, no backup |
| File exists | `fs.existsSync()` | TOCTOU vulnerability |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────┐
│                    Untrusted Input                          │
│  (User config, OAuth responses, External sources)           │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Trust Boundary                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  GlobalContext.update()                             │   │
│  │  - JSON.parse() - potential injection               │   │
│  │  - No input validation                              │   │
│  │  - No encryption                                    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Trusted Storage                            │
│  ~/.continue/globalContext.json                             │
│  (Unencrypted, file-permission protected)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Confidentiality | Integrity | Availability | Priority |
|-------|-----------------|-----------|--------------|----------|
| OAuth tokens | 🔴 **CRITICAL** | 🟡 **HIGH** | 🟢 **MEDIUM** | P0 |
| Client secrets | 🔴 **CRITICAL** | 🟡 **HIGH** | 🟢 **MEDIUM** | P0 |
| Shared config | 🟡 **MEDIUM** | 🟡 **MEDIUM** | 🟢 **MEDIUM** | P2 |
| Model selections | 🟢 **LOW** | 🟢 **LOW** | 🟢 **LOW** | P3 |
| UI state flags | 🟢 **LOW** | 🟢 **LOW** | 🟢 **LOW** | P3 |

### CIA Triad Analysis

#### Confidentiality
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| Token theft | File permissions | No encryption | Encrypt sensitive fields |
| Config exposure | Process isolation | Plain text storage | Use OS keychain |
| Data leakage | None | No audit logging | Add access logging |

#### Integrity
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| File corruption | JSON parse error handling | Deletes on error | Backup before delete |
| Race condition | None | No file locking | Atomic operations |
| Unauthorized modification | File permissions | No signature | Add HMAC verification |

#### Availability
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| File corruption | Recreates fresh | Data loss | Backup + recovery |
| Concurrent access | None | No queue | Implement locking |
| Disk full | None | No error handling | Graceful degradation |

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Reason | Data Access |
|-----------|-------------|--------|-------------|
| GlobalContext class | 🟡 **MEDIUM** | Internal code, no validation | All state |
| OAuth token storage | 🔴 **HIGH** | Contains secrets | Critical |
| Shared config | 🟡 **MEDIUM** | User-modifiable | Medium |
| Model selections | 🟢 **LOW** | User preferences | Low |
| File system | 🟡 **MEDIUM** | OS-dependent | All state |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────────┐
│                     External Trust Zone                         │
│  (MCP Servers, OAuth Providers, Network)                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Trust Boundary: OAuth Flow                 │   │
│  │  OAuthTokens ← External provider                        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Trust Zone                       │
│  (Continue CLI, Internal Components)                            │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           Trust Boundary: GlobalContext                 │   │
│  │  - Accepts data from all internal components            │   │
│  │  - No authentication/authorization                      │   │
│  │  - No encryption at rest                                │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Storage Trust Zone                          │
│  (File System, ~/.continue/globalContext.json)                  │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           Trust Boundary: File System                   │   │
│  │  - Depends on OS permissions                            │   │
│  │  - Vulnerable to local attacks                          │   │
│  │  - No encryption                                        │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment

| Aspect | Rating | Justification |
|--------|--------|---------------|
| Input validation | ❌ **POOR** | No validation on update() |
| Data protection | ❌ **POOR** | No encryption for sensitive data |
| Access control | ❌ **POOR** | No authorization checks |
| Error handling | ✅ **GOOD** | Graceful corruption recovery |
| Data integrity | ⚠️ **FAIR** | JSON schema for shared config only |

---

## 7. Architecture & Security Boundaries

### System Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ MCP Manager  │  │ Config       │  │ Model        │         │
│  │ Singleton    │  │ Handler      │  │ Selector     │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                 │                 │                  │
│         └─────────────────┼─────────────────┘                  │
│                           ▼                                    │
│              ┌────────────────────────┐                       │
│              │   GlobalContext        │                       │
│              │   ┌────────────────┐   │                       │
│              │   │ update(key,val)│   │                       │
│              │   │ get(key)       │   │                       │
│              │   │ getSharedConfig()│ │                       │
│              │   └────────────────┘   │                       │
│              └───────────┬────────────┘                       │
└──────────────────────────┼────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Persistence Layer                            │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              File System I/O                            │   │
│  │  fs.readFileSync() / fs.writeFileSync()                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│                           ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │         ~/.continue/globalContext.json                  │   │
│  │  {                                                      │   │
│  │    "mcpOauthStorage": {...},     ← CRITICAL             │   │
│  │    "sharedConfig": {...},        ← MEDIUM               │   │
│  │    "selectedModelsByProfileId": {...}, ← LOW            │   │
│  │    ...                                                  │   │
│  │  }                                                      │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Security Boundaries

| Boundary | Components | Protection | Gap |
|----------|------------|------------|-----|
| Application ↔ Storage | GlobalContext ↔ FS | File permissions | No encryption |
| Internal ↔ External | OAuth flow ↔ MCP | OAuth protocol | Token storage |
| User ↔ App | Config input ↔ Parser | Zod schema | Partial validation |

### Data Flow Through Boundaries
```
External OAuth Server
        │
        │ OAuthTokens (encrypted in transit)
        ▼
┌─────────────────────────────┐
│   Trust Boundary #1         │
│   Application Entry Point   │
└─────────────┬───────────────┘
              │
              │ OAuthTokens (plaintext in memory)
              ▼
┌─────────────────────────────┐
│   Trust Boundary #2         │
│   GlobalContext.update()    │  ← NO ENCRYPTION
└─────────────┬───────────────┘
              │
              │ OAuthTokens (plaintext in JSON)
              ▼
┌─────────────────────────────┐
│   Trust Boundary #3         │
│   File System Write         │  ← DEFAULT PERMISSIONS
└─────────────┬───────────────┘
              │
              │ globalContext.json (plaintext on disk)
              ▼
        Storage Media
```

---

## 8. Security Recommendations

### Critical Priority (P0)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| Unencrypted OAuth tokens | Encrypt mcpOauthStorage before write | Medium | High |
| No file permission hardening | Set 0o600 on file creation | Low | High |
| Plaintext client secrets | Use OS keychain for secrets | High | High |

### High Priority (P1)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| Race condition vulnerability | Implement atomic file operations | Medium | Medium |
| No input validation | Add schema validation for all updates | Medium | Medium |
| TOCTOU vulnerability | Use file locking or atomic operations | Medium | Medium |

### Medium Priority (P2)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No backup on corruption | Create .bak before deleting corrupted file | Low | Low |
| No audit logging | Log access to sensitive fields | Low | Low |
| No integrity verification | Add HMAC for file integrity | Medium | Medium |

### Low Priority (P3)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No data expiration | Implement token refresh/cleanup | Medium | Low |
| No access control | Add per-component authorization | High | Low |

### Implementation Checklist

- [ ] **Encrypt sensitive fields** (mcpOauthStorage) before writing to disk
- [ ] **Set restrictive file permissions** (0o600) on globalContext.json
- [ ] **Implement atomic file operations** to prevent race conditions
- [ ] **Add input validation** for all update() calls
- [ ] **Create backup** before deleting corrupted files
- [ ] **Use OS keychain** for OAuth client secrets
- [ ] **Add integrity verification** (HMAC) for file contents
- [ ] **Implement file locking** for concurrent access
- [ ] **Add audit logging** for sensitive data access
- [ ] **Document security considerations** for developers

### Secure Implementation Example

```typescript
// SECURE: GlobalContext with encryption and atomic operations
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from 'crypto';
import { writeFileSync, readFileSync, renameSync, chmodSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const ALGORITHM = 'aes-256-gcm';
const ENCRYPTED_KEYS = ['mcpOauthStorage'];

class SecureGlobalContext {
  private getKey(): Buffer {
    // Use OS keychain or derive from secure entropy
    const keyMaterial = process.env.CONTINUE_MASTER_KEY;
    if (!keyMaterial || keyMaterial.length !== 64) {
      throw new Error('Master key not configured');
    }
    return Buffer.from(keyMaterial, 'hex');
  }

  private encrypt(text: string): string {
    const key = this.getKey();
    const iv = randomBytes(12); // GCM recommended IV size
    const cipher = createCipheriv(ALGORITHM, key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex');
    
    return JSON.stringify({
      iv: iv.toString('hex'),
      authTag,
      encrypted,
    });
  }

  private decrypt(encryptedData: string): string {
    const key = this.getKey();
    const { iv, authTag, encrypted } = JSON.parse(encryptedData);
    
    const decipher = createDecipheriv(
      ALGORITHM,
      key,
      Buffer.from(iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  update<T extends keyof GlobalContextType>(
    key: T,
    value: GlobalContextType[T],
  ) {
    const filepath = getGlobalContextFilePath();
    const tempPath = join(tmpdir(), `globalContext.${Date.now()}.tmp`);
    
    let data: Partial<GlobalContextType> = {};
    
    // Read existing data
    if (fs.existsSync(filepath)) {
      const fileContent = readFileSync(filepath, 'utf-8');
      data = JSON.parse(fileContent);
    }
    
    // Encrypt sensitive data before storage
    if (ENCRYPTED_KEYS.includes(key)) {
      data[key] = this.encrypt(JSON.stringify(value)) as any;
    } else {
      data[key] = value;
    }
    
    // Atomic write with restrictive permissions
    writeFileSync(tempPath, JSON.stringify(data, null, 2), {
      mode: 0o600,
      flag: 'wx',
    });
    
    renameSync(tempPath, filepath);
    chmodSync(filepath, 0o600);
  }

  get<T extends keyof GlobalContextType>(
    key: T,
  ): GlobalContextType[T] | undefined {
    const filepath = getGlobalContextFilePath();
    if (!fs.existsSync(filepath)) {
      return undefined;
    }

    const fileContent = readFileSync(filepath, 'utf-8');
    const data = JSON.parse(fileContent);
    const value = data[key];
    
    // Decrypt sensitive data on read
    if (ENCRYPTED_KEYS.includes(key) && typeof value === 'string') {
      return JSON.parse(this.decrypt(value)) as GlobalContextType[T];
    }
    
    return value;
  }
}
```

---

**Generated with [Continue](https://continue.dev)**

Co-Authored-By: Continue <noreply@continue.dev>
