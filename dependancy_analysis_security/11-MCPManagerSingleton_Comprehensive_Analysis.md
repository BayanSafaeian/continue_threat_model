# 🔒 Comprehensive Security Analysis: MCPManagerSingleton Class [MCP Server Management]

**Package:** `@modelcontextprotocol/sdk`  
**Used In:** `/core/context/mcp/MCPManagerSingleton.ts` (MCP server lifecycle management)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🔴 **HIGH**

---

## 1. Dependency Purpose & Usage

### Primary Function
The `MCPManagerSingleton` class manages the lifecycle and connections to Model Context Protocol (MCP) servers. It handles:
- Server initialization and configuration
- OAuth authentication flows
- Connection pooling and management
- Tool discovery and invocation
- Resource access and streaming

### Implementation
```typescript
export class MCPManagerSingleton {
  private static instance: MCPManagerSingleton;
  private connections: Map<string, MCPServerConnection>;
  private oauthStorage: Map<string, OAuthCredentials>;
  
  // Singleton pattern
  static getInstance(): MCPManagerSingleton {
    if (!MCPManagerSingleton.instance) {
      MCPManagerSingleton.instance = new MCPManagerSingleton();
    }
    return MCPManagerSingleton.instance;
  }
  
  // Initialize MCP server connection
  async initializeServer(config: MCPServerConfig): Promise<void> {
    const connection = new MCPServerConnection(config);
    await connection.connect();
    this.connections.set(config.id, connection);
  }
  
  // Handle OAuth authentication
  async authenticateWithOAuth(serverUrl: string): Promise<OAuthTokens> {
    const flow = new OAuthFlow(serverUrl);
    const tokens = await flow.authorize();
    this.oauthStorage.set(serverUrl, tokens);
    return tokens;
  }
  
  // Invoke tools on MCP servers
  async invokeTool(toolName: string, args: any): Promise<any> {
    const connection = this.getActiveConnection();
    return connection.callTool(toolName, args);
  }
}
```

### Dependency Type
- **External SDK** - `@modelcontextprotocol/sdk`
- **Internal manager** - Singleton pattern for connection management
- **Network client** - HTTP/WebSocket connections to MCP servers
- **OAuth client** - Authentication with external providers

---

## 2. Data Flow Analysis

### Inbound Data

| Data Type | Source | Sensitivity | Validation |
|-----------|--------|-------------|------------|
| MCP server configs | User/workspace config | 🟡 **MEDIUM** | Schema validation |
| OAuth credentials | OAuth provider | 🔴 **CRITICAL** | OAuth SDK |
| Tool invocation args | User/AI requests | 🟡 **MEDIUM** | Runtime validation |
| Server responses | MCP servers | 🟡 **MEDIUM** | Protocol validation |
| Access tokens | OAuth flow | 🔴 **CRITICAL** | Token validation |
| Tool definitions | MCP servers | 🟢 **LOW** | Schema validation |

### Outbound Data

| Data Type | Destination | Sensitivity | Access Control |
|-----------|-------------|-------------|----------------|
| OAuth tokens | MCP servers | 🔴 **CRITICAL** | TLS encryption |
| Tool arguments | MCP servers | 🟡 **MEDIUM** | Server trust |
| User context | MCP servers | 🟡 **MEDIUM** | Server trust |
| Code snippets | MCP servers | 🔴 **CRITICAL** | Server trust |
| File contents | MCP servers | 🔴 **CRITICAL** | Server trust |

### Data Storage

| Storage Location | Data Type | Encryption | Access Control |
|------------------|-----------|------------|----------------|
| Memory (connections Map) | Active connections | ❌ **NONE** | Process isolation |
| Memory (oauthStorage Map) | OAuth tokens | ❌ **NONE** | Process isolation |
| GlobalContext.json | Persisted tokens | ❌ **NONE** | File permissions |
| Network transit | All communications | ✅ **TLS** | Server certificates |

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                      External MCP Servers                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ GitHub MCP   │  │ FileSystem   │  │ Database     │         │
│  │ Server       │  │ MCP Server   │  │ MCP Server   │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
└─────────┼─────────────────┼─────────────────┼──────────────────┘
          │                 │                 │
          │ HTTPS/WSS       │ HTTPS/WSS       │ HTTPS/WSS
          │ (TLS)           │ (TLS)           │ (TLS)
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   MCPManagerSingleton                           │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Connection Pool (Map)                                    │ │
│  │  - Server configurations                                  │ │
│  │  - Active WebSocket/HTTP connections                      │ │
│  │  - Tool definitions                                       │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  OAuth Storage (Map)                                      │ │
│  │  - Access tokens                                          │ │
│  │  - Refresh tokens                                         │ │
│  │  - Client credentials                                     │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Tool Invocation Handler                                  │ │
│  │  - Argument validation                                    │ │
│  │  - Response processing                                    │ │
│  │  - Error handling                                         │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ AI Assistant │  │ User Input   │  │ Config       │         │
│  │ (Code LLM)   │  │ (Commands)   │  │ Parser       │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

| Threat | CVSS Score | Attack Vector | Impact | Likelihood |
|--------|------------|---------------|--------|------------|
| **Token Theft (MITM)** | 7.5 (HIGH) | Network interception | Account compromise | Medium |
| **Server Impersonation** | 8.1 (HIGH) | DNS/Network attack | Data exfiltration | Medium |
| **Tool Injection** | 7.8 (HIGH) | Malicious tool args | Code execution | Medium |
| **Credential Leakage** | 6.5 (MEDIUM) | Memory dump | Token exposure | Low |
| **Connection Hijacking** | 7.2 (HIGH) | Session fixation | Unauthorized access | Medium |
| **Privilege Escalation** | 6.8 (MEDIUM) | Config manipulation | Elevated access | Medium |

### Attack Vector: MCP Server Impersonation

**Scenario:**
```
1. Attacker controls network or DNS
   ├── Public WiFi attack
   ├── DNS poisoning
   └── BGP hijacking

2. Attacker redirects MCP server connection
   └── continue-app connects to attacker's server

3. Attacker's server:
   ├── Captures OAuth tokens
   ├── Receives tool invocations with sensitive data
   │   ├── Code snippets
   │   ├── File contents
   │   └── User context
   └── Returns malicious tool responses
       ├── Injected code
       ├── False information
       └── Command injection payloads
```

**CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N = 7.9**

### Attack Vector: Tool Injection

**Scenario:**
```
1. Attacker crafts malicious MCP tool
   └── Tool accepts user-controlled arguments

2. AI assistant invokes tool with user data
   └── Arguments contain injection payload

3. Malicious tool executes:
   ├── Command injection on MCP server
   ├── Path traversal to access sensitive files
   └── SQL injection in database MCP server
```

**CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L = 8.0**

### Mitigation Strategies

#### 1. Certificate Pinning
```typescript
// SECURE: Pin MCP server certificates
import { Agent } from 'https';
import { createHash } from 'crypto';

const MCP_SERVER_PUBKEY_HASH = 'sha256/...'; // Pre-computed hash

class SecureMCPManager {
  private createSecureAgent(): Agent {
    return new Agent({
      rejectUnauthorized: true,
      checkServerIdentity: (hostname, cert) => {
        const pubkey = cert.pubkey;
        const hash = createHash('sha256').update(pubkey).digest('base64');
        
        if (`sha256/${hash}` !== MCP_SERVER_PUBKEY_HASH) {
          throw new Error('Certificate pinning failed');
        }
      }
    });
  }
  
  async connect(serverUrl: string) {
    const agent = this.createSecureAgent();
    // Use agent for all HTTPS connections
  }
}
```

#### 2. OAuth Token Protection
```typescript
// SECURE: Encrypt tokens in memory and validate on use
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

class SecureOAuthStorage {
  private masterKey: Buffer;
  private tokenCache: Map<string, EncryptedToken>;
  
  constructor() {
    // Derive key from secure entropy
    this.masterKey = randomBytes(32);
  }
  
  private encrypt(tokens: OAuthTokens): EncryptedToken {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);
    
    const plaintext = JSON.stringify(tokens);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      iv: iv.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex'),
      encrypted
    };
  }
  
  set(serverUrl: string, tokens: OAuthTokens) {
    this.tokenCache.set(serverUrl, this.encrypt(tokens));
  }
  
  get(serverUrl: string): OAuthTokens | undefined {
    const encrypted = this.tokenCache.get(serverUrl);
    if (!encrypted) return undefined;
    
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.masterKey,
      Buffer.from(encrypted.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  }
}
```

#### 3. Tool Input Validation
```typescript
// SECURE: Validate and sanitize tool arguments
import { z } from 'zod';

class SecureToolInvoker {
  private toolSchemas: Map<string, z.ZodSchema> = new Map();
  
  registerToolSchema(toolName: string, schema: z.ZodSchema) {
    this.toolSchemas.set(toolName, schema);
  }
  
  async invokeTool(toolName: string, args: any): Promise<any> {
    const schema = this.toolSchemas.get(toolName);
    if (!schema) {
      throw new Error(`Unknown tool: ${toolName}`);
    }
    
    // Validate arguments against schema
    const validatedArgs = schema.parse(args);
    
    // Additional sanitization for string inputs
    const sanitizedArgs = this.sanitizeArguments(validatedArgs);
    
    // Invoke with validated and sanitized args
    return this.connection.callTool(toolName, sanitizedArgs);
  }
  
  private sanitizeArguments(args: any): any {
    if (typeof args === 'string') {
      // Remove potential injection patterns
      return args
        .replace(/[;&|`$()]/g, '')  // Remove shell metacharacters
        .replace(/\.\.\//g, '')      // Remove path traversal
        .replace(/<script/gi, '');   // Remove XSS vectors
    }
    if (typeof args === 'object' && args !== null) {
      return Object.fromEntries(
        Object.entries(args).map(([k, v]) => [k, this.sanitizeArguments(v)])
      );
    }
    return args;
  }
}
```

---

## 4. Entry Points

### Public Methods

| Method | Entry Point | Security Considerations |
|--------|-------------|------------------------|
| `initializeServer(config)` | Config parser | Validates server config, establishes network connection |
| `authenticateWithOAuth(url)` | OAuth flow | Handles credentials, stores tokens |
| `invokeTool(name, args)` | AI assistant/User | Executes remote code, sends user data |
| `getConnection(id)` | Internal | Returns active connection with credentials |
| `listTools()` | AI assistant | Exposes server capabilities |
| `readResource(uri)` | AI assistant | Accesses remote resources |

### Network Entry Points

| Connection Type | Protocol | Security Controls | Risks |
|-----------------|----------|-------------------|-------|
| MCP HTTP | HTTPS | TLS validation | MITM, cert spoofing |
| MCP WebSocket | WSS | TLS validation | MITM, session hijack |
| OAuth flow | HTTPS | PKCE, state param | Token theft, CSRF |
| Token refresh | HTTPS | Refresh token | Replay attacks |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────┐
│                    Untrusted Network                        │
│  (Internet, Public WiFi, Potentially Hostile)               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              MCP Servers (External)                 │   │
│  │  - GitHub MCP                                       │   │
│  │  - FileSystem MCP                                   │   │
│  │  - Database MCP                                     │   │
│  │  - Custom MCP (user-defined) ← HIGH RISK            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ TLS Connection
                      │ (Trust Boundary #1)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  MCPManagerSingleton                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Connection Handler                                 │   │
│  │  - Certificate validation                           │   │
│  │  - Session management                               │   │
│  │  - Response parsing                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  OAuth Token Storage                                │   │
│  │  - In-memory (encrypted)                            │   │
│  │  - Persisted (GlobalContext.json)                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Tool Invocation Handler                            │   │
│  │  - Input validation                                 │   │
│  │  - Argument sanitization                            │   │
│  │  - Response validation                              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ Internal API Calls
                      │ (Trust Boundary #2)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Application Layer                          │
│  (AI Assistant, User Commands, Config)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Confidentiality | Integrity | Availability | Priority |
|-------|-----------------|-----------|--------------|----------|
| OAuth tokens | 🔴 **CRITICAL** | 🟡 **HIGH** | 🟡 **HIGH** | P0 |
| MCP server configs | 🟡 **MEDIUM** | 🟡 **HIGH** | 🟢 **MEDIUM** | P1 |
| Tool invocation data | 🔴 **CRITICAL** | 🟡 **HIGH** | 🟢 **MEDIUM** | P0 |
| Connection pool | 🟡 **MEDIUM** | 🟡 **HIGH** | 🟡 **HIGH** | P1 |
| User context sent to MCP | 🔴 **CRITICAL** | 🟢 **LOW** | 🟢 **LOW** | P1 |

### CIA Triad Analysis

#### Confidentiality
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| Token interception | TLS | No cert pinning | Implement certificate pinning |
| Memory exposure | Process isolation | Plaintext in memory | Encrypt in-memory tokens |
| Server eavesdropping | TLS | Trust any valid cert | Server allowlist |
| Config leakage | File permissions | Plain text config | Encrypt sensitive configs |

#### Integrity
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| Tool response tampering | Protocol validation | No signature | Sign tool responses |
| Connection hijacking | Session tokens | No binding | Bind to TLS channel |
| Config modification | Schema validation | No integrity check | Sign config files |
| Server impersonation | Certificate validation | No pinning | Certificate pinning |

#### Availability
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| Server downtime | Reconnection logic | No circuit breaker | Implement circuit breaker |
| Token expiration | Refresh logic | No graceful degradation | Cache tool definitions |
| Network failure | Error handling | No retry policy | Exponential backoff |
| Resource exhaustion | None | No connection limits | Limit concurrent connections |

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Reason | Data Access |
|-----------|-------------|--------|-------------|
| MCP servers (external) | 🔴 **UNTRUSTED** | External, user-defined | Full access |
| OAuth providers | 🟡 **MEDIUM** | Third-party, regulated | Tokens only |
| MCPManagerSingleton | 🟡 **MEDIUM** | Internal, handles secrets | All data |
| Tool invocations | 🔴 **UNTRUSTED** | Remote execution | Code/data |
| Network layer | 🟡 **MEDIUM** | TLS protected | All transit data |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────────┐
│                    Zero Trust Zone                              │
│  (External MCP Servers - Treat as Hostile)                      │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              User-Defined MCP Servers                   │   │
│  │  ⚠️ NO ASSUMPTION OF HONEST BEHAVIOR                    │   │
│  │  - Validate all responses                               │   │
│  │  - Limit data exposure                                  │   │
│  │  - Audit all tool invocations                           │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              │ TLS + Certificate Validation
                              │ (Trust Boundary #1)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Limited Trust Zone                              │
│  (MCPManagerSingleton - Internal but Security-Sensitive)        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Token Management                           │   │
│  │  🔴 Encrypt tokens in memory                            │   │
│  │  🔴 Minimize token lifetime                             │   │
│  │  🔴 Audit token usage                                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Tool Invocation                            │   │
│  │  🟡 Validate all inputs                                 │   │
│  │  🟡 Sanitize all arguments                              │   │
│  │  🟡 Validate all responses                              │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              │ Internal API
                              │ (Trust Boundary #2)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Trusted Zone                                   │
│  (Application Core - AI Assistant, User Interface)              │
│  - Assume honest but verify inputs                              │
│  - Apply principle of least privilege                           │
│  - Audit sensitive operations                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment

| Aspect | Rating | Justification |
|--------|--------|---------------|
| External server trust | ❌ **UNTRUSTED** | User-defined, potentially malicious |
| Network security | ⚠️ **FAIR** | TLS without pinning |
| Token protection | ❌ **POOR** | Plaintext in memory and storage |
| Input validation | ⚠️ **FAIR** | Schema validation, no sanitization |
| Response validation | ⚠️ **FAIR** | Protocol validation, no integrity |

---

## 7. Architecture & Security Boundaries

### System Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    External MCP Servers                         │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ GitHub MCP   │  │ Custom MCP   │  │ Enterprise   │         │
│  │ (Trusted)    │  │ (Untrusted)  │  │ MCP (Trusted)│         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
└─────────┼─────────────────┼─────────────────┼──────────────────┘
          │                 │                 │
          │ WSS/HTTPS       │ WSS/HTTPS       │ WSS/HTTPS
          │ (TLS)           │ (TLS)           │ (TLS)
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Security Boundary #1                           │
│              (Network Perimeter - TLS Termination)              │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   MCPManagerSingleton                           │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                  Connection Manager                       │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │ │
│  │  │ Connection  │  │ Connection  │  │ Connection  │       │ │
│  │  │ Pool        │  │ Validator   │  │ Health      │       │ │
│  │  │             │  │             │  │ Monitor     │       │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘       │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                  Security Boundary #2                     │ │
│  │              (Token Management Layer)                     │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │ │
│  │  │ OAuth       │  │ Token       │  │ Credential  │       │ │
│  │  │ Flow        │  │ Encryptor   │  │ Vault       │       │ │
│  │  │ Handler     │  │             │  │ (Memory)    │       │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘       │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │                  Security Boundary #3                     │ │
│  │              (Tool Invocation Layer)                      │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │ │
│  │  │ Input       │  │ Argument    │  │ Response    │       │ │
│  │  │ Validator   │  │ Sanitizer   │  │ Validator   │       │ │
│  │  │             │  │             │  │             │       │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘       │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Core                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ AI Assistant │  │ User         │  │ Config       │         │
│  │              │  │ Interface    │  │ Parser       │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

### Security Boundaries

| Boundary | Components | Protection | Gap |
|----------|------------|------------|-----|
| Network ↔ App | TLS termination | Certificate validation | No pinning |
| Token Storage | Memory/GlobalContext | Process isolation | No encryption |
| Tool Invocation | App ↔ MCP server | Schema validation | No sanitization |
| Config Loading | File ↔ Memory | Schema validation | No signature |

### Data Flow Through Boundaries
```
External MCP Server
        │
        │ Tool Response (potentially malicious)
        ▼
┌─────────────────────────────┐
│   Security Boundary #1      │
│   TLS Termination           │  ✓ Certificate validation
│                             │  ✗ No certificate pinning
└─────────────┬───────────────┘
              │
              │ Parsed Response
              ▼
┌─────────────────────────────┐
│   Security Boundary #2      │
│   Response Validation       │  ✓ Protocol validation
│                             │  ✗ No integrity check
└─────────────┬───────────────┘
              │
              │ Validated Data
              ▼
┌─────────────────────────────┐
│   Security Boundary #3      │
│   Application Processing    │  ✓ Schema validation
│                             │  ✗ Limited sanitization
└─────────────┬───────────────┘
              │
              ▼
        AI Assistant / User
```

---

## 8. Security Recommendations

### Critical Priority (P0)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| Plaintext OAuth tokens | Encrypt tokens in memory | Medium | High |
| No certificate pinning | Implement for known MCP servers | Medium | High |
| Unvalidated tool responses | Add response integrity checks | High | High |
| User-defined server trust | Implement allowlist/sandboxing | High | High |

### High Priority (P1)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No argument sanitization | Sanitize tool invocation args | Medium | Medium |
| Token persistence | Encrypt in GlobalContext.json | Low | High |
| No connection limits | Limit concurrent MCP connections | Low | Medium |
| No audit logging | Log all tool invocations | Low | Medium |

### Medium Priority (P2)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No circuit breaker | Implement for server failures | Medium | Low |
| No retry policy | Add exponential backoff | Low | Low |
| No token rotation | Implement periodic re-authentication | Medium | Low |
| No resource limits | Limit data sent to MCP servers | Medium | Medium |

### Low Priority (P3)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No health monitoring | Add connection health checks | Low | Low |
| No graceful degradation | Cache tool definitions | Medium | Low |
| No config signing | Sign MCP server configs | Medium | Low |

### Implementation Checklist

- [ ] **Encrypt OAuth tokens** in memory using AES-256-GCM
- [ ] **Implement certificate pinning** for known/trusted MCP servers
- [ ] **Create MCP server allowlist** for user-defined servers
- [ ] **Add tool argument sanitization** to prevent injection
- [ ] **Implement response validation** with integrity checks
- [ ] **Encrypt persisted tokens** in GlobalContext.json
- [ ] **Add audit logging** for all tool invocations
- [ ] **Implement connection limits** to prevent DoS
- [ ] **Add circuit breaker** for server failures
- [ ] **Document security model** for MCP integration

### Secure Implementation Example

```typescript
// SECURE: Hardened MCPManagerSingleton
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { Agent } from 'https';

interface TrustedServer {
  url: string;
  pubkeyHash: string;
  allowedTools: string[];
}

class SecureMCPManagerSingleton {
  private static instance: SecureMCPManagerSingleton;
  private connections: Map<string, MCPServerConnection>;
  private encryptedTokenStore: Map<string, EncryptedToken>;
  private masterKey: Buffer;
  private trustedServers: Map<string, TrustedServer>;
  
  private constructor() {
    this.masterKey = randomBytes(32);
    this.trustedServers = this.loadTrustedServers();
  }
  
  static getInstance(): SecureMCPManagerSingleton {
    if (!SecureMCPManagerSingleton.instance) {
      SecureMCPManagerSingleton.instance = new SecureMCPManagerSingleton();
    }
    return SecureMCPManagerSingleton.instance;
  }
  
  private createSecureAgent(serverUrl: string): Agent {
    const trustedServer = this.trustedServers.get(serverUrl);
    
    return new Agent({
      rejectUnauthorized: true,
      checkServerIdentity: (hostname, cert) => {
        // Certificate pinning for trusted servers
        if (trustedServer) {
          const pubkeyHash = this.hashPubkey(cert.pubkey);
          if (pubkeyHash !== trustedServer.pubkeyHash) {
            throw new Error('Certificate pinning failed');
          }
        }
      }
    });
  }
  
  async invokeTool(
    serverUrl: string,
    toolName: string,
    args: any
  ): Promise<any> {
    // Validate server is trusted
    const trustedServer = this.trustedServers.get(serverUrl);
    if (!trustedServer) {
      throw new Error('Untrusted MCP server');
    }
    
    // Validate tool is allowed
    if (!trustedServer.allowedTools.includes(toolName)) {
      throw new Error(`Tool ${toolName} not allowed on ${serverUrl}`);
    }
    
    // Sanitize arguments
    const sanitizedArgs = this.sanitizeArguments(args);
    
    // Invoke tool with secure connection
    const connection = this.getConnection(serverUrl);
    const response = await connection.callTool(toolName, sanitizedArgs);
    
    // Validate response
    this.validateResponse(response);
    
    return response;
  }
  
  private sanitizeArguments(args: any): any {
    // Remove dangerous patterns
    if (typeof args === 'string') {
      return args
        .replace(/[;&|`$(){}[\]<>]/g, '')  // Shell metacharacters
        .replace(/\.\.\//g, '')             // Path traversal
        .replace(/file:\/\//g, '')          // File protocol
        .replace(/<script/gi, '')           // XSS
        .substring(0, 10000);               // Length limit
    }
    if (typeof args === 'object' && args !== null) {
      return Object.fromEntries(
        Object.entries(args).map(([k, v]) => [k, this.sanitizeArguments(v)])
      );
    }
    return args;
  }
  
  private encryptTokens(tokens: OAuthTokens): EncryptedToken {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);
    
    const plaintext = JSON.stringify(tokens);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      iv: iv.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex'),
      encrypted
    };
  }
  
  private decryptTokens(encrypted: EncryptedToken): OAuthTokens {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.masterKey,
      Buffer.from(encrypted.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  }
}
```

---

**Generated with [Continue](https://continue.dev)**

Co-Authored-By: Continue <noreply@continue.dev>
