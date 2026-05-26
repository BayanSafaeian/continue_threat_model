# 🔒 Comprehensive Security Analysis: Model Context Protocol SDK

**Package:** `@modelcontextprotocol/sdk`  
**Adapter Files:** `core/context/mcp/MCPManagerSingleton.ts`, `core/context/mcp/MCPOauth.ts`  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟠 **HIGH**

---

## 1. Dependency Purpose & Usage

### Primary Function
The Model Context Protocol (MCP) SDK implements the MCP specification, enabling Continue to connect to external MCP servers that provide tools, resources, and prompts. This allows Continue to:
- Invoke remote tools on MCP servers (file operations, API calls, database queries, etc.)
- Access external resources through MCP resource servers
- Retrieve and use prompt templates from remote servers
- Enable extensible AI capabilities through standardized protocol

### Implementation in Continue
```typescript
// core/context/mcp/MCPManagerSingleton.ts
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

class MCPManagerSingleton {
  private static instance: MCPManagerSingleton;
  private connections: Map<string, MCPConnection> = new Map();

  async connectToServer(serverConfig: MCPServerConfig): Promise<void> {
    const transport = this.createTransport(serverConfig);
    const client = new Client({
      name: 'continue-mcp-client',
      version: packageJson.version
    });
    
    await client.connect(transport);
    
    // Discover server capabilities
    const capabilities = await client.getServerCapabilities();
    
    // List available tools
    const tools = await client.listTools();
    
    this.connections.set(serverConfig.id, { client, transport, capabilities });
  }

  async callTool(serverId: string, toolName: string, args: any): Promise<any> {
    const connection = this.connections.get(serverId);
    if (!connection) {
      throw new Error(`No connection to server: ${serverId}`);
    }
    
    return connection.client.callTool({
      name: toolName,
      arguments: args
    });
  }

  async readResource(serverId: string, uri: string): Promise<ResourceContents> {
    const connection = this.connections.get(serverId);
    return connection.client.readResource({ uri });
  }

  private createTransport(config: MCPServerConfig): Transport {
    switch (config.transportType) {
      case 'sse':
        return new SSEClientTransport(new URL(config.url));
      case 'stdio':
        return new StdioClientTransport({
          command: config.command,
          args: config.args
        });
      case 'websocket':
        // WebSocket transport implementation
        break;
    }
  }
}

// core/context/mcp/MCPOauth.ts
class MCPOauth {
  async authenticate(serverConfig: MCPServerConfig): Promise<OAuthTokens> {
    // OAuth 2.0 flow for MCP server authentication
    const authUrl = this.buildAuthUrl(serverConfig);
    const tokens = await this.exchangeCodeForTokens(authUrl, serverConfig);
    return tokens;
  }

  async refreshToken(serverId: string): Promise<OAuthTokens> {
    // Refresh expired access tokens
    const tokens = await this.performTokenRefresh(serverId);
    return tokens;
  }
}
```

### Dependency Type
- **Runtime dependency** - Active during MCP server connections
- **Network dependency** - Communicates with external MCP servers
- **Authentication dependency** - Handles OAuth 2.0 flows
- **Multi-transport** - Supports stdio, SSE, WebSocket, HTTP transports

---

## 2. Data Flow Analysis

### Inbound Data (Data In)

| Data Type | Source | Sensitivity | Processing |
|-----------|--------|-------------|------------|
| `ServerCapabilities` | MCP server discovery | MEDIUM | Declares available tools, resources, prompts |
| `ToolListResponse` | MCP server | HIGH | List of available tools with schemas |
| `ToolCallResult` | MCP server execution | HIGH | Tool execution results, may contain sensitive data |
| `ResourceContents` | MCP resource server | HIGH | External resource data loaded into context |
| `PromptTemplate` | MCP prompt server | MEDIUM | Reusable prompt structures |
| `OAuthTokens` | OAuth authorization server | CRITICAL | Access tokens, refresh tokens |
| `OAuthConfig` | Server metadata endpoint | MEDIUM | Authorization endpoints, scopes |

### Outbound Data (Data Out)

| Data Type | Destination | Sensitivity | Transmission |
|-----------|-------------|-------------|--------------|
| `ToolCallRequest` | MCP server | HIGH | Tool name, arguments (may contain user data) |
| `ResourceReadRequest` | MCP resource server | HIGH | Resource URIs being requested |
| `PromptGetRequest` | MCP prompt server | MEDIUM | Prompt template names |
| `OAuthCredentials` | OAuth authorization server | CRITICAL | Client ID, client secret, authorization codes |
| `UserContent` | MCP server via tools | HIGH | User data sent to external tools |
| `InitializeRequest` | MCP server | MEDIUM | Client capabilities, protocol version |

### Data Storage
- **In Memory:** OAuth tokens, connection state, tool caches, active sessions
- **Persistent:** Server configurations (may include credentials in config file)
- **Remote:** MCP server state, tool execution results, resource data

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                     Continue Application                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              User Interface / LLM                        │   │
│  │  - User requests tool execution                          │   │
│  │  - LLM generates tool call arguments                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           MCPManagerSingleton                            │   │
│  │  - Connection management                                 │   │
│  │  - Server registry                                       │   │
│  │  - Tool invocation                                       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              MCPOauth                                    │   │
│  │  - OAuth 2.0 authentication flow                         │   │
│  │  - Token storage & refresh                               │   │
│  │  - Credential management                                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │         Transport Layer (SDK)                            │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │   │
│  │  │ SSE          │  │ stdio        │  │ WebSocket    │  │   │
│  │  │ (HTTP)       │  │ (Pipe)       │  │ (Bidirectional)│ │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
         │                    │                    │
         │ HTTPS              │ Pipe               │ WSS
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ MCP Server      │  │ Local Process   │  │ MCP Server      │
│ (Remote)        │  │ (Child)         │  │ (Remote)        │
│ - Tools         │  │ - CLI tools     │  │ - Resources     │
│ - Resources     │  │ - Scripts       │  │ - Prompts       │
│ - Prompts       │  │ - Commands      │  │ - Tools         │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │
         ▼ OAuth 2.0 Flow
┌─────────────────────────────────────────────────────────────────┐
│                    Authorization Server                         │
│  - Token issuance                                               │
│  - Token refresh                                                │
│  - Scope validation                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

#### 3.1 Server Impersonation (CVSS: 8.5 - HIGH)
**Description:** Attacker operates malicious MCP server to intercept data, capture credentials, or provide malicious tool responses.

**Attack Vector:**
- Attacker sets up rogue MCP server mimicking legitimate service
- User configures Continue to connect to malicious server
- Server captures OAuth tokens, user data, tool arguments
- Server returns malicious tool results

**Impact:**
- Credential theft (OAuth tokens, API keys)
- User data exfiltration
- Malicious tool execution
- Supply chain compromise

**Mitigation:**
```typescript
// ✅ SECURE - Server allowlist
const ALLOWED_SERVERS = [
  'https://mcp.trusted-provider.com',
  'https://tools.internal.company.com'
];

async function connectToServer(config: MCPServerConfig): Promise<void> {
  // Validate server URL against allowlist
  if (!ALLOWED_SERVERS.includes(config.url)) {
    throw new Error(`Server not in allowlist: ${config.url}`);
  }
  
  // Validate SSL certificate
  await validateCertificate(config.url);
  
  // Proceed with connection
  // ...
}
```

#### 3.2 Protocol Exploitation (CVSS: 7.2 - HIGH)
**Description:** Malformed MCP messages exploit protocol parser vulnerabilities.

**Attack Vector:**
- Malicious server sends malformed JSON-RPC messages
- Parser vulnerability triggered (buffer overflow, injection, etc.)
- Code execution or denial of service

**Impact:**
- Remote code execution
- Denial of service
- Memory corruption

**Mitigation:**
- Validate all incoming messages against schema
- Implement message size limits
- Use well-tested JSON-RPC parser
- Keep SDK updated with security patches

#### 3.3 OAuth Token Theft (CVSS: 8.1 - HIGH)
**Description:** Credentials intercepted during OAuth flow or stolen from storage.

**Attack Vector:**
- MITM attack on OAuth redirect
- Token storage compromised
- Refresh token exfiltration
- Token replay attack

**Impact:**
- Unauthorized access to MCP servers
- Persistent access via refresh tokens
- Data exfiltration

**Mitigation:**
```typescript
// ✅ SECURE - OAuth security
class MCPOauth {
  async authenticate(config: MCPServerConfig): Promise<OAuthTokens> {
    // Validate redirect URI
    if (!this.isValidRedirectUri(config.redirectUri)) {
      throw new Error('Invalid redirect URI');
    }
    
    // Use PKCE for public clients
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    
    // Store tokens securely
    const tokens = await this.exchangeCodeForTokens(code, config);
    await this.secureStoreTokens(tokens); // Encrypt before storage
    
    return tokens;
  }
}
```

#### 3.4 Transport Layer Attack (CVSS: 7.5 - HIGH)
**Description:** SSE/WebSocket hijacking or MITM on transport layer.

**Attack Vector:**
- Unencrypted HTTP connection (not HTTPS)
- Certificate validation bypassed
- WebSocket connection hijacked
- Session fixation attack

**Impact:**
- Data interception
- Credential theft
- Message manipulation

**Mitigation:**
- Enforce HTTPS/WSS for all remote connections
- Validate SSL certificates
- Implement certificate pinning for known servers
- Use secure WebSocket (WSS) only

#### 3.5 Tool Injection (CVSS: 8.8 - HIGH)
**Description:** Malicious tool definitions from compromised server enable code execution or data exfiltration.

**Attack Vector:**
- MCP server compromised or malicious
- Server advertises malicious tool
- Tool executes arbitrary code on server side
- Tool results contain malicious payloads

**Impact:**
- Remote code execution (on server)
- Data exfiltration
- Credential theft
- Supply chain attack

**Mitigation:**
```typescript
// ✅ SECURE - Tool allowlist
const ALLOWED_TOOLS = {
  'trusted-server': ['read_file', 'search_code'],
  'internal-server': ['query_database', 'get_metrics']
};

async function callTool(serverId: string, toolName: string, args: any): Promise<any> {
  // Check tool is allowed for this server
  const allowedTools = ALLOWED_TOOLS[serverId] || [];
  if (!allowedTools.includes(toolName)) {
    throw new Error(`Tool not allowed: ${toolName} on server ${serverId}`);
  }
  
  // Validate arguments against schema
  validateToolArgs(toolName, args);
  
  // Proceed with tool call
  // ...
}
```

#### 3.6 Resource Exfiltration (CVSS: 7.8 - HIGH)
**Description:** Sensitive data leaked via resource access from compromised MCP server.

**Attack Vector:**
- MCP server has access to sensitive resources
- Server compromised, attacker reads resources
- Sensitive data sent to Continue and potentially logged
- Data exfiltration through tool results

**Impact:**
- Data breach
- Credential exposure
- Privacy violations

**Mitigation:**
- Implement resource access controls
- Validate resource URIs
- Log resource access for auditing
- Encrypt sensitive resource data

#### 3.7 Supply Chain Attack (CVSS: 8.1 - HIGH)
**Description:** Compromised @modelcontextprotocol/sdk package introduces malicious code.

**Attack Vector:**
- npm package compromised via account takeover
- Malicious code added to MCP SDK
- Credentials exfiltrated during MCP connections
- Backdoor installed

**Impact:**
- Widespread credential theft
- Data exfiltration
- Supply chain compromise

**Mitigation:**
- Pin exact package versions
- Use npm audit and Snyk
- Monitor for package changes
- Implement package signature verification

#### 3.8 Privilege Escalation (CVSS: 7.5 - HIGH)
**Description:** Tool execution with elevated privileges on MCP server.

**Attack Vector:**
- MCP server runs with elevated privileges
- Tool invocation exploits privilege gap
- Attacker gains elevated access through tool

**Impact:**
- Privilege escalation
- System compromise
- Data access beyond intended scope

**Mitigation:**
- MCP servers should run with least privilege
- Implement tool-level access controls
- Audit tool execution logs
- Use sandboxing for tool execution

---

## 4. Entry Points

### Connection Management

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `MCPManagerSingleton.connectToServer(config)` | Server config | Initialize MCP connection | Config contains URL, auth credentials |
| `MCPManagerSingleton.disconnect(serverId)` | Server ID | Close connection | Cleanup tokens, sessions |
| `MCPManagerSingleton.listConnections()` | None | List active connections | May reveal server infrastructure |

### Tool Operations

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `MCPManagerSingleton.listTools(serverId)` | Server ID | Discover available tools | Tool list may reveal capabilities |
| `MCPManagerSingleton.callTool(serverId, toolName, args)` | Server ID, tool name, arguments | Execute remote tool | Args may contain sensitive data |
| `client.callTool({ name, arguments })` | Tool call params | Low-level tool invocation | Direct SDK call, less validation |

### Resource Operations

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `MCPManagerSingleton.readResource(serverId, uri)` | Server ID, resource URI | Read remote resource | URI may be malicious |
| `client.readResource({ uri })` | Resource URI | Low-level resource read | Direct SDK call |
| `client.listResources()` | None | List available resources | May reveal data structure |

### Prompt Operations

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `MCPManagerSingleton.getPrompt(serverId, promptName)` | Server ID, prompt name | Retrieve prompt template | Prompt may contain malicious instructions |
| `client.getPrompt({ name, arguments })` | Prompt params | Low-level prompt retrieval | Direct SDK call |
| `client.listPrompts()` | None | List available prompts | Prompt names may reveal logic |

### OAuth Authentication

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `MCPOauth.authenticate(config)` | Server config | Perform OAuth flow | Config contains client credentials |
| `MCPOauth.refreshToken(serverId)` | Server ID | Refresh access token | Refresh token is sensitive |
| `MCPOauth.revokeToken(serverId)` | Server ID | Revoke tokens | Cleanup credentials |
| `MCPOauth.secureStoreTokens(tokens)` | OAuth tokens | Encrypt and store tokens | Critical for credential security |

### Transport Layer

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `new SSEClientTransport(url)` | Server URL | Create SSE transport | URL must be HTTPS |
| `new StdioClientTransport({ command, args })` | Command, args | Create stdio transport | Command execution risk |
| `new WebSocketClientTransport(url)` | Server URL | Create WebSocket transport | URL must be WSS |

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Type | Sensitivity | CIA Priority | Notes |
|-------|------|-------------|--------------|-------|
| **OAuth Access Tokens** | Credential | CRITICAL | Confidentiality | Short-lived, powerful access to MCP servers |
| **OAuth Refresh Tokens** | Credential | CRITICAL | Confidentiality | Long-lived, can generate new access tokens |
| **Client Credentials** | Credential | CRITICAL | Confidentiality | Client ID/Secret for OAuth |
| **User Content** | Data | HIGH | Confidentiality | Sent to external tools via MCP |
| **Tool Call Results** | Data | HIGH | Integrity | May contain sensitive information, must be validated |
| **Resource Contents** | Data | HIGH | Confidentiality | External data loaded into context |
| **Tool Definitions** | Configuration | HIGH | Integrity | Describes remote tool capabilities |
| **Server Configuration** | Configuration | HIGH | Confidentiality | Connection details, auth settings |
| **Prompt Templates** | Configuration | MEDIUM | Integrity | Reusable prompt structures |
| **Connection State** | State | MEDIUM | Integrity | Active sessions, server registry |

### CIA Triad Analysis

#### Confidentiality
- **Critical Risk:** OAuth tokens, client credentials, user content sent to tools
- **High Risk:** Tool call results, resource contents, server configurations
- **Controls:** TLS encryption, secure token storage, access controls, server allowlists

#### Integrity
- **Critical Risk:** Tool definitions, prompt templates (may contain malicious instructions)
- **High Risk:** Tool call results, resource contents
- **Controls:** Message validation, signature verification, allowlists, input sanitization

#### Availability
- **High Risk:** MCP server connections (required for tool execution)
- **Medium Risk:** OAuth token refresh, resource access
- **Controls:** Connection pooling, retry logic, timeout handling, fallback mechanisms

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Justification | Risk Mitigation |
|-----------|-------------|---------------|-----------------|
| **@modelcontextprotocol/sdk** | MEDIUM | Official Anthropic package, well-maintained, but runtime dependency with external network access | Pin versions, monitor for changes |
| **MCP Servers** | LOW-MEDIUM | External servers, potentially untrusted, variable security posture | Server allowlist, certificate validation |
| **OAuth Tokens** | MEDIUM | Short-lived but powerful, requires secure storage | Encrypt tokens, implement rotation |
| **User Input** | LOW | Untrusted, potential for injection attacks | Validate and sanitize all inputs |
| **Tool Outputs** | LOW | External data, requires validation | Validate against schemas, sanitize |
| **Network Channel** | MEDIUM | TLS-protected (if HTTPS/WSS), but MITM possible | Enforce HTTPS, certificate pinning |
| **stdio Transport** | MEDIUM-HIGH | Local process execution, but command injection risk | Validate commands, use allowlists |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    HIGH TRUST ZONE                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Continue Application Core                   │   │
│  │  - User interface                                        │   │
│  │  - LLM processing                                        │   │
│  │  - Credential management                                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           MEDIUM TRUST ZONE                              │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  MCPManagerSingleton                               │  │   │
│  │  │  - Connection management                           │  │   │
│  │  │  - Server allowlist ← TRUST BOUNDARY              │  │   │
│  │  │  - Tool validation                                 │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  MCPOauth                                          │  │   │
│  │  │  - Token storage (encrypted)                       │  │   │
│  │  │  - OAuth flow                                      │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           LOWER TRUST ZONE                               │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  @modelcontextprotocol/sdk                         │  │   │
│  │  │  - Protocol handling                               │  │   │
│  │  │  - Transport layer                                 │  │   │
│  │  │  - Message parsing                                 │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼ HTTPS/WSS                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           LOWEST TRUST ZONE                              │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  MCP Servers (External)                            │  │   │
│  │  │  - Unknown security posture                        │  │   │
│  │  │  - Potentially malicious                           │  │   │
│  │  │  - Variable trust levels                           │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment

**Overall Trust Level:** MEDIUM-HIGH RISK

**Rationale:** MCP enables connections to arbitrary external servers with varying trust levels. The protocol itself is well-designed, but the security depends heavily on:
1. Server configuration and allowlisting
2. Transport security (HTTPS/WSS enforcement)
3. OAuth flow implementation and token security
4. Tool and resource validation

**Key Trust Dependencies:**
- MCP server security posture (highly variable)
- OAuth authorization server security
- SDK implementation correctness
- Network security (TLS implementation)

**Critical Trust Boundary:** The boundary between Continue and external MCP servers is the most critical. Servers should be treated as untrusted until validated and allowlisted.

---

## 7. Architecture & Security Boundaries

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Continue Application                         │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    User / LLM Layer                          │   │
│  │  - User requests                                             │   │
│  │  - LLM generates tool calls                                  │   │
│  │  - Context management                                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              MCPManagerSingleton                             │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Server Registry                                       │ │   │
│  │  │  - Allowlist validation                                │ │   │
│  │  │  - Connection state management                         │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Tool Validator                                        │ │   │
│  │  │  - Tool allowlist per server                           │ │   │
│  │  │  - Argument schema validation                          │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Response Validator                                    │ │   │
│  │  │  - Result validation against schema                    │ │   │
│  │  │  - Sanitization                                        │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  MCPOauth                                    │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  OAuth 2.0 Flow                                        │ │   │
│  │  │  - Authorization code exchange                         │ │   │
│  │  │  - PKCE for public clients                             │ │   │
│  │  │  - Token refresh                                       │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Token Storage                                         │ │   │
│  │  │  - Encrypted storage                                   │ │   │
│  │  │  - Secure deletion                                     │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │         Transport Layer (@modelcontextprotocol/sdk)          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │
│  │  │ SSE          │  │ stdio        │  │ WebSocket    │      │   │
│  │  │ (HTTPS)      │  │ (Pipe)       │  │ (WSS)        │      │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Remote MCP      │  │ Local MCP       │  │ Remote MCP      │
│ Server          │  │ Server          │  │ Server          │
│ (HTTPS)         │  │ (stdio)         │  │ (WSS)           │
│                 │  │                 │  │                 │
│ - Tools         │  │ - CLI tools     │  │ - Resources     │
│ - Resources     │  │ - Scripts       │  │ - Prompts       │
│ - Prompts       │  │ - Commands      │  │ - Tools         │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Security Boundaries

#### Boundary 1: User/LLM → MCP Manager
- **Type:** Internal boundary
- **Trust:** HIGH → MEDIUM
- **Controls:** 
  - Tool call validation
  - Argument sanitization
  - Server allowlist check

#### Boundary 2: MCP Manager → SDK
- **Type:** Internal boundary
- **Trust:** MEDIUM → MEDIUM
- **Controls:**
  - Transport configuration validation
  - URL scheme enforcement (HTTPS/WSS)
  - Timeout configuration

#### Boundary 3: SDK → Network
- **Type:** Network boundary (CRITICAL)
- **Trust:** MEDIUM → LOW
- **Controls:**
  - TLS encryption enforcement
  - Certificate validation
  - Certificate pinning (for known servers)
  - Connection timeout

#### Boundary 4: OAuth Flow → Authorization Server
- **Type:** Network boundary (CRITICAL)
- **Trust:** MEDIUM → LOW
- **Controls:**
  - Redirect URI validation
  - PKCE for public clients
  - Secure token storage
  - Token encryption

#### Boundary 5: MCP Server → Tools/Resources
- **Type:** External boundary
- **Trust:** LOW → VARIABLE
- **Controls:**
  - Tool allowlist
  - Response validation
  - Result sanitization

### Data Flow Through Boundaries

```
User/LLM Tool Request
       │
       ▼
┌─────────────────┐
│ MCP Manager     │ ← Boundary 1: Server/Tool Allowlist Check
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Argument        │ ← Boundary 1: Argument Validation
│ Validator       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ MCP SDK         │ ← Boundary 2: Transport Configuration
└────────┬────────┘
         │
         ▼ HTTPS/WSS
┌─────────────────┐
│ Network         │ ← Boundary 3: TLS, Certificate Validation (CRITICAL)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ MCP Server      │
│ (External)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Tool Execution  │ ← Boundary 5: Response Validation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Result          │ ← Boundary 5: Result Sanitization
│ Sanitization    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Return to       │
│ User/LLM        │
└─────────────────┘
```

---

## 8. Security Recommendations

### Critical Priority (🔴)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 1 | **Implement server allowlist (trusted servers only)** | Maintain allowlist of approved MCP server URLs | LOW |
| 2 | **Enforce HTTPS/WSS for all transport layers** | Reject HTTP/WS connections, validate URL schemes | LOW |
| 3 | **Validate OAuth redirect URIs strictly** | Implement strict redirect URI validation, use PKCE | MEDIUM |

### High Priority (🟠)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 4 | **Add tool call allowlists per server** | Define allowed tools for each MCP server | MEDIUM |
| 5 | **Implement response validation for tool results** | Validate results against tool schemas | MEDIUM |
| 6 | **Add request timeouts for all MCP calls** | Configure timeouts (e.g., 30s) for all operations | LOW |
| 7 | **Encrypt OAuth tokens in storage** | Use encrypted storage for tokens (keychain, vault) | MEDIUM |

### Medium Priority (🟡)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 8 | **Implement structured logging with credential redaction** | Log MCP operations without exposing tokens | MEDIUM |
| 9 | **Add certificate pinning for known servers** | Pin certificates for trusted MCP servers | HIGH |
| 10 | **Implement resource URI validation** | Validate resource URIs before access | MEDIUM |
| 11 | **Add rate limiting for tool calls** | Prevent abuse and DoS | LOW |

### Low Priority (🟢)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 12 | **Document trusted server configuration** | Create documentation for server setup | LOW |
| 13 | **Implement server health checks** | Monitor MCP server availability | LOW |
| 14 | **Add audit logging for tool execution** | Track all tool calls for compliance | LOW |
| 15 | **Implement graceful degradation** | Handle server failures gracefully | MEDIUM |

### Implementation Checklist

```markdown
- [ ] Create server allowlist configuration
- [ ] Implement URL scheme validation (HTTPS/WSS only)
- [ ] Add strict OAuth redirect URI validation
- [ ] Implement PKCE for OAuth flow
- [ ] Create tool allowlist per server
- [ ] Add tool argument schema validation
- [ ] Implement tool result validation
- [ ] Configure request timeouts (30s default)
- [ ] Encrypt OAuth tokens in storage
- [ ] Add credential redaction to logging
- [ ] Implement certificate pinning for trusted servers
- [ ] Add resource URI validation
- [ ] Configure rate limiting for tool calls
- [ ] Document trusted server configuration
- [ ] Implement server health monitoring
- [ ] Add audit logging for tool execution
```

### Secure MCP Connection Example

```typescript
// ✅ SECURE - MCP connection with security controls
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

interface MCPServerConfig {
  id: string;
  url: string;
  allowedTools: string[];
  certificateFingerprint?: string; // For pinning
}

const TRUSTED_SERVERS: MCPServerConfig[] = [
  {
    id: 'trusted-tools',
    url: 'https://mcp.trusted-provider.com',
    allowedTools: ['read_file', 'search_code', 'git_status'],
    certificateFingerprint: 'SHA256:ABCD1234...'
  }
];

class SecureMCPManager {
  async connectToServer(config: MCPServerConfig): Promise<Client> {
    // 1. Validate server is in allowlist
    const trustedServer = TRUSTED_SERVERS.find(s => s.url === config.url);
    if (!trustedServer) {
      throw new Error(`Server not in allowlist: ${config.url}`);
    }
    
    // 2. Enforce HTTPS
    if (!config.url.startsWith('https://')) {
      throw new Error('Only HTTPS connections allowed');
    }
    
    // 3. Validate certificate (pinning if configured)
    if (config.certificateFingerprint) {
      await this.validateCertificate(config.url, config.certificateFingerprint);
    }
    
    // 4. Create transport with timeout
    const transport = new SSEClientTransport(new URL(config.url), {
      requestInit: {
        headers: { 'User-Agent': 'continue-mcp-client' },
        signal: AbortSignal.timeout(30000) // 30s timeout
      }
    });
    
    // 5. Connect with client info
    const client = new Client({
      name: 'continue-mcp-client',
      version: packageJson.version
    });
    
    await client.connect(transport);
    
    return client;
  }

  async callTool(
    client: Client,
    serverConfig: MCPServerConfig,
    toolName: string,
    args: any
  ): Promise<any> {
    // 1. Check tool is allowed
    if (!serverConfig.allowedTools.includes(toolName)) {
      throw new Error(`Tool not allowed: ${toolName}`);
    }
    
    // 2. Validate arguments against schema
    this.validateToolArgs(toolName, args);
    
    // 3. Call tool with timeout
    const result = await Promise.race([
      client.callTool({ name: toolName, arguments: args }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Tool call timeout')), 30000)
      )
    ]);
    
    // 4. Validate result
    this.validateToolResult(toolName, result);
    
    return result;
  }

  private validateToolArgs(toolName: string, args: any): void {
    // Validate against tool schema
    // Sanitize inputs
    // Check for injection attempts
  }

  private validateToolResult(toolName: string, result: any): void {
    // Validate result structure
    // Sanitize output
    // Check for malicious content
  }

  private async validateCertificate(url: string, fingerprint: string): Promise<void> {
    // Fetch certificate and validate fingerprint
    // Implement certificate pinning
  }
}
```

---

## Summary

**@modelcontextprotocol/sdk** is a critical dependency that enables Continue to connect to external MCP servers for tools, resources, and prompts. It introduces **HIGH risk** due to:

1. **External Server Connections:** MCP servers are external systems with variable security posture
2. **OAuth Credential Handling:** OAuth tokens provide powerful access and must be protected
3. **Tool Injection Risk:** Malicious tools can execute arbitrary code or exfiltrate data
4. **Transport Layer Attacks:** Network connections require strict TLS enforcement
5. **Protocol Exploitation:** JSON-RPC messages must be validated against schemas

**Key Security Controls:**
- Implement server allowlist (trusted servers only)
- Enforce HTTPS/WSS for all transport layers
- Validate OAuth redirect URIs strictly, use PKCE
- Add tool call allowlists per server
- Implement response validation for tool results
- Encrypt OAuth tokens in storage
- Add request timeouts for all MCP calls

**Overall Assessment:** MCP is a powerful protocol for extending AI capabilities, but it introduces significant security risks through external server connections. The security posture depends heavily on proper configuration (allowlists, TLS enforcement, token security) and validation (tool allowlists, response validation). With comprehensive security controls, MCP can be used safely, but it requires careful implementation and ongoing monitoring.

---

*Generated with [Continue](https://continue.dev)*

*Co-Authored-By: Continue <noreply@continue.dev>*
