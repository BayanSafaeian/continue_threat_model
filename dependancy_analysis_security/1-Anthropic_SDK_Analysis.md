# 🔍 Dependency Analysis: `@anthropic-ai/sdk`

**File Analyzed:** `core/llm/llms/Anthropic.ts`  
**Date:** 2026-05-25  
**Analyst:** Continue CLI Security Analysis

---

## 📋 Purpose (Usage in Codebase)

| Imported Type | Usage in File | Line(s) | Purpose |
|---------------|---------------|---------|---------|
| `AnthropicTool` | `convertToolToAnthropicTool()` | 36 | Type for tool schema conversion |
| `ContentBlockParam` | `convertMessageContentToBlocks()`, `getContentBlocksFromChatMessage()` | 69, 103 | Type for message content blocks |
| `MessageCreateParams` | `_streamChat()` return type | 252 | Type for API request body |
| `MessageParam` | `convertMessages()` return type | 103 | Type for converted messages |
| `RawContentBlockDeltaEvent` | `handleResponse()` | 180 | Type for SSE delta events |
| `RawContentBlockStartEvent` | `handleResponse()` | 175 | Type for SSE block start events |
| `RawMessageDeltaEvent` | `handleResponse()` | 171 | Type for message delta events |
| `RawMessageStartEvent` | `handleResponse()` | 167 | Type for message start events |
| `RawMessageStreamEvent` | `handleResponse()` | 164 | Type for SSE stream events |
| `ToolUseBlock` | `convertToolCallsToBlocks()` | 93 | Type for tool call blocks |

### ⚠️ Critical Finding: **TYPE-ONLY IMPORTS**

```typescript
// These are TypeScript type imports - NO runtime code executes from this package
import {
  Tool as AnthropicTool,
  ContentBlockParam,
  // ... etc
} from "@anthropic-ai/sdk/resources/messages.mjs";
```

**The SDK provides type definitions only - no functions are called from this package.**

---

## 📥 Data In (Parameters for Imported Types)

Since these are **types**, not functions, they define **data structures** that flow through the code:

| Type | Data Structure Defined | Fields/Properties |
|------|----------------------|-------------------|
| `AnthropicTool` | Tool definition | `name`, `description`, `input_schema` |
| `ContentBlockParam` | Message content blocks | `type` (text/image/thinking/tool_use/tool_result), `text`, `source`, `signature`, `tool_use_id` |
| `MessageCreateParams` | API request body | `model`, `max_tokens`, `messages`, `system`, `tools`, `temperature`, `top_p`, `top_k`, `stop_sequences`, `stream`, `thinking`, `tool_choice` |
| `MessageParam` | Converted message | `role` (user/assistant), `content` (ContentBlockParam[]) |
| `RawMessageStreamEvent` | SSE event | `type` (message_start/message_delta/content_block_start/content_block_delta/content_block_stop) |
| `RawMessageStartEvent` | Stream start event | `message`, `usage` (input_tokens, output_tokens, cache_*) |
| `RawMessageDeltaEvent` | Stream delta | `usage`, `stop_reason` |
| `RawContentBlockStartEvent` | Block start | `content_block` (type, id, name, data) |
| `RawContentBlockDeltaEvent` | Block delta | `delta` (type: text_delta/thinking_delta/signature_delta/input_json_delta) |
| `ToolUseBlock` | Tool call block | `type`, `id`, `name`, `input` |

---

## 📤 Data Out (Return Values from Imported Types)

Again, these are **types** - they define the **shape of data** that flows through the system:

| Type | Where Data "Returns" To | Data Flow |
|------|------------------------|-----------|
| `AnthropicTool` | `convertArgs()` → API request body | Internal → HTTP POST |
| `MessageParam` | `convertMessages()` → `_streamChat()` | Internal → HTTP POST |
| `MessageCreateParams` | `_streamChat()` → `this.fetch()` | Internal → HTTP POST |
| `RawMessageStreamEvent` | `streamSse(response)` → `handleResponse()` | HTTP Response → Internal parsing |
| `ToolUseBlock` | `convertToolCallsToBlocks()` → `getContentBlocksFromChatMessage()` | Internal → HTTP POST |

---

## ⚠️ Threats (Ways to Compromise This Component)

| Threat | Attack Vector | Impact | Likelihood |
|--------|---------------|--------|------------|
| **Supply Chain Compromise** | Malicious update to `@anthropic-ai/sdk` package | Type definitions could be modified to bypass validation or introduce vulnerabilities | 🟡 Medium |
| **Type Confusion Attack** | API returns data that doesn't match expected types | Could cause runtime errors or security bypasses if validation relies solely on types | 🟡 Medium |
| **Version Pinning Attack** | Unpinned version allows malicious version install | `package.json` with `^` or `~` could pull compromised version | 🟡 Medium |
| **Type Definition Manipulation** | Compromised types could hide malicious behavior | Types might not match actual API behavior, leading to unexpected data handling | 🟠 Low |
| **Dependency Confusion** | Attacker publishes malicious package with same name | If internal registry misconfigured, could pull malicious package | 🟠 Low |
| **Build-Time Injection** | Malicious code injected during build process | Types are erased at runtime, but build tools could be compromised | 🟠 Low |

### Specific Attack Scenarios:

```typescript
// Scenario 1: Type Mismatch Leading to Security Bypass
// If API returns unexpected fields not in type definition:
const event = rawEvent as RawMessageStreamEvent;
// TypeScript type assertion doesn't validate at runtime!
// Malicious data could pass through unchecked

// Scenario 2: Compromised Type Definition
// If AnthropicTool type is modified to include malicious schema:
private convertToolToAnthropicTool(tool: Tool): AnthropicTool {
  return {
    name: tool.function.name,
    description: tool.function.description,
    input_schema: (tool.function.parameters as AnthropicTool.InputSchema) ?? {
      // Compromised type could have different default structure
      type: "object",
    },
  };
}
```

---

## 🚪 Entry Points (Classes/Functions That Use It)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Entry Points in Anthropic.ts                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Anthropic class (extends BaseLLM)                           │
│     └── convertToolToAnthropicTool(tool: Tool)                  │
│         └── Uses: AnthropicTool type                            │
│                                                                  │
│     └── convertArgs(options: CompletionOptions)                 │
│         └── Returns: MessageCreateParams type                   │
│                                                                  │
│     └── convertMessageContentToBlocks(content: MessageContent)  │
│         └── Returns: ContentBlockParam[] type                   │
│                                                                  │
│     └── convertToolCallsToBlocks(toolCall: ToolCallDelta)       │
│         └── Returns: ToolUseBlock type                          │
│                                                                  │
│     └── getContentBlocksFromChatMessage(message: ChatMessage)   │
│         └── Returns: ContentBlockParam[] type                   │
│                                                                  │
│     └── convertMessages(msgs: ChatMessage[], cachePrompt: bool) │
│         └── Returns: MessageParam[] type                        │
│                                                                  │
│     └── _streamChat(messages, signal, options)                  │
│         └── Uses: MessageCreateParams, MessageParam types       │
│                                                                  │
│     └── handleResponse(response, stream)                        │
│         └── Uses: All Raw*Event types for SSE parsing           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Call Chain:
```
User Input → Continue CLI → Anthropic class methods → Type validation → HTTP request
                                                              ↓
API Response → SSE Stream → handleResponse() → Type parsing → ChatMessage output
```

---

## 💎 Assets (Sensitive Data Being Operated On)

| Asset | Type | Sensitivity | How Types Protect/Expose It |
|-------|------|-------------|----------------------------|
| **API Key** | String | 🔴 HIGH | Not directly in types - handled in `getAnthropicHeaders()` |
| **User Prompts** | MessageContent | 🟠 MEDIUM-HIGH | `ContentBlockParam` defines structure for prompts sent to API |
| **Conversation History** | ChatMessage[] | 🟠 MEDIUM-HIGH | `MessageParam` defines structure for full conversation |
| **Tool Definitions** | Tool[] | 🟡 MEDIUM | `AnthropicTool` defines schema sent to API |
| **Tool Call Arguments** | ToolCallDelta | 🟠 MEDIUM-HIGH | `ToolUseBlock` defines parsed tool inputs |
| **API Responses** | RawMessageStreamEvent | 🟡 MEDIUM | Event types define streaming response structure |
| **Usage Statistics** | Usage object | 🟢 LOW | Token counts in `RawMessageStartEvent`, `RawMessageDeltaEvent` |
| **Thinking/Reasoning** | Thinking blocks | 🟠 MEDIUM | `thinking` type defines model reasoning (may reveal internal logic) |

---

## 🔐 Trust Level

| Aspect | Trust Level | Justification |
|--------|-------------|---------------|
| **Package Source** | 🟢 HIGH | Official Anthropic SDK - published by Anthropic Inc. |
| **Type Safety** | 🟡 MEDIUM | TypeScript types provide compile-time safety, but NO runtime validation |
| **Runtime Code** | 🟢 HIGH | No runtime code from SDK executes - types are erased at compile time |
| **Update Frequency** | 🟡 MEDIUM | Should monitor for unexpected changes in type definitions |
| **Community Scrutiny** | 🟢 HIGH | Widely used package - vulnerabilities likely to be discovered |
| **Overall Trust** | 🟡 MEDIUM-HIGH | Trusted source, but types alone don't provide security guarantees |

### Trust Considerations:

```
✅ POSITIVE:
   - Official package from Anthropic
   - Type-only usage (no runtime code execution)
   - Widely adopted in ecosystem
   - Regular security updates

⚠️ CONCERNS:
   - Types don't validate at runtime
   - Supply chain attacks still possible
   - Version pinning may be lax
   - Type definitions could drift from actual API
```

---

## 🔗 Where Connected (Connection to Main Functionality)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Anthropic.ts Architecture                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                    @anthropic-ai/sdk                                   │ │
│  │              (TYPE DEFINITIONS ONLY)                                   │ │
│  │                                                                        │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐   │ │
│  │  │ AnthropicTool│  │ContentBlock │  │ MessageCreateParams         │   │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘   │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐   │ │
│  │  │ MessageParam │  │ Raw*Event   │  │ ToolUseBlock                │   │ │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                              │ TYPE ANNOTATIONS                             │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                    Anthropic Class (This File)                         │ │
│  │                                                                        │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │ │
│  │  │  convertToolToAnthropicTool()                                    │  │ │
│  │  │  convertMessageContentToBlocks()                                 │  │ │
│  │  │  convertMessages()                                               │  │ │
│  │  │  convertArgs()                                                   │  │ │
│  │  └─────────────────────────────────────────────────────────────────┘  │ │
│  │                              │                                         │ │
│  │                              ▼                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │ │
│  │  │  _streamChat()                                                   │  │ │
│  │  │  - Builds request body using types                               │  │ │
│  │  │  - Calls this.fetch()                                            │  │ │
│  │  └─────────────────────────────────────────────────────────────────┘  │ │
│  │                              │                                         │ │
│  │                              ▼                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │ │
│  │  │  handleResponse()                                                │  │ │
│  │  │  - Parses SSE stream using Raw*Event types                       │  │ │
│  │  │  - Yields ChatMessage objects                                    │  │ │
│  │  └─────────────────────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                    @continuedev/fetch                                  │ │
│  │              (ACTUAL HTTP COMMUNICATION)                               │ │
│  │              this.fetch() → api.anthropic.com/v1/messages              │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Connection Summary:

| Connection Point | How Connected | Data Flow |
|------------------|---------------|-----------|
| **Type Definitions** | Import statements | SDK types → Local type annotations |
| **Request Building** | `convertArgs()`, `convertMessages()` | Internal data → SDK-typed request body |
| **Response Parsing** | `handleResponse()` | SDK-typed SSE events → Internal ChatMessage |
| **Tool Handling** | `convertToolToAnthropicTool()`, `convertToolCallsToBlocks()` | Internal tools → SDK-typed tool blocks |

---

## 📊 Summary Table

| Category | Assessment | Key Takeaways |
|----------|------------|---------------|
| **Purpose** | Provides TypeScript type definitions for Anthropic API request/response structures. Type-only imports (no runtime code execution). | Types ≠ Security. Compile-time safety only. No runtime validation. |
| **Data In** | Tool definitions, user prompts (text/images), conversation history, request parameters, SSE events from API, tool call data, thinking blocks, usage stats. | User prompts and tool calls are HIGH sensitivity. Full conversation exposed to API. |
| **Data Out** | Request body (JSON), converted messages, tool schemas, parsed ChatMessages, tool call objects, thinking blocks, usage data, streaming chunks. | Tool calls are executable - validate before use. No output sanitization visible. |
| **Threats** | Supply chain compromise, type confusion, version pinning attacks, dependency confusion, build-time injection, type definition drift, runtime type erasure exploitation. | Biggest risks: Supply chain attack, type confusion at runtime, false sense of security from types. |
| **Entry Points** | 9 methods total. Critical: `convertMessageContentToBlocks()` (user input), `handleResponse()` (API response), `_streamChat()` (request sending). | Three high-risk entry points need security review. All accept untrusted data. |
| **Assets** | API Key (CRITICAL), User Prompts/History/Tool Args (HIGH), Tool Definitions/Response Stream/Thinking (MEDIUM), Usage Stats (LOW). | API key is crown jewel. Conversation history is high value. Protect all HIGH+ assets. |
| **Trust Level** | 🟡 MEDIUM-HIGH (trusted source, but types ≠ runtime security). Package source trusted (official Anthropic). Runtime safety LOW (types erased). | Don't trust types at runtime. Verify all API responses. Defense in depth required. |
| **Where Connected** | Type annotations only - actual HTTP via `@continuedev/fetch`. Three security boundary modules handle critical operations. | This file coordinates security-critical operations but delegates actual security work to other modules. |

---

## 🛡️ Security Recommendations

### Priority 1 (Critical):
- [ ] Audit `@continuedev/fetch` for TLS validation and certificate pinning
- [ ] Audit `@continuedev/openai-adapters` for secure API key handling
- [ ] Audit `../../tools/parseArgs.js` for tool call input validation

### Priority 2 (High):
- [ ] Pin exact version of `@anthropic-ai/sdk` in package.json (no `^` or `~`)
- [ ] Add runtime validation for API responses (don't trust type assertions)
- [ ] Implement input sanitization before sending to external API

### Priority 3 (Medium):
- [ ] Monitor SDK for security advisories and unexpected type changes
- [ ] Implement request/response logging (without sensitive data)
- [ ] Add timeout and retry logic for API calls

### Priority 4 (Low):
- [ ] Document type assumptions and API version dependencies
- [ ] Add integration tests for type/API mismatches

---

## 🎯 Key Security Takeaway

> **This dependency provides TYPE SAFETY, not SECURITY.** The types help catch bugs at compile-time but provide NO runtime validation. All security-critical operations (authentication, input validation, output sanitization) happen in other modules (`@continuedev/fetch`, `@continuedev/openai-adapters`, `../../tools/parseArgs.js`).

**The real security critical dependencies are:**
1. `@continuedev/fetch` - handles actual HTTP communication
2. `@continuedev/openai-adapters` - handles authentication headers
3. `../../tools/parseArgs.js` - handles tool call parsing

---

*Generated with Continue CLI Security Analysis*
