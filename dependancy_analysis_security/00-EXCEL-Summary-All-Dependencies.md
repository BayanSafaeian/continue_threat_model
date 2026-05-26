# Excel Comparison Table - All 20 Dependencies

**Format:** `Dependency Name | Data In | Data Out | Threats | Entry Points | Assets | Trust Level | Where Connected`

---

## Complete Dependency List

| # | Dependency | Data In | Data Out | Threats | Entry Points | Assets | Trust Level | Where Connected |
|---|------------|---------|----------|---------|--------------|--------|-------------|-----------------|
| 1 | **child_process** | Commands, args, env vars, file paths | stdout/stderr, exit codes, spawned processes | Command injection (9.8), Path traversal (8.5), Env var injection (8.1), Resource exhaustion (7.5) | exec(), spawn(), execSync(), spawnSync() | System integrity, Process isolation, File system | 🔴 LOW | core/util/child_process.ts - Shell command execution |
| 2 | **AWS Bedrock Runtime SDK** | API keys, prompts, model configs, AWS credentials | LLM responses, tokens, embeddings, model outputs | Credential leakage (8.6), Prompt injection (7.5), Model hijacking (7.3), Data exfiltration (8.1) | BedrockRuntimeClient, invokeModel(), converse() | API keys, User prompts, LLM responses, AWS credentials | 🟠 HIGH | core/llm/aws/Bedrock.ts - AWS LLM integration |
| 3 | **Anthropic SDK** | API keys, prompts, system messages, conversation history | LLM completions, tokens, embeddings, error responses | API key exposure (8.6), Prompt injection (7.5), Token leakage (7.3), Data retention (6.5) | Anthropic client, messages.create(), completions | API keys, Prompts, Completions, Conversation history | 🟠 HIGH | core/llm/anthropic.ts - Anthropic API integration |
| 4 | **Gemini SDK** | API keys, prompts, system instructions, context | LLM responses, embeddings, safety ratings, citations | API key leakage (8.6), Prompt injection (7.5), Unsafe content (7.1), Data scraping (6.8) | GoogleGenerativeAI, getGenerativeModel(), generateContent() | API keys, Prompts, Responses, Safety data | 🟠 HIGH | core/llm/gemini.ts - Google Gemini integration |
| 5 | **MCP SDK** | Server configs, tool inputs, prompt args, connection params | Tool results, prompts, resources, server statuses | Server injection (8.1), Tool hijacking (7.8), Config tampering (7.5), Resource access (7.3) | Client, connect(), listTools(), callTool(), getPrompt() | MCP configs, Tool access, Prompts, Resources | 🟠 HIGH | core/context/mcp/MCPConnection.ts - MCP protocol |
| 6 | **axios** | URLs, headers, request bodies, auth tokens | HTTP responses, error objects, response headers | SSRF (8.2), Header injection (6.5), Credential leakage (7.3), Redirect attacks (6.8) | axios(), get(), post(), request() | API endpoints, Auth tokens, Request/response data | 🟡 MEDIUM-HIGH | packages/fetch/src/node-fetch-patch.ts - HTTP client |
| 7 | **sentry_core** | Error objects, stack traces, breadcrumbs, user context | Error reports, session data, performance metrics | Data leakage (7.5), PII exposure (6.8), Stack trace disclosure (5.9), DSN exposure (5.3) | Sentry.init(), captureException(), captureMessage() | Error data, Stack traces, User context, PII | 🟡 MEDIUM-HIGH | core/util/sentry.ts - Error tracking |
| 8 | **opentelemetry** | Spans, traces, metrics, attributes, context | Trace data, metrics, spans, telemetry exports | Trace data leakage (6.5), Context pollution (5.9), Performance overhead (5.3), Export injection (5.7) | trace.getTracer(), span.setAttribute(), metrics.getMeter() | Trace data, Span attributes, Metrics, Context | 🟡 MEDIUM | core/util/telemetry.ts - Observability |
| 9 | **adm-zip** | ZIP file paths, file contents, compression options | Extracted files, ZIP entries, file metadata | Path traversal (8.5), ZIP slip (8.2), File overwrite (7.8), Malicious archives (7.5) | AdmZip(), extractAllTo(), extractEntryTo(), getEntries() | File system, Extracted contents, Archive metadata | 🟡 MEDIUM | core/util/zip.ts - ZIP compression/extraction |
| 10 | **@continuedev/fetch** | URLs, headers, request bodies, proxy configs, RequestOptions | HTTP responses, response headers, error objects | Credential logging (7.5), Proxy injection (8.1), Body injection (7.3), Header smuggling (5.3) | fetchwithRequestOptions() | API keys, Auth tokens, Proxies, Request/response data | 🟡 MEDIUM-HIGH | packages/fetch/src/fetch.ts - Custom HTTP wrapper |
| 11 | **tree-sitter** | File paths, source code contents, language extensions | Symbol lists, parse trees, code content, error messages | Code exfiltration (7.1), WASM tampering (7.8), Path traversal (6.5), DoS via large files (5.9) | getSymbolsForFile(), getParserForFile(), getLanguageForFile() | Source code, Code structure, File paths, WASM modules | 🟡 MEDIUM | core/util/treeSitter.ts - Code parsing |
| 12 | **ConfigHandler** | Config YAML files, session tokens, IDE settings, org/profile selections | ContinueConfig (with API keys), serialized configs, error messages | API key exposure (8.6), Token handling (8.1), Config injection (7.5), Telemetry leakage (5.9) | constructor(), reloadConfig(), setSelectedOrgId(), getSerializedConfig() | API keys, Session tokens, Config files, User selections | 🟠 HIGH | core/config/ConfigHandler.ts - Config management |
| 13 | **MCPManagerSingleton** | Server configs (commands, URLs, env vars), connection params | MCP clients, tool results, prompts, connection statuses | Command execution (8.8), Env var injection (8.1), Singleton abuse (7.3), URL manipulation (7.5) | getInstance(), createConnection(), setEnabled(), getPrompt() | Commands, Env vars, MCP connections, Tool results | 🟠 HIGH | core/context/mcp/MCPManagerSingleton.ts - MCP manager |
| 14 | **control-plane/auth** | IDE settings, auth type, onboarding flag, env config | Auth URLs, state tokens, redirect URIs, client IDs | CSRF (8.1), Open redirect (8.6), Client ID exposure (6.5), Config tampering (7.5) | getAuthUrlForTokenPage() | State tokens, Auth codes, Client IDs, Redirect URIs | 🟠 HIGH | core/control-plane/auth/index.ts - OAuth2 auth |
| 15 | **core.ts (index)** | Module imports, type definitions, exports | Exported types, functions, classes, interfaces | Supply chain (7.5), Type confusion (6.3), Export pollution (5.9), Circular deps (5.3) | All exports from core/index.ts | All core types, Functions, Classes, Interfaces | 🟠 HIGH | core/index.ts - Core module index |
| 16 | **streamDiffLines** | Original code, new code, file paths, language hints | Diff lines, change locations, edit operations | Code injection (7.8), Path disclosure (5.7), Edit hijacking (7.3), Diff pollution (6.5) | streamDiffLines(), applyDiff(), parseDiff() | Source code, Diff operations, File paths, Edits | 🟠 HIGH | core/llm/streamDiffLines.ts - Code streaming |
| 17 | **DocsService** | Documentation URLs, embeddings, index configs, search queries | Search results, indexed docs, embeddings, metadata | URL injection (7.1), Index poisoning (7.5), Search XSS (6.5), Data leakage (6.8) | DocsService.getInstance(), index(), search() | Doc URLs, Embeddings, Search index, Results | 🟡 MEDIUM | core/indexing/docsService.ts - Documentation |
| 18 | **CodebaseIndexer** | File paths, file contents, git info, index configs | Indexed symbols, embeddings, code vectors, metadata | Code leakage (7.1), Path traversal (6.5), Index poisoning (7.3), Git info disclosure (5.9) | CodebaseIndexer, indexFile(), indexWorkspace() | Codebase contents, Index data, Git info, Symbols | 🟡 MEDIUM | core/indexing/CodebaseIndexer.ts - Code indexing |
| 19 | **CompletionProvider** | Editor context, cursor position, user input, config | Completion suggestions, inline edits, code snippets | Code injection (7.5), Context leakage (6.8), Suggestion poisoning (7.1), Prompt manipulation (7.3) | CompletionProvider, provideCompletions(), streamCompletion() | Editor context, Completions, User input, Config | 🟡 MEDIUM | core/completion/CompletionProvider.ts - Autocomplete |
| 20 | **devdataSqlite** | Dev data objects, telemetry events, performance metrics | Query results, aggregated stats, session data | SQL injection (7.3), Data leakage (6.5), Privacy violation (6.8), DB corruption (5.9) | DevDataSqlite, logDevData(), queryDevData() | Telemetry data, Dev logs, Metrics, Session data | 🟢 LOW-MEDIUM | core/util/devdataSqlite.ts - Local data storage |
| 21 | **GlobalContext** | Context keys, values, workspace IDs, selections | Stored values, preferences, cached data | Data tampering (6.5), Persistence abuse (5.9), Info disclosure (5.3), State pollution (5.7) | GlobalContext, get(), update(), delete() | User preferences, Cached data, Selections, State | 🟡 MEDIUM | core/util/GlobalContext.ts - State management |

---

## Risk Summary by Category

### By Risk Level
| Risk Level | Count | Percentage |
|------------|-------|------------|
| 🔴 CRITICAL | 1 | 5% |
| 🟠 HIGH | 8 | 38% |
| 🟡 MEDIUM | 11 | 52% |
| 🟢 LOW | 1 | 5% |

### By Data Type
| Data Category | Dependencies | Primary Risks |
|---------------|--------------|---------------|
| **LLM APIs** | AWS Bedrock, Anthropic, Gemini | API key leakage, Prompt injection |
| **System Access** | child_process, adm-zip | Command injection, Path traversal |
| **HTTP/Network** | axios, @continuedev/fetch | SSRF, Credential leakage |
| **Configuration** | ConfigHandler, MCPManagerSingleton | Config injection, Credential exposure |
| **Authentication** | control-plane/auth, MCP SDK | CSRF, Token theft |
| **Code Processing** | tree-sitter, CodebaseIndexer, streamDiffLines | Code exfiltration, Injection |
| **Telemetry** | sentry_core, opentelemetry, devdataSqlite | Data leakage, PII exposure |
| **Context/State** | GlobalContext, CompletionProvider, DocsService | State pollution, Context leakage |

### By Trust Level
| Trust Level | Count | Dependencies |
|-------------|-------|--------------|
| 🔴 LOW | 2 | child_process, MCPManagerSingleton |
| 🟡 MEDIUM | 13 | AWS Bedrock, Anthropic, Gemini, MCP_SDK, axios, sentry_core, opentelemetry, adm-zip, fetch, tree-sitter, ConfigHandler, control-plane-auth, core_ts |
| 🟢 HIGH | 6 | streamDiffLines, DocsService, CodebaseIndexer, CompletionProvider, devdataSqlite, GlobalContext |

---

## Excel-Ready CSV Format

```csv
Dependency,Data_In,Data_Out,Threats,Entry_Points,Assets,Trust_Level,Where_Connected
child_process,"Commands, args, env vars, file paths","stdout/stderr, exit codes, spawned processes","Command injection (9.8), Path traversal (8.5), Env var injection (8.1), Resource exhaustion (7.5)","exec(), spawn(), execSync(), spawnSync()","System integrity, Process isolation, File system",LOW,"core/util/child_process.ts"
AWS_Bedrock_SDK,"API keys, prompts, model configs, AWS credentials","LLM responses, tokens, embeddings, model outputs","Credential leakage (8.6), Prompt injection (7.5), Model hijacking (7.3), Data exfiltration (8.1)","BedrockRuntimeClient, invokeModel(), converse()","API keys, User prompts, LLM responses, AWS credentials",HIGH,"core/llm/aws/Bedrock.ts"
Anthropic_SDK,"API keys, prompts, system messages, conversation history","LLM completions, tokens, embeddings, error responses","API key exposure (8.6), Prompt injection (7.5), Token leakage (7.3), Data retention (6.5)","Anthropic client, messages.create(), completions","API keys, Prompts, Completions, Conversation history",HIGH,"core/llm/anthropic.ts"
Gemini_SDK,"API keys, prompts, system instructions, context","LLM responses, embeddings, safety ratings, citations","API key leakage (8.6), Prompt injection (7.5), Unsafe content (7.1), Data scraping (6.8)","GoogleGenerativeAI, getGenerativeModel(), generateContent()","API keys, Prompts, Responses, Safety data",HIGH,"core/llm/gemini.ts"
MCP_SDK,"Server configs, tool inputs, prompt args, connection params","Tool results, prompts, resources, server statuses","Server injection (8.1), Tool hijacking (7.8), Config tampering (7.5), Resource access (7.3)","Client, connect(), listTools(), callTool(), getPrompt()","MCP configs, Tool access, Prompts, Resources",HIGH,"core/context/mcp/MCPConnection.ts"
axios,"URLs, headers, request bodies, auth tokens","HTTP responses, error objects, response headers","SSRF (8.2), Header injection (6.5), Credential leakage (7.3), Redirect attacks (6.8)","axios(), get(), post(), request()","API endpoints, Auth tokens, Request/response data",MEDIUM-HIGH,"packages/fetch/src/node-fetch-patch.ts"
sentry_core,"Error objects, stack traces, breadcrumbs, user context","Error reports, session data, performance metrics","Data leakage (7.5), PII exposure (6.8), Stack trace disclosure (5.9), DSN exposure (5.3)","Sentry.init(), captureException(), captureMessage()","Error data, Stack traces, User context, PII",MEDIUM-HIGH,"core/util/sentry.ts"
opentelemetry,"Spans, traces, metrics, attributes, context","Trace data, metrics, spans, telemetry exports","Trace data leakage (6.5), Context pollution (5.9), Performance overhead (5.3), Export injection (5.7)","trace.getTracer(), span.setAttribute(), metrics.getMeter()","Trace data, Span attributes, Metrics, Context",MEDIUM,"core/util/telemetry.ts"
adm-zip,"ZIP file paths, file contents, compression options","Extracted files, ZIP entries, file metadata","Path traversal (8.5), ZIP slip (8.2), File overwrite (7.8), Malicious archives (7.5)","AdmZip(), extractAllTo(), extractEntryTo(), getEntries()","File system, Extracted contents, Archive metadata",MEDIUM,"core/util/zip.ts"
@continuedev/fetch,"URLs, headers, request bodies, proxy configs, RequestOptions","HTTP responses, response headers, error objects","Credential logging (7.5), Proxy injection (8.1), Body injection (7.3), Header smuggling (5.3)","fetchwithRequestOptions()","API keys, Auth tokens, Proxies, Request/response data",MEDIUM-HIGH,"packages/fetch/src/fetch.ts"
tree-sitter,"File paths, source code contents, language extensions","Symbol lists, parse trees, code content, error messages","Code exfiltration (7.1), WASM tampering (7.8), Path traversal (6.5), DoS via large files (5.9)","getSymbolsForFile(), getParserForFile(), getLanguageForFile()","Source code, Code structure, File paths, WASM modules",MEDIUM,"core/util/treeSitter.ts"
ConfigHandler,"Config YAML files, session tokens, IDE settings, org/profile selections","ContinueConfig (with API keys), serialized configs, error messages","API key exposure (8.6), Token handling (8.1), Config injection (7.5), Telemetry leakage (5.9)","constructor(), reloadConfig(), setSelectedOrgId(), getSerializedConfig()","API keys, Session tokens, Config files, User selections",HIGH,"core/config/ConfigHandler.ts"
MCPManagerSingleton,"Server configs (commands, URLs, env vars), connection params","MCP clients, tool results, prompts, connection statuses","Command execution (8.8), Env var injection (8.1), Singleton abuse (7.3), URL manipulation (7.5)","getInstance(), createConnection(), setEnabled(), getPrompt()","Commands, Env vars, MCP connections, Tool results",HIGH,"core/context/mcp/MCPManagerSingleton.ts"
control-plane/auth,"IDE settings, auth type, onboarding flag, env config","Auth URLs, state tokens, redirect URIs, client IDs","CSRF (8.1), Open redirect (8.6), Client ID exposure (6.5), Config tampering (7.5)","getAuthUrlForTokenPage()","State tokens, Auth codes, Client IDs, Redirect URIs",HIGH,"core/control-plane/auth/index.ts"
core.ts,"Module imports, type definitions, exports","Exported types, functions, classes, interfaces","Supply chain (7.5), Type confusion (6.3), Export pollution (5.9), Circular deps (5.3)","All exports from core/index.ts","All core types, Functions, Classes, Interfaces",HIGH,"core/index.ts"
streamDiffLines,"Original code, new code, file paths, language hints","Diff lines, change locations, edit operations","Code injection (7.8), Path disclosure (5.7), Edit hijacking (7.3), Diff pollution (6.5)","streamDiffLines(), applyDiff(), parseDiff()","Source code, Diff operations, File paths, Edits",HIGH,"core/llm/streamDiffLines.ts"
DocsService,"Documentation URLs, embeddings, index configs, search queries","Search results, indexed docs, embeddings, metadata","URL injection (7.1), Index poisoning (7.5), Search XSS (6.5), Data leakage (6.8)","DocsService.getInstance(), index(), search()","Doc URLs, Embeddings, Search index, Results",MEDIUM,"core/indexing/docsService.ts"
CodebaseIndexer,"File paths, file contents, git info, index configs","Indexed symbols, embeddings, code vectors, metadata","Code leakage (7.1), Path traversal (6.5), Index poisoning (7.3), Git info disclosure (5.9)","CodebaseIndexer, indexFile(), indexWorkspace()","Codebase contents, Index data, Git info, Symbols",MEDIUM,"core/indexing/CodebaseIndexer.ts"
CompletionProvider,"Editor context, cursor position, user input, config","Completion suggestions, inline edits, code snippets","Code injection (7.5), Context leakage (6.8), Suggestion poisoning (7.1), Prompt manipulation (7.3)","CompletionProvider, provideCompletions(), streamCompletion()","Editor context, Completions, User input, Config",MEDIUM,"core/completion/CompletionProvider.ts"
devdataSqlite,"Dev data objects, telemetry events, performance metrics","Query results, aggregated stats, session data","SQL injection (7.3), Data leakage (6.5), Privacy violation (6.8), DB corruption (5.9)","DevDataSqlite, logDevData(), queryDevData()","Telemetry data, Dev logs, Metrics, Session data",LOW-MEDIUM,"core/util/devdataSqlite.ts"
GlobalContext,"Context keys, values, workspace IDs, selections","Stored values, preferences, cached data","Data tampering (6.5), Persistence abuse (5.9), Info disclosure (5.3), State pollution (5.7)","GlobalContext, get(), update(), delete()","User preferences, Cached data, Selections, State",MEDIUM,"core/util/GlobalContext.ts"
```

---

## Quick Reference - Top 10 Critical Risks

| Rank | Dependency | Top Threat | CVSS | Immediate Action |
|------|------------|------------|------|------------------|
| 1 | child_process | Command Injection | 9.8 | Implement command whitelisting |
| 2 | control-plane/auth | Open Redirect | 8.6 | Validate redirect URIs |
| 3 | AWS Bedrock SDK | Credential Leakage | 8.6 | Redact credentials in logs |
| 4 | Anthropic SDK | API Key Exposure | 8.6 | Use secure token storage |
| 5 | Gemini SDK | API Key Leakage | 8.6 | Implement key rotation |
| 6 | ConfigHandler | API Key Exposure | 8.6 | Redact in config distribution |
| 7 | MCPManagerSingleton | Command Execution | 8.8 | Validate server commands |
| 8 | axios | SSRF | 8.2 | Implement URL validation |
| 9 | adm-zip | Path Traversal | 8.5 | Validate extraction paths |
| 10 | MCP SDK | Server Injection | 8.1 | Whitelist MCP servers |

---

*Generated: 2026-05-25*  
*Course: CSS577 - Secure Software Development*  
*Project: Continue CLI Security Analysis*
