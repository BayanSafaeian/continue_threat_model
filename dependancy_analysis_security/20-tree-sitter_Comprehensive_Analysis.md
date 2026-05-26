# 🔒 Comprehensive Security Analysis: tree-sitter WASM [Code Parsing]

**Package:** `web-tree-sitter@0.21.0`, `tree-sitter-wasms@0.1.11`  
**Used In:** `/core/util/treeSitter.ts` (code parsing and symbol extraction)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟡 **MEDIUM**

---

## 1. Dependency Purpose & Usage

### Primary Function
The tree-sitter integration provides code parsing and AST (Abstract Syntax Tree) generation for:
- Multi-language source code parsing (30+ languages)
- Symbol extraction (classes, functions, methods)
- Code indexing for semantic search
- Context-aware code completion
- Static analysis for autocomplete features

### Implementation
```typescript
import Parser, { Language } from "web-tree-sitter";

// Initialize parser and load language
export async function getParserForFile(filepath: string) {
  await Parser.init();
  const parser = new Parser();
  const language = await getLanguageForFile(filepath);
  parser.setLanguage(language);
  return parser;
}

// Load WASM-based language grammar
async function loadLanguageForFileExt(fileExtension: string): Promise<Language> {
  const wasmPath = path.join(
    __dirname,
    "tree-sitter-wasms",
    `tree-sitter-${supportedLanguages[fileExtension]}.wasm`
  );
  return await Parser.Language.load(wasmPath);
}

// Parse file and extract symbols
export async function getSymbolsForFile(
  filepath: string,
  contents: string,
): Promise<SymbolWithRange[] | undefined> {
  const parser = await getParserForFile(filepath);
  if (!parser) return;
  
  const tree = parser.parse(contents);
  
  const symbols: SymbolWithRange[] = [];
  function findNamedNodesRecursive(node: Parser.SyntaxNode) {
    if (GET_SYMBOLS_FOR_NODE_TYPES.includes(node.type)) {
      // Extract identifier and location
      symbols.push({
        filepath,
        type: node.type,
        name: identifier.text,
        range: { start, end },
        content: node.text,  // Full code content
      });
    }
    node.children.forEach(findNamedNodesRecursive);
  }
  findNamedNodesRecursive(tree.rootNode);
  return symbols;
}
```

### Dependency Type
- **External npm packages** - `web-tree-sitter`, `tree-sitter-wasms`
- **WASM binaries** - Pre-compiled language grammars
- **Native code execution** - WASM runtime in Node.js/browser
- **Internal utility** - Code parsing and indexing

---

## 2. Data Flow Analysis

### Inbound Data

| Data Type | Source | Sensitivity | Validation |
|-----------|--------|-------------|------------|
| Source code files | User's filesystem | 🔴 **CRITICAL** | None |
| File paths | IDE/workspace | 🟡 **MEDIUM** | Path validation |
| File contents | User's codebase | 🔴 **CRITICAL** | None |
| WASM binaries | npm registry | 🟡 **MEDIUM** | Package integrity |
| Language queries | tree-sitter repo | 🟢 **LOW** | Fixed at build |

### Outbound Data

| Data Type | Destination | Sensitivity | Access Control |
|-----------|-------------|-------------|----------------|
| Symbol data | Indexing service | 🟡 **MEDIUM** | In-process |
| AST nodes | Code completion | 🟡 **MEDIUM** | In-process |
| Parsed code | Context service | 🔴 **CRITICAL** | In-process |
| File contents | Memory (AST) | 🔴 **CRITICAL** | Process isolation |

### Data Storage

| Storage Location | Data Type | Encryption | Access Control |
|------------------|-----------|------------|----------------|
| Memory (Parser) | AST tree | ❌ **NONE** | Process isolation |
| Memory (symbols) | Symbol metadata | ❌ **NONE** | Process isolation |
| Disk (WASM) | Language grammars | ❌ **NONE** | File permissions |
| Disk (cache) | Parsed results | ❌ **NONE** | File permissions |

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                      User's Filesystem                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Source Files │  │ Config Files │  │ Dependencies │         │
│  │ (.ts, .py,   │  │ (.json,      │  │ (node_modules│         │
│  │  .js, .rs)   │  │  .yaml)      │  │  code)       │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
└─────────┼─────────────────┼─────────────────┼──────────────────┘
          │                 │                 │
          │ File Contents   │ File Path       │ Code Content
          │ (CRITICAL)      │                 │ (CRITICAL)
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   treeSitter.ts Module                          │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  1. WASM Language Loading                                 │ │
│  │     - Load tree-sitter-{lang}.wasm                        │ │
│  │     - Initialize Parser                                   │ │
│  │     - Set language grammar                                │ │
│  └───────────────────────────────────────────────────────────┘ │
│                           │                                     │
│                           ▼                                     │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  2. Code Parsing                                          │ │
│  │     - Parse file contents to AST                          │ │
│  │     - Build syntax tree in memory                         │ │
│  │     - Full code content in memory                         │ │
│  └───────────────────────────────────────────────────────────┘ │
│                           │                                     │
│                           ▼                                     │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  3. Symbol Extraction                                     │ │
│  │     - Traverse AST recursively                            │ │
│  │     - Extract class/function declarations                 │ │
│  │     - Capture code content (node.text)                    │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
     ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
     │   Code      │ │  Indexing   │ │  Autocomplete│
     │   Snippets  │ │  Service    │ │  Context    │
     │   Index     │ │  (Symbols)  │ │  Service    │
     └─────────────┘ └─────────────┘ └─────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

| Threat | CVSS Score | Attack Vector | Impact | Likelihood |
|--------|------------|---------------|--------|------------|
| **WASM Supply Chain Attack** | 8.8 (HIGH) | Compromised npm package | Code execution | Medium |
| **WASM Memory Exploitation** | 7.5 (HIGH) | Malicious code input | Memory corruption | Low |
| **Code Content Exposure** | 6.5 (MEDIUM) | Memory dump | IP theft | Low |
| **Path Traversal** | 7.2 (HIGH) | Malicious file paths | File access | Medium |
| **Parser DoS** | 5.3 (MEDIUM) | Malformed code | Resource exhaustion | Medium |
| **Symbol Leakage** | 4.3 (MEDIUM) | Index exfiltration | Code structure exposure | Low |

### Attack Vector: WASM Supply Chain Attack

**Scenario:**
```
1. Attacker compromises tree-sitter-wasms package
   ├── npm account takeover
   ├── Build system compromise
   └── Malicious PR merged

2. Malicious WASM binary distributed:
   └── Contains hidden functionality:
       ├── Memory access to sensitive data
       ├── Network calls to attacker server
       └── Code exfiltration during parsing

3. User installs/updates package:
   └── WASM loaded in Continue CLI

4. During code parsing:
   ├── Sensitive code extracted from AST
   ├── Sent to attacker's server
   └── Credentials, API keys, proprietary code stolen
```

**CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8**

### Attack Vector: WASM Memory Exploitation

**Scenario:**
```
1. Attacker crafts malicious code file:
   └── Specially structured to trigger WASM bug:
       ├── Buffer overflow in parser
       ├── Integer overflow in node allocation
       └── Use-after-free in tree traversal

2. User opens/parses malicious file:
   └── treeSitter.ts loads and parses content

3. WASM memory corruption:
   ├── Arbitrary memory read/write
   ├── Access to other process memory
   └── Potential code execution

4. Attacker gains:
   ├── Access to other file contents in memory
   ├── LLM API credentials
   └── User session data
```

**CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H = 7.8**

### Attack Vector: Path Traversal

**Scenario:**
```
1. Attacker controls file path input:
   └── Malicious workspace configuration:
       ```json
       {
         "include": ["../../.ssh/id_rsa"]
       }
       ```

2. getSymbolsForFile processes path:
   └── No path validation or sanitization
       └── Reads sensitive file content

3. Sensitive file parsed:
   ├── SSH keys loaded into memory
   ├── .env files with credentials
   └── Config files with secrets

4. Data exposed via:
   ├── Memory inspection
   ├── Error messages
   └── Symbol index leakage
```

**CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N = 7.2**

### Mitigation Strategies

#### 1. WASM Integrity Verification
```typescript
// SECURE: Verify WASM binary integrity before loading
import { createHash } from 'crypto';
import { readFileSync } from 'fs';

const EXPECTED_WASM_HASHES: Record<string, string> = {
  'tree-sitter-typescript.wasm': 'sha256-abc123...',
  'tree-sitter-python.wasm': 'sha256-def456...',
  'tree-sitter-rust.wasm': 'sha256-ghi789...',
  // Add hashes for all supported languages
};

async function verifyWasmIntegrity(wasmPath: string, languageName: string): Promise<boolean> {
  const wasmBuffer = readFileSync(wasmPath);
  const hash = createHash('sha256').update(wasmBuffer).digest('hex');
  const expectedHash = EXPECTED_WASM_HASHES[`tree-sitter-${languageName}.wasm`];
  
  if (!expectedHash) {
    console.warn(`No hash known for ${languageName}`);
    return false;
  }
  
  if (`sha256-${hash}` !== expectedHash) {
    throw new Error(`WASM integrity check failed for ${languageName}`);
  }
  
  return true;
}

async function loadLanguageForFileExt(fileExtension: string): Promise<Language> {
  const languageName = supportedLanguages[fileExtension];
  const wasmPath = path.join(__dirname, 'tree-sitter-wasms', `tree-sitter-${languageName}.wasm`);
  
  // Verify integrity before loading
  await verifyWasmIntegrity(wasmPath, languageName);
  
  return await Parser.Language.load(wasmPath);
}
```

#### 2. Path Validation and Sanitization
```typescript
// SECURE: Validate file paths before parsing
import { normalize, resolve, isAbsolute } from 'path';
import { existsSync, statSync } from 'fs';

const ALLOWED_EXTENSIONS = new Set(Object.keys(supportedLanguages));

function validateFilePath(filepath: string): { valid: boolean; reason?: string } {
  // Normalize and resolve path
  const normalizedPath = normalize(filepath);
  const resolvedPath = resolve(filepath);
  
  // Check for path traversal attempts
  if (normalizedPath.includes('..')) {
    // Allow node_modules traversal for dependencies
    if (!normalizedPath.includes('node_modules')) {
      return { valid: false, reason: 'Path traversal detected' };
    }
  }
  
  // Check file exists
  if (!existsSync(resolvedPath)) {
    return { valid: false, reason: 'File does not exist' };
  }
  
  // Check is file (not directory)
  const stats = statSync(resolvedPath);
  if (!stats.isFile()) {
    return { valid: false, reason: 'Path is not a file' };
  }
  
  // Check extension is supported
  const ext = getUriFileExtension(filepath);
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return { valid: false, reason: `Unsupported extension: ${ext}` };
  }
  
  // Check file size (prevent DoS)
  const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
  if (stats.size > MAX_FILE_SIZE) {
    return { valid: false, reason: 'File too large' };
  }
  
  return { valid: true };
}

export async function getSymbolsForFile(
  filepath: string,
  contents: string,
): Promise<SymbolWithRange[] | undefined> {
  // SECURITY: Validate path before parsing
  const validation = validateFilePath(filepath);
  if (!validation.valid) {
    console.warn(`Invalid file path: ${filepath} - ${validation.reason}`);
    return;
  }
  
  const parser = await getParserForFile(filepath);
  if (!parser) return;
  
  // ... rest of parsing logic
}
```

#### 3. Memory and Resource Limits
```typescript
// SECURE: Implement resource limits for parsing
import { Timeout } from 'node:timers/promises';

const MAX_PARSE_TIME_MS = 5000;
const MAX_AST_NODES = 100000;
const MAX_SYMBOL_COUNT = 1000;

export async function getSymbolsForFile(
  filepath: string,
  contents: string,
): Promise<SymbolWithRange[] | undefined> {
  // Check content size
  if (contents.length > 10 * 1024 * 1024) { // 10MB
    console.warn(`File too large to parse: ${filepath}`);
    return;
  }
  
  const parser = await getParserForFile(filepath);
  if (!parser) return;
  
  let tree: Parser.Tree;
  try {
    // Parse with timeout
    tree = await Promise.race([
      parser.parse(contents),
      Timeout(MAX_PARSE_TIME_MS).then(() => {
        throw new Error('Parse timeout exceeded');
      })
    ]);
  } catch (e) {
    console.log(`Error parsing file: ${filepath}`, e);
    return;
  }
  
  const symbols: SymbolWithRange[] = [];
  let nodeCount = 0;
  
  function findNamedNodesRecursive(node: Parser.SyntaxNode) {
    // SECURITY: Limit AST traversal depth
    nodeCount++;
    if (nodeCount > MAX_AST_NODES) {
      console.warn(`AST node limit exceeded for ${filepath}`);
      return;
    }
    
    if (symbols.length > MAX_SYMBOL_COUNT) {
      console.warn(`Symbol count limit exceeded for ${filepath}`);
      return;
    }
    
    if (GET_SYMBOLS_FOR_NODE_TYPES.includes(node.type)) {
      // ... symbol extraction logic
    }
    
    node.children.forEach(findNamedNodesRecursive);
  }
  
  findNamedNodesRecursive(tree.rootNode);
  return symbols;
}
```

#### 4. Content Redaction for Sensitive Files
```typescript
// SECURE: Skip parsing for sensitive file patterns
const SENSITIVE_FILE_PATTERNS = [
  /.*\.env$/,
  /.*\.pem$/,
  /.*\.key$/,
  /.*id_rsa$/,
  /.*id_ed25519$/,
  /.*\.secret$/,
  /.*credentials$/,
  /.*\.auth$/,
  /package-lock\.json$/,  // Contains tokens
  /yarn\.lock$/,
  /.*\.min\.(js|css)$/,  // Minified files
];

function isSensitiveFile(filepath: string): boolean {
  const filename = path.basename(filepath);
  return SENSITIVE_FILE_PATTERNS.some(pattern => pattern.test(filename));
}

export async function getSymbolsForFile(
  filepath: string,
  contents: string,
): Promise<SymbolWithRange[] | undefined> {
  // SECURITY: Skip sensitive files
  if (isSensitiveFile(filepath)) {
    console.debug(`Skipping sensitive file: ${filepath}`);
    return [];
  }
  
  // ... rest of parsing logic
}
```

---

## 4. Entry Points

### Public Functions

| Function | Entry Point | Security Considerations |
|----------|-------------|------------------------|
| `getParserForFile(filepath)` | Indexing service | Loads WASM, no path validation |
| `getLanguageForFile(filepath)` | Parser initialization | WASM loading, path-based |
| `getSymbolsForFile(filepath, contents)` | Symbol extraction | Full code content in memory |
| `getQueryForFile(filepath, queryPath)` | Custom queries | File read, query compilation |
| `getSymbolsForManyFiles(uris, ide)` | Batch processing | Multiple file access |

### WASM Loading

| Operation | Function | Security Considerations |
|-----------|----------|------------------------|
| WASM init | `Parser.init()` | One-time initialization |
| Language load | `Parser.Language.load(wasmPath)` | File system access |
| Parser creation | `new Parser()` | Memory allocation |
| Code parsing | `parser.parse(contents)` | AST in memory |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────┐
│                    Untrusted Input                          │
│  (User Files, Malicious Code, Path Manipulation)            │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  File Contents                                      │   │
│  │  - May contain malicious structures                 │   │
│  │  - Designed to exploit parser bugs                  │   │
│  │  - Sensitive data (credentials, secrets)            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ File Path + Contents
                      │ (Trust Boundary #1)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  treeSitter.ts Module                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Path Validation (MISSING)                          │   │
│  │  - No traversal prevention                          │   │
│  │  - No existence check                               │   │
│  │  - No size limits                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  WASM Loading                                       │   │
│  │  - Loads from node_modules                          │   │
│  │  - No integrity verification                        │   │
│  │  - Trusts npm package                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Code Parsing                                       │   │
│  │  - Full content in memory                           │   │
│  │  - No content validation                            │   │
│  │  - No resource limits                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Symbol Extraction                                  │   │
│  │  - AST traversal                                    │   │
│  │  - Code content captured (node.text)                │   │
│  │  - No redaction for sensitive data                  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ Symbol Data + Code Snippets
                      │ (Trust Boundary #2)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Indexing Services                          │
│  (CodeSnippetsIndex, StaticContextService, etc.)            │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Confidentiality | Integrity | Availability | Priority |
|-------|-----------------|-----------|--------------|----------|
| User's source code | 🔴 **CRITICAL** | 🟢 **LOW** | 🟡 **MEDIUM** | P0 |
| WASM binaries | 🟡 **MEDIUM** | 🔴 **CRITICAL** | 🟡 **MEDIUM** | P1 |
| Symbol index | 🟡 **MEDIUM** | 🟡 **MEDIUM** | 🟡 **MEDIUM** | P2 |
| AST in memory | 🔴 **CRITICAL** | 🟢 **LOW** | 🟢 **LOW** | P1 |
| Parser state | 🟡 **MEDIUM** | 🟡 **MEDIUM** | 🟢 **LOW** | P2 |

### CIA Triad Analysis

#### Confidentiality
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| Code exposure in memory | Process isolation | No encryption | Sensitive file skip |
| WASM tampering | npm integrity | No verification | Hash verification |
| Symbol leakage | In-process only | Index persistence | Encrypt index |
| Path disclosure | None | Error messages | Sanitize errors |

#### Integrity
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| WASM corruption | npm package | No runtime check | Integrity verification |
| AST manipulation | Parser logic | No validation | Output validation |
| Symbol injection | Code-based | Trusts input | Source verification |
| Parser bugs | WASM sandbox | Memory safety | Resource limits |

#### Availability
| Threat | Current Control | Gap | Recommendation |
|--------|-----------------|-----|----------------|
| Parse timeout | None | No limits | Timeout implementation |
| Memory exhaustion | GC | No limits | Node count limits |
| WASM load failure | Error handling | No fallback | Graceful degradation |
| Large file DoS | None | No size check | File size limits |

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Reason | Data Access |
|-----------|-------------|--------|-------------|
| WASM binaries | 🟡 **MEDIUM** | External, pre-compiled | Parser logic |
| User source files | 🔴 **UNTRUSTED** | Potentially malicious | Full content |
| npm registry | 🟡 **MEDIUM** | Third-party, audited | Package delivery |
| Parser output | 🟡 **MEDIUM** | WASM-generated | AST, symbols |
| File paths | 🟡 **MEDIUM** | User-controlled | File access |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────────┐
│                 Untrusted Zone                                  │
│  (User Files, External WASM, Network)                           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              User Source Files                          │   │
│  │  ⚠️ May contain malicious structures                    │   │
│  │  - Validate before parsing                              │   │
│  │  - Apply resource limits                                │   │
│  │  - Skip sensitive files                                 │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              WASM Binaries                              │   │
│  │  ⚠️ External, pre-compiled code                         │   │
│  │  - Verify integrity before loading                      │   │
│  │  - Monitor for suspicious behavior                      │   │
│  │  - Keep updated with security patches                   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              │ Trust Boundary
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Trusted Zone                                   │
│  (Local Application, Memory, Indexing Services)                 │
│  - Protect parsed data in memory                                │
│  - Limit access to symbol index                                 │
│  - Apply principle of least privilege                           │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment

| Aspect | Rating | Justification |
|--------|--------|---------------|
| WASM integrity | ❌ **POOR** | No verification |
| Input validation | ❌ **POOR** | No path/content validation |
| Resource limits | ❌ **POOR** | No timeout or size limits |
| Memory protection | ⚠️ **FAIR** | WASM sandbox, process isolation |
| Error handling | ✅ **GOOD** | Graceful failure on parse errors |

---

## 7. Architecture & Security Boundaries

### System Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                      External Sources                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ npm Registry │  │ User Files   │  │ IDE/Workspace│         │
│  │ (WASM pkgs)  │  │ (Code)       │  │ (Paths)      │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
└─────────┼─────────────────┼─────────────────┼──────────────────┘
          │                 │                 │
          │ WASM Packages   │ File Contents   │ File Paths
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Security Boundary #1: Input Validation             │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  treeSitter.ts Module                                     │ │
│  │                                                           │ │
│  │  Current:                                                 │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ - No path validation                                │ │ │
│  │  │ - No content validation                             │ │ │
│  │  │ - No file size limits                               │ │ │
│  │  │ - No sensitive file filtering                       │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │                                                           │ │
│  │  Recommended:                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ + Path traversal prevention                         │ │ │
│  │  │ + File existence/type validation                    │ │ │
│  │  │ + Size and timeout limits                           │ │ │
│  │  │ + Sensitive file skip list                          │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Security Boundary #2: WASM Loading                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  WASM Initialization & Language Loading                   │ │
│  │                                                           │ │
│  │  Current:                                                 │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ - Loads from node_modules                           │ │ │
│  │  │ - No integrity verification                         │ │ │
│  │  │ - Trusts npm package                                │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │                                                           │ │
│  │  Recommended:                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ + SHA-256 hash verification                         │ │ │
│  │  │ + Package signature verification                    │ │ │
│  │  │ + Allowlist of approved versions                    │ │ │
│  │  │ + Integrity monitoring                              │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Security Boundary #3: Code Parsing                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Parser Execution & AST Generation                        │ │
│  │                                                           │ │
│  │  Current:                                                 │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ - Full content in memory                            │ │ │
│  │  │ - No resource limits                                │ │ │
│  │  │ - No timeout                                        │ │ │
│  │  │ - WASM sandbox protection                           │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │                                                           │ │
│  │  Recommended:                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ + Parse timeout (5s)                                │ │ │
│  │  │ + AST node count limit                              │ │ │
│  │  │ + Memory usage monitoring                           │ │ │
│  │  │ + Graceful error handling                           │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Security Boundary #4: Symbol Extraction            │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  AST Traversal & Symbol Collection                        │ │
│  │                                                           │ │
│  │  Current:                                                 │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ - Full code content captured                        │ │ │
│  │  │ - No redaction                                      │ │ │
│  │  │ - No access control                                 │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  │                                                           │ │
│  │  Recommended:                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │ + Redact sensitive code snippets                    │ │ │
│  │  │ + Limit symbol count                                │ │ │
│  │  │ + Access logging                                    │ │ │
│  │  │ + Index encryption                                  │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Indexing Services                              │
│  (CodeSnippetsIndex, StaticContextService, Autocomplete)        │
└─────────────────────────────────────────────────────────────────┘
```

### Security Boundaries

| Boundary | Components | Protection | Gap |
|----------|------------|------------|-----|
| Files → Parser | Path validation | None | No validation |
| npm → WASM | Package loading | npm integrity | No hash verification |
| Content → AST | Parser execution | WASM sandbox | No resource limits |
| AST → Symbols | Symbol extraction | In-process | No redaction |

### Data Flow Through Boundaries
```
User Source Files (potentially malicious)
        │
        ▼
┌─────────────────────────────┐
│   Security Boundary #1      │
│   Input Validation          │  ✗ No path validation
│                             │  ✗ No content validation
└─────────────┬───────────────┘
              │
              │ File Path + Contents
              ▼
┌─────────────────────────────┐
│   Security Boundary #2      │
│   WASM Loading              │  ✗ No integrity check
│                             │  ✓ npm package verification
└─────────────┬───────────────┘
              │
              │ WASM Binary (trusted)
              ▼
┌─────────────────────────────┐
│   Security Boundary #3      │
│   Code Parsing              │  ✓ WASM sandbox
│                             │  ✗ No resource limits
└─────────────┬───────────────┘
              │
              │ AST (full code in memory)
              ▼
┌─────────────────────────────┐
│   Security Boundary #4      │
│   Symbol Extraction         │  ✗ No redaction
│                             │  ✗ No access control
└─────────────┬───────────────┘
              │
              │ Symbol Data + Code Snippets
              ▼
        Indexing Services
```

---

## 8. Security Recommendations

### Critical Priority (P0)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No WASM integrity check | Implement SHA-256 hash verification | Low | High |
| No path validation | Add path traversal prevention | Low | High |
| No resource limits | Implement timeout and size limits | Medium | High |
| Sensitive file parsing | Skip .env, keys, credentials | Low | High |

### High Priority (P1)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No content validation | Validate file content before parsing | Medium | Medium |
| No memory limits | Limit AST node count | Low | Medium |
| No error sanitization | Sanitize error messages | Low | Medium |
| No access logging | Log symbol extraction | Low | Low |

### Medium Priority (P2)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No index encryption | Encrypt symbol index at rest | Medium | Low |
| No fallback handling | Graceful degradation on failure | Medium | Low |
| No version pinning | Pin exact WASM versions | Low | Low |
| No audit trail | Log parsing operations | Low | Low |

### Low Priority (P3)

| Issue | Recommendation | Effort | Impact |
|-------|----------------|--------|--------|
| No caching | Cache parsed symbols | Medium | Low |
| No parallel limits | Limit concurrent parses | Low | Low |
| No metrics | Track parse performance | Low | Low |

### Implementation Checklist

- [ ] **Implement WASM hash verification** for all language binaries
- [ ] **Add path validation** to prevent traversal attacks
- [ ] **Implement file size limits** (10MB max)
- [ ] **Add parse timeout** (5 seconds max)
- [ ] **Create sensitive file skip list** (.env, .pem, .key, etc.)
- [ ] **Limit AST node count** (100,000 nodes max)
- [ ] **Limit symbol count** (1,000 symbols max)
- [ ] **Sanitize error messages** to prevent path disclosure
- [ ] **Add access logging** for symbol extraction
- [ ] **Document security model** for tree-sitter usage

### Secure Implementation Example

```typescript
// SECURE: Hardened tree-sitter integration
import { createHash } from 'crypto';
import { normalize, resolve, basename } from 'path';
import { existsSync, statSync, readFileSync } from 'fs';

// WASM integrity hashes (update with actual values)
const EXPECTED_WASM_HASHES: Record<string, string> = {
  'typescript': 'sha256-abc123...',
  'python': 'sha256-def456...',
  'rust': 'sha256-ghi789...',
  // ... all supported languages
};

// Sensitive file patterns to skip
const SENSITIVE_PATTERNS = [
  /.*\.env$/,
  /.*\.pem$/,
  /.*\.key$/,
  /.*id_rsa$/,
  /.*\.secret$/,
  /package-lock\.json$/,
];

// Resource limits
const MAX_FILE_SIZE = 10 * 1024 * 1024;  // 10MB
const MAX_PARSE_TIME_MS = 5000;          // 5 seconds
const MAX_AST_NODES = 100000;            // 100k nodes
const MAX_SYMBOLS = 1000;                // 1k symbols

function validateFilePath(filepath: string): { valid: boolean; reason?: string } {
  const normalized = normalize(filepath);
  const resolved = resolve(filepath);
  
  // Check path traversal
  if (normalized.includes('..') && !normalized.includes('node_modules')) {
    return { valid: false, reason: 'Path traversal detected' };
  }
  
  // Check exists and is file
  if (!existsSync(resolved)) {
    return { valid: false, reason: 'File does not exist' };
  }
  
  const stats = statSync(resolved);
  if (!stats.isFile()) {
    return { valid: false, reason: 'Not a file' };
  }
  
  // Check size
  if (stats.size > MAX_FILE_SIZE) {
    return { valid: false, reason: 'File too large' };
  }
  
  // Check extension
  const ext = getUriFileExtension(filepath);
  if (!supportedLanguages[ext]) {
    return { valid: false, reason: 'Unsupported extension' };
  }
  
  // Check sensitive patterns
  const filename = basename(filepath);
  if (SENSITIVE_PATTERNS.some(p => p.test(filename))) {
    return { valid: false, reason: 'Sensitive file' };
  }
  
  return { valid: true };
}

async function verifyWasmIntegrity(languageName: string): Promise<void> {
  const wasmPath = path.join(
    __dirname,
    'tree-sitter-wasms',
    `tree-sitter-${languageName}.wasm`
  );
  
  const wasmBuffer = readFileSync(wasmPath);
  const hash = createHash('sha256').update(wasmBuffer).digest('hex');
  const expectedHash = EXPECTED_WASM_HASHES[languageName];
  
  if (expectedHash && `sha256-${hash}` !== expectedHash) {
    throw new Error(`WASM integrity check failed for ${languageName}`);
  }
}

async function loadLanguageForFileExt(fileExtension: string): Promise<Language> {
  const languageName = supportedLanguages[fileExtension];
  
  // Verify WASM integrity
  await verifyWasmIntegrity(languageName);
  
  const wasmPath = path.join(__dirname, 'tree-sitter-wasms', `tree-sitter-${languageName}.wasm`);
  return await Parser.Language.load(wasmPath);
}

export async function getSymbolsForFile(
  filepath: string,
  contents: string,
): Promise<SymbolWithRange[] | undefined> {
  // Validate file path
  const validation = validateFilePath(filepath);
  if (!validation.valid) {
    console.debug(`Skipping file ${filepath}: ${validation.reason}`);
    return;
  }
  
  // Check content size
  if (contents.length > MAX_FILE_SIZE) {
    console.warn(`Content too large: ${filepath}`);
    return;
  }
  
  const parser = await getParserForFile(filepath);
  if (!parser) return;
  
  let tree: Parser.Tree;
  try {
    // Parse with timeout
    tree = await Promise.race([
      parser.parse(contents),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Parse timeout')), MAX_PARSE_TIME_MS)
      )
    ]);
  } catch (e) {
    console.log(`Error parsing file: ${filepath}`, e);
    return;
  }
  
  const symbols: SymbolWithRange[] = [];
  let nodeCount = 0;
  
  function findNamedNodesRecursive(node: Parser.SyntaxNode) {
    // Resource limits
    nodeCount++;
    if (nodeCount > MAX_AST_NODES) {
      console.warn(`AST node limit exceeded: ${filepath}`);
      return;
    }
    
    if (symbols.length >= MAX_SYMBOLS) {
      console.warn(`Symbol limit exceeded: ${filepath}`);
      return;
    }
    
    if (GET_SYMBOLS_FOR_NODE_TYPES.includes(node.type)) {
      // Extract identifier
      let identifier: Parser.SyntaxNode | undefined;
      for (let i = node.children.length - 1; i >= 0; i--) {
        if (['identifier', 'property_identifier'].includes(node.children[i].type)) {
          identifier = node.children[i];
          break;
        }
      }
      
      if (identifier?.text) {
        symbols.push({
          filepath,
          type: node.type,
          name: identifier.text,
          range: {
            start: { character: node.startPosition.column, line: node.startPosition.row },
            end: { character: node.endPosition.column + 1, line: node.endPosition.row + 1 },
          },
          content: node.text,
        });
      }
    }
    
    node.children.forEach(findNamedNodesRecursive);
  }
  
  findNamedNodesRecursive(tree.rootNode);
  return symbols;
}
```

---

**Generated with [Continue](https://continue.dev)**

Co-Authored-By: Continue <noreply@continue.dev>
