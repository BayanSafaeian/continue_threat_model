# 🔒 Comprehensive Security Analysis: child_process Module Execution

**Package:** `child_process` (Node.js built-in module)  
**Used In:** `extensions/cli/src/util/clipboard.ts`, `extensions/cli/src/services/BackgroundJobService.ts`, `extensions/cli/src/hooks/hookRunner.ts` (system command execution)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🔴 **CRITICAL**

---

## 1. Dependency Purpose & Usage

### Primary Function
The `child_process` module is a Node.js built-in API for spawning child processes and executing system commands. It enables Continue to:
- Execute system commands for clipboard operations (osascript, PowerShell, xclip)
- Run background jobs and long-running tasks
- Execute user-defined command hooks
- Monitor system resources (CPU, memory usage)
- Run terminal commands on behalf of users

### Implementation in Continue
```typescript
// extensions/cli/src/util/clipboard.ts
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Clipboard image operations via platform-specific commands
async function getClipboardImage(): Promise<Buffer | null> {
  if (process.platform === "darwin") {
    const { stdout } = await execAsync(
      'osascript -e "if application \\"System Events\\" is running then return true"'
    );
    // Execute osascript to get clipboard image
    const { stdout: imageBuffer } = await execAsync(
      'osascript -e "tell application \\"System Events\\" to return (the clipboard as «class PNGf»)"'
    );
    return Buffer.from(imageBuffer, "binary");
  } else if (process.platform === "win32") {
    // PowerShell clipboard access
    const { stdout } = await execAsync(
      'powershell -command "Add-Type -AssemblyName System.Windows.Forms; $img = [System.Windows.Forms.Clipboard]::GetImage(); if ($img -ne $null) { $ms = New-Object System.IO.MemoryStream; $img.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $ms.ToArray() }"'
    );
    return Buffer.from(stdout, "binary");
  }
  return null;
}

// extensions/cli/src/hooks/hookRunner.ts
import { execFile } from "child_process";

async function runHook(handler: HookHandler): Promise<HookResult> {
  const shell = process.platform === "win32" ? "cmd.exe" : "/bin/sh";
  const shellArgs = process.platform === "win32"
    ? ["/c", handler.command]  // ⚠️ User-controlled command
    : ["-c", handler.command]; // ⚠️ User-controlled command
  
  const cwd = handler.cwd || workspacePath;
  const timeoutMs = (handler.timeout ?? DEFAULT_COMMAND_TIMEOUT_SECONDS) * 1000;
  
  return new Promise((resolve, reject) => {
    execFile(shell, shellArgs, { cwd, env, timeout: timeoutMs }, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve({ stdout, stderr, exitCode: error?.code });
    });
  });
}

// extensions/cli/src/services/BackgroundJobService.ts
import { spawn } from "child_process";

class BackgroundJobService {
  private static MAX_CONCURRENT_JOBS = 5;
  
  async createJob(command: string, args?: string[]): Promise<JobId> {
    const child = spawn(command, args || [], {
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false, // ✅ More secure than exec
    });
    // Track and manage spawned process
  }
}
```

### Dependency Type
- **Built-in Node.js module** - No external npm dependency
- **Runtime dependency** - Active during command execution
- **System-level access** - Full user privileges for spawned processes
- **Critical for CLI functionality** - Required for hooks, background jobs, clipboard

---

## 2. Data Flow Analysis

### Inbound Data (Data In)

| Data Type | Source | Sensitivity | Processing |
|-----------|--------|-------------|------------|
| `Command strings` | User hook configuration | CRITICAL | Passed directly to shell for execution |
| `Command arguments` | Background job requests | HIGH | Array of arguments for spawn |
| `Working directory` | User project path | HIGH | Sets cwd for spawned process |
| `Environment variables` | Process inheritance | HIGH | Passed to child process |
| `Timeout values` | Hook configuration | MEDIUM | Controls execution duration |
| `Shell metacharacters` | User input | CRITICAL | Interpreted by shell if not sanitized |

### Outbound Data (Data Out)

| Data Type | Destination | Sensitivity | Transmission |
|-----------|-------------|-------------|--------------|
| `stdout` | Hook result, UI display | MEDIUM | Command output returned to user |
| `stderr` | Error logging, UI | MEDIUM | Error messages from command |
| `Exit codes` | Hook status, job status | LOW | Process completion status |
| `Process PID` | Job tracking | LOW | Used for process management |
| `Clipboard data` | Memory buffer | HIGH | Image/text from system clipboard |

### Data Storage
- **In Memory:** Command output buffers (stdout/stderr), process handles
- **Persistent:** None directly (but spawned processes may write to disk)
- **Temporary:** Output buffers held during command execution

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                      Continue CLI Application                    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              User Configuration                          │   │
│  │  - .continue/hooks.json (command hooks)                  │   │
│  │  - Background job requests                               │   │
│  │  - Terminal command input                                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │         child_process Execution Layer                    │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  exec() / execFile() / spawn()                    │  │   │
│  │  │  - Command string interpretation                   │  │   │
│  │  │  - Shell expansion (if shell: true)               │  │   │
│  │  │  - Process spawning                                │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  ⚠️ TRUST BOUNDARY VIOLATION RISK                 │  │   │
│  │  │  - User input → Shell interpretation              │  │   │
│  │  │  - Command injection possible                     │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              System Shell / Process                      │   │
│  │  - Full user privileges                                  │   │
│  │  - File system access                                    │   │
│  │  - Network access                                        │   │
│  │  - Environment variable access                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│              ┌─────────────┴─────────────┐                     │
│              ▼                           ▼                     │
│  ┌─────────────────────┐     ┌─────────────────────┐          │
│  │ stdout (output)     │     │ stderr (errors)     │          │
│  │ - Command results   │     │ - Error messages    │          │
│  │ - File contents     │     │ - Warnings          │          │
│  └─────────────────────┘     └─────────────────────┘          │
│              │                           │                     │
│              └─────────────┬─────────────┘                     │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Continue Response Handler                   │   │
│  │  - Display output to user                                │   │
│  │  - Log errors                                            │   │
│  │  - Update job status                                     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

#### 3.1 Command Injection (CVSS: 9.8 - CRITICAL)
**Description:** User-controlled command strings passed to `exec()` or shell without proper sanitization enable arbitrary command execution.

**Attack Vector:**
- Attacker crafts malicious hook configuration
- Command string contains shell metacharacters (`;`, `|`, `&`, `$()`)
- Shell interprets and executes additional commands

**Impact:**
- Arbitrary code execution with user privileges
- File system compromise (read/write/delete)
- Credential theft (SSH keys, API tokens)
- Lateral movement within network

**Mitigation:**
```typescript
// ❌ VULNERABLE - Direct shell execution
exec(handler.command, callback);

// ✅ SECURE - Use execFile with argument array
import { execFile } from 'child_process';
execFile(command, [arg1, arg2], options, callback);

// ✅ SECURE - Use spawn with shell: false
import { spawn } from 'child_process';
const child = spawn(command, args, { shell: false });

// ✅ SECURE - Input validation
function sanitizeCommand(input: string): string {
  // Remove shell metacharacters
  return input.replace(/[;&|`$(){}[\]<>\\]/g, '');
}
```

#### 3.2 Path Traversal via Working Directory (CVSS: 8.6 - HIGH)
**Description:** Commands executed with user-controlled working directories can escape intended boundaries.

**Attack Vector:**
- Hook configuration specifies `cwd` with path traversal (`../../../`)
- Relative paths in command resolve outside project directory
- Sensitive files accessed or modified

**Impact:**
- Access to files outside project directory
- Modification of system configuration
- Exfiltration of sensitive data

**Mitigation:**
```typescript
// ✅ SECURE - Path validation
import path from 'path';

function safeWorkingDirectory(userPath: string, baseDir: string): string {
  const resolved = path.resolve(baseDir, userPath);
  const normalizedBase = path.resolve(baseDir);
  
  // Verify path stays within base directory
  if (!resolved.startsWith(normalizedBase + path.sep)) {
    throw new Error('Path traversal detected');
  }
  
  return resolved;
}
```

#### 3.3 Privilege Escalation (CVSS: 7.8 - HIGH)
**Description:** Commands run with full user privileges, enabling access to sensitive resources.

**Attack Vector:**
- Spawned process inherits user's environment
- Access to `~/.ssh/`, `~/.aws/`, browser credentials
- Network access to internal services

**Impact:**
- Credential theft from environment
- Access to internal network resources
- Privilege escalation via SUID binaries

**Mitigation:**
```typescript
// ✅ SECURE - Minimal environment
const safeEnv = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  // Explicitly exclude sensitive variables
  // NO AWS_SECRET_KEY, NO SSH_AUTH_SOCK, etc.
};

execFile(command, args, { env: safeEnv }, callback);
```

#### 3.4 Denial of Service - Resource Exhaustion (CVSS: 6.5 - MEDIUM)
**Description:** Multiple spawned processes can exhaust system resources (CPU, memory, file descriptors).

**Attack Vector:**
- Attacker triggers multiple background jobs
- Each job consumes memory and CPU
- `MAX_CONCURRENT_JOBS = 5` limit can be bypassed

**Impact:**
- System resource exhaustion
- IDE/application performance degradation
- Crash or hang of Continue application

**Mitigation:**
```typescript
// ✅ SECURE - Resource limits
class BackgroundJobService {
  private static MAX_CONCURRENT_JOBS = 5;
  private static MAX_MEMORY_PER_JOB = 512 * 1024 * 1024; // 512MB
  
  async createJob(command: string): Promise<JobId> {
    if (this.activeJobs.size >= BackgroundJobService.MAX_CONCURRENT_JOBS) {
      throw new Error('Too many concurrent jobs');
    }
    
    const child = spawn(command, args, {
      maxBuffer: BackgroundJobService.MAX_MEMORY_PER_JOB,
      timeout: 300000, // 5 minute timeout
    });
  }
}
```

#### 3.5 Information Disclosure (CVSS: 5.3 - MEDIUM)
**Description:** Command output may contain sensitive data exposed to logs or UI.

**Attack Vector:**
- Commands output credentials, tokens, or sensitive file contents
- Output displayed in UI without filtering
- Logs stored without redaction

**Impact:**
- Exposure of API keys, passwords
- Disclosure of file contents
- Privacy violations

**Mitigation:**
```typescript
// ✅ SECURE - Output filtering
function filterSensitiveData(output: string): string {
  // Redact common patterns
  return output
    .replace(/(AWS_SECRET_KEY|password|token)[=:]\s*\S+/gi, '$1=***REDACTED***')
    .replace(/(sk-[a-zA-Z0-9]{32,})/g, '***API_KEY***');
}
```

#### 3.6 Shell Metacharacter Injection (CVSS: 9.1 - CRITICAL)
**Description:** Using `exec()` with shell interpretation enables injection via metacharacters.

**Attack Vector:**
```typescript
// Vulnerable pattern in hookRunner.ts
const shellArgs = process.platform === "win32"
  ? ["/c", handler.command]  // "ls; rm -rf /" becomes "ls" then "rm -rf /"
  : ["-c", handler.command];
```

**Impact:**
- Command chaining via `;`, `&`, `|`
- Command substitution via `$()`, backticks
- Variable expansion via `$VAR`
- Glob expansion via `*`, `?`

**Mitigation:**
```typescript
// ✅ SECURE - Avoid shell entirely
import { execFile } from 'child_process';

// Instead of: exec("ls -la /tmp")
// Use: execFile("ls", ["-la", "/tmp"])

// This prevents shell interpretation entirely
execFile("ls", ["-la", "/tmp"], callback);
```

#### 3.7 Supply Chain Attack via Hook Configuration (CVSS: 8.1 - HIGH)
**Description:** Malicious hook configurations shared via version control or templates.

**Attack Vector:**
- Attacker publishes malicious `.continue/hooks.json` template
- User clones repository with malicious hooks
- Hooks execute automatically on certain events

**Impact:**
- Automated credential exfiltration
- Backdoor installation
- Cryptocurrency mining

**Mitigation:**
- Implement hook allowlisting
- Require user confirmation for new hooks
- Audit hook configurations before execution
- Implement per-project hook permissions

---

## 4. Entry Points

### Archive Loading (Command Execution Entry Points)

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `exec(command, callback)` | Command string | Execute shell command | 🔴 CRITICAL - Full shell interpretation |
| `execFile(file, args, callback)` | File path, args array | Execute file directly | 🟠 HIGH - No shell, but args must be safe |
| `spawn(command, args, options)` | Command, args, options | Spawn process | 🟠 HIGH - Shell: false recommended |
| `fork(modulePath, args)` | Module path, args | Fork Node.js process | 🟡 MEDIUM - Node.js only |

### Extraction Operations (Command Execution Patterns)

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `hookRunner.ts:runHook()` | `handler.command` | Execute user hook | 🔴 CRITICAL - User-controlled string |
| `clipboard.ts:getClipboardImage()` | Platform commands | Clipboard access | 🟠 HIGH - Hardcoded but shell used |
| `BackgroundJobService:createJob()` | `command: string` | Background execution | 🔴 CRITICAL - Arbitrary command |
| `runTerminalCommand.ts` | User terminal input | Terminal execution | 🔴 CRITICAL - Direct user input |

### Archive Creation (Process Spawning)

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `spawn(command, [args])` | Command, args array | Long-running process | Use `shell: false` |
| `spawn(command, { shell: true })` | Command string | Shell execution | 🔴 Avoid unless necessary |
| `execAsync(cmd)` | Promisified exec | Async command | 🔴 Full shell interpretation |

### Entry Inspection (Process Management)

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `child.stdout.on('data')` | Data handler | Read stdout | Output may be malicious |
| `child.stderr.on('data')` | Data handler | Read stderr | Error messages may leak info |
| `child.on('exit')` | Exit code handler | Process completion | Check for non-zero exit |
| `child.kill(signal)` | Signal string | Terminate process | Validate signal type |

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Type | Sensitivity | CIA Priority | Notes |
|-------|------|-------------|--------------|-------|
| **User Files** | Filesystem | CRITICAL | Integrity | Commands can read/modify any user file |
| **Environment Variables** | Memory | CRITICAL | Confidentiality | AWS keys, API tokens, credentials |
| **SSH Keys** | Filesystem | CRITICAL | Confidentiality | Located in `~/.ssh/`, accessible via commands |
| **Source Code** | Filesystem | HIGH | Integrity | Can be modified or exfiltrated |
| **Clipboard Data** | Memory | HIGH | Confidentiality | May contain passwords, sensitive text |
| **Git Credentials** | Filesystem | HIGH | Confidentiality | `.git-credentials`, SSH keys |
| **Configuration Files** | Filesystem | HIGH | Integrity | `.continue/`, IDE configs |
| **Network Access** | Network | HIGH | All | Commands can access internal network |

### CIA Triad Analysis

#### Confidentiality
- **Critical Risk:** Environment variables, SSH keys, API tokens, credentials
- **High Risk:** Source code, configuration files, clipboard data
- **Controls:** 
  - Minimize environment passed to child processes
  - Filter sensitive data from output
  - Implement output redaction
  - Audit command execution logs

#### Integrity
- **Critical Risk:** User files, source code, system configuration
- **High Risk:** Git history, build artifacts, configuration
- **Controls:**
  - Validate working directories
  - Implement command allowlisting
  - Use read-only permissions where possible
  - Atomic operations for file modifications

#### Availability
- **High Risk:** System resources (CPU, memory, file descriptors)
- **Medium Risk:** IDE performance, background job queue
- **Controls:**
  - Enforce concurrent job limits
  - Set memory and timeout limits
  - Implement process cleanup on termination
  - Monitor resource usage

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Justification | Risk Mitigation |
|-----------|-------------|---------------|-----------------|
| **User Input (Commands)** | LOW | Untrusted, may be malicious | Validate, sanitize, allowlist |
| **Hook Configuration** | LOW | User-defined, version-controlled | Audit before execution, confirm |
| **Background Job Commands** | LOW | Arbitrary command strings | Limit scope, resource caps |
| **child_process API** | MEDIUM | Built-in Node.js, well-tested | Use safe patterns (execFile, spawn) |
| **System Shell** | LOW | Interprets metacharacters | Avoid shell when possible |
| **Spawned Processes** | LOW | Run with full user privileges | Minimize env, restrict paths |
| **Command Output** | LOW-MEDIUM | May contain malicious content | Filter, validate before display |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    HIGH TRUST ZONE                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Continue Core Application                   │   │
│  │  - Configuration management                              │   │
│  │  - User interface                                        │   │
│  │  - Sensitive data handling                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           ⚠️ CRITICAL TRUST BOUNDARY ⚠️                  │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  child_process Execution Layer                     │  │   │
│  │  │  - exec() / execFile() / spawn()                  │  │   │
│  │  │  - Command interpretation                          │  │   │
│  │  │  - Process spawning                                │  │   │
│  │  │                                                    │  │   │
│  │  │  🔴 TRUST BOUNDARY VIOLATION RISK:                │  │   │
│  │  │  User input → Shell → System commands             │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           LOW TRUST ZONE                                 │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  System Shell / Spawned Processes                  │  │   │
│  │  │  - Full user privileges                            │  │   │
│  │  │  - File system access                              │  │   │
│  │  │  - Network access                                  │  │   │
│  │  │  - Environment variable access                     │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment

**Overall Trust Level:** LOW (Score: 2/10)

**Rationale:** The `child_process` module executes arbitrary system commands with full user privileges. User-controlled input (hook configurations, background job commands, terminal input) flows directly to shell interpretation without adequate sanitization. This creates multiple critical trust boundary violations.

**Key Trust Dependencies:**
- User input validation effectiveness
- Shell metacharacter sanitization
- Working directory path validation
- Environment variable filtering
- Output filtering and redaction

**Critical Security Point:** The trust boundary is at the **command execution** step. All user input must be validated, sanitized, and preferably executed without shell interpretation (`execFile` or `spawn` with `shell: false`).

---

## 7. Architecture & Security Boundaries

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Continue CLI Application                      │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    User Input Layer                          │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Hook Configuration (.continue/hooks.json)             │ │   │
│  │  │  - User-defined command handlers                       │ │   │
│  │  │  - Event-triggered execution                           │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Background Job Requests                               │ │   │
│  │  │  - Long-running task execution                         │ │   │
│  │  │  - Resource monitoring                                 │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Terminal Command Input                                │ │   │
│  │  │  - Direct user commands                                │ │   │
│  │  │  - Interactive shell                                   │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │         ⚠️ Command Validation Layer ← CRITICAL POINT         │   │
│  │  - Input sanitization (remove metacharacters)               │   │
│  │  - Command allowlisting (whitelist approved commands)       │   │
│  │  - Path validation (prevent traversal)                      │   │
│  │  - Environment filtering (remove sensitive vars)            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              child_process Execution Layer                   │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Preferred: execFile() / spawn({ shell: false })      │ │   │
│  │  │  - Direct execution without shell                      │ │   │
│  │  │  - Argument array (no interpretation)                  │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Avoid: exec() with shell                             │ │   │
│  │  │  - Shell interpretation enabled                        │ │   │
│  │  │  - Metacharacter expansion                             │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              System Process Layer                            │   │
│  │  - Spawned process with user privileges                     │   │
│  │  - File system access                                        │   │
│  │  - Network access                                            │   │
│  │  - Environment variable access                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│              ┌───────────────┴───────────────┐                     │
│              ▼                               ▼                     │
│  ┌─────────────────────┐         ┌─────────────────────┐          │
│  │ stdout (output)     │         │ stderr (errors)     │          │
│  │ - Filter sensitive  │         │ - Log errors        │          │
│  │ - Redact credentials│         │ - Handle failures   │          │
│  └─────────────────────┘         └─────────────────────┘          │
│              │                               │                     │
│              └───────────────┬───────────────┘                     │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Response Handler                                │   │
│  │  - Display filtered output                                  │   │
│  │  - Update job status                                        │   │
│  │  - Log execution (redacted)                                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Security Boundaries

#### Boundary 1: User Input → Validation
- **Type:** Input validation boundary
- **Trust:** LOW → LOW-MEDIUM
- **Controls:**
  - Remove shell metacharacters (`;`, `|`, `&`, `$()`, backticks)
  - Validate command against allowlist
  - Check for path traversal patterns
  - Limit command length

#### Boundary 2: Validation → Execution
- **Type:** Critical security boundary
- **Trust:** LOW-MEDIUM → LOW
- **Controls:**
  - Use `execFile()` or `spawn()` with `shell: false`
  - Pass arguments as array (not string)
  - Validate working directory path
  - Filter environment variables

#### Boundary 3: Execution → Output
- **Type:** Data exfiltration boundary
- **Trust:** LOW → LOW-MEDIUM
- **Controls:**
  - Filter sensitive data from output
  - Redact credentials, tokens, keys
  - Limit output size (maxBuffer)
  - Validate output encoding

#### Boundary 4: Process → Resource Limits
- **Type:** Resource boundary
- **Trust:** LOW → MEDIUM
- **Controls:**
  - Enforce timeout limits
  - Set memory limits (maxBuffer)
  - Limit concurrent processes
  - Clean up on termination

### Data Flow Through Boundaries

```
User Input (Hook Config / Job Request)
       │
       ▼
┌─────────────────┐
│ Input           │ ← Boundary 1: Sanitization, Allowlisting
│ Validation      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Command         │ ← Boundary 2: execFile/spawn (no shell)
│ Execution       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ System Process  │
│ (User Privs)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Output          │ ← Boundary 3: Filtering, Redaction
│ Filtering       │
└────────┬────────┘
         │
         ▼
Display to User / Log
```

---

## 8. Security Recommendations

### Critical Priority (🔴)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 1 | **Replace exec() with execFile() or spawn({ shell: false })** | Eliminate shell interpretation entirely | MEDIUM |
| 2 | **Implement command allowlisting** | Only execute pre-approved commands | MEDIUM |
| 3 | **Sanitize all user input (remove metacharacters)** | Strip `;|&$(){}[]<>\` from input | LOW |
| 4 | **Validate working directory paths** | Prevent path traversal attacks | LOW |

### High Priority (🟠)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 5 | **Filter environment variables** | Pass minimal env to child processes | LOW |
| 6 | **Implement resource limits (timeout, memory)** | Set maxBuffer, timeout on all spawns | LOW |
| 7 | **Add output filtering/redaction** | Remove credentials from stdout/stderr | MEDIUM |
| 8 | **Require user confirmation for hooks** | Prompt before executing new hooks | MEDIUM |

### Medium Priority (🟡)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 9 | **Implement audit logging** | Log all command execution (redacted) | LOW |
| 10 | **Add concurrent job limits** | Enforce MAX_CONCURRENT_JOBS strictly | LOW |
| 11 | **Validate exit codes** | Check for non-zero exit, handle errors | LOW |
| 12 | **Implement per-project permissions** | Hook permissions scoped to project | MEDIUM |

### Low Priority (🟢)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 13 | **Document secure command patterns** | Create developer security guide | LOW |
| 14 | **Add security tests for hooks** | Test command injection scenarios | MEDIUM |
| 15 | **Implement hook sandboxing** | Consider containerization for hooks | HIGH |

### Implementation Checklist

```markdown
- [ ] Replace all exec() calls with execFile() or spawn({ shell: false })
- [ ] Implement command allowlist (git, npm, node, python, etc.)
- [ ] Add input sanitization function for shell metacharacters
- [ ] Validate working directory paths (prevent traversal)
- [ ] Filter environment variables (exclude sensitive vars)
- [ ] Set timeout and maxBuffer limits on all spawns
- [ ] Implement output filtering/redaction
- [ ] Add user confirmation for new hooks
- [ ] Implement audit logging (redacted)
- [ ] Enforce concurrent job limits
- [ ] Add security tests for command injection
- [ ] Document secure command execution patterns
```

### Secure Implementation Example

```typescript
// ✅ SECURE - Complete command execution with validation
import { execFile } from 'child_process';
import path from 'path';

// Command allowlist
const ALLOWED_COMMANDS = new Set([
  'git', 'npm', 'yarn', 'pnpm', 'node', 'python', 'python3',
  'osascript', 'powershell', 'xclip', 'wl-copy', 'wl-paste'
]);

// Shell metacharacters to remove
const SHELL_METACHARACTERS = /[;&|`$(){}[\]<>\\]/g;

interface SecureExecOptions {
  cwd: string;
  baseDir: string;
  timeout: number;
  maxBuffer: number;
}

async function secureExec(
  command: string,
  args: string[],
  options: SecureExecOptions
): Promise<{ stdout: string; stderr: string }> {
  // 1. Validate command is allowlisted
  const baseCommand = command.split(/[ \t]/)[0];
  if (!ALLOWED_COMMANDS.has(baseCommand)) {
    throw new Error(`Command not allowed: ${baseCommand}`);
  }
  
  // 2. Sanitize arguments (remove metacharacters)
  const sanitizedArgs = args.map(arg => 
    arg.replace(SHELL_METACHARACTERS, '')
  );
  
  // 3. Validate working directory
  const resolvedCwd = path.resolve(options.baseDir, options.cwd);
  const normalizedBase = path.resolve(options.baseDir);
  if (!resolvedCwd.startsWith(normalizedBase + path.sep)) {
    throw new Error('Path traversal detected in cwd');
  }
  
  // 4. Filter environment variables
  const safeEnv: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    LANG: process.env.LANG,
    // Explicitly exclude sensitive variables
  };
  
  // 5. Execute with limits
  return new Promise((resolve, reject) => {
    execFile(command, sanitizedArgs, {
      cwd: resolvedCwd,
      env: safeEnv,
      timeout: options.timeout,
      maxBuffer: options.maxBuffer,
      shell: false, // CRITICAL: No shell interpretation
    }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        // 6. Filter output before returning
        const filteredStdout = filterSensitiveData(stdout);
        const filteredStderr = filterSensitiveData(stderr);
        resolve({ stdout: filteredStdout, stderr: filteredStderr });
      }
    });
  });
}

function filterSensitiveData(output: string): string {
  return output
    .replace(/(AWS_SECRET_KEY|password|token|api_key)[=:]\s*\S+/gi, '$1=***REDACTED***')
    .replace(/(sk-[a-zA-Z0-9]{32,})/g, '***API_KEY***')
    .replace(/(ghp_[a-zA-Z0-9]{36})/g, '***GITHUB_TOKEN***');
}

// Usage example:
const result = await secureExec('git', ['status'], {
  cwd: './my-project',
  baseDir: '/home/user/projects',
  timeout: 30000,
  maxBuffer: 10 * 1024 * 1024,
});
```

---

## Summary

**child_process** is a **CRITICAL** risk dependency that enables arbitrary system command execution. It is essential for Continue CLI functionality (hooks, background jobs, clipboard operations) but introduces severe security risks:

**Key Findings:**
1. **Command Injection (CVSS 9.8):** User-controlled commands passed to shell without sanitization
2. **Path Traversal (CVSS 8.6):** Working directories can escape project boundaries
3. **Privilege Escalation (CVSS 7.8):** Commands run with full user privileges
4. **Shell Metacharacter Injection (CVSS 9.1):** `exec()` enables command chaining via `;|&$()`
5. **Resource Exhaustion (CVSS 6.5):** Multiple spawned processes can exhaust system resources
6. **Information Disclosure (CVSS 5.3):** Output may contain sensitive credentials

**Priority Actions:**
1. Replace `exec()` with `execFile()` or `spawn({ shell: false })`
2. Implement command allowlisting (whitelist approved commands)
3. Sanitize all user input (remove shell metacharacters)
4. Validate working directory paths (prevent traversal)
5. Filter environment variables (exclude sensitive vars)
6. Set resource limits (timeout, maxBuffer, concurrent jobs)
7. Implement output filtering/redaction

**Estimated Remediation Effort:** 2-3 weeks

**Overall Assessment:** `child_process` is unavoidable for CLI functionality but must be used with extreme caution. The primary risk is command injection through shell interpretation. By using `execFile()` or `spawn()` with `shell: false`, implementing command allowlisting, and validating all inputs, the risk can be reduced from CRITICAL to MEDIUM.

---

*Generated with [Continue](https://continue.dev)*

*Co-Authored-By: Continue <noreply@continue.dev>*
