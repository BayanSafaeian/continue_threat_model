# 🔒 Comprehensive Security Analysis: adm-zip Archive Handling

**Package:** `adm-zip`  
**Used In:** `extensions/vscode/src/util/extension.ts` (extension updates)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟡 **MEDIUM**

---

## 1. Dependency Purpose & Usage

### Primary Function
adm-zip is a pure JavaScript ZIP library for Node.js that provides compression and extraction capabilities for ZIP archives. In Continue, it's used to:
- Extract downloaded extension packages during installation/updates
- Create ZIP archives for extension bundling
- Handle compressed extension assets from remote sources
- Manage extension lifecycle operations (install, update, remove)

### Implementation in Continue
```typescript
// extensions/vscode/src/util/extension.ts
import AdmZip from 'adm-zip';
import * as path from 'path';
import * as fs from 'fs';

// Download and install extension
async function installExtension(extensionUrl: string, targetDir: string) {
  // Download ZIP from remote source
  const archivePath = await downloadExtension(extensionUrl);
  
  // Load and extract ZIP
  const zip = new AdmZip(archivePath);
  const entries = zip.getEntries();
  
  // Validate entries before extraction
  for (const entry of entries) {
    if (!isValidEntryPath(entry.entryName, targetDir)) {
      throw new Error(`Invalid entry path: ${entry.entryName}`);
    }
  }
  
  // Extract to target directory
  zip.extractAllTo(targetDir, true); // overwrite = true
  
  // Cleanup
  fs.unlinkSync(archivePath);
}

// Create extension bundle
function createExtensionBundle(sourceDir: string, outputPath: string) {
  const zip = new AdmZip();
  zip.addLocalFolder(sourceDir);
  zip.writeZip(outputPath);
}
```

### Dependency Type
- **Runtime dependency** - Active during extension installation/updates
- **File system operations** - Reads/writes to local filesystem
- **Untrusted input handling** - Processes ZIP files from remote sources
- **Critical for extension management** - Required for extension lifecycle

---

## 2. Data Flow Analysis

### Inbound Data (Data In)

| Data Type | Source | Sensitivity | Processing |
|-----------|--------|-------------|------------|
| `ZIP Archive` | Remote extension repository | HIGH | Downloaded from external sources, potentially malicious |
| `ZipEntry` objects | Archive contents | HIGH | Individual files/directories within archive |
| `Entry Metadata` | ZIP central directory | MEDIUM | Permissions, timestamps, sizes, compression method |
| `Compressed Data` | Entry data (deflated) | HIGH | Actual file content, decompressed in memory |
| `Entry Names/Paths` | ZIP file headers | HIGH | May contain path traversal attempts (`../`) |

### Outbound Data (Data Out)

| Data Type | Destination | Sensitivity | Transmission |
|-----------|-------------|-------------|--------------|
| `Extracted Files` | Filesystem (extension directory) | HIGH | Written to disk, may be executed |
| `File Paths` | Filesystem paths | HIGH | Destination paths for extraction |
| `Created Archive` | Filesystem or network | MEDIUM | ZIP file created for bundling/distribution |
| `Entry Content` | Memory/buffer | VARIABLE | Read as text or binary buffer |

### Data Storage
- **In Memory:** Decompressed entry data, ZIP central directory structure
- **Persistent:** Extracted files written to extension directories
- **Temporary:** Downloaded ZIP archives (deleted after extraction)

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                     Continue Application                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Extension Manager                           │   │
│  │  - Extension discovery                                   │   │
│  │  - Download from repository                              │   │
│  │  - Installation/updates                                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           Downloaded ZIP Archive                         │   │
│  │  - From remote source (potentially untrusted)            │   │
│  │  - Stored temporarily in temp directory                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              adm-zip Processing                          │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  new AdmZip(archivePath)                          │  │   │
│  │  │  - Parse ZIP central directory                    │  │   │
│  │  │  - Load entry metadata                            │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  Entry Validation ← CRITICAL SECURITY POINT       │  │   │
│  │  │  - Path traversal detection (../)                 │  │   │
│  │  │  - Absolute path rejection                        │  │   │
│  │  │  - Symlink detection                              │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  zip.extractAllTo(targetDir)                      │  │   │
│  │  │  - Decompress entries                             │  │   │
│  │  │  - Write to filesystem                            │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           Extension Directory                            │   │
│  │  - Extracted files written to disk                       │   │
│  │  - May contain executable code (scripts, binaries)       │   │
│  │  - Loaded by VSCode extension host                       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

#### 3.1 Zip Slip (Path Traversal) (CVSS: 8.6 - HIGH)
**Description:** Malicious ZIP archive contains entries with path traversal sequences (`../`) that escape the target extraction directory.

**Attack Vector:**
- Attacker publishes malicious extension with crafted ZIP
- Entry name: `../../../tmp/malicious.js`
- Extraction writes file outside intended directory
- Overwrites system files or plants malicious scripts

**Impact:**
- Arbitrary file write
- System compromise
- Code execution with user privileges
- Data exfiltration

**Mitigation:**
```typescript
// ✅ SECURE - Path validation
function isValidEntryPath(entryName: string, targetDir: string): boolean {
  // Reject absolute paths
  if (path.isAbsolute(entryName)) {
    return false;
  }
  
  // Reject path traversal
  if (entryName.includes('..')) {
    return false;
  }
  
  // Verify final path stays within target
  const fullPath = path.resolve(targetDir, entryName);
  const resolvedTarget = path.resolve(targetDir);
  
  if (!fullPath.startsWith(resolvedTarget + path.sep)) {
    return false;
  }
  
  return true;
}
```

#### 3.2 Arbitrary File Write (CVSS: 8.6 - HIGH)
**Description:** Files written outside intended directory through path manipulation.

**Attack Vector:**
- Similar to Zip Slip but may use other techniques
- Symlinks in archive redirect extraction
- Windows alternate data streams
- Unicode normalization attacks

**Impact:**
- System file overwriting
- Configuration manipulation
- Malicious code planting

**Mitigation:**
- Validate all entry paths before extraction
- Don't follow symlinks during extraction
- Use canonical path resolution
- Implement extraction allowlist

#### 3.3 Symlink Attack (CVSS: 7.5 - HIGH)
**Description:** ZIP archive contains symlinks that redirect extraction to arbitrary locations.

**Attack Vector:**
- Attacker creates ZIP with symlink entry
- Symlink points to `/etc/passwd` or sensitive file
- Extraction follows symlink, writes to sensitive location

**Impact:**
- Sensitive file overwriting
- System compromise
- Privilege escalation

**Mitigation:**
```typescript
// ✅ SECURE - Symlink detection
for (const entry of zip.getEntries()) {
  // Check if entry is a symlink
  if (entry.header.flags & 0x08) { // Symlink flag
    throw new Error(`Symlinks not allowed: ${entry.entryName}`);
  }
  
  // Also check Unix permissions for symlink
  const mode = entry.attr >> 16;
  if ((mode & 0o170000) === 0o120000) { // S_IFLNK
    throw new Error(`Symlinks not allowed: ${entry.entryName}`);
  }
}
```

#### 3.4 Archive Bomb (DoS) (CVSS: 7.5 - HIGH)
**Description:** Highly compressed ZIP archive causes resource exhaustion during extraction.

**Attack Vector:**
- Attacker creates ZIP with extreme compression ratio
- Small ZIP (e.g., 42 bytes) expands to terabytes
- Extraction exhausts disk space or memory
- Denial of service

**Impact:**
- Resource exhaustion
- System crash or hang
- Service unavailability

**Mitigation:**
```typescript
// ✅ SECURE - Size limits
const MAX_ENTRY_SIZE = 100 * 1024 * 1024; // 100 MB
const MAX_TOTAL_SIZE = 500 * 1024 * 1024; // 500 MB

let totalSize = 0;
for (const entry of zip.getEntries()) {
  if (entry.header.size > MAX_ENTRY_SIZE) {
    throw new Error(`Entry too large: ${entry.entryName}`);
  }
  totalSize += entry.header.size;
  if (totalSize > MAX_TOTAL_SIZE) {
    throw new Error('Total archive size exceeds limit');
  }
}
```

#### 3.5 File Overwrite (CVSS: 6.5 - MEDIUM)
**Description:** Existing files overwritten during extraction, potentially causing data loss or code injection.

**Attack Vector:**
- Extension update overwrites existing files
- Malicious extension replaces legitimate files
- Race condition during extraction

**Impact:**
- Data loss
- Code injection
- Extension compromise

**Mitigation:**
- Extract to temporary directory first
- Validate contents before moving to final location
- Use atomic rename operations
- Check for existing files before extraction

#### 3.6 Malicious Payload (CVSS: 8.1 - HIGH)
**Description:** Extracted files contain malicious scripts or binaries that are executed.

**Attack Vector:**
- Attacker publishes malicious extension
- Extension contains backdoor, malware, or exploit code
- Code executed when extension loads

**Impact:**
- System compromise
- Credential theft
- Data exfiltration
- Lateral movement

**Mitigation:**
- Implement extension signature verification
- Scan extracted files for known malware patterns
- Use extension allowlist/allowlist
- Implement sandboxing for extension execution

#### 3.7 Supply Chain Attack (CVSS: 8.1 - HIGH)
**Description:** Compromised adm-zip package introduces malicious code.

**Attack Vector:**
- npm package compromised via account takeover
- Malicious code added to adm-zip library
- All users who update are compromised

**Impact:**
- Widespread compromise
- Credential theft
- Data exfiltration

**Mitigation:**
- Pin exact package versions
- Use npm audit and Snyk
- Monitor for package changes
- Implement package signature verification

#### 3.8 Metadata Manipulation (CVSS: 5.3 - MEDIUM)
**Description:** File permissions, timestamps, or other metadata manipulated in archive.

**Attack Vector:**
- Attacker sets executable permissions on scripts
- Timestamps manipulated to evade detection
- Ownership changed to escalate privileges

**Impact:**
- Privilege escalation
- Detection evasion
- Unauthorized execution

**Mitigation:**
- Reset file permissions after extraction
- Don't trust archive metadata
- Apply least-privilege permissions
- Validate file types match expected content

---

## 4. Entry Points

### Archive Loading

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `new AdmZip(zipPath)` | Path to ZIP file | Load ZIP from filesystem | File must be validated before loading |
| `new AdmZip(buffer)` | Buffer containing ZIP | Load ZIP from memory | Buffer from untrusted source |
| `zip.getEntries()` | None | Get all archive entries | Returns untrusted entry data |
| `zip.getEntry(entryName)` | Entry name string | Get specific entry | Entry name may be malicious |

### Extraction Operations

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `zip.extractAllTo(targetPath, overwrite)` | Target dir, overwrite flag | Extract all entries | CRITICAL - must validate paths first |
| `zip.extractEntryTo(entry, targetPath)` | Entry, target dir | Extract single entry | Validate entry before extraction |
| `zip.readAsText(entry)` | ZipEntry object | Read entry as text | May contain malicious content |
| `zip.readAsBinaryBuffer(entry)` | ZipEntry object | Read entry as buffer | Buffer size must be validated |

### Archive Creation

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `zip.addFile(path, content)` | Path, content buffer | Add file to archive | Path should be sanitized |
| `zip.addLocalFile(localPath)` | Local file path | Add local file to archive | Validate source file path |
| `zip.addLocalFolder(folderPath)` | Folder path | Add folder recursively | Validate folder structure |
| `zip.writeZip()` | None | Write ZIP to filesystem | Destination should be validated |
| `zip.writeZipPromise()` | None | Async write ZIP | Same validation required |

### Entry Inspection

| Entry Point | Parameters | Purpose | Security Considerations |
|-------------|------------|---------|------------------------|
| `entry.entryName` | Property | Get entry name | May contain path traversal |
| `entry.header.size` | Property | Get uncompressed size | Use for size validation |
| `entry.header.compressedSize` | Property | Get compressed size | Use for archive bomb detection |
| `entry.attr` | Property | Get file attributes | Check for symlinks, permissions |
| `entry.isDirectory` | Property | Check if directory | Directories may have traversal |

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Type | Sensitivity | CIA Priority | Notes |
|-------|------|-------------|--------------|-------|
| **Extension Packages** | Archive | HIGH | Integrity | Downloaded from remote sources, must be verified |
| **Extracted Files** | Filesystem | HIGH | Integrity | Written to extension directories, may be executed |
| **Target Directory** | Path | HIGH | Integrity | Extraction destination, must be protected |
| **Entry Paths** | Path | HIGH | Integrity | May contain path traversal attempts |
| **File Permissions** | Metadata | MEDIUM | Integrity | Unix permissions from archive |
| **Created Archives** | Archive | MEDIUM | Integrity | Bundled extension packages |
| **Extension Code** | Executable | CRITICAL | Integrity | Must not be tampered with |
| **User Data** | Data | CRITICAL | Confidentiality | Must not be exposed to malicious extensions |

### CIA Triad Analysis

#### Confidentiality
- **High Risk:** User data, credentials, API keys
- **Medium Risk:** Extension configuration, settings
- **Controls:** Sandbox extensions, limit file system access, encrypt sensitive data

#### Integrity
- **High Risk:** Extension packages, extracted files, target directories
- **Critical Risk:** Extension code integrity
- **Controls:** Signature verification, hash validation, path validation, atomic operations

#### Availability
- **High Risk:** Extension installation/update process
- **Medium Risk:** Archive extraction performance
- **Controls:** Size limits, timeout enforcement, resource quotas

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Justification | Risk Mitigation |
|-----------|-------------|---------------|-----------------|
| **adm-zip library** | MEDIUM | Mature library (10+ years), but handles untrusted input (archives) | Pin versions, validate all inputs |
| **Remote Archives** | LOW | Downloaded from external sources, potentially malicious | Signature verification, hash validation |
| **Extension Repository** | MEDIUM | Official repository has some vetting, but not comprehensive | Implement additional validation |
| **Filesystem** | HIGH | Write access to extension directories | Restrict permissions, use temp directories |
| **Entry Names** | LOW | Untrusted, may contain path traversal | Validate all entry paths |
| **Entry Content** | LOW | Untrusted, may contain malicious code | Scan, sandbox, validate |
| **Extracted Files** | LOW-MEDIUM | Untrusted until validated | Move to final location only after validation |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    HIGH TRUST ZONE                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Continue Core Application                   │   │
│  │  - Extension manager                                     │   │
│  │  - File system operations                                │   │
│  │  - User data handling                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           MEDIUM TRUST ZONE                              │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  Temporary Extraction Directory                    │  │   │
│  │  │  - Downloaded ZIP stored here                      │  │   │
│  │  │  - Extracted files validated here                  │  │   │
│  │  │  - Path validation ← TRUST BOUNDARY               │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼ (after validation)               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           FINAL EXTENSION DIRECTORY                      │   │
│  │  - Validated files moved here                            │   │
│  │  - Loaded by VSCode extension host                       │   │
│  │  - Sandboxed execution                                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              ▲                                  │
│                              │                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           LOW TRUST ZONE                                 │   │
│  │  ┌───────────────────────────────────────────────────┐  │   │
│  │  │  Remote Extension Repository                       │  │   │
│  │  │  - Untrusted ZIP archives                          │  │   │
│  │  │  - Potentially malicious content                   │  │   │
│  │  └───────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment

**Overall Trust Level:** MEDIUM

**Rationale:** adm-zip is a mature library with widespread use, but it processes untrusted input (remote ZIP files). The primary risk is path traversal (Zip Slip) leading to arbitrary file writes. The library itself is not malicious, but it can be weaponized through malicious archives.

**Key Trust Dependencies:**
- Extension repository security and vetting
- Proper path validation implementation
- File system permission restrictions
- Extension sandboxing effectiveness

**Critical Security Point:** The trust boundary is at the **path validation** step. All entry paths must be validated before extraction to prevent Zip Slip and arbitrary file writes.

---

## 7. Architecture & Security Boundaries

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Continue Application                         │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Extension Manager                         │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Extension Discovery                                   │ │   │
│  │  │  - Browse available extensions                         │ │   │
│  │  │  - Fetch metadata from repository                      │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │                            │                                │   │
│  │                            ▼                                │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Extension Downloader                                  │ │   │
│  │  │  - Download ZIP from remote source                     │ │   │
│  │  │  - Store in temporary directory                        │ │   │
│  │  │  - Verify hash/signature (if available)                │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │                            │                                │   │
│  │                            ▼                                │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Archive Validator ← CRITICAL SECURITY POINT           │ │   │
│  │  │  - Path traversal detection                            │ │   │
│  │  │  - Symlink detection                                   │ │   │
│  │  │  - Size limit validation                               │ │   │
│  │  │  - Entry type validation                               │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │                            │                                │   │
│  │                            ▼                                │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  adm-zip Extraction                                    │ │   │
│  │  │  - new AdmZip(archivePath)                             │ │   │
│  │  │  - zip.extractAllTo(tempDir)                           │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │                            │                                │   │
│  │                            ▼                                │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Post-Extraction Validation                            │ │   │
│  │  │  - Scan for malicious content                          │ │   │
│  │  │  - Validate manifest/structure                         │ │   │
│  │  │  - Check file types                                    │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  │                            │                                │   │
│  │                            ▼                                │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  Atomic Move to Final Directory                        │ │   │
│  │  │  - Move from temp to extension directory               │ │   │
│  │  │  - Update extension registry                           │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Security Boundaries

#### Boundary 1: Download → Temporary Storage
- **Type:** Network boundary
- **Trust:** LOW → MEDIUM
- **Controls:** 
  - HTTPS for downloads
  - Hash verification (if available)
  - Signature verification (if available)
  - Store in isolated temp directory

#### Boundary 2: Archive Loading → Validation
- **Type:** Critical security boundary
- **Trust:** LOW → MEDIUM
- **Controls:**
  - Path traversal detection
  - Symlink detection
  - Size limit validation
  - Entry type validation

#### Boundary 3: Validation → Extraction
- **Type:** Critical security boundary
- **Trust:** MEDIUM → MEDIUM
- **Controls:**
  - Only extract validated entries
  - Use isolated temp directory
  - Don't follow symlinks
  - Enforce size limits

#### Boundary 4: Temp Directory → Final Directory
- **Type:** Filesystem boundary
- **Trust:** MEDIUM → HIGH
- **Controls:**
  - Post-extraction validation
  - Atomic move operation
  - Permission reset
  - Registry update

### Data Flow Through Boundaries

```
Remote Repository
       │
       ▼ HTTPS
┌─────────────────┐
│ Download ZIP    │ ← Boundary 1: Hash/Signature Verification
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Temp Storage    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Archive         │ ← Boundary 2: Path/Symlink/Size Validation (CRITICAL)
│ Validation      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ adm-zip         │ ← Boundary 3: Validated Extraction Only
│ Extraction      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Post-Extraction │ ← Boundary 4: Content Validation
│ Validation      │
└────────┬────────┘
         │
         ▼ Atomic Move
┌─────────────────┐
│ Final Extension │
│ Directory       │
└─────────────────┘
```

---

## 8. Security Recommendations

### Critical Priority (🔴)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 1 | **Validate entry paths (reject `../`, absolute paths)** | Implement comprehensive path validation before extraction | MEDIUM |
| 2 | **Restrict extraction to designated directories only** | Use temp directory, verify all paths stay within bounds | LOW |
| 3 | **Implement signature/hash verification for extensions** | Verify downloaded archives against known hashes | MEDIUM |

### High Priority (🟠)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 4 | **Verify archive integrity before extraction** | Check ZIP structure, CRC values | MEDIUM |
| 5 | **Don't follow symlinks during extraction** | Detect and reject symlink entries | LOW |
| 6 | **Limit extraction size (prevent archive bomb)** | Set max entry size and total archive size | LOW |
| 7 | **Extract to temp directory first, then atomic move** | Two-stage extraction with validation | MEDIUM |

### Medium Priority (🟡)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 8 | **Check for existing files before extraction** | Prevent accidental overwrites | LOW |
| 9 | **Scan extracted files for malicious content** | Implement malware scanning or pattern detection | MEDIUM |
| 10 | **Reset file permissions after extraction** | Apply least-privilege permissions | LOW |

### Low Priority (🟢)

| # | Recommendation | Implementation | Effort |
|---|---------------|----------------|--------|
| 11 | **Log extraction operations for auditing** | Record all extraction activities | LOW |
| 12 | **Implement extension allowlist** | Only allow extensions from trusted sources | MEDIUM |
| 13 | **Document extraction security practices** | Create security documentation for developers | LOW |

### Implementation Checklist

```markdown
- [ ] Implement path validation function (reject `../`, absolute paths)
- [ ] Add symlink detection and rejection
- [ ] Configure size limits (max entry: 100MB, total: 500MB)
- [ ] Extract to temporary directory first
- [ ] Implement post-extraction validation
- [ ] Add atomic move to final directory
- [ ] Reset file permissions after extraction
- [ ] Implement hash verification for known extensions
- [ ] Add extraction logging for auditing
- [ ] Create extension allowlist mechanism
- [ ] Document secure extraction patterns
```

### Secure Extraction Implementation

```typescript
// ✅ SECURE - Complete extraction with validation
import AdmZip from 'adm-zip';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';

interface ExtractionOptions {
  maxEntrySize: number;
  maxTotalSize: number;
  allowedExtensions: string[];
}

async function secureExtract(
  archivePath: string,
  targetDir: string,
  options: ExtractionOptions
): Promise<void> {
  const tempDir = path.join(targetDir, '.temp_' + Date.now());
  
  try {
    // Create temp directory
    fs.mkdirSync(tempDir, { recursive: true });
    
    // Load archive
    const zip = new AdmZip(archivePath);
    const entries = zip.getEntries();
    
    // Validate all entries
    let totalSize = 0;
    for (const entry of entries) {
      const entryName = entry.entryName;
      
      // 1. Reject absolute paths
      if (path.isAbsolute(entryName)) {
        throw new Error(`Absolute path not allowed: ${entryName}`);
      }
      
      // 2. Reject path traversal
      if (entryName.includes('..')) {
        throw new Error(`Path traversal detected: ${entryName}`);
      }
      
      // 3. Reject symlinks
      const mode = entry.attr >> 16;
      if ((mode & 0o170000) === 0o120000) {
        throw new Error(`Symlinks not allowed: ${entryName}`);
      }
      
      // 4. Check size limits
      if (entry.header.size > options.maxEntrySize) {
        throw new Error(`Entry too large: ${entryName}`);
      }
      totalSize += entry.header.size;
      if (totalSize > options.maxTotalSize) {
        throw new Error('Total archive size exceeds limit');
      }
      
      // 5. Verify final path stays within target
      const fullPath = path.resolve(tempDir, entryName);
      const resolvedTarget = path.resolve(tempDir);
      if (!fullPath.startsWith(resolvedTarget + path.sep)) {
        throw new Error(`Path escapes target: ${entryName}`);
      }
    }
    
    // Extract to temp directory
    zip.extractAllTo(tempDir, true);
    
    // Post-extraction validation
    await validateExtractedContents(tempDir, options);
    
    // Atomic move to final directory
    const finalDir = path.join(targetDir, 'extension');
    fs.renameSync(tempDir, finalDir);
    
  } catch (error) {
    // Cleanup on error
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
}

async function validateExtractedContents(
  dir: string,
  options: ExtractionOptions
): Promise<void> {
  // Check file types, scan for malicious patterns, etc.
  const files = fs.readdirSync(dir, { recursive: true });
  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (options.allowedExtensions.length > 0 && 
        !options.allowedExtensions.includes(ext)) {
      throw new Error(`Disallowed file type: ${file}`);
    }
  }
}
```

---

## Summary

**adm-zip** is a critical dependency for extension management that handles untrusted input (remote ZIP archives). It introduces **MEDIUM risk** due to:

1. **Path Traversal (Zip Slip):** Malicious archives can escape target directory and write arbitrary files
2. **Symlink Attacks:** Symlinks in archives can redirect extraction to sensitive locations
3. **Archive Bombs:** Highly compressed archives can cause resource exhaustion
4. **Malicious Payloads:** Extracted code may contain backdoors or malware

**Key Security Controls:**
- Validate all entry paths before extraction (reject `../`, absolute paths)
- Detect and reject symlink entries
- Enforce size limits to prevent archive bombs
- Extract to temporary directory first, then atomic move
- Implement signature/hash verification for extensions
- Reset file permissions after extraction

**Overall Assessment:** adm-zip is a mature library, but it processes untrusted input from remote sources. The primary risks are path traversal and arbitrary file writes. With proper validation and a two-stage extraction process (temp directory → validation → atomic move), adm-zip can be used safely for extension management.

---

*Generated with [Continue](https://continue.dev)*

*Co-Authored-By: Continue <noreply@continue.dev>*
