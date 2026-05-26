# 🔒 Comprehensive Security Analysis: devdataSqlite [Development Data Storage]

**Package:** `core/data/devdataSqlite.ts`  
**Used In:** `/core/data/devdataSqlite.ts` (local token usage tracking and analytics)  
**Analysis Date:** 2026-05-25  
**Risk Level:** 🟢 **LOW-MEDIUM**

---

## 1. Dependency Purpose & Usage

### Primary Function
DevDataSqliteDb provides local SQLite storage for development telemetry data, specifically tracking token usage (generated and prompt tokens) per model and provider. It's used for local analytics and usage reporting.

### Implementation
```typescript
import fs from "fs";
import { open } from "sqlite";
import sqlite3 from "sqlite3";

export class DevDataSqliteDb {
  static db: DatabaseConnection | null = null;

  private static async createTables(db: DatabaseConnection) {
    await db.exec(
      `CREATE TABLE IF NOT EXISTS tokens_generated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model TEXT NOT NULL,
        provider TEXT NOT NULL,
        tokens_generated INTEGER NOT NULL,
        tokens_prompt INTEGER NOT NULL DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
    );
  }

  public static async logTokensGenerated(
    model: string,
    provider: string,
    promptTokens: number,
    generatedTokens: number,
  ) {
    const db = await DevDataSqliteDb.get();
    await db?.run(
      "INSERT INTO tokens_generated (model, provider, tokens_prompt, tokens_generated) VALUES (?, ?, ?, ?)",
      [model, provider, promptTokens, generatedTokens],
    );
  }

  public static async getTokensPerDay() {
    const db = await DevDataSqliteDb.get();
    const result = await db?.all(
      `SELECT date(timestamp) as day, 
              sum(tokens_prompt) as promptTokens, 
              sum(tokens_generated) as generatedTokens
       FROM tokens_generated
       GROUP BY date(timestamp)`,
    );
    return result ?? [];
  }
}
```

### Dependency Type
- **Internal Core Module** - Local telemetry data storage
- **External Dependencies:** 
  - `sqlite` - Database connection management
  - `sqlite3` - SQLite driver
  - `fs` - File system operations
- **Storage:** Local SQLite database file

---

## 2. Data Flow Analysis

### Inbound Data
| Data Type | Source | Sensitivity | Validation |
|-----------|--------|-------------|------------|
| Model name | LLM component | Low | String type check |
| Provider name | LLM component | Low | String type check |
| Prompt token count | LLM component | Low | Number type check |
| Generated token count | LLM component | Low | Number type check |
| Timestamp | System (CURRENT_TIMESTAMP) | Low | Auto-generated |

### Outbound Data
| Data Type | Destination | Sensitivity | Security Controls |
|-----------|-------------|-------------|-------------------|
| Aggregated token data | Analytics/GUI | Low | Summarized data only |
| Raw token logs | Internal queries | Low | File system permissions |
| Database file | Local file system | Low | File system permissions |

### Data Storage
| Storage | Location | Data Type | Encryption |
|---------|----------|-----------|------------|
| SQLite DB | `getDevDataSqlitePath()` | Token usage logs | No (file system only) |
| In-memory cache | `DevDataSqliteDb.db` | Database connection | N/A |

### Data Flow Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                      Data Sources                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  LLM         │  │  LLM         │  │  System              │  │
│  │  Component   │  │  Component   │  │  Timestamp           │  │
│  │  (Model)     │  │  (Provider)  │  │                      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
└─────────┼─────────────────┼─────────────────────┼──────────────┘
          │                 │                     │
          ▼                 ▼                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DevDataSqliteDb                             │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  logTokensGenerated()                                      │ │
│  │  - Parameterized INSERT                                    │ │
│  │  - Model, Provider, Token counts                           │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  SQLite Database                                           │ │
│  │  - tokens_generated table                                  │ │
│  │  - Local file storage                                      │ │
│  │  - busy_timeout = 3000ms                                   │ │
│  └───────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Query Methods                                             │ │
│  │  - getTokensPerDay()                                       │ │
│  │  - getTokensPerModel()                                     │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Output                                     │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Aggregated Token Usage                                    │ │
│  │  - By day                                                   │ │
│  │  - By model                                                 │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Analysis

### Primary Threats

| Threat | CVSS Score | Attack Vector | Impact | Likelihood |
|--------|------------|---------------|--------|------------|
| SQL Injection via Model/Provider | 7.5 (High) | Local | Data corruption, potential code execution | Low (parameterized queries) |
| Database File Tampering | 5.5 (Medium) | Local | Data integrity loss | Medium |
| SQLite Busy/Corruption | 4.5 (Medium) | Local | Data loss, service disruption | Low |
| Usage Data Exposure | 3.5 (Low) | Local | Privacy concern (usage patterns) | Low |
| Path Traversal (DB path) | 5.0 (Medium) | Local | File system access | Low (fixed path) |

### Attack Vectors

**1. SQL Injection (Currently Mitigated)**
```typescript
// SECURE: Using parameterized queries
public static async logTokensGenerated(
  model: string,
  provider: string,
  promptTokens: number,
  generatedTokens: number,
) {
  const db = await DevDataSqliteDb.get();
  await db?.run(
    "INSERT INTO tokens_generated (model, provider, tokens_prompt, tokens_generated) VALUES (?, ?, ?, ?)",
    [model, provider, promptTokens, generatedTokens],  // Parameters safely bound
  );
}
```

**Note:** Current implementation uses parameterized queries which prevents SQL injection. ✅

**2. Database File Tampering**
```typescript
// VULNERABLE: No integrity verification
DevDataSqliteDb.db = await open({
  filename: devDataSqlitePath,
  driver: sqlite3.Database,
});

// SECURE: Add integrity verification
import { createHash } from "crypto";
import fs from "fs";

public static async get() {
  const devDataSqlitePath = getDevDataSqlitePath();
  
  if (DevDataSqliteDb.db && fs.existsSync(devDataSqlitePath)) {
    // SECURITY: Verify database integrity
    const integrityCheck = await this.verifyDatabaseIntegrity(devDataSqlitePath);
    if (!integrityCheck.valid) {
      console.warn("Database integrity check failed, recreating");
      DevDataSqliteDb.db = null;
      // Optionally backup corrupted DB
      await this.backupCorruptedDatabase(devDataSqlitePath);
    } else {
      return DevDataSqliteDb.db;
    }
  }

  DevDataSqliteDb.db = await open({
    filename: devDataSqlitePath,
    driver: sqlite3.Database,
  });

  await DevDataSqliteDb.db.exec("PRAGMA integrity_check;");
  await DevDataSqliteDb.db.exec("PRAGMA busy_timeout = 3000;");
  await DevDataSqliteDb.createTables(DevDataSqliteDb.db!);

  return DevDataSqliteDb.db;
}

private static async verifyDatabaseIntegrity(dbPath: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const db = await open({ filename: dbPath, driver: sqlite3.Database });
    const result = await db.get("PRAGMA integrity_check;");
    await db.close();
    return { valid: result.integrity_check === 'ok' };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}
```

**3. Concurrent Access Protection**
```typescript
// CURRENT: Basic busy timeout
await DevDataSqliteDb.db.exec("PRAGMA busy_timeout = 3000;");

// SECURE: Enhanced concurrency handling
public static async get() {
  const devDataSqlitePath = getDevDataSqlitePath();
  
  DevDataSqliteDb.db = await open({
    filename: devDataSqlitePath,
    driver: sqlite3.Database,
  });

  // SECURITY: Enhanced SQLite settings for concurrency
  await DevDataSqliteDb.db.exec("PRAGMA busy_timeout = 5000;");  // 5 second timeout
  await DevDataSqliteDb.db.exec("PRAGMA journal_mode = WAL;");   // Write-Ahead Logging
  await DevDataSqliteDb.db.exec("PRAGMA synchronous = NORMAL;");  // Balance safety/performance
  await DevDataSqliteDb.db.exec("PRAGMA foreign_keys = ON;");    // Enable foreign keys
  
  await DevDataSqliteDb.createTables(DevDataSqliteDb.db!);
  return DevDataSqliteDb.db;
}
```

**4. Data Validation**
```typescript
// SECURE: Validate input data before storage
public static async logTokensGenerated(
  model: string,
  provider: string,
  promptTokens: number,
  generatedTokens: number,
) {
  // SECURITY: Input validation
  if (!model || typeof model !== 'string' || model.length > 256) {
    throw new Error("Invalid model name");
  }
  if (!provider || typeof provider !== 'string' || provider.length > 256) {
    throw new Error("Invalid provider name");
  }
  if (typeof promptTokens !== 'number' || promptTokens < 0 || promptTokens > 1000000) {
    throw new Error("Invalid prompt token count");
  }
  if (typeof generatedTokens !== 'number' || generatedTokens < 0 || generatedTokens > 1000000) {
    throw new Error("Invalid generated token count");
  }

  const db = await DevDataSqliteDb.get();
  await db?.run(
    "INSERT INTO tokens_generated (model, provider, tokens_prompt, tokens_generated) VALUES (?, ?, ?, ?)",
    [model, provider, promptTokens, generatedTokens],
  );
}
```

---

## 4. Entry Points

### Public Methods

| Entry Point | Parameters | Security Considerations |
|-------------|------------|------------------------|
| `logTokensGenerated(model, provider, promptTokens, generatedTokens)` | Model name, Provider, Token counts | **LOW** - Input validation needed |
| `getTokensPerDay()` | None | **LOW** - Read-only aggregation |
| `getTokensPerModel()` | None | **LOW** - Read-only aggregation |
| `get()` | None | **MEDIUM** - Database connection, file access |

### Internal Methods

| Method | Called By | Security Considerations |
|--------|-----------|------------------------|
| `createTables(db)` | get() | **LOW** - Schema creation |
| Database connection | All public methods | **MEDIUM** - File system access |

### Security Boundary Entry Points
```typescript
// SECURE: Validate all inputs at entry points
public static async logTokensGenerated(
  model: string,
  provider: string,
  promptTokens: number,
  generatedTokens: number,
) {
  // SECURITY BOUNDARY: Input validation
  const MAX_STRING_LENGTH = 256;
  const MAX_TOKEN_COUNT = 1000000;

  // Validate model
  if (!model || typeof model !== 'string') {
    console.warn("Invalid model parameter");
    return;
  }
  if (model.length > MAX_STRING_LENGTH) {
    model = model.substring(0, MAX_STRING_LENGTH);
  }

  // Validate provider
  if (!provider || typeof provider !== 'string') {
    console.warn("Invalid provider parameter");
    return;
  }
  if (provider.length > MAX_STRING_LENGTH) {
    provider = provider.substring(0, MAX_STRING_LENGTH);
  }

  // Validate token counts
  if (typeof promptTokens !== 'number' || promptTokens < 0) {
    console.warn("Invalid promptTokens parameter");
    promptTokens = 0;
  }
  if (typeof generatedTokens !== 'number' || generatedTokens < 0) {
    console.warn("Invalid generatedTokens parameter");
    generatedTokens = 0;
  }

  // Cap token counts to reasonable maximum
  promptTokens = Math.min(promptTokens, MAX_TOKEN_COUNT);
  generatedTokens = Math.min(generatedTokens, MAX_TOKEN_COUNT);

  const db = await DevDataSqliteDb.get();
  await db?.run(
    "INSERT INTO tokens_generated (model, provider, tokens_prompt, tokens_generated) VALUES (?, ?, ?, ?)",
    [model, provider, promptTokens, generatedTokens],
  );
}
```

---

## 5. Assets & CIA Triad

### Critical Assets

| Asset | Confidentiality | Integrity | Availability | Priority |
|-------|-----------------|-----------|--------------|----------|
| Token usage data | Low | Medium | Medium | Low |
| SQLite database file | Low | **High** | Medium | Medium |
| Database connection | Low | Medium | **High** | Medium |
| Aggregated analytics | Low | Medium | Low | Low |

### CIA Triad Analysis

**Confidentiality:**
- **Risk:** Token usage data could reveal development patterns
- **Current Controls:** Local file storage, file system permissions
- **Gaps:** No encryption at rest
- **Recommendation:** Low priority - data is not sensitive

**Integrity:**
- **Risk:** Database corruption or tampering could affect usage reporting
- **Current Controls:** SQLite transactions, parameterized queries
- **Gaps:** No integrity verification, no backup mechanism
- **Recommendation:** Add integrity checks, periodic backups

**Availability:**
- **Risk:** Database lock or corruption could block logging
- **Current Controls:** busy_timeout (3000ms), connection caching
- **Gaps:** No fallback if DB unavailable, no error recovery
- **Recommendation:** Add graceful degradation, error handling

---

## 6. Trust Level Assessment

### Component Trust Levels

| Component | Trust Level | Rationale | Security Requirements |
|-----------|-------------|-----------|----------------------|
| SQLite Driver | **High** | Well-established library | Keep updated |
| File System | **Medium** | Local storage | File permissions |
| Input Data (LLM) | **Medium** | Internal component | Input validation |
| Database Path | **Medium** | Configurable path | Path validation |

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE (Core Logic)                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  DevDataSqliteDb                                          │  │
│  │  - Token logging                                          │  │
│  │  - Aggregation queries                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          │
          ═══════════════════════════════════════
          TRUST BOUNDARY: File System & SQLite
          ═══════════════════════════════════════
                          │
┌─────────────────────────────────────────────────────────────────┐
│                  UNTRUSTED ZONE (External)                      │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │  SQLite File     │  │  Input Data      │                    │
│  │  (Local FS)      │  │  (LLM Component) │                    │
│  └──────────────────┘  └──────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

### Overall Trust Assessment
- **Trust Score:** 7/10 (Medium-High)
- **Primary Concern:** Minimal - low-sensitivity data
- **Secondary Concern:** Database integrity without verification
- **Recommendation:** Add integrity checks for production use

---

## 7. Architecture & Security Boundaries

### System Architecture
```
┌─────────────────────────────────────────────────────────────────────┐
│                        Data Sources                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  LLM        │  │  LLM        │  │  System     │                 │
│  │  (Model)    │  │  (Provider) │  │  (Time)     │                 │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                 │
└─────────┼─────────────────┼─────────────────┼───────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      SECURITY BOUNDARY                              │
│  ═══════════════════════════════════════════════════════════════    │
│  │ Input Validation │ Parameter Binding │ Path Verification │        │
│  ═══════════════════════════════════════════════════════════════    │
└─────────────────────────────────────────────────────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       DevDataSqliteDb                               │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Input Validation Layer                                       │ │
│  │  - Parameter type checking                                    │ │
│  │  - Length validation                                          │ │
│  │  - Range validation                                           │ │
│  └───────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Database Layer                                               │ │
│  │  - SQLite connection                                          │ │
│  │  - Parameterized queries                                      │ │
│  │  - Transaction management                                     │ │
│  └───────────────────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Storage Layer                                                │ │
│  │  - Local file system                                          │ │
│  │  - tokens_generated table                                     │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Output Layer                                   │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Aggregated Analytics                                         │ │
│  │  - Tokens per day                                             │ │
│  │  - Tokens per model                                           │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Security Boundaries

| Boundary | From | To | Protection Mechanism |
|----------|------|-----|---------------------|
| LLM → DevData | Token data | logTokensGenerated() | Parameter type validation |
| DevData → SQLite | Queries | Database | Parameterized queries |
| DevData → File System | DB file | Local FS | File system permissions |
| DevData → Analytics | Aggregated data | GUI/Internal | Summarization (no raw data) |

### Data Flow Through Boundaries
```
Token Usage Event
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 1: Input Validation    │
│ - Type checking                 │
│ - Length limits                 │
│ - Range validation              │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 2: Query Safety        │
│ - Parameterized INSERT          │
│ - SQL injection prevention      │
└─────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│ BOUNDARY 3: Storage Security    │
│ - File system permissions       │
│ - [MISSING: Integrity check]    │
└─────────────────────────────────┘
         │
         ▼
   Data Stored in SQLite
```

---

## 8. Security Recommendations

### Critical Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 1 | No critical issues | Current implementation is secure for low-sensitivity data | N/A |

### High Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 2 | Add input validation | Prevent data corruption, DoS via large inputs | Low (2-4 hours) |
| 3 | Implement database integrity checks | Detect corruption early | Low (2-4 hours) |

### Medium Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 4 | Enable WAL mode for concurrency | Better concurrent access handling | Low (1-2 hours) |
| 5 | Add graceful degradation | Handle DB unavailability gracefully | Low (2-4 hours) |
| 6 | Implement periodic backups | Data recovery capability | Medium (4-8 hours) |

### Low Priority

| # | Recommendation | Rationale | Implementation Effort |
|---|----------------|-----------|----------------------|
| 7 | Add error logging | Debugging and monitoring | Low (1-2 hours) |
| 8 | Implement data retention policy | Prevent unbounded growth | Low (2-4 hours) |
| 9 | Add database encryption | Enhanced privacy (if needed) | Medium (4-8 hours) |

### Implementation Checklist

- [ ] **HIGH:** Add input validation for logTokensGenerated parameters
- [ ] **HIGH:** Implement database integrity verification on open
- [ ] **MEDIUM:** Enable WAL journal mode for better concurrency
- [ ] **MEDIUM:** Add graceful error handling (log to console if DB fails)
- [ ] **MEDIUM:** Implement periodic database backup
- [ ] **LOW:** Add structured error logging
- [ ] **LOW:** Implement data retention policy (e.g., delete data > 90 days)
- [ ] **LOW:** Evaluate need for database encryption

### Secure Implementation Example

```typescript
// SECURE: Enhanced DevDataSqliteDb with validation and integrity checks

import fs from "fs";
import { open } from "sqlite";
import sqlite3 from "sqlite3";
import { DatabaseConnection } from "../indexing/refreshIndex.js";
import { getDevDataSqlitePath } from "../util/paths.js";

// Security constants
const MAX_STRING_LENGTH = 256;
const MAX_TOKEN_COUNT = 1_000_000;
const DB_INTEGRITY_CHECK = true;

export class DevDataSqliteDb {
  static db: DatabaseConnection | null = null;
  static lastBackupTimestamp: number = 0;

  private static async createTables(db: DatabaseConnection) {
    await db.exec(
      `CREATE TABLE IF NOT EXISTS tokens_generated (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model TEXT NOT NULL,
        provider TEXT NOT NULL,
        tokens_generated INTEGER NOT NULL,
        tokens_prompt INTEGER NOT NULL DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,
    );

    // Add tokens_prompt column if it doesn't exist
    const columnCheckResult = await db.all("PRAGMA table_info(tokens_generated);");
    const columnExists = columnCheckResult.some((col: any) => col.name === "tokens_prompt");
    if (!columnExists) {
      await db.exec(
        "ALTER TABLE tokens_generated ADD COLUMN tokens_prompt INTEGER NOT NULL DEFAULT 0;",
      );
    }
  }

  private static validateInput(
    model: string,
    provider: string,
    promptTokens: number,
    generatedTokens: number,
  ): { valid: boolean; model: string; provider: string; promptTokens: number; generatedTokens: number } {
    // Validate model
    if (!model || typeof model !== 'string') {
      console.warn("[DevDataSqliteDb] Invalid model parameter");
      return { valid: false, model: '', provider: '', promptTokens: 0, generatedTokens: 0 };
    }
    model = model.substring(0, MAX_STRING_LENGTH);

    // Validate provider
    if (!provider || typeof provider !== 'string') {
      console.warn("[DevDataSqliteDb] Invalid provider parameter");
      return { valid: false, model: '', provider: '', promptTokens: 0, generatedTokens: 0 };
    }
    provider = provider.substring(0, MAX_STRING_LENGTH);

    // Validate token counts
    if (typeof promptTokens !== 'number' || promptTokens < 0) {
      console.warn("[DevDataSqliteDb] Invalid promptTokens parameter");
      promptTokens = 0;
    }
    if (typeof generatedTokens !== 'number' || generatedTokens < 0) {
      console.warn("[DevDataSqliteDb] Invalid generatedTokens parameter");
      generatedTokens = 0;
    }

    // Cap token counts
    promptTokens = Math.min(promptTokens, MAX_TOKEN_COUNT);
    generatedTokens = Math.min(generatedTokens, MAX_TOKEN_COUNT);

    return { valid: true, model, provider, promptTokens, generatedTokens };
  }

  public static async logTokensGenerated(
    model: string,
    provider: string,
    promptTokens: number,
    generatedTokens: number,
  ) {
    try {
      // SECURITY: Validate inputs
      const validation = this.validateInput(model, provider, promptTokens, generatedTokens);
      if (!validation.valid) {
        return;
      }

      const db = await DevDataSqliteDb.get();
      if (!db) {
        console.warn("[DevDataSqliteDb] Database unavailable, skipping token logging");
        return;
      }

      await db.run(
        "INSERT INTO tokens_generated (model, provider, tokens_prompt, tokens_generated) VALUES (?, ?, ?, ?)",
        [validation.model, validation.provider, validation.promptTokens, validation.generatedTokens],
      );
    } catch (error) {
      // SECURITY: Graceful degradation - don't crash on DB errors
      console.warn("[DevDataSqliteDb] Failed to log tokens:", error);
    }
  }

  public static async getTokensPerDay() {
    try {
      const db = await DevDataSqliteDb.get();
      if (!db) return [];
      
      const result = await db.all(
        `SELECT date(timestamp) as day, 
                sum(tokens_prompt) as promptTokens, 
                sum(tokens_generated) as generatedTokens
         FROM tokens_generated
         GROUP BY date(timestamp)`,
      );
      return result ?? [];
    } catch (error) {
      console.warn("[DevDataSqliteDb] Failed to get tokens per day:", error);
      return [];
    }
  }

  public static async getTokensPerModel() {
    try {
      const db = await DevDataSqliteDb.get();
      if (!db) return [];
      
      const result = await db.all(
        `SELECT model, 
                sum(tokens_prompt) as promptTokens, 
                sum(tokens_generated) as generatedTokens
         FROM tokens_generated
         GROUP BY model`,
      );
      return result ?? [];
    } catch (error) {
      console.warn("[DevDataSqliteDb] Failed to get tokens per model:", error);
      return [];
    }
  }

  private static async verifyDatabaseIntegrity(dbPath: string): Promise<boolean> {
    try {
      const db = await open({ filename: dbPath, driver: sqlite3.Database });
      const result = await db.get("PRAGMA integrity_check;");
      await db.close();
      return result.integrity_check === 'ok';
    } catch (error) {
      console.warn("[DevDataSqliteDb] Integrity check failed:", error);
      return false;
    }
  }

  private static async backupDatabase(dbPath: string): Promise<void> {
    try {
      const backupPath = `${dbPath}.backup.${Date.now()}`;
      await fs.promises.copyFile(dbPath, backupPath);
      console.log("[DevDataSqliteDb] Database backed up to:", backupPath);
    } catch (error) {
      console.warn("[DevDataSqliteDb] Backup failed:", error);
    }
  }

  static async get() {
    const devDataSqlitePath = getDevDataSqlitePath();
    
    if (DevDataSqliteDb.db && fs.existsSync(devDataSqlitePath)) {
      return DevDataSqliteDb.db;
    }

    // SECURITY: Verify database integrity before opening
    if (DB_INTEGRITY_CHECK && fs.existsSync(devDataSqlitePath)) {
      const integrityValid = await this.verifyDatabaseIntegrity(devDataSqlitePath);
      if (!integrityValid) {
        console.warn("[DevDataSqliteDb] Database integrity check failed, creating backup");
        await this.backupDatabase(devDataSqlitePath);
        // Remove corrupted DB (will be recreated)
        await fs.promises.unlink(devDataSqlitePath).catch(() => {});
      }
    }

    DevDataSqliteDb.db = await open({
      filename: devDataSqlitePath,
      driver: sqlite3.Database,
    });

    // SECURITY: Enhanced SQLite settings
    await DevDataSqliteDb.db.exec("PRAGMA busy_timeout = 5000;");  // 5 second timeout
    await DevDataSqliteDb.db.exec("PRAGMA journal_mode = WAL;");   // Write-Ahead Logging
    await DevDataSqliteDb.db.exec("PRAGMA synchronous = NORMAL;");  // Balance safety/performance

    await DevDataSqliteDb.createTables(DevDataSqliteDb.db!);

    // SECURITY: Periodic backup (every 24 hours)
    const now = Date.now();
    if (now - this.lastBackupTimestamp > 24 * 60 * 60 * 1000) {
      await this.backupDatabase(devDataSqlitePath);
      this.lastBackupTimestamp = now;
    }

    return DevDataSqliteDb.db;
  }
}
```

---

**Analysis Complete** ✅

*This security analysis was generated with [Continue](https://continue.dev)*

*Co-Authored-By: Continue <noreply@continue.dev>*
