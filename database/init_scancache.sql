-- ===================================================================
-- AEGISPC (ULTRON DEFENDER) HIGH-PERFORMANCE SCAN CACHE DATABASE SCHEMA
-- File: ScanCache.db
-- ===================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA cache_size = -32000; -- 32 MB Page Cache

-- 1. Tarama Önbellek Kayıtları (L2 Cache)
CREATE TABLE IF NOT EXISTS ScanCacheEntries (
    CacheKey TEXT PRIMARY KEY,                       -- Sha256::FileSize::LastWriteTicks
    FastPathKey TEXT,                                -- FilePath::FileSize::LastWriteTicks
    Sha256 TEXT NOT NULL COLLATE NOCASE,
    FilePath TEXT NOT NULL COLLATE NOCASE,
    FileSize INTEGER NOT NULL,
    LastWriteTimeUtc TEXT NOT NULL,
    Verdict INTEGER NOT NULL,                        -- Enum RealTimeVerdict
    PolicyAction INTEGER NOT NULL DEFAULT 0,         -- Enum RealTimePolicyAction
    RiskScore INTEGER NOT NULL,                      -- 0 - 100
    RiskLevel INTEGER NOT NULL,                      -- Enum RiskLevel
    ThreatTitle TEXT,
    Confidence REAL NOT NULL DEFAULT 1.0,
    EvidencesJson TEXT,
    CachedAtUtc TEXT NOT NULL,
    ExpiresAtUtc TEXT NOT NULL                       -- CachedAtUtc + 7 Gün (TTL)
);

CREATE INDEX IF NOT EXISTS IX_ScanCache_FastPathKey ON ScanCacheEntries(FastPathKey);
CREATE INDEX IF NOT EXISTS IX_ScanCache_Sha256 ON ScanCacheEntries(Sha256);
CREATE INDEX IF NOT EXISTS IX_ScanCache_FilePath ON ScanCacheEntries(FilePath);
CREATE INDEX IF NOT EXISTS IX_ScanCache_ExpiresAt ON ScanCacheEntries(ExpiresAtUtc);

-- 2. Artımlı Tarama Geçmişi (Incremental Scan History)
CREATE TABLE IF NOT EXISTS ScanHistory (
    TargetDirectory TEXT PRIMARY KEY COLLATE NOCASE, -- Kök taranan yol (Örn: C:\, Downloads, Desktop)
    ScanType INTEGER NOT NULL,                       -- 0: Quick, 1: Full, 2: Custom
    LastScanCompletedUtc TEXT NOT NULL,
    TotalFiles INTEGER NOT NULL DEFAULT 0,
    SkippedCachedFiles INTEGER NOT NULL DEFAULT 0,
    FreshScannedFiles INTEGER NOT NULL DEFAULT 0,
    ThreatsFound INTEGER NOT NULL DEFAULT 0,
    DurationMs INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS IX_ScanHistory_TargetDirectory ON ScanHistory(TargetDirectory);
