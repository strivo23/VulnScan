PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS scans (
 scan_id TEXT PRIMARY KEY, target_url TEXT NOT NULL, started_at TEXT NOT NULL,
 completed_at TEXT, status TEXT NOT NULL, pages_checked INTEGER NOT NULL DEFAULT 0,
 total_findings INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE IF NOT EXISTS findings (
 finding_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
 rule_id TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
 affected_url TEXT NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL,
 impact TEXT NOT NULL, remediation TEXT NOT NULL, detected_at TEXT NOT NULL,
 UNIQUE(scan_id, rule_id, affected_url)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE TABLE IF NOT EXISTS authorized_targets (
 target_id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL UNIQUE,
 authorization_confirmed INTEGER NOT NULL CHECK(authorization_confirmed IN (0,1)),
 created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
