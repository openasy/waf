import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones. What people set up (sites,
// exclusions, custom rules) and what the proxy reported (requests that matched, and counts of all requests) are kept
// here (ADR 0011, 0069).
const MIGRATIONS = [
  `-- A site: the host names the proxy answers for, the upstream it passes requests to, and how the Core Rule Set runs
   -- for it. New sites start in detection-only mode, so turning the WAF on cannot break the application.
   CREATE TABLE sites (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     hosts TEXT NOT NULL,
     upstream TEXT NOT NULL,
     mode TEXT NOT NULL DEFAULT 'detection' CHECK (mode IN ('detection', 'blocking')),
     paranoia INTEGER NOT NULL DEFAULT 1 CHECK (paranoia BETWEEN 1 AND 4),
     inbound_threshold INTEGER NOT NULL DEFAULT 5 CHECK (inbound_threshold BETWEEN 1 AND 1000),
     disabled_groups TEXT NOT NULL DEFAULT '[]',
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   -- An exception for a false positive: a rule, or one of its targets, left out on one site, everywhere or under a path.
   CREATE TABLE exclusions (
     id TEXT PRIMARY KEY,
     site_id TEXT NOT NULL REFERENCES sites (id) ON DELETE CASCADE,
     rule_id TEXT NOT NULL,
     target TEXT,
     path TEXT,
     reason TEXT NOT NULL,
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   CREATE INDEX exclusions_site ON exclusions (site_id, created_at);
   -- A rule of your own in SecLang, for one site or, with no site, for every site. Virtual patches are rules too.
   CREATE TABLE rules (
     id TEXT PRIMARY KEY,
     site_id TEXT REFERENCES sites (id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     seclang TEXT NOT NULL,
     rule_ids TEXT NOT NULL,
     enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );
   -- A request a rule matched: blocked, detected (it would have been blocked, in detection-only mode) or logged (it
   -- scored below the threshold). Values that name a secret are not kept; the proxy drops them before they leave it.
   -- Events outlive their site, so its history can still be read after it is deleted.
   CREATE TABLE events (
     id TEXT PRIMARY KEY,
     site_id TEXT NOT NULL,
     time TEXT NOT NULL,
     client_ip TEXT NOT NULL,
     method TEXT NOT NULL,
     host TEXT NOT NULL,
     path TEXT NOT NULL,
     query TEXT NOT NULL,
     user_agent TEXT NOT NULL,
     action TEXT NOT NULL CHECK (action IN ('blocked', 'detected', 'logged')),
     score INTEGER NOT NULL,
     threshold INTEGER NOT NULL,
     status INTEGER NOT NULL,
     rule_id INTEGER,
     message TEXT NOT NULL,
     attack TEXT NOT NULL,
     matches TEXT NOT NULL
   );
   CREATE INDEX events_time ON events (time, id);
   CREATE INDEX events_site_time ON events (site_id, time);
   -- Each rule an event matched, for hits per rule and per group.
   CREATE TABLE event_rules (
     event_id TEXT NOT NULL REFERENCES events (id) ON DELETE CASCADE,
     rule_id INTEGER NOT NULL,
     site_id TEXT NOT NULL,
     time TEXT NOT NULL,
     PRIMARY KEY (event_id, rule_id)
   );
   CREATE INDEX event_rules_rule ON event_rules (rule_id, time);
   -- Every request, counted by the minute.
   CREATE TABLE traffic (
     site_id TEXT NOT NULL,
     minute TEXT NOT NULL,
     requests INTEGER NOT NULL DEFAULT 0,
     blocked INTEGER NOT NULL DEFAULT 0,
     detected INTEGER NOT NULL DEFAULT 0,
     logged INTEGER NOT NULL DEFAULT 0,
     upstream_errors INTEGER NOT NULL DEFAULT 0,
     PRIMARY KEY (site_id, minute)
   )`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
