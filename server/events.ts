// What the proxy reported: each request a rule matched, and every request counted by the minute. Reports are written
// in batches once a second; when more arrive than can be kept, the rest are dropped and counted, so an attack cannot
// fill the disk or slow the product down (ADR 0069).
import type { DatabaseSync } from "node:sqlite";
import type { Counts, ProxyEvent, ProxyMatch } from "./engine.ts";
import { bad, notFound } from "./problem.ts";

export type Action = "blocked" | "detected" | "logged";
export const ACTIONS: Action[] = ["blocked", "detected", "logged"];

export interface Event {
  /** The reference the blocked client was shown. */
  id: string;
  siteId: string;
  time: string;
  clientIp: string;
  method: string;
  host: string;
  path: string;
  /** The query string; values of parameters that name a secret are left out. */
  query: string;
  userAgent: string;
  action: Action;
  /** The Core Rule Set's inbound anomaly score, and the threshold it was held against. */
  score: number;
  threshold: number;
  /** What the client got: 403 when blocked, the upstream's status otherwise. */
  status: number;
  /** The rule that weighed most, for lists. */
  ruleId: number | null;
  message: string;
  /** sqli, xss, lfi, rce, ... from the rule's tags; custom for rules of your own. */
  attack: string;
  matches: ProxyMatch[];
}

type Row = {
  id: string;
  site_id: string;
  time: string;
  client_ip: string;
  method: string;
  host: string;
  path: string;
  query: string;
  user_agent: string;
  action: Action;
  score: number;
  threshold: number;
  status: number;
  rule_id: number | null;
  message: string;
  attack: string;
  matches: string;
};

const toEvent = (r: Row): Event => ({
  id: r.id,
  siteId: r.site_id,
  time: r.time,
  clientIp: r.client_ip,
  method: r.method,
  host: r.host,
  path: r.path,
  query: r.query,
  userAgent: r.user_agent,
  action: r.action,
  score: r.score,
  threshold: r.threshold,
  status: r.status,
  ruleId: r.rule_id,
  message: r.message,
  attack: r.attack,
  matches: JSON.parse(r.matches) as ProxyMatch[],
});

const SEVERITY = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];
const rank = (s: string) => (SEVERITY.includes(s) ? SEVERITY.indexOf(s) : SEVERITY.length);

/** The match that weighs most: the highest severity, the first of those. */
export function primary(matches: ProxyMatch[]): ProxyMatch | undefined {
  return [...matches].sort((a, b) => rank(a.severity) - rank(b.severity))[0];
}

export function attackOf(m: ProxyMatch | undefined): string {
  if (!m) return "other";
  if (m.id >= 1_000_000) return "custom";
  const tag = m.tags.find((t) => t.startsWith("attack-"));
  return tag ? tag.slice("attack-".length) : "other";
}

/** Ranges the screens ask for, with the size of each bucket of the chart. */
export const RANGES = {
  "1h": { ms: 3600_000, bucketMs: 60_000 },
  "24h": { ms: 86_400_000, bucketMs: 30 * 60_000 },
  "7d": { ms: 7 * 86_400_000, bucketMs: 6 * 3600_000 },
  "30d": { ms: 30 * 86_400_000, bucketMs: 86_400_000 },
} as const;
export type Range = keyof typeof RANGES;

export function checkRange(v: string | null): Range {
  if (!v) return "24h";
  if (!(v in RANGES)) throw bad(`range must be one of ${Object.keys(RANGES).join(", ")}.`);
  return v as Range;
}

const cursorOf = (e: { time: string; id: string }) => Buffer.from(`${e.time}|${e.id}`).toString("base64url");
function readCursor(c: string): [string, string] {
  const [time, id] = Buffer.from(c, "base64url").toString("utf8").split("|");
  if (!time || !id) throw bad("cursor is not one this API gave.");
  return [time, id];
}

export interface EventsOptions {
  /** Most events kept from one second of reports; the rest are dropped and counted. */
  maxPerSecond?: number;
}

export function createEvents(db: DatabaseSync, opts: EventsOptions = {}) {
  const maxPerSecond = opts.maxPerSecond ?? 500;
  let queue: ProxyEvent[] = [];
  const stats = { stored: 0, dropped: 0 };
  const insert = db.prepare(
    `INSERT OR IGNORE INTO events (id, site_id, time, client_ip, method, host, path, query, user_agent, action, score, threshold, status, rule_id, message, attack, matches)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const insertRule = db.prepare("INSERT OR IGNORE INTO event_rules (event_id, rule_id, site_id, time) VALUES (?, ?, ?, ?)");
  const addTraffic = db.prepare(
    `INSERT INTO traffic (site_id, minute, requests, blocked, detected, logged, upstream_errors) VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (site_id, minute) DO UPDATE SET requests = requests + excluded.requests, blocked = blocked + excluded.blocked,
       detected = detected + excluded.detected, logged = logged + excluded.logged, upstream_errors = upstream_errors + excluded.upstream_errors`,
  );

  function flush() {
    if (!queue.length) return;
    const batch = queue;
    queue = [];
    db.exec("BEGIN");
    try {
      for (const e of batch) {
        const matches = Array.isArray(e.matches) ? e.matches : [];
        const p = primary(matches);
        const time = new Date(e.time).toISOString();
        insert.run(
          e.id,
          e.site,
          time,
          e.clientIp,
          e.method,
          e.host,
          e.path,
          e.query,
          e.userAgent,
          e.action,
          e.score,
          e.threshold,
          e.status,
          p?.id ?? null,
          p?.message ?? (e.action === "blocked" ? "Blocked" : ""),
          attackOf(p),
          JSON.stringify(matches),
        );
        for (const m of new Set(matches.map((x) => x.id))) insertRule.run(e.id, m, e.site, time);
      }
      db.exec("COMMIT");
      stats.stored += batch.length;
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }

  return {
    stats,
    flush,

    /** Takes a report from the proxy; it is written with the others of the same second. */
    record(e: ProxyEvent) {
      if (queue.length >= maxPerSecond || typeof e.id !== "string" || !ACTIONS.includes(e.action)) {
        stats.dropped++;
        return;
      }
      queue.push(e);
    },

    count(siteId: string, at: Date, c: Counts) {
      const minute = new Date(Math.floor(at.getTime() / 60_000) * 60_000).toISOString();
      addTraffic.run(siteId, minute, c.requests | 0, c.blocked | 0, c.detected | 0, c.logged | 0, c.upstreamErrors | 0);
    },

    get(id: string): Event {
      const row = db.prepare("SELECT * FROM events WHERE id = ?").get(id) as Row | undefined;
      if (!row) throw notFound("The event");
      return toEvent(row);
    },

    /** Newest first, a page at a time. */
    list(f: { siteId?: string; actions?: Action[]; q?: string; range: Range; cursor?: string; limit: number }) {
      const where = ["time >= ?"];
      const args: Array<string | number> = [new Date(Date.now() - RANGES[f.range].ms).toISOString()];
      if (f.siteId) (where.push("site_id = ?"), args.push(f.siteId));
      if (f.actions?.length) (where.push(`action IN (${f.actions.map(() => "?").join(", ")})`), args.push(...f.actions));
      if (f.q) {
        const like = `%${f.q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
        where.push(
          "(client_ip LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR query LIKE ? ESCAPE '\\' OR message LIKE ? ESCAPE '\\' OR CAST(rule_id AS TEXT) = ? OR id = ?)",
        );
        args.push(like, like, like, like, f.q, f.q);
      }
      if (f.cursor) {
        const [time, id] = readCursor(f.cursor);
        where.push("(time < ? OR (time = ? AND id < ?))");
        args.push(time, time, id);
      }
      const rows = db.prepare(`SELECT * FROM events WHERE ${where.join(" AND ")} ORDER BY time DESC, id DESC LIMIT ?`).all(...args, f.limit + 1) as Row[];
      const page = rows.slice(0, f.limit).map(toEvent);
      return { events: page, next: rows.length > f.limit ? cursorOf(page[page.length - 1]!) : null };
    },

    /** Requests over the range in buckets, totals, and what was matched most. */
    traffic(range: Range, siteId?: string) {
      const { ms, bucketMs } = RANGES[range];
      const now = Date.now();
      const start = Math.floor((now - ms) / bucketMs) * bucketMs + bucketMs;
      const since = new Date(start).toISOString();
      const site = siteId ? " AND site_id = ?" : "";
      const args = siteId ? [since, siteId] : [since];
      const rows = db
        .prepare(
          `SELECT minute, SUM(requests) AS requests, SUM(blocked) AS blocked, SUM(detected) AS detected, SUM(logged) AS logged,
             SUM(upstream_errors) AS upstreamErrors FROM traffic WHERE minute >= ?${site} GROUP BY minute`,
        )
        .all(...args) as unknown as Array<Counts & { minute: string }>;
      const n = Math.round(ms / bucketMs);
      const buckets = Array.from({ length: n }, (_, i) => ({
        time: new Date(start + i * bucketMs).toISOString(),
        requests: 0,
        blocked: 0,
        detected: 0,
        logged: 0,
        upstreamErrors: 0,
      }));
      const totals = { requests: 0, blocked: 0, detected: 0, logged: 0, upstreamErrors: 0 };
      for (const r of rows) {
        const b = buckets[Math.floor((Date.parse(r.minute) - start) / bucketMs)];
        for (const k of Object.keys(totals) as Array<keyof Counts>) {
          if (b) b[k] += r[k];
          totals[k] += r[k];
        }
      }
      const attacks = db
        .prepare(`SELECT attack, COUNT(*) AS count FROM events WHERE time >= ? AND action != 'logged'${site} GROUP BY attack ORDER BY count DESC LIMIT 10`)
        .all(...args) as Array<{ attack: string; count: number }>;
      const rules = db
        .prepare(
          `SELECT r.rule_id AS ruleId, COUNT(*) AS count, MAX(e.message) AS message FROM event_rules r JOIN events e ON e.id = r.event_id AND e.rule_id = r.rule_id
           WHERE r.time >= ?${siteId ? " AND r.site_id = ?" : ""} GROUP BY r.rule_id ORDER BY count DESC LIMIT 10`,
        )
        .all(...args) as Array<{ ruleId: number; count: number; message: string }>;
      const clients = db
        .prepare(
          `SELECT client_ip AS clientIp, COUNT(*) AS count FROM events WHERE time >= ? AND action != 'logged'${site} GROUP BY client_ip ORDER BY count DESC LIMIT 10`,
        )
        .all(...args) as Array<{ clientIp: string; count: number }>;
      return { range, bucketSeconds: bucketMs / 1000, buckets, totals, attacks, rules, clients };
    },

    /** How often each rule matched since `since`, by rule id. */
    hits(since: Date, siteId?: string): Map<number, number> {
      const rows = db
        .prepare(`SELECT rule_id AS id, COUNT(*) AS n FROM event_rules WHERE time >= ?${siteId ? " AND site_id = ?" : ""} GROUP BY rule_id`)
        .all(...(siteId ? [since.toISOString(), siteId] : [since.toISOString()])) as Array<{ id: number; n: number }>;
      return new Map(rows.map((r) => [r.id, r.n]));
    },

    /** Drops what is older than the retention. */
    purge(days: number) {
      const before = new Date(Date.now() - days * 86_400_000).toISOString();
      db.prepare("DELETE FROM events WHERE time < ?").run(before);
      db.prepare("DELETE FROM traffic WHERE minute < ?").run(before);
    },
  };
}

export type Events = ReturnType<typeof createEvents>;
