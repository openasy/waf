// Sites and their exclusions. A site is the host names the proxy answers for and the upstream it passes requests to,
// with how the Core Rule Set runs for it. It starts in detection-only mode: rules match and are reported, nothing is
// refused, until someone who has read what it would have blocked turns blocking on (ADR 0069).
import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { bad, conflict, isObject, notFound } from "./problem.ts";
import { checkPath, checkRuleId, checkTarget, GROUP_IDS } from "./seclang.ts";

export type Mode = "detection" | "blocking";

export interface Site {
  id: string;
  name: string;
  /** Host names without a port; `*` takes every host no other site names. */
  hosts: string[];
  upstream: string;
  mode: Mode;
  paranoia: number;
  inboundThreshold: number;
  /** Groups of the rule set turned off for this site, such as 933 for PHP. */
  disabledGroups: string[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface Exclusion {
  id: string;
  siteId: string;
  /** A rule's id, or a range such as 942000-942999. */
  ruleId: string;
  /** Only this part of the request, such as ARGS:filter; null for the whole rule. */
  target: string | null;
  /** Only under this path; null for the whole site. */
  path: string | null;
  reason: string;
  createdBy: string;
  createdAt: string;
}

type SiteRow = {
  id: string;
  name: string;
  hosts: string;
  upstream: string;
  mode: Mode;
  paranoia: number;
  inbound_threshold: number;
  disabled_groups: string;
  created_by: string;
  created_at: string;
  updated_at: string;
};

type ExclusionRow = {
  id: string;
  site_id: string;
  rule_id: string;
  target: string | null;
  path: string | null;
  reason: string;
  created_by: string;
  created_at: string;
};

const toSite = (r: SiteRow): Site => ({
  id: r.id,
  name: r.name,
  hosts: JSON.parse(r.hosts) as string[],
  upstream: r.upstream,
  mode: r.mode,
  paranoia: r.paranoia,
  inboundThreshold: r.inbound_threshold,
  disabledGroups: JSON.parse(r.disabled_groups) as string[],
  createdBy: r.created_by,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

const toExclusion = (r: ExclusionRow): Exclusion => ({
  id: r.id,
  siteId: r.site_id,
  ruleId: r.rule_id,
  target: r.target,
  path: r.path,
  reason: r.reason,
  createdBy: r.created_by,
  createdAt: r.created_at,
});

const HOST = /^(\*|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*)$/;
const MAX_EXCLUSIONS = 1000;

/** Checks the upstream a site passes requests to and returns it as it will be kept. */
export function checkUpstream(raw: unknown): string {
  if (typeof raw !== "string" || !raw.trim()) throw bad("upstream must be the application's address, such as http://app:3000.");
  const url = URL.parse(raw.trim());
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname) throw bad(`${raw.trim()} is not an http:// or https:// address.`);
  // Every viewer reads the site's upstream, so it may not carry a password.
  if (url.username || url.password) throw bad("upstream may not hold a user or password.");
  if (url.search || url.hash) throw bad("upstream is an address without ?query or #fragment.");
  return url.href.replace(/\/$/, "");
}

function checkHosts(raw: unknown): string[] {
  if (!Array.isArray(raw) || !raw.length || raw.length > 50) throw bad("hosts must be 1 to 50 host names, such as app.example.com.");
  const hosts = raw.map((h) => {
    if (typeof h !== "string") throw bad("Each host must be a host name.");
    const v = h.trim().toLowerCase().replace(/\.$/, "");
    if (!HOST.test(v) || v.length > 253) throw bad(`${h} is not a host name; leave out the scheme and the port.`);
    return v;
  });
  return [...new Set(hosts)];
}

function whole(v: unknown, name: string, min: number, max: number, fallback: number): number {
  if (v === undefined) return fallback;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) throw bad(`${name} must be a whole number from ${min} to ${max}.`);
  return v;
}

export function createSites(db: DatabaseSync) {
  const getRow = (id: string) => db.prepare("SELECT * FROM sites WHERE id = ?").get(id) as SiteRow | undefined;

  function parse(body: Record<string, unknown>, current?: Site) {
    const name = body.name ?? current?.name;
    if (typeof name !== "string" || !name.trim() || name.trim().length > 100) throw bad("name must be 1 to 100 characters.");
    const hosts = body.hosts === undefined && current ? current.hosts : checkHosts(body.hosts);
    const upstream = body.upstream === undefined && current ? current.upstream : checkUpstream(body.upstream);
    const mode = body.mode ?? current?.mode ?? "detection";
    if (mode !== "detection" && mode !== "blocking") throw bad("mode must be detection or blocking.");
    const paranoia = whole(body.paranoia, "paranoia", 1, 4, current?.paranoia ?? 1);
    const inboundThreshold = whole(body.inboundThreshold, "inboundThreshold", 1, 1000, current?.inboundThreshold ?? 5);
    const groups = body.disabledGroups ?? current?.disabledGroups ?? [];
    if (!Array.isArray(groups) || groups.some((g) => typeof g !== "string" || !GROUP_IDS.includes(g)))
      throw bad(`disabledGroups may hold ${GROUP_IDS.join(", ")}.`);
    // Each host belongs to one site, so a request goes to one place.
    for (const other of list()) {
      if (other.id === current?.id) continue;
      if (other.name === name.trim()) throw conflict(`A site is already called ${name.trim()}.`);
      const taken = hosts.find((h) => other.hosts.includes(h));
      if (taken) throw conflict(`${taken === "*" ? "Every other host" : taken} already goes to ${other.name}.`);
    }
    return { name: name.trim(), hosts, upstream, mode: mode as Mode, paranoia, inboundThreshold, disabledGroups: [...new Set(groups as string[])].sort() };
  }

  function list(): Site[] {
    return (db.prepare("SELECT * FROM sites ORDER BY name").all() as SiteRow[]).map(toSite);
  }

  function get(id: string): Site {
    const row = getRow(id);
    if (!row) throw notFound("The site");
    return toSite(row);
  }

  return {
    list,
    get,

    create(body: Record<string, unknown>, actor: string): Site {
      if (!isObject(body)) throw bad("The body must be a JSON object.");
      const s = parse(body);
      const id = randomUUID();
      const now = new Date().toISOString();
      db.prepare(
        `INSERT INTO sites (id, name, hosts, upstream, mode, paranoia, inbound_threshold, disabled_groups, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(id, s.name, JSON.stringify(s.hosts), s.upstream, s.mode, s.paranoia, s.inboundThreshold, JSON.stringify(s.disabledGroups), actor, now, now);
      return get(id);
    },

    /** Changes what the body names and keeps the rest. */
    update(id: string, body: Record<string, unknown>): Site {
      const current = get(id);
      const s = parse(body, current);
      db.prepare(
        `UPDATE sites SET name = ?, hosts = ?, upstream = ?, mode = ?, paranoia = ?, inbound_threshold = ?, disabled_groups = ?, updated_at = ?
         WHERE id = ?`,
      ).run(
        s.name,
        JSON.stringify(s.hosts),
        s.upstream,
        s.mode,
        s.paranoia,
        s.inboundThreshold,
        JSON.stringify(s.disabledGroups),
        new Date().toISOString(),
        id,
      );
      return get(id);
    },

    remove(id: string): void {
      get(id);
      db.prepare("DELETE FROM sites WHERE id = ?").run(id);
    },

    exclusions(siteId?: string): Exclusion[] {
      const rows = siteId
        ? db.prepare("SELECT * FROM exclusions WHERE site_id = ? ORDER BY created_at, id").all(siteId)
        : db.prepare("SELECT * FROM exclusions ORDER BY created_at, id").all();
      return (rows as ExclusionRow[]).map(toExclusion);
    },

    exclude(body: Record<string, unknown>, actor: string): Exclusion {
      if (!isObject(body)) throw bad("The body must be a JSON object.");
      if (typeof body.siteId !== "string") throw bad("siteId must be the site's id.");
      if (!getRow(body.siteId)) throw bad("siteId: no such site.");
      const ruleId = checkRuleId(body.ruleId);
      const target = checkTarget(body.target);
      const path = checkPath(body.path);
      if (target && ruleId.includes("-")) throw bad("A target is left out of one rule; give one ruleId, not a range.");
      if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 500)
        throw bad("reason must say why, in 1 to 500 characters: every exclusion weakens protection a little.");
      const n = (db.prepare("SELECT COUNT(*) AS n FROM exclusions WHERE site_id = ?").get(body.siteId) as { n: number }).n;
      if (n >= MAX_EXCLUSIONS) throw conflict(`A site may have at most ${MAX_EXCLUSIONS} exclusions.`);
      const same = db
        .prepare("SELECT id FROM exclusions WHERE site_id = ? AND rule_id = ? AND target IS ? AND path IS ?")
        .get(body.siteId, ruleId, target, path);
      if (same) throw conflict("This site already has that exclusion.");
      const id = randomUUID();
      db.prepare("INSERT INTO exclusions (id, site_id, rule_id, target, path, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(
        id,
        body.siteId,
        ruleId,
        target,
        path,
        body.reason.trim(),
        actor,
        new Date().toISOString(),
      );
      return toExclusion(db.prepare("SELECT * FROM exclusions WHERE id = ?").get(id) as ExclusionRow);
    },

    unexclude(id: string): void {
      if (!db.prepare("DELETE FROM exclusions WHERE id = ?").run(id).changes) throw notFound("The exclusion");
    },
  };
}

export type Sites = ReturnType<typeof createSites>;
