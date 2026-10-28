// Custom rules: SecLang people write for one site or for every site, after the Core Rule Set. A virtual patch for a
// flaw DAST found, such as SQL injection in one parameter of one page, is one of them until the code is fixed.
import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { bad, conflict, isObject, notFound } from "./problem.ts";
import { checkSecLang } from "./seclang.ts";

export interface Rule {
  id: string;
  /** null: every site. */
  siteId: string | null;
  name: string;
  seclang: string;
  /** The SecLang ids of its rules. */
  ruleIds: number[];
  /** Of those, the ones that refuse a request. */
  disruptive: number[];
  enabled: boolean;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

type Row = {
  id: string;
  site_id: string | null;
  name: string;
  seclang: string;
  rule_ids: string;
  enabled: number;
  created_by: string;
  created_at: string;
  updated_at: string;
};

const toRule = (r: Row): Rule => {
  const ids = JSON.parse(r.rule_ids) as { ids: number[]; disruptive: number[] };
  return {
    id: r.id,
    siteId: r.site_id,
    name: r.name,
    seclang: r.seclang,
    ruleIds: ids.ids,
    disruptive: ids.disruptive,
    enabled: r.enabled === 1,
    createdBy: r.created_by,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
};

export interface RulesOptions {
  /** Compiles SecLang in the proxy, and throws what Coraza made of it when it does not compile. */
  compile: (seclang: string) => Promise<void>;
}

export function createRules(db: DatabaseSync, { compile }: RulesOptions) {
  const list = (): Rule[] => (db.prepare("SELECT * FROM rules ORDER BY name, id").all() as Row[]).map(toRule);

  function get(id: string): Rule {
    const row = db.prepare("SELECT * FROM rules WHERE id = ?").get(id) as Row | undefined;
    if (!row) throw notFound("The rule");
    return toRule(row);
  }

  /** Checks a rule as it would be kept: its fields, its SecLang, ids no other rule uses, and that Coraza compiles it. */
  async function parse(body: unknown, current?: Rule) {
    if (!isObject(body)) throw bad("The body must be a JSON object.");
    const name = body.name ?? current?.name;
    if (typeof name !== "string" || !name.trim() || name.trim().length > 200) throw bad("name must be 1 to 200 characters.");
    const siteId = body.siteId === undefined ? (current?.siteId ?? null) : body.siteId;
    if (siteId !== null && (typeof siteId !== "string" || !db.prepare("SELECT 1 FROM sites WHERE id = ?").get(siteId)))
      throw bad("siteId must be a site's id, or null for every site.");
    const enabled = body.enabled ?? current?.enabled ?? true;
    if (typeof enabled !== "boolean") throw bad("enabled must be true or false.");
    const seclang = body.seclang ?? current?.seclang;
    const checked = checkSecLang(seclang);
    await compile(seclang as string);
    // After the compile, so that nothing else runs between this check and the write that follows it.
    for (const other of list()) {
      if (other.id === current?.id) continue;
      const taken = checked.ids.find((i) => other.ruleIds.includes(i));
      if (taken) throw conflict(`The id ${taken} is already used by the rule ${other.name}.`);
    }
    return { name: name.trim(), siteId: siteId as string | null, seclang: (seclang as string).replace(/\r\n?/g, "\n").trim(), enabled, checked };
  }

  return {
    list,
    get,
    /** Only checks, for the editor's Check button; nothing is kept. */
    async check(body: unknown) {
      if (!isObject(body)) throw bad("The body must be a JSON object.");
      const checked = checkSecLang(body.seclang);
      await compile(body.seclang as string);
      return { ruleIds: checked.ids, disruptive: checked.disruptive };
    },

    async create(body: unknown, actor: string): Promise<Rule> {
      const r = await parse(body);
      const id = randomUUID();
      const now = new Date().toISOString();
      db.prepare(
        "INSERT INTO rules (id, site_id, name, seclang, rule_ids, enabled, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(id, r.siteId, r.name, r.seclang, JSON.stringify(r.checked), r.enabled ? 1 : 0, actor, now, now);
      return get(id);
    },

    async update(id: string, body: unknown): Promise<Rule> {
      const r = await parse(body, get(id));
      db.prepare("UPDATE rules SET site_id = ?, name = ?, seclang = ?, rule_ids = ?, enabled = ?, updated_at = ? WHERE id = ?").run(
        r.siteId,
        r.name,
        r.seclang,
        JSON.stringify(r.checked),
        r.enabled ? 1 : 0,
        new Date().toISOString(),
        id,
      );
      return get(id);
    },

    remove(id: string): void {
      if (!db.prepare("DELETE FROM rules WHERE id = ?").run(id).changes) throw notFound("The rule");
    },
  };
}

export type Rules = ReturnType<typeof createRules>;
