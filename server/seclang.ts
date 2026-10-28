// What the proxy runs for each site, written as SecLang, the language of ModSecurity that Coraza reads (ADR 0069):
// the OWASP Core Rule Set with the site's mode, paranoia level and threshold, its exclusions, and the custom rules
// people add. Everything but the custom rules is generated from checked fields; the custom rules are checked here
// against a short list of what a rule may do, so a rule can match and refuse requests but not reach the disk, run
// programs or switch the engine off.
import { bad } from "./problem.ts";

/** Groups of the Core Rule Set's request rules that a site can turn off, by the first three digits of their ids. */
export const CRS_GROUPS = [
  { id: "911", name: "Method enforcement" },
  { id: "913", name: "Scanner detection" },
  { id: "920", name: "Protocol enforcement" },
  { id: "921", name: "Protocol attack" },
  { id: "922", name: "Multipart attack" },
  { id: "930", name: "Local file inclusion" },
  { id: "931", name: "Remote file inclusion" },
  { id: "932", name: "Remote code execution" },
  { id: "933", name: "PHP injection" },
  { id: "934", name: "Generic injection" },
  { id: "941", name: "Cross-site scripting" },
  { id: "942", name: "SQL injection" },
  { id: "943", name: "Session fixation" },
  { id: "944", name: "Java attacks" },
] as const;
export const GROUP_IDS: readonly string[] = CRS_GROUPS.map((g) => g.id);

/** Ids people give their own rules. The rule set uses 900000 to 999999; exclusions get ids below 100000. */
export const CUSTOM_IDS = { min: 1_000_000, max: 1_999_999 };
const EXCLUSION_ID = 10_000;

export interface SiteRules {
  mode: "detection" | "blocking";
  paranoia: number;
  inboundThreshold: number;
  disabledGroups: string[];
  exclusions: Array<{ ruleId: string; target: string | null; path: string | null }>;
  /** Custom rules for this site and for every site, enabled ones only. */
  rules: string[];
}

/** The site's whole SecLang, in the order Coraza needs it. */
export function render(s: SiteRules): string {
  const before: string[] = [];
  const after: string[] = [];
  s.exclusions.forEach((e, i) => {
    if (e.path) {
      // Under a path, the rule is taken out per request, before the rule set runs.
      const ctl = e.target ? `ctl:ruleRemoveTargetById=${e.ruleId};${e.target}` : `ctl:ruleRemoveById=${e.ruleId}`;
      before.push(`SecRule REQUEST_FILENAME "@beginsWith ${e.path}" "id:${EXCLUSION_ID + i},phase:1,pass,t:none,nolog,${ctl}"`);
    } else if (e.target) {
      after.push(`SecRuleUpdateTargetById ${e.ruleId} "!${e.target}"`);
    } else {
      after.push(`SecRuleRemoveById ${e.ruleId}`);
    }
  });
  for (const g of s.disabledGroups) after.push(`SecRuleRemoveById ${g}000-${g}999`);
  return [
    "Include @coraza.conf-recommended",
    // Detection-only: every rule runs and is reported, nothing is refused.
    `SecRuleEngine ${s.mode === "blocking" ? "On" : "DetectionOnly"}`,
    // Responses are passed on as they come; their rules (data leakages) are not run yet.
    "SecResponseBodyAccess Off",
    // What matched is reported on stdout to the application, not to an audit log on the disk.
    "SecAuditEngine Off",
    "Include @crs-setup.conf.example",
    `SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=${s.paranoia}"`,
    `SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=${s.inboundThreshold},setvar:tx.outbound_anomaly_score_threshold=4"`,
    ...before,
    "Include @owasp_crs/*.conf",
    ...after,
    ...s.rules,
    "",
  ].join("\n");
}

// ---------------------------------------------------------------- Exclusions

const RULE_ID = /^\d{3,7}(-\d{3,7})?$/;
const COLLECTIONS = [
  "ARGS",
  "ARGS_GET",
  "ARGS_POST",
  "ARGS_NAMES",
  "ARGS_GET_NAMES",
  "ARGS_POST_NAMES",
  "REQUEST_COOKIES",
  "REQUEST_COOKIES_NAMES",
  "REQUEST_HEADERS",
  "REQUEST_HEADERS_NAMES",
  "REQUEST_BODY",
  "REQUEST_URI",
  "REQUEST_FILENAME",
  "REQUEST_BASENAME",
  "XML",
  "FILES",
  "FILES_NAMES",
];
const TARGET = new RegExp(`^(${COLLECTIONS.join("|")})(:[A-Za-z0-9_.\\-\\[\\]]{1,100})?$`);
const PATH = /^\/[A-Za-z0-9/_.~%-]{0,500}$/;

export function checkRuleId(v: unknown): string {
  const id = typeof v === "number" ? String(v) : typeof v === "string" ? v.trim() : "";
  if (!RULE_ID.test(id)) throw bad("ruleId must be a rule's id, such as 942100, or a range, such as 942000-942999.");
  const [from, to] = id.split("-").map(Number);
  if (to !== undefined && to < from!) throw bad("ruleId: a range goes from the lower id to the higher.");
  return id;
}

/** What part of the request a rule leaves alone, such as ARGS:filter or REQUEST_COOKIES:session. */
export function checkTarget(v: unknown): string | null {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string" || !TARGET.test(v.trim()))
    throw bad(`target must be a variable such as ARGS:filter or REQUEST_HEADERS:User-Agent, one of ${COLLECTIONS.join(", ")}.`);
  return v.trim();
}

export function checkPath(v: unknown): string | null {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string" || !PATH.test(v.trim())) throw bad("path must start with / and hold only letters, digits and / _ . ~ % -.");
  return v.trim();
}

// ---------------------------------------------------------------- Custom rules

/** Operators a custom rule may use. The ones that read files, look up DNS or run scripts are left out. */
const OPERATORS = new Set([
  "rx",
  "pm",
  "streq",
  "strmatch",
  "contains",
  "containsWord",
  "beginsWith",
  "endsWith",
  "within",
  "eq",
  "ne",
  "gt",
  "ge",
  "lt",
  "le",
  "ipMatch",
  "detectSQLi",
  "detectXSS",
  "validateByteRange",
  "validateUrlEncoding",
  "validateUtf8Encoding",
  "unconditionalMatch",
  "noMatch",
  "restpath",
]);

/**
 * Actions a custom rule may use. Left out: ctl (it could switch the engine or the rule set off), exec, setenv,
 * collections kept between requests, redirect and allow, which would let a request skip every other rule; exclusions
 * do that in the open.
 */
const ACTIONS = new Set([
  "id",
  "phase",
  "msg",
  "severity",
  "tag",
  "deny",
  "drop",
  "pass",
  "status",
  "t",
  "chain",
  "capture",
  "setvar",
  "logdata",
  "log",
  "nolog",
  "auditlog",
  "noauditlog",
  "rev",
  "ver",
  "maturity",
  "accuracy",
  "multiMatch",
]);

/** Splits a line into its words; a word in double quotes keeps its spaces, and \" inside it is a quote. */
function words(line: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    while (line[i] === " " || line[i] === "\t") i++;
    if (i >= line.length) break;
    if (line[i] === '"') {
      let w = "";
      i++;
      for (;;) {
        if (i >= line.length) throw bad("A quote is not closed.");
        if (line[i] === "\\" && i + 1 < line.length) {
          w += line[i]! + line[i + 1]!;
          i += 2;
          continue;
        }
        if (line[i] === '"') break;
        w += line[i++];
      }
      i++;
      out.push(w);
    } else {
      let w = "";
      while (i < line.length && line[i] !== " " && line[i] !== "\t") w += line[i++];
      if (w.includes('"')) throw bad("A quote is out of place.");
      out.push(w);
    }
  }
  return out;
}

/** Splits actions at commas outside single quotes: msg:'a, b' is one action. */
function actions(text: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === "\\" && i + 1 < text.length) {
      cur += c + text[++i]!;
      continue;
    }
    if (c === "'") quoted = !quoted;
    if (c === "," && !quoted) {
      if (cur.trim()) out.push(split(cur.trim()));
      cur = "";
      continue;
    }
    cur += c;
  }
  if (quoted) throw bad("A single quote in the actions is not closed.");
  if (cur.trim()) out.push(split(cur.trim()));
  return out;
}

const split = (a: string) => {
  const at = a.indexOf(":");
  return at < 0
    ? { name: a, value: "" }
    : {
        name: a.slice(0, at).trim(),
        value: a
          .slice(at + 1)
          .trim()
          .replace(/^'|'$/g, ""),
      };
};

export interface CheckedRule {
  /** The ids of its rules, for uniqueness across all custom rules. */
  ids: number[];
  /** Ids of the rules that refuse a request (deny or drop), so detection-only mode reports what they would refuse. */
  disruptive: number[];
}

/**
 * Checks a custom rule's SecLang: only SecRule and SecAction, only the operators and actions above, ids in the range
 * kept for custom rules, phase 1 or 2 (the request; responses are not inspected yet). The proxy then compiles it, which
 * finds what is left: a regular expression that does not compile, a misspelt variable.
 */
export function checkSecLang(text: unknown): CheckedRule {
  if (typeof text !== "string" || !text.trim()) throw bad("seclang must hold at least one SecRule or SecAction.");
  if (text.length > 16 * 1024) throw bad("seclang must be at most 16 KiB.");
  if (text.includes("\0")) throw bad("seclang must be text.");
  const lines = text.replace(/\r\n?/g, "\n").replace(/\\\n/g, " ").split("\n");
  const result: CheckedRule = { ids: [], disruptive: [] };
  let chained = false;
  let top: number | undefined;
  let count = 0;
  for (const [n, raw] of lines.entries()) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const at = (msg: string) => bad(`Line ${n + 1}: ${msg}`);
    let w: string[];
    try {
      w = words(line);
    } catch (err) {
      throw at((err as Error).message);
    }
    const directive = w[0]!;
    let actionText: string | undefined;
    if (directive === "SecRule") {
      if (w.length < 3 || w.length > 4) throw at("a SecRule has variables, an operator and actions in quotes.");
      const op = w[2]!.replace(/^!/, "");
      if (op.startsWith("@")) {
        const name = op.slice(1).split(/\s/)[0]!;
        if (!OPERATORS.has(name)) throw at(`the operator @${name} is not allowed in a custom rule.`);
      }
      actionText = w[3];
    } else if (directive === "SecAction") {
      if (chained) throw at("a chained rule must be a SecRule.");
      if (w.length !== 2) throw at("a SecAction has its actions in quotes.");
      actionText = w[1];
    } else {
      throw at(`only SecRule and SecAction are allowed in a custom rule, not ${directive}.`);
    }
    if (++count > 50) throw bad("A custom rule may hold at most 50 rules.");
    const acts = actionText ? actions(actionText) : [];
    for (const a of acts) {
      if (!ACTIONS.has(a.name)) throw at(`the action ${a.name} is not allowed in a custom rule.`);
      if (a.name === "phase" && !["1", "2", "request"].includes(a.value)) throw at("phase must be 1 or 2: custom rules look at the request.");
      if (a.name === "status" && !/^[45]\d\d$/.test(a.value)) throw at("status must be from 400 to 599.");
    }
    const id = acts.find((a) => a.name === "id");
    if (chained) {
      if (id) throw at("a chained rule has no id of its own.");
    } else {
      if (!id) throw at("every rule needs an id, from 1000000 to 1999999.");
      const v = Number(id.value);
      if (!Number.isInteger(v) || v < CUSTOM_IDS.min || v > CUSTOM_IDS.max) throw at("the id must be from 1000000 to 1999999.");
      if (result.ids.includes(v)) throw at(`the id ${v} is used twice.`);
      result.ids.push(v);
      top = v;
      if (acts.some((a) => a.name === "deny" || a.name === "drop")) result.disruptive.push(v);
    }
    chained = acts.some((a) => a.name === "chain");
    if (chained && top === undefined) throw at("a chain must start with a rule that has an id.");
  }
  if (chained) throw bad("The last rule says chain, but no rule follows it.");
  if (!result.ids.length) throw bad("seclang must hold at least one SecRule or SecAction.");
  return result;
}
