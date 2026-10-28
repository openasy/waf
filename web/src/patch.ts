// A virtual patch: a custom rule that refuses one kind of attack in one parameter of one page, as a DAST finding
// describes it, until the code is fixed (ADR 0069). It is written here as SecLang, which the API checks like any rule.

export type PatchKind = "sqli" | "xss" | "traversal" | "number";
export const PATCH_KINDS: PatchKind[] = ["sqli", "xss", "traversal", "number"];

const OPERATOR: Record<PatchKind, string> = {
  sqli: "@detectSQLi",
  xss: "@detectXSS",
  // A file name with .. in it climbs out of its folder.
  traversal: "@contains ..",
  number: "!@rx ^[0-9]+$",
};

export const PATCH_PATH = /^\/[A-Za-z0-9/_.~%-]*$/;
export const PATCH_PARAMETER = /^[A-Za-z0-9_.[\]-]{1,100}$/;

/** The first id from 1000000 no rule uses yet. */
export function nextId(used: number[]): number {
  return Math.max(999_999, ...used.filter((i) => i < 2_000_000)) + 1;
}

export function virtualPatch(p: { id: number; path: string; parameter: string; kind: PatchKind; label: string }): string {
  if (!PATCH_PATH.test(p.path)) throw new Error("path");
  if (!PATCH_PARAMETER.test(p.parameter)) throw new Error("parameter");
  // The message is in single quotes inside double quotes: neither may appear in it.
  const label = p.label.replace(/['"\\\r\n]/g, "").slice(0, 120) || `${p.kind} in ${p.parameter}`;
  return [
    `SecRule REQUEST_FILENAME "@streq ${p.path}" "id:${p.id},phase:2,deny,status:403,log,msg:'Virtual patch: ${label}',tag:'virtual-patch',chain"`,
    `  SecRule ARGS:${p.parameter} "${OPERATOR[p.kind]}" "t:none"`,
  ].join("\n");
}
