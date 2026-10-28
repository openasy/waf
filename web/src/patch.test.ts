import { describe, expect, it } from "vitest";
import { checkSecLang } from "../../server/seclang.ts";
import { nextId, PATCH_KINDS, virtualPatch } from "./patch.ts";

describe("virtual patches", () => {
  it("writes a rule the API takes, for every kind", () => {
    for (const kind of PATCH_KINDS) {
      const text = virtualPatch({ id: 1000318, path: "/v1/orders", parameter: "q", kind, label: "DAST-318, it's open" });
      expect(checkSecLang(text)).toEqual({ ids: [1000318], disruptive: [1000318] });
      expect(text).toContain("msg:'Virtual patch: DAST-318, its open'");
    }
  });

  it("refuses a path or parameter that would leave the quotes", () => {
    expect(() => virtualPatch({ id: 1000001, path: '/a" "id:1', parameter: "q", kind: "sqli", label: "" })).toThrow("path");
    expect(() => virtualPatch({ id: 1000001, path: "/a", parameter: 'q "@rx x', kind: "sqli", label: "" })).toThrow("parameter");
  });

  it("takes the next free id", () => {
    expect(nextId([])).toBe(1_000_000);
    expect(nextId([1_000_000, 1_000_318, 942100])).toBe(1_000_319);
  });
});
