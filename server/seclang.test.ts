import { describe, expect, it } from "vitest";
import { checkPath, checkRuleId, checkSecLang, checkTarget, render } from "./seclang.ts";

const base = { mode: "detection" as const, paranoia: 1, inboundThreshold: 5, disabledGroups: [], exclusions: [], rules: [] };

describe("render", () => {
  it("runs the rule set in detection-only mode unless the site blocks", () => {
    expect(render(base)).toContain("SecRuleEngine DetectionOnly");
    expect(render({ ...base, mode: "blocking" })).toContain("SecRuleEngine On");
    expect(render(base)).toContain("SecAuditEngine Off");
  });

  it("sets the paranoia level and threshold before the rule set reads them", () => {
    const s = render({ ...base, paranoia: 3, inboundThreshold: 10 });
    const at = (needle: string) => s.indexOf(needle);
    expect(at("tx.blocking_paranoia_level=3")).toBeGreaterThan(at("Include @crs-setup.conf.example"));
    expect(at("tx.inbound_anomaly_score_threshold=10")).toBeLessThan(at("Include @owasp_crs/*.conf"));
  });

  it("puts exclusions under a path before the rule set and the others after it", () => {
    const s = render({
      ...base,
      disabledGroups: ["933"],
      exclusions: [
        { ruleId: "942100", target: "ARGS:filter", path: "/reports" },
        { ruleId: "941100", target: null, path: "/notes" },
        { ruleId: "920420", target: null, path: null },
        { ruleId: "942100", target: "ARGS:q", path: null },
      ],
      rules: ['SecRule ARGS:q "@detectSQLi" "id:1000001,phase:2,deny,status:403"'],
    });
    const crs = s.indexOf("Include @owasp_crs/*.conf");
    expect(s.indexOf('"@beginsWith /reports" "id:10000,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=942100;ARGS:filter"')).toBeLessThan(crs);
    expect(s.indexOf("id:10001,phase:1,pass,t:none,nolog,ctl:ruleRemoveById=941100")).toBeLessThan(crs);
    expect(s.indexOf("SecRuleRemoveById 920420")).toBeGreaterThan(crs);
    expect(s.indexOf('SecRuleUpdateTargetById 942100 "!ARGS:q"')).toBeGreaterThan(crs);
    expect(s.indexOf("SecRuleRemoveById 933000-933999")).toBeGreaterThan(crs);
    expect(s.indexOf("id:1000001")).toBeGreaterThan(crs);
  });
});

describe("exclusion fields", () => {
  it("takes rule ids, ranges, targets and paths", () => {
    expect(checkRuleId(942100)).toBe("942100");
    expect(checkRuleId(" 942000-942999 ")).toBe("942000-942999");
    expect(checkTarget("ARGS:filter")).toBe("ARGS:filter");
    expect(checkTarget("REQUEST_HEADERS:User-Agent")).toBe("REQUEST_HEADERS:User-Agent");
    expect(checkTarget("")).toBeNull();
    expect(checkPath("/v1/reports")).toBe("/v1/reports");
    expect(checkPath(undefined)).toBeNull();
  });

  it("refuses what could break out of the SecLang it is written into", () => {
    expect(() => checkRuleId("942100,ctl:ruleEngine=Off")).toThrow(/ruleId/);
    expect(() => checkRuleId("942999-942000")).toThrow(/lower/);
    expect(() => checkTarget('ARGS:q" "id:1,pass')).toThrow(/target/);
    expect(() => checkTarget("TX:anything")).toThrow(/target/);
    expect(() => checkPath('/a" "id:1')).toThrow(/path/);
    expect(() => checkPath("relative")).toThrow(/path/);
    expect(() => checkPath("/a\nSecRuleEngine Off")).toThrow(/path/);
  });
});

describe("custom rules", () => {
  it("takes a virtual patch, chains and rules across lines", () => {
    expect(checkSecLang('SecRule ARGS:q "@detectSQLi" "id:1000318,phase:2,deny,status:403,log,msg:\'Virtual patch, DAST-318\'"')).toEqual({
      ids: [1000318],
      disruptive: [1000318],
    });
    const chain = [
      'SecRule REQUEST_FILENAME "@beginsWith /admin" "id:1000401,phase:1,deny,chain"',
      '  SecRule REMOTE_ADDR "!@ipMatch 10.8.0.0/16" "t:none"',
      "# a comment",
      'SecRule ARGS:q "@gt 256" \\',
      '  "id:1000403,phase:2,pass,log,t:length"',
    ].join("\n");
    expect(checkSecLang(chain)).toEqual({ ids: [1000401, 1000403], disruptive: [1000401] });
    expect(checkSecLang('SecAction "id:1000500,phase:1,pass,nolog,setvar:tx.custom=1"').ids).toEqual([1000500]);
  });

  it("keeps a rule from reaching the disk, running programs or switching the engine off", () => {
    const refused = [
      ["SecRuleEngine Off", /only SecRule and SecAction/],
      ['SecAuditLog "/data/waf.db"', /only SecRule and SecAction/],
      ["Include /etc/passwd", /only SecRule and SecAction/],
      ['SecRule ARGS "@inspectFile /bin/sh" "id:1000001,phase:2,deny"', /@inspectFile/],
      ['SecRule ARGS "@pmFromFile /etc/passwd" "id:1000001,phase:2,deny"', /@pmFromFile/],
      ['SecRule REMOTE_ADDR "@rbl bl.example.com" "id:1000001,phase:1,deny"', /@rbl/],
      ['SecRule ARGS "x" "id:1000001,phase:1,pass,ctl:ruleEngine=Off"', /ctl/],
      ['SecRule ARGS "x" "id:1000001,phase:1,pass,exec:/bin/sh"', /exec/],
      ['SecRule ARGS "x" "id:1000001,phase:1,allow"', /allow/],
      ['SecRule ARGS "x" "id:1000001,phase:4,deny"', /phase/],
      ['SecRule ARGS "x" "id:42,phase:2,deny"', /1000000/],
      ['SecRule ARGS "x" "phase:2,deny"', /needs an id/],
      ['SecRule ARGS "x" "id:1000001,phase:2,deny,status:200"', /status/],
      ['SecRule ARGS "x" "id:1000001,phase:2,deny,chain"', /chain/],
      ['SecRule ARGS "x "id:1000001,phase:2,deny"', /quote/],
      ["", /at least one/],
    ] as const;
    for (const [text, why] of refused) expect(() => checkSecLang(text), text).toThrow(why);
    expect(() => checkSecLang(['SecRule ARGS "a" "id:1000001,phase:2,deny"', 'SecRule ARGS "b" "id:1000001,phase:2,deny"'].join("\n"))).toThrow(/twice/);
  });
});
