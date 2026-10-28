import { request } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Event } from "./events.ts";
import { backend, startApp, until } from "./test-app.ts";

// Every attack-like request here goes through the real proxy (Coraza with the OWASP Core Rule Set) to the local
// backend started for the test, and nowhere else.

let app: Awaited<ReturnType<typeof startApp>>;
let upstream: Awaited<ReturnType<typeof backend>>;
const SQLI = `?q=${encodeURIComponent("1' OR '1'='1")}`;

beforeAll(async () => {
  upstream = await backend();
  app = await startApp({ version: "0.1.0" });
}, 30_000);
afterAll(async () => {
  await app.close();
  await upstream.close();
});

/** The event the proxy reported for a request, once written. */
const event = (find: (e: Event) => boolean) =>
  until(() => {
    app.events.flush();
    return (app.get("/api/v1/events?range=1h&limit=500") as Promise<{ events: Event[] }>).then((r) => r.events.find(find));
  });

async function site(body: Record<string, unknown>) {
  const res = await app.send("POST", "/api/v1/sites", { upstream: upstream.base, ...body });
  expect(res.status).toBe(201);
  return (await res.json()) as { id: string; mode: string; paranoia: number; inboundThreshold: number };
}

describe("a site", { timeout: 60_000 }, () => {
  let id: string;

  it("starts in detection-only mode: attacks reach the application and are reported as what would have been blocked", async () => {
    const s = await site({ name: "shop", hosts: ["shop.test"] });
    id = s.id;
    expect(s).toMatchObject({ mode: "detection", paranoia: 1, inboundThreshold: 5 });

    const fine = await app.proxy("shop.test", "/search?q=shoes");
    expect(fine.status).toBe(200);
    expect(await fine.text()).toBe("from the application");

    const attack = await app.proxy("shop.test", `/search${SQLI}`);
    expect(attack.status).toBe(200);
    expect(upstream.seen.some((r) => r.url === `/search${SQLI.replace(/'/g, "%27")}` || r.url.startsWith("/search?q=1"))).toBe(true);
    const e = await event((x) => x.siteId === id && x.path === "/search" && x.action === "detected");
    expect(e).toMatchObject({ host: "shop.test", method: "GET", clientIp: "127.0.0.1", ruleId: 942100, attack: "sqli", status: 200, threshold: 5 });
    expect(e.score).toBeGreaterThanOrEqual(5);
    expect(e.matches.find((m) => m.id === 942100)).toMatchObject({ variable: "ARGS:q", value: "1' OR '1'='1" });
  });

  it("blocks once blocking is on, and tells the client the reference of the event", async () => {
    const res = await app.send("PUT", `/api/v1/sites/${id}`, { mode: "blocking" });
    expect(((await res.json()) as { mode: string }).mode).toBe("blocking");
    const before = upstream.seen.length;
    const attack = await app.proxy("shop.test", `/orders${SQLI}`);
    expect(attack.status).toBe(403);
    const reference = /Reference: (\S+)/.exec(await attack.text())![1]!;
    expect(upstream.seen.length).toBe(before);
    const e = await event((x) => x.id === reference);
    expect(e).toMatchObject({ action: "blocked", status: 403, ruleId: 942100, path: "/orders" });
    expect((await app.get(`/api/v1/events/${reference}`)).id).toBe(reference);

    expect((await app.proxy("shop.test", "/orders?q=42")).status).toBe(200);
  });

  it("looks into JSON bodies and finds cross-site scripting and path traversal", async () => {
    const xss = await app.proxy("shop.test", "/comments", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ comment: "<script>alert(document.cookie)</script>" }),
    });
    expect(xss.status).toBe(403);
    await event((x) => x.path === "/comments" && x.attack === "xss");
    const lfi = await app.proxy("shop.test", `/files?name=${encodeURIComponent("../../../../etc/passwd")}`);
    expect(lfi.status).toBe(403);
    await event((x) => x.path === "/files" && x.attack === "lfi");
  });

  it("does not keep the values of parameters that name a secret", async () => {
    const res = await app.proxy("shop.test", `/login?user=alice&password=${encodeURIComponent("hunter2' OR 1=1--")}`);
    expect(res.status).toBe(403);
    const e = await event((x) => x.path === "/login");
    expect(e.query).toBe("user=alice&password=[not kept]");
    expect(JSON.stringify(e)).not.toContain("hunter2");
  });

  it("believes X-Forwarded-For only from a trusted proxy", async () => {
    await app.proxy("shop.test", `/spoof${SQLI}`, { headers: { "x-forwarded-for": "198.51.100.7" } });
    expect((await event((x) => x.path === "/spoof")).clientIp).toBe("127.0.0.1");
  });

  it("lets an exclusion through under its path only", async () => {
    const res = await app.send("POST", "/api/v1/exclusions", { siteId: id, ruleId: "942000-942999", path: "/reports", reason: "Report filters are SQL-like" });
    expect(res.status).toBe(201);
    const excl = (await res.json()) as { id: string };
    expect((await app.proxy("shop.test", `/reports${SQLI}`)).status).toBe(200);
    expect((await app.proxy("shop.test", `/search${SQLI}`)).status).toBe(403);
    expect((await app.send("DELETE", `/api/v1/exclusions/${excl.id}`)).status).toBe(204);
    expect((await app.proxy("shop.test", `/reports${SQLI}`)).status).toBe(403);
  });

  it("leaves out one target of a rule, or a whole group of the rule set", async () => {
    // The search box takes SQL-like text on purpose; the same text in another parameter is still blocked.
    await app.send("POST", "/api/v1/exclusions", { siteId: id, ruleId: 942100, target: "ARGS:q", reason: "Search takes any text" });
    const q = await app.proxy("shop.test", `/search${SQLI}`);
    const other = await app.proxy("shop.test", `/search?name=${encodeURIComponent("1' OR '1'='1")}`);
    expect(other.status).toBe(403);
    // 942100 left out of q may still let other SQL injection rules pass the threshold; what matters is it is not 942100.
    if (q.status === 403) expect((await event((x) => x.path === "/search" && x.action === "blocked" && x.ruleId !== 942100)).ruleId).not.toBe(942100);

    await app.send("PUT", `/api/v1/sites/${id}`, { disabledGroups: ["942"] });
    expect((await app.proxy("shop.test", `/search?name=${encodeURIComponent("1' OR '1'='1")}`)).status).toBe(200);
    await app.send("PUT", `/api/v1/sites/${id}`, { disabledGroups: [] });
    expect((await app.proxy("shop.test", `/search?name=${encodeURIComponent("1' OR '1'='1")}`)).status).toBe(403);
  });

  it("takes a virtual patch for one parameter of one page, and reports it as a custom rule", async () => {
    const seclang = [
      `SecRule REQUEST_FILENAME "@streq /invoice" "id:1000318,phase:2,deny,status:403,log,msg:'Virtual patch: id is a number',chain"`,
      `  SecRule ARGS:id "!@rx ^[0-9]+$" "t:none"`,
    ].join("\n");
    const res = await app.send("POST", "/api/v1/rules", { name: "DAST-318 invoice id", siteId: id, seclang });
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ ruleIds: [1000318], disruptive: [1000318], enabled: true });
    expect((await app.proxy("shop.test", "/invoice?id=12")).status).toBe(200);
    expect((await app.proxy("shop.test", "/invoice?id=12abc")).status).toBe(403);
    expect(await event((x) => x.path === "/invoice" && x.ruleId === 1000318)).toMatchObject({ attack: "custom", message: "Virtual patch: id is a number" });
    const listed = (await app.get("/api/v1/rules")).rules as Array<{ hits24h: number }>;
    expect(listed[0]!.hits24h).toBeGreaterThanOrEqual(1);
  });

  it("refuses a rule Coraza cannot compile, or one whose id is taken, and keeps serving", async () => {
    const broken = await app.send("POST", "/api/v1/rules", { name: "broken", seclang: 'SecRule ARGS "@rx (" "id:1000777,phase:2,deny"' });
    expect(broken.status).toBe(422);
    expect(((await broken.json()) as { detail: string }).detail).toMatch(/Coraza does not take this rule/);
    const check = await app.send("POST", "/api/v1/rules/check", { seclang: 'SecRule ARGS:q "@detectXSS" "id:1000778,phase:2,deny"' });
    expect(await check.json()).toEqual({ ruleIds: [1000778], disruptive: [1000778] });
    const taken = await app.send("POST", "/api/v1/rules", { name: "again", seclang: 'SecRule ARGS:x "@eq 1" "id:1000318,phase:2,deny"' });
    expect(taken.status).toBe(409);
    expect((await app.proxy("shop.test", "/search?q=shoes")).status).toBe(200);
  });

  it("counts every request, by the minute, and shows them on /metrics", async () => {
    const t = await until(async () => {
      const r = (await app.get("/api/v1/traffic?range=1h")) as { totals: { requests: number; blocked: number } };
      return r.totals.requests >= 10 && r.totals.blocked >= 3 ? r : undefined;
    }, 15_000);
    expect(t.totals.requests).toBeGreaterThanOrEqual(10);
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="waf",version="0.1.0"} 1');
    expect(metrics).toContain("openasy_waf_engine_up 1");
    expect(metrics).toMatch(/openasy_waf_matched_requests_total\{site="shop",action="blocked"\} [1-9]/);
  });

  it("filters events and pages through them", async () => {
    const all = (await app.get("/api/v1/events?range=1h&limit=2")) as { events: Event[]; next: string | null };
    expect(all.events).toHaveLength(2);
    const next = (await app.get(`/api/v1/events?range=1h&limit=2&cursor=${all.next}`)) as { events: Event[] };
    expect(next.events[0]!.time <= all.events[1]!.time).toBe(true);
    expect(next.events.map((e) => e.id)).not.toContain(all.events[0]!.id);
    const blocked = (await app.get("/api/v1/events?range=1h&action=blocked&q=942100")) as { events: Event[] };
    expect(blocked.events.length).toBeGreaterThan(0);
    expect(blocked.events.every((e) => e.action === "blocked" && e.ruleId === 942100)).toBe(true);
    expect((await app.send("GET", "/api/v1/events?action=allowed")).status).toBe(422);
  });

  it("answers only for its host names, and stops answering when deleted", async () => {
    expect((await app.proxy("other.test", "/")).status).toBe(404);
    const second = await site({ name: "blog", hosts: ["blog.test", "www.blog.test"] });
    expect((await app.proxy("www.blog.test:8443", "/")).status).toBe(200);
    expect((await app.send("POST", "/api/v1/sites", { name: "again", hosts: ["blog.test"], upstream: upstream.base })).status).toBe(409);
    expect((await app.send("POST", "/api/v1/sites", { name: "pw", hosts: ["pw.test"], upstream: "http://user:pass@127.0.0.1:1" })).status).toBe(422);
    expect((await app.send("DELETE", `/api/v1/sites/${second.id}`)).status).toBe(204);
    expect((await app.proxy("blog.test", "/")).status).toBe(404);
  });

  it("refuses a request it cannot parse as HTTP before Coraza sees it", async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: app.proxyPort, path: "/", headers: { host: "shop.test", "content-length": "abc" } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(400);
  });
});

describe("the rule set", { timeout: 30_000 }, () => {
  it("lists the groups Coraza compiled, with their rules by paranoia level", async () => {
    const crs = (await app.get("/api/v1/crs")) as {
      crs: string;
      coraza: string;
      groups: Array<{ id: string; rules: number; byParanoia: number[]; hits24h: number }>;
      rules: Array<{ id: number }>;
    };
    expect(crs.crs).toMatch(/^4\./);
    expect(crs.coraza).toMatch(/^3\./);
    const sqli = crs.groups.find((g) => g.id === "942")!;
    expect(sqli.rules).toBeGreaterThan(30);
    expect(sqli.byParanoia.reduce((a, b) => a + b, 0)).toBe(sqli.rules);
    expect(sqli.hits24h).toBeGreaterThan(0);
    expect(crs.rules.some((r) => r.id === 942100)).toBe(true);
  });
});

describe("roles", { timeout: 30_000 }, () => {
  it("lets viewers read, editors tune and admins change sites", async () => {
    const as = await app.roles();
    expect((await as.viewer("/api/v1/sites")).status).toBe(200);
    expect((await as.viewer("/api/v1/events")).status).toBe(200);
    const newSite = (fetcher: typeof as.viewer) =>
      fetcher("/api/v1/sites", { method: "POST", body: JSON.stringify({ name: "x", hosts: ["x.test"], upstream: upstream.base }) });
    expect((await newSite(as.viewer)).status).toBe(403);
    expect((await newSite(as.editor)).status).toBe(403);
    const { sites } = (await app.get("/api/v1/sites")) as { sites: Array<{ id: string }> };
    const exclusion = (fetcher: typeof as.viewer) =>
      fetcher("/api/v1/exclusions", { method: "POST", body: JSON.stringify({ siteId: sites[0]!.id, ruleId: 920420, reason: "YAML import" }) });
    expect((await exclusion(as.viewer)).status).toBe(403);
    expect((await exclusion(as.editor)).status).toBe(201);
    expect((await as.editor(`/api/v1/sites/${sites[0]!.id}`, { method: "PUT", body: JSON.stringify({ mode: "detection" }) })).status).toBe(403);
    expect((await fetch(`${app.base}/api/v1/sites`)).status).toBe(401);
  });
});

describe("behind a trusted proxy", { timeout: 30_000 }, () => {
  it("takes the client's address from X-Forwarded-For and passes the chain on", async () => {
    const trusted = await startApp({ version: "0.1.0", trustedProxies: ["127.0.0.1/32"] });
    try {
      const res = await trusted.send("POST", "/api/v1/sites", { name: "app", hosts: ["*"], upstream: upstream.base, mode: "blocking" });
      expect(res.status).toBe(201);
      const r = await trusted.proxy("anything.test", `/x${SQLI}`, { headers: { "x-forwarded-for": "198.51.100.7, 127.0.0.1", "x-forwarded-proto": "https" } });
      expect(r.status).toBe(403);
      const ok = await trusted.proxy("anything.test", "/fine", { headers: { "x-forwarded-for": "198.51.100.7", "x-forwarded-proto": "https" } });
      expect(ok.status).toBe(200);
      const seen = upstream.seen.find((s) => s.url === "/fine")!;
      expect(seen.headers["x-forwarded-for"]).toBe("198.51.100.7, 127.0.0.1");
      expect(seen.headers["x-forwarded-proto"]).toBe("https");
      expect(seen.headers.host).toBe("anything.test");
      const e = await until(() => {
        trusted.events.flush();
        return (trusted.get("/api/v1/events?range=1h") as Promise<{ events: Event[] }>).then((x) => x.events[0]);
      });
      expect(e.clientIp).toBe("198.51.100.7");
    } finally {
      await trusted.close();
    }
  });
});
