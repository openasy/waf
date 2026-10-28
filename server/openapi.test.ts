import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OPENAPI } from "../scripts/openapi.ts";
import { ADMIN_TOKEN, backend, startApp, until } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "waf-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let upstream: Awaited<ReturnType<typeof backend>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  upstream = await backend();
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
}, 30_000);

afterAll(async () => {
  await app.close();
  await upstream.close();
});

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1").replaceAll("{", "%7B").replaceAll("}", "%7D")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const admin = (body?: unknown) => ({
  headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
  ...(body !== undefined && { body: typeof body === "string" ? body : JSON.stringify(body) }),
});

describe("openapi.json", () => {
  it("is what scripts/openapi.ts writes", () => {
    expect(spec).toEqual(JSON.parse(JSON.stringify(OPENAPI)));
  });

  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // WAF's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", { timeout: 60_000 }, () => {
  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("sites, exclusions and rules", async () => {
    const s = "/api/v1/sites/{id}";
    const site = ((await call("POST", "/api/v1/sites", admin({ name: "shop", hosts: ["shop.test"], upstream: upstream.base }))).body as { id: string }).id;
    await call("POST", "/api/v1/sites", admin({ name: "shop2", hosts: ["shop.test"], upstream: upstream.base }));
    await call("POST", "/api/v1/sites", admin({ name: "x", hosts: ["x.test"], upstream: "ftp://x" }));
    await call("POST", "/api/v1/sites", admin("nope"));
    await call("POST", "/api/v1/sites", { method: "POST" });
    await call("GET", "/api/v1/sites", admin());
    await call("GET", "/api/v1/sites", {});
    await call("GET", s, admin(), `/api/v1/sites/${site}`);
    await call("GET", s, admin(), "/api/v1/sites/missing");
    await call("GET", s, {}, `/api/v1/sites/${site}`);
    await call("PUT", s, admin({ mode: "blocking", paranoia: 2, disabledGroups: ["933"] }), `/api/v1/sites/${site}`);
    await call("PUT", s, admin({ paranoia: 9 }), `/api/v1/sites/${site}`);
    await call("PUT", s, admin("nope"), `/api/v1/sites/${site}`);
    await call("PUT", s, admin({ mode: "blocking" }), "/api/v1/sites/missing");
    await call("PUT", s, { method: "PUT" }, `/api/v1/sites/${site}`);
    const other = ((await call("POST", "/api/v1/sites", admin({ name: "blog", hosts: ["blog.test"], upstream: upstream.base }))).body as { id: string }).id;
    await call("PUT", s, admin({ hosts: ["shop.test"] }), `/api/v1/sites/${other}`);

    const e = "/api/v1/exclusions/{id}";
    const excl = (
      (await call("POST", "/api/v1/exclusions", admin({ siteId: site, ruleId: 942100, target: "ARGS:q", path: "/search", reason: "Search" }))).body as {
        id: string;
      }
    ).id;
    await call("POST", "/api/v1/exclusions", admin({ siteId: site, ruleId: 942100, target: "ARGS:q", path: "/search", reason: "Search" }));
    await call("POST", "/api/v1/exclusions", admin({ siteId: site, ruleId: "x", reason: "r" }));
    await call("POST", "/api/v1/exclusions", admin("nope"));
    await call("POST", "/api/v1/exclusions", { method: "POST" });
    await call("GET", "/api/v1/exclusions", admin());
    await call("GET", "/api/v1/exclusions", admin(), `/api/v1/exclusions?siteId=${site}`);
    await call("GET", "/api/v1/exclusions", admin(), "/api/v1/exclusions?siteId=missing");
    await call("GET", "/api/v1/exclusions", {});
    await call("DELETE", e, admin(), `/api/v1/exclusions/${excl}`);
    await call("DELETE", e, admin(), "/api/v1/exclusions/missing");
    await call("DELETE", e, { method: "DELETE" }, "/api/v1/exclusions/missing");

    const r = "/api/v1/rules/{id}";
    const seclang = 'SecRule ARGS:id "!@rx ^[0-9]+$" "id:1000100,phase:2,deny,status:403,log,msg:\'Virtual patch\'"';
    const rule = ((await call("POST", "/api/v1/rules", admin({ name: "patch", siteId: site, seclang }))).body as { id: string }).id;
    await call("POST", "/api/v1/rules", admin({ name: "again", seclang }));
    await call("POST", "/api/v1/rules", admin({ name: "bad", seclang: "SecRuleEngine Off" }));
    await call("POST", "/api/v1/rules", admin("nope"));
    await call("POST", "/api/v1/rules", { method: "POST" });
    await call("POST", "/api/v1/rules/check", admin({ seclang }));
    await call("POST", "/api/v1/rules/check", admin({ seclang: 'SecRule ARGS "@rx (" "id:1000101,phase:2,deny"' }));
    await call("POST", "/api/v1/rules/check", admin("nope"));
    await call("POST", "/api/v1/rules/check", { method: "POST" });
    await call("GET", "/api/v1/rules", admin());
    await call("GET", "/api/v1/rules", {});
    await call("GET", r, admin(), `/api/v1/rules/${rule}`);
    await call("GET", r, admin(), "/api/v1/rules/missing");
    await call("GET", r, {}, `/api/v1/rules/${rule}`);
    await call("PUT", r, admin({ enabled: false }), `/api/v1/rules/${rule}`);
    await call("PUT", r, admin({ seclang: "SecAction nope" }), `/api/v1/rules/${rule}`);
    await call("PUT", r, admin("nope"), `/api/v1/rules/${rule}`);
    await call("PUT", r, admin({ enabled: true }), "/api/v1/rules/missing");
    await call("PUT", r, { method: "PUT" }, `/api/v1/rules/${rule}`);
    const second = (
      (await call("POST", "/api/v1/rules", admin({ name: "two", seclang: 'SecRule ARGS:x "@eq 1" "id:1000200,phase:2,deny"' }))).body as { id: string }
    ).id;
    await call("PUT", r, admin({ seclang }), `/api/v1/rules/${second}`);
    await call("DELETE", r, admin(), `/api/v1/rules/${rule}`);
    await call("DELETE", r, admin(), "/api/v1/rules/missing");
    await call("DELETE", r, { method: "DELETE" }, `/api/v1/rules/${second}`);

    await call("GET", "/api/v1/crs", admin());
    await call("GET", "/api/v1/crs", admin(), `/api/v1/crs?siteId=${site}`);
    await call("GET", "/api/v1/crs", admin(), "/api/v1/crs?siteId=missing");
    await call("GET", "/api/v1/crs", {});

    await call("DELETE", s, admin(), `/api/v1/sites/${other}`);
    await call("DELETE", s, admin(), "/api/v1/sites/missing");
    await call("DELETE", s, { method: "DELETE" }, `/api/v1/sites/${site}`);
  });

  it("events and traffic", async () => {
    // One request a rule blocks, through the proxy to the test's own backend.
    const { sites } = (await app.get("/api/v1/sites")) as { sites: Array<{ id: string }> };
    const blocked = await app.proxy("shop.test", `/search?name=${encodeURIComponent("1' OR '1'='1")}`);
    expect(blocked.status).toBe(403);
    const reference = /Reference: (\S+)/.exec(await blocked.text())![1]!;
    await until(() => (app.events.flush(), app.events.list({ range: "1h", limit: 1 }).events.length));

    const ev = "/api/v1/events/{id}";
    const list = (await call("GET", "/api/v1/events", admin(), "/api/v1/events?limit=1")).body as { next: string | null };
    await call("GET", "/api/v1/events", admin(), `/api/v1/events?siteId=${sites[0]!.id}&action=blocked,detected&q=942&range=7d`);
    if (list.next) await call("GET", "/api/v1/events", admin(), `/api/v1/events?limit=1&cursor=${list.next}`);
    await call("GET", "/api/v1/events", admin(), "/api/v1/events?range=1y");
    await call("GET", "/api/v1/events", admin(), "/api/v1/events?siteId=missing");
    await call("GET", "/api/v1/events", {});
    await call("GET", ev, admin(), `/api/v1/events/${reference}`);
    await call("GET", ev, admin(), "/api/v1/events/missing");
    await call("GET", ev, {}, `/api/v1/events/${reference}`);
    await call("GET", "/api/v1/traffic", admin());
    await call("GET", "/api/v1/traffic", admin(), `/api/v1/traffic?range=1h&siteId=${sites[0]!.id}`);
    await call("GET", "/api/v1/traffic", admin(), "/api/v1/traffic?range=forever");
    await call("GET", "/api/v1/traffic", admin(), "/api/v1/traffic?siteId=missing");
    await call("GET", "/api/v1/traffic", {});
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
