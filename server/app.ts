import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { AuthError, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { ACTIONS, checkRange, type Action, type Events } from "./events.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import { bad, WafError, type ProblemCode } from "./problem.ts";
import type { ProductLink } from "./products.ts";
import type { Rules } from "./rules.ts";
import type { Service } from "./service.ts";
import type { Sites } from "./sites.ts";

export interface AppOptions {
  db: DatabaseSync;
  service: Service;
  sites: Sites;
  rules: Rules;
  events: Events;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(o: Pick<AppOptions, "service" | "sites" | "version">) {
  return renderMetrics(o.version, o.service.summary(), o.service, new Map(o.sites.list().map((s) => [s.id, s.name])));
}

/** Serves only /metrics, for a port that is not exposed with the rest (WAF_METRICS_PORT). */
export function createMetricsHandler(o: Pick<AppOptions, "service" | "sites" | "version">) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(o), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": `default-src 'self'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'`,
};

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown) => send(res, status, JSON.stringify(data), "application/json");

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  "engine-unavailable": "Proxy unavailable",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0014). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

async function readJson(req: IncomingMessage, limit = 256 * 1024): Promise<Record<string, unknown>> {
  if (req.headers["content-encoding"] && req.headers["content-encoding"] !== "identity")
    throw new WafError(400, "invalid-json", "The body must be JSON, not compressed.");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limit) throw new WafError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new WafError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003). */
type Access = "none" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the record of a change. */
  actor: () => string;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

function limitOf(v: string | null): number {
  if (v === null) return 100;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 500) throw bad("limit must be a whole number from 1 to 500.");
  return n;
}

function actionsOf(v: string | null): Action[] | undefined {
  if (!v) return undefined;
  const list = v.split(",").map((a) => a.trim());
  if (list.some((a) => !ACTIONS.includes(a as Action))) throw bad(`action must be one or more of ${ACTIONS.join(", ")}, separated by commas.`);
  return list as Action[];
}

export function createApp({
  db,
  service,
  sites,
  rules,
  events,
  version,
  auth,
  adminToken,
  webDir,
  docsDir,
  openapi,
  serveMetrics = true,
  products = [],
}: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };

  /** A change takes effect at once: the proxy's config is written again and it loads it. */
  const synced = async <T>(value: T) => (await service.sync(), value);
  const siteParam = (url: URL) => {
    const id = url.searchParams.get("siteId");
    if (id) sites.get(id);
    return id ?? undefined;
  };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "waf", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => service.summary() },

    // Sites: what the proxy answers for and where it passes requests. Turning blocking on can refuse real users, so
    // sites are for admins.
    { method: "GET", path: "/api/v1/sites", auth: "viewer", handle: () => ({ sites: sites.list() }) },
    {
      method: "POST",
      path: "/api/v1/sites",
      auth: "admin",
      handle: async ({ res, body, actor }) => json(res, 201, await synced(sites.create(await body(), actor()))),
    },
    { method: "GET", path: "/api/v1/sites/:id", auth: "viewer", handle: ({ params }) => sites.get(params[0]!) },
    { method: "PUT", path: "/api/v1/sites/:id", auth: "admin", handle: async ({ params, body }) => synced(sites.update(params[0]!, await body())) },
    {
      method: "DELETE",
      path: "/api/v1/sites/:id",
      auth: "admin",
      handle: async ({ res, params }) => (sites.remove(params[0]!), await service.sync(), noContent(res)),
    },

    // Tuning: exclusions for false positives and rules of your own, for editors.
    { method: "GET", path: "/api/v1/exclusions", auth: "viewer", handle: ({ url }) => ({ exclusions: sites.exclusions(siteParam(url)) }) },
    {
      method: "POST",
      path: "/api/v1/exclusions",
      auth: "editor",
      handle: async ({ res, body, actor }) => json(res, 201, await synced(sites.exclude(await body(), actor()))),
    },
    {
      method: "DELETE",
      path: "/api/v1/exclusions/:id",
      auth: "editor",
      handle: async ({ res, params }) => (sites.unexclude(params[0]!), await service.sync(), noContent(res)),
    },
    { method: "GET", path: "/api/v1/rules", auth: "viewer", handle: () => ({ rules: service.rules() }) },
    {
      method: "POST",
      path: "/api/v1/rules",
      auth: "editor",
      handle: async ({ res, body, actor }) => json(res, 201, await synced(await rules.create(await body(), actor()))),
    },
    { method: "POST", path: "/api/v1/rules/check", auth: "editor", handle: async ({ body }) => rules.check(await body()) },
    { method: "GET", path: "/api/v1/rules/:id", auth: "viewer", handle: ({ params }) => rules.get(params[0]!) },
    { method: "PUT", path: "/api/v1/rules/:id", auth: "editor", handle: async ({ params, body }) => synced(await rules.update(params[0]!, await body())) },
    {
      method: "DELETE",
      path: "/api/v1/rules/:id",
      auth: "editor",
      handle: async ({ res, params }) => (rules.remove(params[0]!), await service.sync(), noContent(res)),
    },
    { method: "GET", path: "/api/v1/crs", auth: "viewer", handle: ({ url }) => service.crs(siteParam(url)) },

    // What the proxy saw.
    {
      method: "GET",
      path: "/api/v1/events",
      auth: "viewer",
      handle: ({ url }) => {
        const q = url.searchParams;
        return events.list({
          siteId: siteParam(url),
          actions: actionsOf(q.get("action")),
          q: q.get("q")?.trim().slice(0, 200) || undefined,
          range: checkRange(q.get("range")),
          cursor: q.get("cursor") ?? undefined,
          limit: limitOf(q.get("limit")),
        });
      },
    },
    { method: "GET", path: "/api/v1/events/:id", auth: "viewer", handle: ({ params }) => events.get(params[0]!) },
    { method: "GET", path: "/api/v1/traffic", auth: "viewer", handle: ({ url }) => events.traffic(checkRange(url.searchParams.get("range")), siteParam(url)) },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[A-Za-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling. */
  function authorize(req: IncomingMessage, access: Access): string | null {
    if (access === "none") return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return "admin token";
    const p = auth.authorize(req, access);
    return p.kind === "session" ? p.user.name : `API token ${p.name}`;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready while the database answers and the proxy serves the rules last saved.
      let ready = "ready";
      try {
        db.prepare("SELECT 1").get();
      } catch {
        ready = "database unavailable";
      }
      const s = service.summary().engine;
      if (ready === "ready" && !s.running) ready = "proxy not running";
      else if (ready === "ready" && !s.loaded) ready = "proxy has not loaded the rules";
      json(res, ready === "ready" ? 200 : 503, { status: ready });
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText({ service, sites, version }), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const who = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({ req, res, url, params, body: () => readJson(req), actor: () => who ?? "unknown" });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof WafError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
