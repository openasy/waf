// Starts the app on a random port for tests, with the real proxy from vendor/ (npm test builds it) in front of a local
// backend that records what reached it. Attack-like requests in the tests go only to this backend, through the proxy.
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, request, type IncomingMessage, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuth } from "@openasy/auth";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { compile, crsInfo, startEngine, writeConfig, type CrsInfo } from "./engine.ts";
import { createEvents } from "./events.ts";
import { createRules } from "./rules.ts";
import { createService } from "./service.ts";
import { createSites } from "./sites.ts";

export const ADMIN_TOKEN = "test-admin-token";
export const BINARY = new URL("../vendor/waf-proxy", import.meta.url).pathname;

/** A free port on 127.0.0.1, for the proxy. */
async function freePort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

/** The application behind the WAF: it answers 200 and remembers each request it got. */
export async function backend() {
  const seen: Array<{ method: string; url: string; headers: IncomingMessage["headers"]; body: string }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method ?? "GET", url: req.url ?? "/", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(200, { "content-type": "text/plain" }).end("from the application");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { base, seen, close: () => new Promise<void>((r) => server.close(() => r())) };
}

/** Waits until check returns something truthy, up to ms. */
export async function until<T>(check: () => T | undefined | false | null | "" | Promise<T | undefined | false | null | "">, ms = 20_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await Promise.resolve()
      .then(check)
      .catch(() => undefined);
    if (v) return v;
    if (Date.now() > end) throw new Error("timed out waiting");
    await new Promise((r) => setTimeout(r, 100));
  }
}

let info: CrsInfo | undefined;

export async function startApp(opts: Partial<AppOptions> & { version: string; trustedProxies?: string[] }) {
  const dir = mkdtempSync(join(tmpdir(), "waf-test-"));
  const db = openDb(":memory:");
  const sites = createSites(db);
  const rules = createRules(db, { compile: (seclang) => compile(BINARY, join(dir, "run"), seclang) });
  const events = createEvents(db);
  info ??= await crsInfo(BINARY);
  const { trustedProxies = [], ...appOptions } = opts;
  const service = createService({ sites, rules, events, trustedProxies, crs: () => info });
  const proxyPort = await freePort();
  const configPath = join(dir, "run", "proxy.json");
  writeConfig(configPath, service.config());
  const engine = startEngine({ binary: BINARY, listen: `127.0.0.1:${proxyPort}`, configPath, onEvent: service.onEvent, onTraffic: service.onTraffic });
  service.attach(engine);
  await until(() => engine.state.loaded);
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as AddressInfo).port;
  const base = `http://localhost:${port}`;
  const auth = createAuth({ db, product: "waf", productName: "OpenAsy WAF", origin: base });
  handler = createApp({ db, service, sites, rules, events, auth, adminToken: ADMIN_TOKEN, ...appOptions });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const send = (method: string, path: string, body?: unknown) => admin(path, { method, ...(body !== undefined && { body: JSON.stringify(body) }) });
  /** A request to a site, through the proxy, as a browser would send it to that host name. fetch cannot set Host. */
  const proxy = (host: string, path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) =>
    new Promise<{ status: number; text: () => Promise<string> }>((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: proxyPort, path, method: init.method ?? "GET", headers: { host, ...init.headers } }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: async () => Buffer.concat(chunks).toString("utf8") }));
      });
      req.on("error", reject);
      req.end(init.body);
    });
  /** The owner, signed in with a second factor, makes an API token for each role. */
  async function roles() {
    const jar = new Map<string, string>();
    const browser = async (path: string, body: unknown) => {
      const res = await fetch(base + path, {
        method: "POST",
        headers: { origin: base, cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "), "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      for (const c of res.headers.getSetCookie()) {
        const [pair] = c.split(";");
        const i = pair!.indexOf("=");
        jar.set(pair!.slice(0, i), pair!.slice(i + 1));
      }
      return res;
    };
    const setup = new URL(auth.setupLink()!).searchParams.get("setup");
    await browser("/api/v1/auth/setup", { token: setup, name: "Olivia", email: "owner@example.com", password: "correct horse battery staple 42" });
    const { secret } = (await (await browser("/api/v1/auth/me/totp", {})).json()) as { secret: string };
    await browser("/api/v1/auth/me/totp/confirm", { code: totp(secret) });
    const token = async (role: string) => ((await (await browser("/api/v1/auth/tokens", { name: role, role })).json()) as { token: string }).token;
    return { admin: as(await token("admin")), editor: as(await token("editor")), viewer: as(await token("viewer")) };
  }
  const close = async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await engine.stop();
    rmSync(dir, { recursive: true, force: true });
  };
  return { db, sites, rules, events, service, engine, auth, base, dir, proxyPort, admin, get, send, proxy, roles, close };
}

function totp(secret: string) {
  const bits = [...secret].map((c) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  return String((mac.readUInt32BE(mac[19]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
