import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { compile, crsInfo, startEngine, writeConfig, type CrsInfo } from "./engine.ts";
import { createEvents } from "./events.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { createRules } from "./rules.ts";
import { createService } from "./service.ts";
import { createSites } from "./sites.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dataDir = process.env.WAF_DATA ?? "/data";
// The proxy's config: on tmpfs, never on the data volume.
const runDir = process.env.WAF_RUN_DIR ?? "/tmp/waf";
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.WAF_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.WAF_METRICS_PORT ? Number(process.env.WAF_METRICS_PORT) : undefined;
const whole = (name: string, fallback: number, min: number, max: number) => {
  const v = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(v) || v < min || v > max) throw new Error(`${name} must be a whole number, ${min} to ${max}`);
  return v;
};
const proxyPort = whole("WAF_PROXY_PORT", 8000, 1, 65_535);
const retentionDays = whole("WAF_RETENTION_DAYS", 30, 1, 3650);
const binary = process.env.WAF_PROXY ?? new URL("../vendor/waf-proxy", import.meta.url).pathname;
// The TLS proxy in front, whose X-Forwarded-For names the client (ADR 0026). By default none is trusted.
const trustedProxies = (process.env.OPENASY_TRUSTED_PROXIES ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .map((s) => (s.includes("/") ? s : s.includes(":") ? `${s}/128` : `${s}/32`));

const db = openDb(join(dataDir, "waf.db"));
// The address people open WAF at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.WAF_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.WAF_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const auth = createAuth({
  db,
  product: "waf",
  productName: "OpenAsy WAF",
  origin: publicUrl,
  // Locally the same WAF is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.WAF_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "WAF_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

let crs: CrsInfo | undefined;
const sites = createSites(db);
const rules = createRules(db, { compile: (seclang) => compile(binary, runDir, seclang) });
const events = createEvents(db);
const service = createService({ sites, rules, events, trustedProxies, crs: () => crs });
const configPath = join(runDir, "proxy.json");
// The config is written before the proxy starts, so it serves the sites' rules from its first request.
writeConfig(configPath, service.config());
const engine = startEngine({ binary, listen: `0.0.0.0:${proxyPort}`, configPath, onEvent: service.onEvent, onTraffic: service.onTraffic });
service.attach(engine);
void crsInfo(binary).then(
  (info) => ((crs = info), log("info", "rule set", { coraza: info.coraza, crs: info.crs, rules: info.rules.length })),
  (err: Error) => log("error", "the proxy could not list its rules", { error: err.message }),
);

const server = createServer(
  createApp({
    db,
    service,
    sites,
    rules,
    events,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler({ service, sites, version })) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "waf started", { version, port, proxyPort, data: dataDir, headless, retentionDays, trustedProxies }));
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "WAF_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put waf behind TLS (ADR 0026)", { url: publicUrl });
}
if (!secretsKey)
  log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", {
    file: secretsKeyFile,
  });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

const timers: NodeJS.Timeout[] = [
  setInterval(() => auth.purge(), 5 * 60_000),
  setInterval(() => {
    try {
      events.flush();
    } catch (err) {
      log("error", "matched requests could not be written", { error: String(err) });
    }
  }, 1000),
  setInterval(() => events.purge(retentionDays), 3600_000),
];
events.purge(retentionDays);

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    void engine.stop().then(() => {
      events.flush();
      db.close();
      process.exit(0);
    });
  });
  setTimeout(() => process.exit(1), 15_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
