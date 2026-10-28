// The proxy inside the product's container (ADR 0069, as VictoriaMetrics is in Metrics, ADR 0063): Coraza with the
// OWASP Core Rule Set in front of every site, started as a child process, restarted when it stops, and told of changes
// by rewriting its config file and sending SIGHUP. It reports on stdout, one JSON line at a time: what it loaded, the
// requests a rule matched and how many requests each site had.
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { log } from "./log.ts";
import { bad, WafError } from "./problem.ts";

/** One site as the proxy reads it. */
export interface ProxySite {
  id: string;
  hosts: string[];
  upstream: string;
  blocking: boolean;
  directives: string;
  disruptive: number[];
}

export interface ProxyConfig {
  trustedProxies: string[];
  sites: ProxySite[];
}

export interface ProxyMatch {
  id: number;
  message: string;
  severity: string;
  tags: string[];
  variable: string;
  value: string;
  data: string;
}

/** A request a rule matched, as the proxy reports it. */
export interface ProxyEvent {
  type: "event";
  id: string;
  site: string;
  time: string;
  clientIp: string;
  method: string;
  host: string;
  path: string;
  query: string;
  userAgent: string;
  action: "blocked" | "detected" | "logged";
  score: number;
  threshold: number;
  status: number;
  matches: ProxyMatch[] | null;
}

export interface Counts {
  requests: number;
  blocked: number;
  detected: number;
  logged: number;
  upstreamErrors: number;
}

/** What each site counted since the last report, every five seconds. */
export interface ProxyTraffic {
  type: "traffic";
  time: string;
  sites: Record<string, Counts>;
  unknownHost: number;
  dropped: number;
}

/** The rule set as the proxy has it compiled. */
export interface CrsInfo {
  coraza: string;
  crs: string;
  rules: Array<{ id: number; file: string; message: string; severity: string; paranoia: number; tags: string[] }>;
}

export interface EngineOptions {
  binary: string;
  /** Where the sites are served, such as 0.0.0.0:8000. */
  listen: string;
  /** The config file, on a tmpfs; rewritten and reloaded on every change. */
  configPath: string;
  onEvent: (e: ProxyEvent) => void;
  onTraffic: (t: ProxyTraffic) => void;
}

const run = (binary: string, args: string[], timeout: number) =>
  new Promise<{ code: number; stdout: string }>((resolve, reject) => {
    execFile(binary, args, { timeout, maxBuffer: 16 * 1024 * 1024 }, (err, stdout) => {
      if (err && typeof err.code !== "number") return reject(new WafError(503, "engine-unavailable", `The proxy could not be run: ${err.message}`));
      resolve({ code: err ? Number(err.code) : 0, stdout });
    });
  });

/** Writes a file whole, readable only by this process: the proxy never reads one half written. */
export function writeConfig(path: string, config: ProxyConfig) {
  mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(`${path}.next`, JSON.stringify(config), { mode: 0o600 });
  renameSync(`${path}.next`, path);
}

/** Compiles SecLang in the proxy, without the rule set, and throws what Coraza made of it. */
export async function compile(binary: string, dir: string, seclang: string): Promise<void> {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = mkdtempSync(join(dir, "check-"));
  try {
    const file = join(tmp, "config.json");
    writeConfig(file, {
      trustedProxies: [],
      sites: [{ id: "check", hosts: [], upstream: "http://127.0.0.1", blocking: true, directives: `SecRuleEngine On\n${seclang}\n`, disruptive: [] }],
    });
    const { code, stdout } = await run(binary, ["-check", "-config", file], 30_000);
    if (code !== 0)
      throw bad(
        `Coraza does not take this rule: ${stdout
          .trim()
          .replace(/^site check: /, "")
          .slice(0, 2000)}`,
      );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** The versions of Coraza and the rule set, and the rule set's rules. */
export async function crsInfo(binary: string): Promise<CrsInfo> {
  const { code, stdout } = await run(binary, ["-info"], 60_000);
  if (code !== 0) throw new WafError(503, "engine-unavailable", `The proxy could not list its rules: ${stdout.trim().slice(0, 500)}`);
  return JSON.parse(stdout) as CrsInfo;
}

/**
 * Starts the proxy and keeps it running: it is restarted a second after it stops, then after longer waits if it keeps
 * stopping. Reloads are taken one at a time, so each SIGHUP has its own answer.
 */
export function startEngine(o: EngineOptions) {
  let child: ChildProcess | undefined;
  let stopping = false;
  let failures = 0;
  let timer: NodeJS.Timeout | undefined;
  const state = {
    running: false,
    /** Whether the rules of the last config written are the ones serving. */
    loaded: false,
    loadedAt: null as string | null,
    lastError: null as string | null,
    restarts: 0,
    loadFailures: 0,
  };
  let waiting: ((r: { ok: boolean; error?: string }) => void) | undefined;
  let queue: Promise<unknown> = Promise.resolve();
  // Settles when the running proxy has made its first load; a SIGHUP before that would be answered by that load.
  let ready: Promise<void> = Promise.resolve();
  let markReady = () => {};
  const settle = (r: { ok: boolean; error?: string }) => {
    if (waiting) waiting(r);
    else markReady();
    waiting = undefined;
  };

  function line(text: string) {
    let msg: { type?: string; error?: string } & Record<string, unknown>;
    try {
      msg = JSON.parse(text) as typeof msg;
    } catch {
      return log("warn", "waf-proxy", { detail: text.slice(0, 2000) });
    }
    switch (msg.type) {
      case "event":
        return o.onEvent(msg as unknown as ProxyEvent);
      case "traffic":
        return o.onTraffic(msg as unknown as ProxyTraffic);
      case "loaded":
        state.loaded = true;
        state.loadedAt = new Date().toISOString();
        state.lastError = null;
        log("info", "waf-proxy loaded the sites' rules", { sites: msg.sites });
        return settle({ ok: true });
      case "load-failed":
        state.loaded = false;
        state.loadFailures++;
        state.lastError = msg.error ?? "unknown";
        log("error", "waf-proxy did not take the new rules; the ones before keep serving", { error: msg.error });
        return settle({ ok: false, error: msg.error });
      case "listening":
        return log("info", "waf-proxy is serving the sites", { address: msg.address });
      case "fatal":
        state.lastError = msg.error ?? "unknown";
        return log("error", "waf-proxy stopped", { error: msg.error });
      default:
        return log("warn", "waf-proxy", { detail: text.slice(0, 2000) });
    }
  }

  function start() {
    const c = spawn(o.binary, ["-listen", o.listen, "-config", o.configPath], { stdio: ["ignore", "pipe", "pipe"] });
    child = c;
    ready = new Promise((r) => (markReady = r));
    state.running = true;
    createInterface({ input: c.stdout!, crlfDelay: Infinity }).on("line", line);
    createInterface({ input: c.stderr!, crlfDelay: Infinity }).on("line", (l) => log("warn", "waf-proxy", { detail: l.slice(0, 2000) }));
    c.on("error", (err) => log("error", "waf-proxy could not start", { error: String(err), binary: o.binary }));
    c.on("exit", (code, signal) => {
      state.running = false;
      state.loaded = false;
      settle({ ok: false, error: "The proxy stopped." });
      markReady();
      if (child !== c) return;
      child = undefined;
      if (stopping) return;
      failures++;
      state.restarts++;
      const wait = Math.min(30_000, 1000 * 2 ** Math.min(failures - 1, 5));
      log("error", "waf-proxy stopped; starting it again", { code, signal, inMs: wait });
      timer = setTimeout(start, wait);
    });
    // Running for a minute counts as healthy again.
    setTimeout(() => child === c && (failures = 0), 60_000).unref();
  }
  start();

  /** Writes the config and has the proxy load it; resolves with whether it took it. */
  function apply(config: ProxyConfig): Promise<{ ok: boolean; error?: string }> {
    const next = queue.then(async () => {
      writeConfig(o.configPath, config);
      await ready;
      return new Promise<{ ok: boolean; error?: string }>((resolve) => {
        const c = child;
        // A proxy that is starting reads the file when it starts.
        if (!c || c.exitCode !== null || c.pid === undefined)
          return resolve({ ok: false, error: "The proxy is not running; it reads the rules when it starts." });
        const t = setTimeout(() => {
          waiting = undefined;
          resolve({ ok: false, error: "The proxy did not answer in 30 seconds." });
        }, 30_000);
        waiting = (r) => {
          clearTimeout(t);
          resolve(r);
        };
        c.kill("SIGHUP");
      });
    });
    queue = next.catch(() => undefined);
    return next;
  }

  function stop(): Promise<void> {
    stopping = true;
    clearTimeout(timer);
    const c = child;
    if (!c || c.exitCode !== null) return Promise.resolve();
    return new Promise((resolve) => {
      const kill = setTimeout(() => c.kill("SIGKILL"), 10_000);
      c.once("exit", () => {
        clearTimeout(kill);
        resolve();
      });
      c.kill("SIGTERM");
    });
  }

  return { state, apply, stop };
}

export type Engine = ReturnType<typeof startEngine>;
