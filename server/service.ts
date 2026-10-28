// Ties what people set up to the proxy: every change is rendered into the proxy's config and loaded at once, and
// what the proxy reports is kept (ADR 0069).
import type { CrsInfo, Engine, ProxyConfig, ProxyEvent, ProxyTraffic } from "./engine.ts";
import type { Events } from "./events.ts";
import { WafError } from "./problem.ts";
import type { Rules } from "./rules.ts";
import { CRS_GROUPS, render } from "./seclang.ts";
import type { Sites } from "./sites.ts";

export interface ServiceOptions {
  sites: Sites;
  rules: Rules;
  events: Events;
  /** OPENASY_TRUSTED_PROXIES: the addresses whose X-Forwarded-For is believed (ADR 0026). */
  trustedProxies: string[];
  /** The rule set as the proxy compiled it, once it has said. */
  crs: () => CrsInfo | undefined;
}

export interface Summary {
  engine: {
    running: boolean;
    loaded: boolean;
    loadedAt: string | null;
    lastError: string | null;
    restarts: number;
    coraza: string | null;
    crs: string | null;
  };
  sites: { total: number; detection: number; blocking: number };
  rules: number;
  exclusions: number;
  /** Requests in the last 24 hours. */
  day: { requests: number; blocked: number; detected: number; logged: number; upstreamErrors: number };
  events: { stored: number; dropped: number };
}

export function createService(o: ServiceOptions) {
  let engine: Engine | undefined;
  /** Every request each site had since the product started, for /metrics. */
  const totals = new Map<string, { requests: number; blocked: number; detected: number; logged: number; upstreamErrors: number }>();
  const proxyDropped = { events: 0, unknownHost: 0 };

  function config(): ProxyConfig {
    const rules = o.rules.list().filter((r) => r.enabled);
    const exclusions = o.sites.exclusions();
    return {
      trustedProxies: o.trustedProxies,
      sites: o.sites.list().map((s) => {
        const own = rules.filter((r) => r.siteId === null || r.siteId === s.id);
        return {
          id: s.id,
          hosts: s.hosts,
          upstream: s.upstream,
          blocking: s.mode === "blocking",
          directives: render({
            mode: s.mode,
            paranoia: s.paranoia,
            inboundThreshold: s.inboundThreshold,
            disabledGroups: s.disabledGroups,
            exclusions: exclusions.filter((e) => e.siteId === s.id),
            rules: own.map((r) => r.seclang),
          }),
          disruptive: own.flatMap((r) => r.disruptive),
        };
      }),
    };
  }

  return {
    config,

    attach(e: Engine) {
      engine = e;
    },

    /** Loads the current sites and rules in the proxy. A change the proxy does not take is an error the caller sees. */
    async sync(): Promise<void> {
      if (!engine) return;
      const r = await engine.apply(config());
      if (!r.ok) throw new WafError(503, "engine-unavailable", `Saved, but the proxy has not taken it yet: ${r.error ?? "unknown"}`);
    },

    onEvent(e: ProxyEvent) {
      o.events.record(e);
    },

    onTraffic(t: ProxyTraffic) {
      const at = new Date(t.time);
      for (const [site, c] of Object.entries(t.sites ?? {})) {
        o.events.count(site, Number.isNaN(at.getTime()) ? new Date() : at, c);
        const sum = totals.get(site) ?? { requests: 0, blocked: 0, detected: 0, logged: 0, upstreamErrors: 0 };
        for (const k of Object.keys(sum) as Array<keyof typeof sum>) sum[k] += c[k] | 0;
        totals.set(site, sum);
      }
      proxyDropped.events += t.dropped | 0;
      proxyDropped.unknownHost += t.unknownHost | 0;
    },

    totals: () => totals,
    proxyDropped: () => proxyDropped,

    summary(): Summary {
      const sites = o.sites.list();
      const crs = o.crs();
      return {
        engine: {
          running: engine?.state.running ?? false,
          loaded: engine?.state.loaded ?? false,
          loadedAt: engine?.state.loadedAt ?? null,
          lastError: engine?.state.lastError ?? null,
          restarts: engine?.state.restarts ?? 0,
          coraza: crs?.coraza ?? null,
          crs: crs?.crs ?? null,
        },
        sites: {
          total: sites.length,
          detection: sites.filter((s) => s.mode === "detection").length,
          blocking: sites.filter((s) => s.mode === "blocking").length,
        },
        rules: o.rules.list().length,
        exclusions: o.sites.exclusions().length,
        day: o.events.traffic("24h").totals,
        events: { stored: o.events.stats.stored, dropped: o.events.stats.dropped + proxyDropped.events },
      };
    },

    /** The rule set's request groups, their rules and how often they matched in the last 24 hours. */
    crs(siteId?: string) {
      const info = o.crs();
      if (!info) throw new WafError(503, "engine-unavailable", "The proxy has not listed its rules yet.");
      const hits = o.events.hits(new Date(Date.now() - 86_400_000), siteId);
      const rules = info.rules
        .filter((r) => CRS_GROUPS.some((g) => r.file.startsWith(`REQUEST-${g.id}-`)))
        .map((r) => ({ ...r, group: r.file.slice("REQUEST-".length, "REQUEST-".length + 3), hits24h: hits.get(r.id) ?? 0 }));
      return {
        coraza: info.coraza,
        crs: info.crs,
        groups: CRS_GROUPS.map((g) => {
          const own = rules.filter((r) => r.group === g.id);
          return {
            id: g.id,
            name: g.name,
            rules: own.length,
            byParanoia: [1, 2, 3, 4].map((pl) => own.filter((r) => r.paranoia === pl).length),
            hits24h: own.reduce((n, r) => n + r.hits24h, 0),
          };
        }),
        rules: rules.map(({ file: _file, ...r }) => r),
      };
    },

    /** Custom rules, each with how often its rules matched in the last 24 hours. */
    rules() {
      const hits = o.events.hits(new Date(Date.now() - 86_400_000));
      return o.rules.list().map((r) => ({ ...r, hits24h: r.ruleIds.reduce((n, id) => n + (hits.get(id) ?? 0), 0) }));
    },
  };
}

export type Service = ReturnType<typeof createService>;
