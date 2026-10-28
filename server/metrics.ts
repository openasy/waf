// Prometheus text exposition, written by hand: a few lines, no client library needed.
import type { Service, Summary } from "./service.ts";

const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

const esc = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");

export function renderMetrics(version: string, s: Summary, service: Service, siteNames: Map<string, string>): string {
  const totals = [...service.totals()].map(([id, c]) => ({ site: esc(siteNames.get(id) ?? id), c }));
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="waf",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_waf_engine_up 1 while the proxy, Coraza with the Core Rule Set, runs and serves the rules last saved. Watch this from another system.",
    "# TYPE openasy_waf_engine_up gauge",
    `openasy_waf_engine_up ${s.engine.running && s.engine.loaded ? 1 : 0}`,
    "# HELP openasy_waf_engine_restarts_total Times the proxy stopped and was started again.",
    "# TYPE openasy_waf_engine_restarts_total counter",
    `openasy_waf_engine_restarts_total ${s.engine.restarts}`,
    "# HELP openasy_waf_sites Sites by mode.",
    "# TYPE openasy_waf_sites gauge",
    `openasy_waf_sites{mode="detection"} ${s.sites.detection}`,
    `openasy_waf_sites{mode="blocking"} ${s.sites.blocking}`,
    "# HELP openasy_waf_requests_total Requests each site had since the product started.",
    "# TYPE openasy_waf_requests_total counter",
    ...totals.map((t) => `openasy_waf_requests_total{site="${t.site}"} ${t.c.requests}`),
    "# HELP openasy_waf_matched_requests_total Requests a rule matched, by what was done: blocked, detected (would have been blocked, in detection-only mode) or logged (below the threshold).",
    "# TYPE openasy_waf_matched_requests_total counter",
    ...totals.flatMap((t) =>
      (["blocked", "detected", "logged"] as const).map((a) => `openasy_waf_matched_requests_total{site="${t.site}",action="${a}"} ${t.c[a]}`),
    ),
    "# HELP openasy_waf_upstream_errors_total Requests the site's upstream did not answer.",
    "# TYPE openasy_waf_upstream_errors_total counter",
    ...totals.map((t) => `openasy_waf_upstream_errors_total{site="${t.site}"} ${t.c.upstreamErrors}`),
    "# HELP openasy_waf_events_dropped_total Reports of matched requests not kept because more came than could be written.",
    "# TYPE openasy_waf_events_dropped_total counter",
    `openasy_waf_events_dropped_total ${s.events.dropped}`,
    "# HELP openasy_waf_unknown_host_requests_total Requests for a host name no site has.",
    "# TYPE openasy_waf_unknown_host_requests_total counter",
    `openasy_waf_unknown_host_requests_total ${service.proxyDropped().unknownHost}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
