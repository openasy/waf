// What the search window (Cmd+K) finds in WAF: sites by name and host, custom rules by name, and a blocked request by
// the reference its client was shown. The lists are read whole and filtered here.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Ban, FileCode2, Globe } from "lucide-react";
import type { Rule, Site, WafEvent } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [{ sites }, { rules }, event] = await Promise.all([
      call<{ sites: Site[] }>("/api/v1/sites", { signal }),
      call<{ rules: Rule[] }>("/api/v1/rules", { signal }),
      /^[A-Za-z0-9]{8,40}$/.test(q.trim())
        ? call<WafEvent>(`/api/v1/events/${encodeURIComponent(q.trim())}`, { signal }).catch(() => undefined)
        : Promise.resolve(undefined),
    ]);
    const found: SearchResult[] = sites
      .filter((s) => [s.name, ...s.hosts].some((v) => v.toLowerCase().includes(q)))
      .slice(0, 5)
      .map((s) => ({
        id: `site:${s.id}`,
        label: s.name,
        detail: s.hosts.join(", "),
        kind: t("search.site"),
        icon: Globe,
        href: `/rules?site=${encodeURIComponent(s.id)}`,
      }));
    found.push(
      ...rules
        .filter((r) => r.name.toLowerCase().includes(q) || r.ruleIds.some((i) => String(i) === q.trim()))
        .slice(0, 5)
        .map((r) => ({ id: `rule:${r.id}`, label: r.name, detail: r.ruleIds.join(", "), kind: t("search.rule"), icon: FileCode2, href: "/custom" })),
    );
    if (event)
      found.unshift({
        id: `event:${event.id}`,
        label: `${event.method} ${event.host}${event.path}`,
        detail: event.message,
        kind: t("search.event"),
        icon: Ban,
        href: `/blocked?id=${encodeURIComponent(event.id)}`,
      });
    return found;
  };
}
