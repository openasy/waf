import {
  AppShell,
  Badge,
  BarList,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  EntityChip,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SegmentedControl,
  SelectField,
  StatusBadge,
  Switch,
  TextField,
  TimeRangePicker,
  TimeSeriesChart,
  formatNumber,
  formatPercent,
  toLocale,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
  type Tone,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import {
  Activity,
  Ban,
  BookOpen,
  Copy,
  FileCode2,
  Globe,
  KeyRound,
  ListX,
  LogIn,
  LogOut,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2,
  UserRound,
  Users,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import {
  api,
  MfaSetupRequired,
  RANGES,
  Unauthorized,
  type Action,
  type Crs,
  type Exclusion,
  type Mode,
  type ProductLink,
  type Range,
  type Rule,
  type Site,
  type Summary,
  type Traffic,
  type WafEvent,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";
import { nextId, PATCH_KINDS, PATCH_PARAMETER, PATCH_PATH, virtualPatch, type PatchKind } from "./patch.ts";
import { search } from "./search.ts";

const PAGES = ["traffic", "blocked", "rules", "custom", "sites", "exclusions", "account", "members", "signin", "tokens"] as const;
type Page = (typeof PAGES)[number];
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = [...PAGES];
function parsePage(path: string): Page {
  const page = path.replace(/^\//, "").split("/")[0] ?? "";
  return (PAGES as readonly string[]).includes(page) ? (page as Page) : "traffic";
}

/** A query parameter of the address. */
const param = (name: string) => new URLSearchParams(window.location.search).get(name);

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <R,>(path: string, init?: RequestInit): Promise<R> => {
      try {
        return await api<R>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

/** Loads once, again when the path changes, and on demand. */
function useLoad<R>(call: Call, path: string | null, every = 0) {
  const [data, setData] = useState<R>();
  const [error, setError] = useState<string>();
  const load = useCallback(() => {
    if (!path) return;
    void call<R>(path).then(
      (r) => (setData(r), setError(undefined)),
      (err: Error) => setError(err.message),
    );
  }, [call, path]);
  useEffect(() => {
    load();
    if (!every) return;
    const id = setInterval(load, every * 1000);
    return () => clearInterval(id);
  }, [load, every]);
  return [data, load, error] as const;
}

/** Runs a change and reports its error, the way every form here does. */
function useAction(after: () => void) {
  const [error, setError] = useState<string>();
  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        setError(undefined);
        after();
        return true;
      } catch (err) {
        setError((err as Error).message);
        return false;
      }
    },
    [after],
  );
  return [run, error, setError] as const;
}

const send = (method: string, body?: unknown): RequestInit => ({ method, ...(body !== undefined && { body: JSON.stringify(body) }) });
const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const clock = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });

function ErrorText({ message }: { message?: string }) {
  return message ? <p className="m-0 text-xs text-danger">{message}</p> : null;
}

const ACTION_TONE: Record<Action, Tone> = { blocked: "danger", detected: "warning", logged: "neutral" };

function ActionBadge({ action }: { action: Action }) {
  const t = useT();
  return <StatusBadge tone={ACTION_TONE[action]}>{t(`action.${action}`)}</StatusBadge>;
}

function ModeBadge({ mode }: { mode: Mode }) {
  const t = useT();
  return <StatusBadge tone={mode === "blocking" ? "success" : "warning"}>{t(`mode.${mode}`)}</StatusBadge>;
}

const ATTACKS = [
  "sqli",
  "xss",
  "lfi",
  "rfi",
  "rce",
  "php",
  "java",
  "generic",
  "protocol",
  "multipart",
  "fixation",
  "reputation-scanner",
  "custom",
  "other",
] as const;
type Attack = (typeof ATTACKS)[number];
const GROUPS = ["911", "913", "920", "921", "922", "930", "931", "932", "933", "934", "941", "942", "943", "944"] as const;
type Group = (typeof GROUPS)[number];

/** The name of an attack class from the rule set's tags, in the page's language. */
const attackName = (t: T, attack: string) => ((ATTACKS as readonly string[]).includes(attack) ? t(`attack.${attack as Attack}`) : attack);
/** The name of a group of the rule set, in the page's language. */
const groupName = (t: T, id: string) => ((GROUPS as readonly string[]).includes(id) ? t(`groups.${id as Group}`) : id);

function SiteSelect({ sites, value, onChange, all = true }: { sites: Site[]; value: string; onChange: (id: string) => void; all?: boolean }) {
  const t = useT();
  return (
    <SelectField
      label={t("common.site")}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      options={[...(all ? [{ value: "", label: t("common.allSites") }] : []), ...sites.map((s) => ({ value: s.id, label: s.name }))]}
    />
  );
}

function RangePicker({ value, onChange }: { value: Range; onChange: (r: Range) => void }) {
  const t = useT();
  return <TimeRangePicker value={value} onChange={(v) => onChange(v as Range)} ranges={RANGES.map((r) => ({ value: r, label: t(`range.${r}`) }))} />;
}

/** Requests the rules matched, as the Traffic and Blocked pages list them. */
function EventTable({
  events,
  sites,
  label,
  onOpen,
  active,
}: {
  events: WafEvent[];
  sites: Site[];
  label: string;
  onOpen: (e: WafEvent) => void;
  active?: string;
}) {
  const t = useT();
  const name = (id: string) => sites.find((s) => s.id === id)?.name ?? id;
  const columns: Column<WafEvent>[] = [
    {
      id: "time",
      header: t("events.time"),
      mono: true,
      width: "92px",
      sortValue: (e) => e.time,
      cell: (e) => <span title={when(e.time)}>{clock(e.time)}</span>,
    },
    { id: "ip", header: t("events.client"), width: "150px", sortValue: (e) => e.clientIp, cell: (e) => <EntityChip kind="ip" value={e.clientIp} hideKind /> },
    {
      id: "request",
      header: t("events.request"),
      cell: (e) => (
        <span className="flex min-w-0 flex-col">
          <span className="flex min-w-0 items-center gap-1.5 font-mono text-xs">
            <Badge mono>{e.method}</Badge>
            <span className="truncate" title={e.path + (e.query ? `?${e.query}` : "")}>
              {e.path}
              {e.query ? `?${e.query}` : ""}
            </span>
          </span>
          <span className="truncate text-2xs text-fg-muted">
            {e.host} · {name(e.siteId)}
          </span>
        </span>
      ),
    },
    {
      id: "rule",
      header: t("events.rule"),
      width: "240px",
      sortValue: (e) => e.ruleId ?? 0,
      cell: (e) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-mono text-xs">{e.ruleId ?? "–"}</span>
          <span className="truncate text-2xs text-fg-muted" title={e.message}>
            {e.message}
          </span>
        </span>
      ),
    },
    { id: "score", header: t("events.score"), align: "right", mono: true, width: "84px", sortValue: (e) => e.score, cell: (e) => e.score },
    { id: "action", header: t("events.action"), width: "120px", sortValue: (e) => e.action, cell: (e) => <ActionBadge action={e.action} /> },
  ];
  return (
    <DataTable
      label={label}
      columns={columns}
      rows={events}
      getRowId={(e) => e.id}
      onRowClick={onOpen}
      activeRowId={active}
      defaultSort={{ id: "time", direction: "desc" }}
      minWidth={900}
      empty={<p className="py-8">{t("events.none")}</p>}
    />
  );
}

// ---------------------------------------------------------------- Traffic

function TrafficPage({ call, sites, summary }: { call: Call; sites: Site[]; summary: Summary }) {
  const t = useT();
  const [range, setRange] = useState<Range>("24h");
  const [siteId, setSiteId] = useState("");
  const q = `range=${range}${siteId ? `&siteId=${siteId}` : ""}`;
  const [traffic] = useLoad<Traffic>(call, `/api/v1/traffic?${q}`, 30);
  const [recent] = useLoad<{ events: WafEvent[] }>(call, `/api/v1/events?${q}&action=blocked,detected&limit=10`, 30);
  const detecting = sites.filter((s) => s.mode === "detection" && (!siteId || s.id === siteId));
  const tot = traffic?.totals;
  const labels = useMemo(
    () =>
      (traffic?.buckets ?? []).map((b) =>
        new Date(b.time).toLocaleString(
          undefined,
          range === "1h" || range === "24h" ? { hour: "2-digit", minute: "2-digit" } : { month: "short", day: "numeric" },
        ),
      ),
    [traffic, range],
  );
  return (
    <>
      <PageHeader
        title={t("traffic.title")}
        description={t("traffic.description", { coraza: summary.engine.coraza ?? "?", crs: summary.engine.crs ?? "?", count: sites.length })}
        actions={
          <Button size="md" icon={<Ban />} onClick={() => navigate("/blocked")}>
            {t("traffic.openBlocked")}
          </Button>
        }
      />
      <FilterBar>
        <RangePicker value={range} onChange={setRange} />
        <SiteSelect sites={sites} value={siteId} onChange={setSiteId} />
      </FilterBar>
      {detecting.length > 0 && tot && tot.detected > 0 && (
        <Callout tone="warning" title={t("traffic.detecting", { count: detecting.length })}>
          {t("traffic.detectingDetail", { detected: formatNumber(tot.detected) })}
        </Callout>
      )}
      <KpiGrid>
        <KpiCard
          label={t("traffic.requests", { range: t(`range.${range}`) })}
          value={tot ? formatNumber(tot.requests) : "–"}
          unit={tot ? t("traffic.perSecond", { n: (tot.requests / ((traffic?.buckets.length ?? 1) * (traffic?.bucketSeconds ?? 60))).toFixed(2) }) : undefined}
          trend={traffic?.buckets.map((b) => b.requests)}
        />
        <KpiCard
          label={t("traffic.blocked")}
          value={tot ? formatNumber(tot.blocked) : "–"}
          unit={tot && tot.requests ? formatPercent(tot.blocked / tot.requests) : undefined}
          tone="danger"
          trendColor="var(--oa-danger)"
          trend={traffic?.buckets.map((b) => b.blocked)}
        />
        <KpiCard
          label={t("traffic.detected")}
          value={tot ? formatNumber(tot.detected) : "–"}
          unit={t("traffic.detectedUnit")}
          tone="warning"
          trend={traffic?.buckets.map((b) => b.detected)}
        />
        <KpiCard label={t("traffic.upstreamErrors")} value={tot ? formatNumber(tot.upstreamErrors) : "–"} unit={t("traffic.upstreamErrorsUnit")} />
      </KpiGrid>
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title={t("traffic.chart")} description={t("traffic.chartDetail", { minutes: (traffic?.bucketSeconds ?? 60) / 60 })}>
          {traffic && (
            <TimeSeriesChart
              label={t("traffic.chart")}
              labels={labels}
              stacked
              area
              height={200}
              xTicks={6}
              format={(v) => formatNumber(Math.round(v))}
              series={[
                { id: "allowed", name: t("traffic.allowed"), data: traffic.buckets.map((b) => b.requests - b.blocked - b.detected) },
                { id: "detected", name: t("traffic.detected"), color: "var(--oa-warning)", data: traffic.buckets.map((b) => b.detected) },
                { id: "blocked", name: t("traffic.blocked"), color: "var(--oa-danger)", data: traffic.buckets.map((b) => b.blocked) },
              ]}
            />
          )}
        </Panel>
        <Panel title={t("traffic.attacks")} description={t("traffic.attacksDetail")}>
          {traffic && traffic.attacks.length ? (
            <BarList label={t("traffic.attacks")} items={traffic.attacks.map((a) => ({ id: a.attack, label: attackName(t, a.attack), value: a.count }))} />
          ) : (
            <p className="m-0 text-xs text-fg-muted">{t("traffic.noAttacks")}</p>
          )}
        </Panel>
      </div>
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title={t("traffic.recent")} description={t("traffic.recentDetail")} flush>
          <EventTable
            events={recent?.events ?? []}
            sites={sites}
            label={t("traffic.recent")}
            onOpen={(e) => navigate(`/blocked?id=${encodeURIComponent(e.id)}`)}
          />
        </Panel>
        <div className="flex flex-col gap-2.5">
          <Panel title={t("traffic.topRules")}>
            {traffic && traffic.rules.length ? (
              <BarList
                label={t("traffic.topRules")}
                items={traffic.rules.map((r) => ({ id: String(r.ruleId), label: `${r.ruleId} ${r.message}`, value: r.count }))}
              />
            ) : (
              <p className="m-0 text-xs text-fg-muted">{t("traffic.noAttacks")}</p>
            )}
          </Panel>
          <Panel title={t("traffic.topClients")}>
            {traffic && traffic.clients.length ? (
              <BarList label={t("traffic.topClients")} items={traffic.clients.map((c) => ({ id: c.clientIp, label: c.clientIp, value: c.count }))} />
            ) : (
              <p className="m-0 text-xs text-fg-muted">{t("traffic.noAttacks")}</p>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Blocked

const TARGET =
  /^(ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|REQUEST_FILENAME|REQUEST_BASENAME|XML|FILES|FILES_NAMES)(:[A-Za-z0-9_.\-[\]]{1,100})?$/;

function BlockedPage({ call, sites, reload }: { call: Call; sites: Site[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [range, setRange] = useState<Range>("24h");
  const [siteId, setSiteId] = useState("");
  const [actions, setActions] = useState<string[]>([]);
  const [text, setText] = useState("");
  const [q, setQ] = useState("");
  const [events, setEvents] = useState<WafEvent[]>();
  const [next, setNext] = useState<string | null>(null);
  const [active, setActive] = useState<WafEvent>();
  const [excluding, setExcluding] = useState<Partial<Exclusion>>();
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    const id = setTimeout(() => setQ(text.trim()), 300);
    return () => clearTimeout(id);
  }, [text]);
  const path = (cursor?: string) =>
    `/api/v1/events?${new URLSearchParams({
      range,
      limit: "100",
      ...(siteId && { siteId }),
      ...(actions.length && { action: actions.join(",") }),
      ...(q && { q }),
      ...(cursor && { cursor }),
    })}`;
  useEffect(() => {
    let live = true;
    void call<{ events: WafEvent[]; next: string | null }>(path()).then(
      (r) => live && (setEvents(r.events), setNext(r.next)),
      () => live && setEvents([]),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [call, range, siteId, actions, q]);
  // An event opened from another page, or from the reference a blocked client was shown.
  useEffect(() => {
    const id = param("id");
    if (id) void call<WafEvent>(`/api/v1/events/${encodeURIComponent(id)}`).then(setActive, () => {});
  }, [call]);
  const more = () =>
    next && void call<{ events: WafEvent[]; next: string | null }>(path(next)).then((r) => (setEvents((e) => [...(e ?? []), ...r.events]), setNext(r.next)));
  const site = active && sites.find((s) => s.id === active.siteId);
  return (
    <>
      <PageHeader title={t("blocked.title")} description={t("blocked.description")} />
      <FilterBar
        onClear={
          siteId || actions.length || text
            ? () => {
                setSiteId("");
                setActions([]);
                setText("");
              }
            : undefined
        }
      >
        <RangePicker value={range} onChange={setRange} />
        <SiteSelect sites={sites} value={siteId} onChange={setSiteId} />
        <FacetFilter
          label={t("events.action")}
          selected={actions}
          onChange={setActions}
          options={(["blocked", "detected", "logged"] as const).map((a) => ({ value: a, label: t(`action.${a}`) }))}
        />
        <SearchInput label={t("blocked.search")} value={text} onChange={(e) => setText(e.target.value)} className="w-64" />
      </FilterBar>
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Panel
          title={t("blocked.requests")}
          description={t("blocked.shown", { count: events?.length ?? 0 })}
          flush
          footer={
            next && (
              <Button size="sm" variant="ghost" onClick={more}>
                {t("blocked.more")}
              </Button>
            )
          }
        >
          <EventTable events={events ?? []} sites={sites} label={t("blocked.log")} onOpen={(e) => (setActive(e), setCopied(false))} active={active?.id} />
        </Panel>
        <Panel
          title={t("blocked.match")}
          description={active ? `${active.ruleId ?? "–"} · ${active.message}` : t("blocked.noneSelected")}
          aria-label={t("blocked.match")}
        >
          {active && (
            <div className="flex flex-col gap-2.5 text-sm">
              <dl className="waf-facts">
                <dt>{t("blocked.reference")}</dt>
                <dd className="font-mono text-xs">{active.id}</dd>
                <dt>{t("events.action")}</dt>
                <dd>
                  <ActionBadge action={active.action} /> {t("blocked.status", { status: active.status })}
                </dd>
                <dt>{t("blocked.when")}</dt>
                <dd>{when(active.time)}</dd>
                <dt>{t("common.site")}</dt>
                <dd>{site?.name ?? active.siteId}</dd>
                <dt>{t("events.request")}</dt>
                <dd className="waf-wrap font-mono text-xs">
                  {active.method} {active.host}
                  {active.path}
                  {active.query ? `?${active.query}` : ""}
                </dd>
                <dt>{t("blocked.userAgent")}</dt>
                <dd className="waf-wrap font-mono text-xs">{active.userAgent || "–"}</dd>
                <dt>{t("events.score")}</dt>
                <dd>{t("blocked.scoreOf", { score: active.score, threshold: active.threshold })}</dd>
              </dl>
              <ul className="waf-list flex flex-col gap-2" aria-label={t("blocked.matches")}>
                {active.matches.map((m, i) => (
                  <li key={`${m.id}-${i}`} className="rounded-md border border-line p-2">
                    <div className="flex items-start justify-between gap-2">
                      <span className="flex min-w-0 flex-col">
                        <span className="font-mono text-xs">{m.id}</span>
                        <span className="text-xs">{m.message}</span>
                      </span>
                      <Badge tone={m.severity === "critical" ? "danger" : m.severity === "error" || m.severity === "warning" ? "warning" : "neutral"}>
                        {m.severity}
                      </Badge>
                    </div>
                    {m.variable && (
                      <p className="waf-wrap m-0 mt-1 font-mono text-2xs text-fg-muted">
                        {m.variable}: {m.value}
                      </p>
                    )}
                    {can("editor") && (
                      <Button
                        size="xs"
                        variant="ghost"
                        className="mt-1"
                        onClick={() =>
                          setExcluding({
                            siteId: active.siteId,
                            ruleId: String(m.id),
                            target: TARGET.test(m.variable) ? m.variable : null,
                            path: /^\/[A-Za-z0-9/_.~%-]{0,500}$/.test(active.path) ? active.path : null,
                            reason: "",
                          })
                        }
                      >
                        {t("blocked.falsePositive")}
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
              <div className="flex flex-wrap gap-1.5 border-t border-line pt-2">
                <Button size="sm" icon={<Copy />} onClick={() => void navigator.clipboard?.writeText(active.id).then(() => setCopied(true))}>
                  {copied ? t("blocked.copied") : t("blocked.copy")}
                </Button>
              </div>
            </div>
          )}
        </Panel>
      </div>
      {excluding && <ExclusionDialog call={call} sites={sites} initial={excluding} onClose={() => setExcluding(undefined)} onSaved={reload} />}
    </>
  );
}

// ---------------------------------------------------------------- Rules (OWASP CRS)

function RulesPage({ call, sites, reload }: { call: Call; sites: Site[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [siteId, setSiteId] = useState(param("site") ?? sites[0]?.id ?? "");
  const site = sites.find((s) => s.id === siteId) ?? sites[0];
  const [crs, loadCrs, crsError] = useLoad<Crs>(call, site ? `/api/v1/crs?siteId=${site.id}` : null);
  const [group, setGroup] = useState<string>();
  const [paranoia, setParanoia] = useState(String(site?.paranoia ?? 1));
  const [threshold, setThreshold] = useState(String(site?.inboundThreshold ?? 5));
  useEffect(() => {
    setParanoia(String(site?.paranoia ?? 1));
    setThreshold(String(site?.inboundThreshold ?? 5));
  }, [site?.id, site?.paranoia, site?.inboundThreshold]);
  const after = useCallback(() => (reload(), loadCrs()), [reload, loadCrs]);
  const [run, error] = useAction(after);
  if (!site) return <EmptyState title={t("rules.noSites")}>{t("rules.noSitesDetail")}</EmptyState>;
  const pl = Number(paranoia);
  const change = (body: Partial<Site>) => run(() => call(`/api/v1/sites/${site.id}`, send("PUT", body)));
  const groups = crs?.groups ?? [];
  const columns: Column<Crs["groups"][number]>[] = [
    { id: "id", header: t("rules.group"), mono: true, width: "80px", sortValue: (g) => g.id, cell: (g) => `${g.id}xxx` },
    { id: "name", header: t("rules.name"), sortValue: (g) => g.name, cell: (g) => <span className="font-medium">{groupName(t, g.id)}</span> },
    {
      id: "rules",
      header: t("rules.rules"),
      align: "right",
      mono: true,
      description: t("rules.rulesHint"),
      sortValue: (g) => g.rules,
      cell: (g) => `${g.byParanoia.slice(0, site.paranoia).reduce((a, b) => a + b, 0)} / ${g.rules}`,
    },
    { id: "hits", header: t("rules.hits"), align: "right", mono: true, sortValue: (g) => g.hits24h, cell: (g) => formatNumber(g.hits24h) },
    {
      id: "on",
      header: t("rules.enabled"),
      width: "100px",
      cell: (g) => (
        <Switch
          checked={!site.disabledGroups.includes(g.id)}
          disabled={!can("admin")}
          onCheckedChange={(on) => void change({ disabledGroups: on ? site.disabledGroups.filter((x) => x !== g.id) : [...site.disabledGroups, g.id] })}
          label={<span className="sr-only">{t("rules.enable", { name: groupName(t, g.id) })}</span>}
        />
      ),
    },
  ];
  const shown = (crs?.rules ?? []).filter((r) => r.group === group);
  return (
    <>
      <PageHeader
        title={t("rules.title")}
        description={crs ? t("rules.description", { crs: crs.crs, coraza: crs.coraza }) : undefined}
        meta={<ModeBadge mode={site.mode} />}
      />
      <FilterBar>
        <SiteSelect sites={sites} value={site.id} onChange={setSiteId} all={false} />
        <SelectField
          label={t("rules.paranoia")}
          value={paranoia}
          disabled={!can("admin")}
          onChange={(e) => setParanoia(e.target.value)}
          options={(["1", "2", "3", "4"] as const).map((v) => ({ value: v, label: t(`rules.pl${v}`) }))}
        />
        <TextField
          label={t("rules.threshold")}
          type="number"
          min={1}
          max={1000}
          value={threshold}
          disabled={!can("admin")}
          onChange={(e) => setThreshold(e.target.value)}
          className="w-28"
        />
        {can("admin") && (pl !== site.paranoia || Number(threshold) !== site.inboundThreshold) && (
          <Button variant="primary" onClick={() => void change({ paranoia: pl, inboundThreshold: Number(threshold) })}>
            {t("form.save")}
          </Button>
        )}
      </FilterBar>
      <ErrorText message={error ?? crsError} />
      {pl > site.paranoia && site.mode === "blocking" && (
        <Callout tone="warning" title={t("rules.higher", { level: pl })}>
          {t("rules.higherDetail")}
        </Callout>
      )}
      <Panel title={t("rules.groups")} description={t("rules.groupsShown", { on: groups.length - site.disabledGroups.length, all: groups.length })} flush>
        <DataTable
          label={t("rules.groups")}
          columns={columns}
          rows={groups}
          getRowId={(g) => g.id}
          onRowClick={(g) => setGroup(g.id)}
          activeRowId={group}
          defaultSort={{ id: "id", direction: "asc" }}
          minWidth={720}
        />
      </Panel>
      {group && (
        <Panel title={t("rules.inGroup", { name: groupName(t, group) })} description={t("rules.inGroupDetail")} flush>
          <DataTable
            label={t("rules.inGroup", { name: groupName(t, group) })}
            rows={shown}
            getRowId={(r) => String(r.id)}
            defaultSort={{ id: "id", direction: "asc" }}
            minWidth={720}
            columns={[
              { id: "id", header: t("rules.id"), mono: true, width: "90px", sortValue: (r) => r.id, cell: (r) => r.id },
              { id: "message", header: t("rules.message"), cell: (r) => <span className="text-xs">{r.message}</span> },
              {
                id: "pl",
                header: t("rules.from"),
                mono: true,
                width: "80px",
                sortValue: (r) => r.paranoia,
                cell: (r) => <span className={r.paranoia > site.paranoia ? "text-fg-muted" : ""}>PL{r.paranoia}</span>,
              },
              { id: "severity", header: t("rules.severity"), width: "100px", cell: (r) => r.severity },
              {
                id: "hits",
                header: t("rules.hits"),
                align: "right",
                mono: true,
                width: "100px",
                sortValue: (r) => r.hits24h,
                cell: (r) => formatNumber(r.hits24h),
              },
            ]}
          />
        </Panel>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Custom rules

function CustomRulesPage({ call, sites, reload }: { call: Call; sites: Site[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [rules, loadRules] = useLoad<{ rules: Rule[] }>(call, "/api/v1/rules", 60);
  const [active, setActive] = useState<string | "new">();
  const list = rules?.rules ?? [];
  const cur = active && active !== "new" ? list.find((r) => r.id === active) : undefined;
  const after = useCallback(() => (loadRules(), reload()), [loadRules, reload]);
  const siteName = (id: string | null) => (id ? (sites.find((s) => s.id === id)?.name ?? id) : t("common.allSites"));
  const columns: Column<Rule>[] = [
    { id: "name", header: t("custom.rule"), width: "36%", sortValue: (r) => r.name, cell: (r) => <span className="block truncate font-medium">{r.name}</span> },
    { id: "site", header: t("common.site"), sortValue: (r) => siteName(r.siteId), cell: (r) => <span className="text-xs">{siteName(r.siteId)}</span> },
    { id: "ids", header: t("custom.ids"), mono: true, cell: (r) => <span className="text-xs">{r.ruleIds.join(", ")}</span> },
    { id: "hits", header: t("rules.hits"), align: "right", mono: true, sortValue: (r) => r.hits24h ?? 0, cell: (r) => formatNumber(r.hits24h ?? 0) },
    {
      id: "on",
      header: t("custom.state"),
      width: "100px",
      cell: (r) => <StatusBadge tone={r.enabled ? "success" : "neutral"}>{r.enabled ? t("custom.on") : t("custom.off")}</StatusBadge>,
    },
    { id: "author", header: t("common.author"), cell: (r) => <span className="text-xs">{r.createdBy}</span> },
  ];
  return (
    <>
      <PageHeader
        title={t("custom.title")}
        description={t("custom.description")}
        actions={
          can("editor") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setActive("new")}>
              {t("custom.new")}
            </Button>
          )
        }
      />
      <div className="grid gap-2.5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Panel title={t("custom.rules")} flush>
          <DataTable
            label={t("custom.rules")}
            columns={columns}
            rows={list}
            getRowId={(r) => r.id}
            onRowClick={(r) => setActive(r.id)}
            activeRowId={cur?.id}
            minWidth={560}
            empty={<p className="py-8">{t("custom.none")}</p>}
          />
        </Panel>
        {active && (
          <RuleEditor
            key={active}
            call={call}
            sites={sites}
            rule={cur}
            used={list.flatMap((r) => r.ruleIds)}
            onSaved={(id) => (after(), setActive(id))}
            onDeleted={() => (after(), setActive(undefined))}
          />
        )}
      </div>
    </>
  );
}

function RuleEditor({
  call,
  sites,
  rule,
  used,
  onSaved,
  onDeleted,
}: {
  call: Call;
  sites: Site[];
  rule?: Rule;
  used: number[];
  onSaved: (id: string) => void;
  onDeleted: () => void;
}) {
  const t = useT();
  const { can } = useAuth();
  const [name, setName] = useState(rule?.name ?? "");
  const [siteId, setSiteId] = useState(rule?.siteId ?? "");
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [seclang, setSeclang] = useState(rule?.seclang ?? "");
  const [checked, setChecked] = useState<string>();
  const [patch, setPatch] = useState({ path: "/", parameter: "", kind: "sqli" as PatchKind, label: "" });
  const [run, error, setError] = useAction(() => {});
  const editable = can("editor");
  const check = () =>
    run(async () => {
      const r = await call<{ ruleIds: number[] }>("/api/v1/rules/check", send("POST", { seclang }));
      setChecked(t("custom.checked", { ids: r.ruleIds.join(", ") }));
    });
  const save = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const body = { name, siteId: siteId || null, enabled, seclang };
      const saved = await call<Rule>(rule ? `/api/v1/rules/${rule.id}` : "/api/v1/rules", send(rule ? "PUT" : "POST", body));
      onSaved(saved.id);
    });
  };
  const generate = () => {
    try {
      setSeclang(virtualPatch({ ...patch, id: nextId(used) }));
      if (!name) setName(t("custom.patchName", { parameter: patch.parameter, path: patch.path }));
      setError(undefined);
    } catch {
      setError(t("custom.patchInvalid"));
    }
  };
  return (
    <Panel title={rule ? t("custom.edit") : t("custom.new")} description={rule?.name} aria-label={t("custom.edit")}>
      <form className="flex flex-col gap-2" onSubmit={save}>
        {!rule && editable && (
          <fieldset className="waf-fieldset">
            <legend className="text-xs font-medium">{t("custom.patch")}</legend>
            <p className="m-0 text-2xs text-fg-muted">{t("custom.patchDetail")}</p>
            <div className="waf-cols-2">
              <TextField label={t("custom.patchPath")} mono value={patch.path} onChange={(e) => setPatch({ ...patch, path: e.target.value })} />
              <TextField
                label={t("custom.patchParameter")}
                mono
                value={patch.parameter}
                onChange={(e) => setPatch({ ...patch, parameter: e.target.value })}
                error={patch.parameter && !PATCH_PARAMETER.test(patch.parameter) ? t("custom.patchInvalid") : undefined}
              />
              <SelectField
                label={t("custom.patchKind")}
                value={patch.kind}
                onChange={(e) => setPatch({ ...patch, kind: e.target.value as PatchKind })}
                options={PATCH_KINDS.map((k) => ({ value: k, label: t(`custom.kind.${k}`) }))}
              />
              <TextField
                label={t("custom.patchLabel")}
                value={patch.label}
                onChange={(e) => setPatch({ ...patch, label: e.target.value })}
                hint={t("custom.patchLabelHint")}
              />
            </div>
            <Button
              size="sm"
              type="button"
              icon={<ShieldCheck />}
              disabled={!PATCH_PATH.test(patch.path) || !PATCH_PARAMETER.test(patch.parameter)}
              onClick={generate}
            >
              {t("custom.patchWrite")}
            </Button>
          </fieldset>
        )}
        <div className="waf-cols-2">
          <TextField label={t("custom.name")} value={name} onChange={(e) => setName(e.target.value)} disabled={!editable} required />
          <SiteSelect sites={sites} value={siteId} onChange={setSiteId} />
        </div>
        <label className="flex flex-col gap-1 text-xs font-medium">
          {t("custom.seclang")}
          <textarea
            value={seclang}
            onChange={(e) => (setSeclang(e.target.value), setChecked(undefined))}
            rows={8}
            spellCheck={false}
            disabled={!editable}
            className="waf-textarea"
            placeholder={'SecRule ARGS:q "@detectSQLi" "id:1000001,phase:2,deny,status:403,log,msg:\'...\'"'}
          />
        </label>
        <p className="m-0 text-2xs text-fg-muted">{t("custom.seclangHint")}</p>
        <Switch checked={enabled} onCheckedChange={setEnabled} disabled={!editable} label={t("custom.enabled")} />
        {editable && (
          <div className="flex flex-wrap gap-1.5">
            <Button size="sm" type="button" onClick={() => void check()} disabled={!seclang.trim()}>
              {t("custom.check")}
            </Button>
            <Button size="sm" variant="primary" type="submit" disabled={!seclang.trim() || !name.trim()}>
              {t("form.save")}
            </Button>
            {rule && (
              <Button
                size="sm"
                variant="danger"
                type="button"
                icon={<Trash2 />}
                onClick={() => void run(() => call(`/api/v1/rules/${rule.id}`, send("DELETE")).then(onDeleted))}
              >
                {t("form.delete")}
              </Button>
            )}
          </div>
        )}
        {checked && !error && (
          <p role="status" className="m-0 text-xs text-success">
            {checked}
          </p>
        )}
        <ErrorText message={error} />
      </form>
    </Panel>
  );
}

// ---------------------------------------------------------------- Sites

function SitesPage({ call, sites, reload }: { call: Call; sites: Site[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [editing, setEditing] = useState<Site | "new">();
  const [removing, setRemoving] = useState<Site>();
  const [blocking, setBlocking] = useState<Site>();
  const [week, setWeek] = useState<Record<string, Traffic["totals"]>>({});
  const [run, error] = useAction(reload);
  const [exclusions] = useLoad<{ exclusions: Exclusion[] }>(call, "/api/v1/exclusions");
  useEffect(() => {
    let live = true;
    void Promise.all(sites.map((s) => call<Traffic>(`/api/v1/traffic?range=7d&siteId=${s.id}`).then((r) => [s.id, r.totals] as const))).then(
      (all) => live && setWeek(Object.fromEntries(all)),
      () => {},
    );
    return () => {
      live = false;
    };
  }, [call, sites]);
  const setMode = (s: Site, mode: Mode) => run(() => call(`/api/v1/sites/${s.id}`, send("PUT", { mode })));
  const detecting = sites.filter((s) => s.mode === "detection");
  const columns: Column<Site>[] = [
    {
      id: "name",
      header: t("sites.site"),
      sortValue: (s) => s.name,
      cell: (s) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-medium">{s.name}</span>
          <span className="waf-wrap font-mono text-2xs text-fg-muted">{s.hosts.join(", ")}</span>
        </span>
      ),
    },
    { id: "upstream", header: t("sites.upstream"), cell: (s) => <span className="waf-wrap font-mono text-xs">{s.upstream}</span> },
    {
      id: "requests",
      header: t("sites.requests"),
      align: "right",
      mono: true,
      sortValue: (s) => week[s.id]?.requests ?? 0,
      cell: (s) => formatNumber(week[s.id]?.requests ?? 0),
    },
    {
      id: "matched",
      header: t("sites.matched"),
      align: "right",
      mono: true,
      description: t("sites.matchedHint"),
      sortValue: (s) => (week[s.id]?.blocked ?? 0) + (week[s.id]?.detected ?? 0),
      cell: (s) => formatNumber((week[s.id]?.blocked ?? 0) + (week[s.id]?.detected ?? 0)),
    },
    { id: "pl", header: t("sites.paranoia"), mono: true, width: "70px", cell: (s) => `PL${s.paranoia}` },
    {
      id: "excl",
      header: t("sites.exclusions"),
      align: "right",
      mono: true,
      cell: (s) => exclusions?.exclusions.filter((e) => e.siteId === s.id).length ?? "–",
    },
    {
      id: "mode",
      header: t("sites.mode"),
      width: "190px",
      cell: (s) =>
        can("admin") ? (
          <SegmentedControl
            label={t("sites.modeFor", { name: s.name })}
            value={s.mode}
            onChange={(m) => (m === "blocking" ? setBlocking(s) : void setMode(s, m))}
            options={[
              { value: "detection", label: t("mode.detect") },
              { value: "blocking", label: t("mode.block") },
            ]}
          />
        ) : (
          <ModeBadge mode={s.mode} />
        ),
    },
    ...(can("admin")
      ? [
          {
            id: "actions",
            header: "",
            width: "90px",
            align: "right" as const,
            hideable: false,
            cell: (s: Site) => (
              <span className="flex justify-end gap-1">
                <IconButton label={t("sites.edit", { name: s.name })} size="sm" variant="ghost" onClick={() => setEditing(s)}>
                  <Pencil />
                </IconButton>
                <IconButton label={t("sites.delete", { name: s.name })} size="sm" variant="ghost" onClick={() => setRemoving(s)}>
                  <Trash2 />
                </IconButton>
              </span>
            ),
          },
        ]
      : []),
  ];
  return (
    <>
      <PageHeader
        title={t("sites.title")}
        description={t("sites.description")}
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setEditing("new")}>
              {t("sites.add")}
            </Button>
          )
        }
      />
      {detecting.map((s) => {
        const n = week[s.id]?.detected ?? 0;
        return (
          <Callout key={s.id} tone="warning" title={t("sites.detecting", { name: s.name })}>
            {t("sites.detectingDetail", { count: n })}
          </Callout>
        );
      })}
      <ErrorText message={error} />
      {sites.length ? (
        <Panel title={t("sites.title")} flush>
          <DataTable label={t("sites.title")} columns={columns} rows={sites} getRowId={(s) => s.id} minWidth={1000} />
        </Panel>
      ) : (
        <EmptyState title={t("sites.none")} icon={<Globe />}>
          {t("sites.noneDetail")}
        </EmptyState>
      )}
      <Panel title={t("sites.howTitle")}>
        <p className="m-0 text-xs">{t("sites.how")}</p>
      </Panel>
      {editing && <SiteDialog call={call} site={editing === "new" ? undefined : editing} onClose={() => setEditing(undefined)} onSaved={reload} />}
      <Dialog
        open={!!blocking}
        onOpenChange={(o) => !o && setBlocking(undefined)}
        title={t("sites.blockTitle", { name: blocking?.name ?? "" })}
        description={t("sites.blockDetail", { count: blocking ? (week[blocking.id]?.detected ?? 0) : 0 })}
        iconTone="warning"
        icon={<ShieldCheck />}
        footer={
          <>
            <Button onClick={() => setBlocking(undefined)}>{t("form.cancel")}</Button>
            <Button variant="primary" onClick={() => blocking && void setMode(blocking, "blocking").then(() => setBlocking(undefined))}>
              {t("sites.blockConfirm")}
            </Button>
          </>
        }
      />
      <Dialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(undefined)}
        title={t("sites.deleteTitle", { name: removing?.name ?? "" })}
        description={t("sites.deleteDetail")}
        footer={
          <>
            <Button onClick={() => setRemoving(undefined)}>{t("form.cancel")}</Button>
            <Button
              variant="danger"
              onClick={() => removing && void run(() => call(`/api/v1/sites/${removing.id}`, send("DELETE"))).then(() => setRemoving(undefined))}
            >
              {t("form.delete")}
            </Button>
          </>
        }
      />
    </>
  );
}

function SiteDialog({ call, site, onClose, onSaved }: { call: Call; site?: Site; onClose: () => void; onSaved: () => void }) {
  const t = useT();
  const [name, setName] = useState(site?.name ?? "");
  const [hosts, setHosts] = useState(site?.hosts.join(", ") ?? "");
  const [upstream, setUpstream] = useState(site?.upstream ?? "");
  const [run, error] = useAction(() => (onSaved(), onClose()));
  const save = (e: FormEvent) => {
    e.preventDefault();
    const body = {
      name,
      upstream,
      hosts: hosts
        .split(/[\s,]+/)
        .map((h) => h.trim())
        .filter(Boolean),
    };
    void run(() => call(site ? `/api/v1/sites/${site.id}` : "/api/v1/sites", send(site ? "PUT" : "POST", body)));
  };
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={site ? t("sites.editTitle", { name: site.name }) : t("sites.add")}
      description={site ? undefined : t("sites.addDetail")}
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {t("form.cancel")}
          </Button>
          <Button variant="primary" type="submit">
            {t("form.save")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-2">
        <TextField label={t("sites.name")} value={name} onChange={(e) => setName(e.target.value)} required />
        <TextField label={t("sites.hosts")} hint={t("sites.hostsHint")} mono value={hosts} onChange={(e) => setHosts(e.target.value)} required />
        <TextField label={t("sites.upstream")} hint={t("sites.upstreamHint")} mono value={upstream} onChange={(e) => setUpstream(e.target.value)} required />
        <ErrorText message={error} />
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------- Exclusions

function ExclusionsPage({ call, sites, reload }: { call: Call; sites: Site[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [siteId, setSiteId] = useState("");
  const [list, load] = useLoad<{ exclusions: Exclusion[] }>(call, `/api/v1/exclusions${siteId ? `?siteId=${siteId}` : ""}`);
  const [adding, setAdding] = useState<Partial<Exclusion>>();
  const after = useCallback(() => (load(), reload()), [load, reload]);
  const [run, error] = useAction(after);
  const name = (id: string) => sites.find((s) => s.id === id)?.name ?? id;
  const columns: Column<Exclusion>[] = [
    { id: "rule", header: t("events.rule"), mono: true, width: "130px", sortValue: (e) => e.ruleId, cell: (e) => e.ruleId },
    { id: "site", header: t("common.site"), sortValue: (e) => name(e.siteId), cell: (e) => <span className="text-xs">{name(e.siteId)}</span> },
    {
      id: "target",
      header: t("exclusions.appliesTo"),
      width: "28%",
      cell: (e) => (
        <span className="waf-wrap font-mono text-xs">
          {e.target ?? t("exclusions.wholeRule")} {e.path ? t("exclusions.under", { path: e.path }) : t("exclusions.everywhere")}
        </span>
      ),
    },
    { id: "reason", header: t("exclusions.reason"), width: "26%", cell: (e) => <span className="text-xs">{e.reason}</span> },
    { id: "author", header: t("common.author"), cell: (e) => <span className="text-xs">{e.createdBy}</span> },
    { id: "created", header: t("exclusions.created"), sortValue: (e) => e.createdAt, cell: (e) => <span className="text-xs">{when(e.createdAt)}</span> },
    ...(can("editor")
      ? [
          {
            id: "act",
            header: "",
            width: "90px",
            hideable: false,
            cell: (e: Exclusion) => (
              <Button
                size="xs"
                variant="ghost"
                aria-label={t("exclusions.remove", { rule: e.ruleId, site: name(e.siteId) })}
                onClick={() => void run(() => call(`/api/v1/exclusions/${e.id}`, send("DELETE")))}
              >
                {t("exclusions.removeShort")}
              </Button>
            ),
          },
        ]
      : []),
  ];
  return (
    <>
      <PageHeader
        title={t("exclusions.title")}
        description={t("exclusions.description")}
        actions={
          can("editor") &&
          sites.length > 0 && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding({ siteId: siteId || sites[0]!.id })}>
              {t("exclusions.new")}
            </Button>
          )
        }
      />
      <FilterBar onClear={siteId ? () => setSiteId("") : undefined}>
        <SiteSelect sites={sites} value={siteId} onChange={setSiteId} />
      </FilterBar>
      <ErrorText message={error} />
      <Panel title={t("exclusions.title")} description={t("blocked.shown", { count: list?.exclusions.length ?? 0 })} flush>
        <DataTable
          label={t("exclusions.title")}
          columns={columns}
          rows={list?.exclusions ?? []}
          getRowId={(e) => e.id}
          minWidth={1000}
          empty={<p className="py-8">{t("exclusions.none")}</p>}
        />
      </Panel>
      {adding && <ExclusionDialog call={call} sites={sites} initial={adding} onClose={() => setAdding(undefined)} onSaved={after} />}
    </>
  );
}

function ExclusionDialog({
  call,
  sites,
  initial,
  onClose,
  onSaved,
}: {
  call: Call;
  sites: Site[];
  initial: Partial<Exclusion>;
  onClose: () => void;
  onSaved: () => void;
}) {
  const t = useT();
  const [siteId, setSiteId] = useState(initial.siteId ?? sites[0]?.id ?? "");
  const [ruleId, setRuleId] = useState(initial.ruleId ?? "");
  const [target, setTarget] = useState(initial.target ?? "");
  const [path, setPath] = useState(initial.path ?? "");
  const [reason, setReason] = useState(initial.reason ?? "");
  const [run, error] = useAction(() => (onSaved(), onClose()));
  const save = (e: FormEvent) => {
    e.preventDefault();
    void run(() => call("/api/v1/exclusions", send("POST", { siteId, ruleId, target: target || null, path: path || null, reason })));
  };
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={t("exclusions.new")}
      description={t("exclusions.newDetail")}
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {t("form.cancel")}
          </Button>
          <Button variant="primary" type="submit">
            {t("form.save")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-2">
        <SiteSelect sites={sites} value={siteId} onChange={setSiteId} all={false} />
        <TextField label={t("exclusions.rule")} hint={t("exclusions.ruleHint")} mono value={ruleId} onChange={(e) => setRuleId(e.target.value)} required />
        <TextField label={t("exclusions.target")} hint={t("exclusions.targetHint")} mono value={target} onChange={(e) => setTarget(e.target.value)} />
        <TextField label={t("exclusions.path")} hint={t("exclusions.pathHint")} mono value={path} onChange={(e) => setPath(e.target.value)} />
        <TextField label={t("exclusions.reason")} hint={t("exclusions.reasonHint")} value={reason} onChange={(e) => setReason(e.target.value)} required />
        <ErrorText message={error} />
      </div>
    </Dialog>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

/** Shown above every page while the proxy is not serving the rules last saved. */
function Attention({ summary }: { summary: Summary }) {
  const t = useT();
  if (!summary.engine.running)
    return (
      <Callout tone="danger" title={t("attention.down")}>
        {t("attention.downDetail")}
      </Callout>
    );
  if (!summary.engine.loaded && summary.engine.lastError)
    return (
      <Callout tone="warning" title={t("attention.notLoaded")}>
        <span className="waf-wrap font-mono text-xs">{summary.engine.lastError}</span>
      </Callout>
    );
  if (summary.events.dropped > 0)
    return (
      <Callout tone="info" title={t("attention.dropped", { count: summary.events.dropped })}>
        {t("attention.droppedDetail")}
      </Callout>
    );
  return null;
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const page = parsePage(usePath());
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const [summary, reloadSummary] = useLoad<Summary>(call, "/api/v1/summary", 15);
  const [siteList, reloadSites] = useLoad<{ sites: Site[] }>(call, "/api/v1/sites", 60);
  const reload = useCallback(() => (reloadSummary(), reloadSites()), [reloadSummary, reloadSites]);
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "waf" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const sites = siteList?.sites;
  const nav = [
    { id: "traffic", label: msg("product.traffic"), icon: Activity },
    { id: "blocked", label: msg("product.blocked"), icon: Ban, count: summary?.day.blocked ? formatNumber(summary.day.blocked) : undefined },
    { id: "rules", label: msg("product.rules"), icon: BookOpen },
    { id: "custom", label: msg("product.custom"), icon: FileCode2, count: summary?.rules || undefined },
    { id: "sites", label: msg("product.sites"), icon: Globe, count: summary?.sites.total || undefined },
    { id: "exclusions", label: msg("product.exclusions"), icon: ListX, count: summary?.exclusions || undefined },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = page === "account" || page === "members" || page === "signin" || page === "tokens";

  return (
    <AppShell
      product="waf"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={page}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={page as "account" | "members" | "signin" | "tokens"} />
      ) : !summary || !sites ? (
        <EmptyState title={msg("product.loading")} icon={<ShieldCheck />}>
          {msg("product.reading")}
        </EmptyState>
      ) : (
        <>
          <Attention summary={summary} />
          {page === "blocked" ? (
            <BlockedPage key={window.location.search} call={call} sites={sites} reload={reload} />
          ) : page === "rules" ? (
            <RulesPage call={call} sites={sites} reload={reload} />
          ) : page === "custom" ? (
            <CustomRulesPage call={call} sites={sites} reload={reload} />
          ) : page === "sites" ? (
            <SitesPage call={call} sites={sites} reload={reload} />
          ) : page === "exclusions" ? (
            <ExclusionsPage call={call} sites={sites} reload={reload} />
          ) : (
            <TrafficPage call={call} sites={sites} summary={summary} />
          )}
        </>
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy WAF">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
