// Writes openapi.json (ADR 0014, 0024). Run `node scripts/openapi.ts` after changing the API; a test fails when the
// file is out of date. Sign-in routes come from @openasy/auth and are merged in when the description is served.
import { writeFileSync } from "node:fs";

type S = Record<string, unknown>;
const ref = (n: string) => ({ $ref: `#/components/schemas/${n}` });
const str = { type: "string" };
const int = { type: "integer" };
const bool = { type: "boolean" };
const dt = { type: "string", format: "date-time" };
const nul = (s: S) => ({ anyOf: [s, { type: "null" }] });
const arr = (s: S) => ({ type: "array", items: s });
const obj = (properties: Record<string, S>, required = Object.keys(properties)) => ({ type: "object", required, properties });

const problem = { $ref: "#/components/responses/Problem" };
const ok = (schema: S, description = "OK") => ({ description, content: { "application/json": { schema } } });
const VIEWER = [{ session: [] }, { apiToken: [] }, { adminToken: [] }];
const id = (what: string) => [{ name: "id", in: "path", required: true, description: `The ${what}'s id.`, schema: str }];
const query = (name: string, description: string, schema: S = str) => ({ name, in: "query", required: false, description, schema });
const RANGE = query("range", "How far back. 24h when left out.", { type: "string", enum: ["1h", "24h", "7d", "30d"] });
const SITE = query("siteId", "Only this site.");

/** An operation that needs a role (ADR 0003), with the refusals every such operation can answer. */
function op(role: "viewer" | "editor" | "admin", o: S & { responses: Record<string, unknown> }) {
  return {
    ...o,
    security: VIEWER,
    "x-openasy-role": role,
    description: [`Needs the ${role} role.`, o.description].filter(Boolean).join(" "),
    responses: { ...o.responses, "401": problem, "403": problem },
  };
}
const body = (schema: S) => ({ required: true, content: { "application/json": { schema } } });

const COUNTS = obj({ requests: int, blocked: int, detected: int, logged: int, upstreamErrors: int });
const ACTION = {
  type: "string",
  enum: ["blocked", "detected", "logged"],
  description: "blocked; detected: it would have been blocked, the site is in detection-only mode; logged: a rule matched below the threshold.",
};
const SITE_FIELDS = {
  name: { type: "string", minLength: 1, maxLength: 100 },
  hosts: {
    ...arr(str),
    minItems: 1,
    maxItems: 50,
    description: "Host names without the port, each on one site only. `*` takes every host no other site names.",
    examples: [["shop.example.com", "www.shop.example.com"]],
  },
  upstream: { type: "string", format: "uri", description: "The application, http:// or https://, without a user or password.", examples: ["http://shop:3000"] },
  mode: {
    type: "string",
    enum: ["detection", "blocking"],
    default: "detection",
    description: "detection: rules match and are reported, nothing is refused. New sites start here.",
  },
  paranoia: {
    type: "integer",
    minimum: 1,
    maximum: 4,
    default: 1,
    description: "The rule set's paranoia level: higher catches more and blocks more real users.",
  },
  inboundThreshold: {
    type: "integer",
    minimum: 1,
    maximum: 1000,
    default: 5,
    description: "The anomaly score at which a request is blocked. 5 is one critical match.",
  },
  disabledGroups: {
    ...arr({ type: "string", enum: ["911", "913", "920", "921", "922", "930", "931", "932", "933", "934", "941", "942", "943", "944"] }),
    description: "Groups of the rule set turned off, for a stack the site does not run, such as 933 for PHP.",
  },
};

const schemas: Record<string, S> = {
  Problem: obj(
    {
      type: { type: "string", format: "uri" },
      title: str,
      status: int,
      code: {
        type: "string",
        enum: [
          "invalid-token",
          "invalid-json",
          "invalid-body",
          "conflict",
          "not-found",
          "engine-unavailable",
          "internal-error",
          "unauthenticated",
          "invalid-credentials",
          "mfa-required",
          "mfa-setup-required",
          "forbidden",
          "cross-site",
          "rate-limited",
        ],
        description: "Stable; match on this.",
      },
      detail: str,
    },
    ["type", "title", "status", "code"],
  ),
  Status: obj({ status: str }),
  Version: obj({ product: { const: "waf" }, version: str }),
  ProductLink: obj({
    id: { type: "string", description: "The product, as OpenAsy names it.", examples: ["dast"] },
    url: { type: "string", format: "uri", description: "The address people open it at.", examples: ["https://dast.example.com"] },
  }),
  ProductList: obj({ products: arr(ref("ProductLink")) }),
  Summary: obj({
    engine: obj({
      running: { type: "boolean", description: "The proxy, Coraza with the Core Rule Set, is running." },
      loaded: { type: "boolean", description: "It serves the rules last saved." },
      loadedAt: nul(dt),
      lastError: { ...nul(str), description: "Why it did not take the last rules, or stopped." },
      restarts: int,
      coraza: nul(str),
      crs: nul(str),
    }),
    sites: obj({ total: int, detection: int, blocking: int }),
    rules: int,
    exclusions: int,
    day: { ...COUNTS, description: "Requests in the last 24 hours." },
    events: obj({ stored: int, dropped: { type: "integer", description: "Reports of matched requests not kept, because more came than could be written." } }),
  }),
  Site: obj({ id: str, ...SITE_FIELDS, createdBy: str, createdAt: dt, updatedAt: dt }),
  SiteList: obj({ sites: arr(ref("Site")) }),
  NewSite: obj(SITE_FIELDS, ["name", "hosts", "upstream"]),
  SiteChange: { ...obj(SITE_FIELDS, []), description: "What it names changes; the rest stays." },
  Exclusion: obj({
    id: str,
    siteId: str,
    ruleId: { type: "string", description: "A rule's id or a range of ids.", examples: ["942100", "942000-942999"] },
    target: { ...nul(str), description: "Only this part of the request, such as ARGS:filter; null for the whole rule." },
    path: { ...nul(str), description: "Only under this path; null for the whole site." },
    reason: str,
    createdBy: str,
    createdAt: dt,
  }),
  ExclusionList: obj({ exclusions: arr(ref("Exclusion")) }),
  NewExclusion: obj(
    {
      siteId: str,
      ruleId: { anyOf: [{ type: "string", pattern: "^\\d{3,7}(-\\d{3,7})?$" }, { type: "integer" }] },
      target: {
        ...nul(str),
        description:
          "ARGS, ARGS_GET, ARGS_POST, REQUEST_COOKIES, REQUEST_HEADERS, REQUEST_FILENAME and the like, with a :name. Only with one ruleId, not a range.",
      },
      path: { ...nul({ type: "string", pattern: "^/" }), description: "A path prefix, such as /v1/reports." },
      reason: { type: "string", minLength: 1, maxLength: 500 },
    },
    ["siteId", "ruleId", "reason"],
  ),
  Rule: obj(
    {
      id: str,
      siteId: { ...nul(str), description: "null: every site." },
      name: str,
      seclang: str,
      ruleIds: arr(int),
      disruptive: { ...arr(int), description: "Of its rules, the ones that refuse a request (deny or drop)." },
      enabled: bool,
      createdBy: str,
      createdAt: dt,
      updatedAt: dt,
      hits24h: { type: "integer", description: "Requests its rules matched in the last 24 hours. In lists only." },
    },
    ["id", "siteId", "name", "seclang", "ruleIds", "disruptive", "enabled", "createdBy", "createdAt", "updatedAt"],
  ),
  RuleList: obj({ rules: arr(ref("Rule")) }),
  NewRule: obj(
    {
      name: { type: "string", minLength: 1, maxLength: 200 },
      siteId: { ...nul(str), description: "Leave out or null for every site." },
      seclang: {
        type: "string",
        maxLength: 16384,
        description:
          "SecRule and SecAction only, with ids from 1000000 to 1999999, in phase 1 or 2. Operators that read files, look up DNS or run scripts, and the actions ctl, exec, setenv, allow and redirect are refused.",
        examples: ['SecRule ARGS:q "@detectSQLi" "id:1000318,phase:2,deny,status:403,log,msg:\'Virtual patch: SQL injection in q\'"'],
      },
      enabled: { type: "boolean", default: true },
    },
    ["name", "seclang"],
  ),
  RuleChange: { ...obj({ name: str, siteId: nul(str), seclang: str, enabled: bool }, []), description: "What it names changes; the rest stays." },
  RuleCheck: obj({ seclang: str }),
  RuleChecked: obj({ ruleIds: arr(int), disruptive: arr(int) }),
  CrsRule: obj({
    id: int,
    group: str,
    message: str,
    severity: str,
    paranoia: { type: "integer", description: "The level from which it runs." },
    tags: arr(str),
    hits24h: int,
  }),
  Crs: obj({
    coraza: str,
    crs: str,
    groups: arr(
      obj({
        id: str,
        name: str,
        rules: int,
        byParanoia: { ...arr(int), description: "Rules from paranoia level 1, 2, 3 and 4." },
        hits24h: int,
      }),
    ),
    rules: arr(ref("CrsRule")),
  }),
  Match: obj({
    id: int,
    message: str,
    severity: str,
    tags: arr(str),
    variable: { type: "string", examples: ["ARGS:q"] },
    value: { type: "string", description: "What matched; for a parameter that names a secret, only its length." },
    data: str,
  }),
  Event: obj({
    id: { type: "string", description: "The reference a blocked client was shown." },
    siteId: str,
    time: dt,
    clientIp: str,
    method: str,
    host: str,
    path: str,
    query: { type: "string", description: "Values of parameters that name a secret are left out." },
    userAgent: str,
    action: ACTION,
    score: { type: "integer", description: "The rule set's inbound anomaly score." },
    threshold: int,
    status: { type: "integer", description: "What the client got." },
    ruleId: { ...nul(int), description: "The rule that weighed most." },
    message: str,
    attack: { type: "string", description: "sqli, xss, lfi, rce, protocol, ... from the rule's tags; custom for rules of your own." },
    matches: arr(ref("Match")),
  }),
  EventList: obj({ events: arr(ref("Event")), next: { ...nul(str), description: "Pass as cursor for the next page." } }),
  Traffic: obj({
    range: str,
    bucketSeconds: int,
    buckets: arr({ ...COUNTS, required: [...COUNTS.required, "time"], properties: { ...COUNTS.properties, time: dt } }),
    totals: COUNTS,
    attacks: arr(obj({ attack: str, count: int })),
    rules: arr(obj({ ruleId: int, count: int, message: str })),
    clients: arr(obj({ clientIp: str, count: int })),
  }),
};

const spec = {
  openapi: "3.1.0",
  info: {
    title: "OpenAsy WAF API",
    version: "0.1.0",
    description:
      "Sites behind the web application firewall, the OWASP Core Rule Set they run in Coraza, exclusions, custom rules, and the requests the rules matched (ADR 0069).",
    license: { name: "AGPL-3.0-only", identifier: "AGPL-3.0-only" },
  },
  tags: [
    { name: "Sites", description: "Host names, upstreams, mode and how the rule set runs." },
    { name: "Tuning", description: "Exclusions for false positives and rules of your own." },
    { name: "Events", description: "Requests the rules matched, and every request counted." },
    { name: "Product" },
  ],
  paths: {
    "/api/v1/sites": {
      get: op("viewer", { operationId: "listSites", tags: ["Sites"], summary: "Sites", responses: { "200": ok(ref("SiteList")) } }),
      post: op("admin", {
        operationId: "createSite",
        tags: ["Sites"],
        summary: "Add a site",
        description: "It starts in detection-only mode unless mode says otherwise, and is served at once.",
        requestBody: body(ref("NewSite")),
        responses: { "201": ok(ref("Site"), "Added."), "400": problem, "409": problem, "422": problem, "503": problem },
      }),
    },
    "/api/v1/sites/{id}": {
      get: op("viewer", {
        operationId: "getSite",
        tags: ["Sites"],
        summary: "A site",
        parameters: id("site"),
        responses: { "200": ok(ref("Site")), "404": problem },
      }),
      put: op("admin", {
        operationId: "updateSite",
        tags: ["Sites"],
        summary: "Change a site",
        description: "Such as turning blocking on. It takes effect at once.",
        parameters: id("site"),
        requestBody: body(ref("SiteChange")),
        responses: { "200": ok(ref("Site")), "400": problem, "404": problem, "409": problem, "422": problem, "503": problem },
      }),
      delete: op("admin", {
        operationId: "deleteSite",
        tags: ["Sites"],
        summary: "Delete a site",
        description: "Its host names are no longer served; its exclusions and rules go, its events stay until the retention.",
        parameters: id("site"),
        responses: { "204": { description: "Deleted." }, "404": problem, "503": problem },
      }),
    },
    "/api/v1/exclusions": {
      get: op("viewer", {
        operationId: "listExclusions",
        tags: ["Tuning"],
        summary: "Exclusions",
        parameters: [SITE],
        responses: { "200": ok(ref("ExclusionList")), "404": problem },
      }),
      post: op("editor", {
        operationId: "createExclusion",
        tags: ["Tuning"],
        summary: "Add an exclusion",
        description: "For a false positive: a rule, or one target of it, left out on a site, everywhere or under a path.",
        requestBody: body(ref("NewExclusion")),
        responses: { "201": ok(ref("Exclusion"), "Added."), "400": problem, "409": problem, "422": problem, "503": problem },
      }),
    },
    "/api/v1/exclusions/{id}": {
      delete: op("editor", {
        operationId: "deleteExclusion",
        tags: ["Tuning"],
        summary: "Delete an exclusion",
        parameters: id("exclusion"),
        responses: { "204": { description: "Deleted." }, "404": problem, "503": problem },
      }),
    },
    "/api/v1/rules": {
      get: op("viewer", { operationId: "listRules", tags: ["Tuning"], summary: "Custom rules", responses: { "200": ok(ref("RuleList")) } }),
      post: op("editor", {
        operationId: "createRule",
        tags: ["Tuning"],
        summary: "Add a custom rule",
        description: "Checked, compiled by Coraza, then served at once, after the rule set.",
        requestBody: body(ref("NewRule")),
        responses: { "201": ok(ref("Rule"), "Added."), "400": problem, "409": problem, "422": problem, "503": problem },
      }),
    },
    "/api/v1/rules/check": {
      post: op("editor", {
        operationId: "checkRule",
        tags: ["Tuning"],
        summary: "Check a custom rule",
        description: "Checks and compiles SecLang without keeping it.",
        requestBody: body(ref("RuleCheck")),
        responses: { "200": ok(ref("RuleChecked")), "400": problem, "422": problem, "503": problem },
      }),
    },
    "/api/v1/rules/{id}": {
      get: op("viewer", {
        operationId: "getRule",
        tags: ["Tuning"],
        summary: "A custom rule",
        parameters: id("rule"),
        responses: { "200": ok(ref("Rule")), "404": problem },
      }),
      put: op("editor", {
        operationId: "updateRule",
        tags: ["Tuning"],
        summary: "Change a custom rule",
        parameters: id("rule"),
        requestBody: body(ref("RuleChange")),
        responses: { "200": ok(ref("Rule")), "400": problem, "404": problem, "409": problem, "422": problem, "503": problem },
      }),
      delete: op("editor", {
        operationId: "deleteRule",
        tags: ["Tuning"],
        summary: "Delete a custom rule",
        parameters: id("rule"),
        responses: { "204": { description: "Deleted." }, "404": problem, "503": problem },
      }),
    },
    "/api/v1/crs": {
      get: op("viewer", {
        operationId: "getRuleSet",
        tags: ["Tuning"],
        summary: "The Core Rule Set",
        description: "Its request rules as Coraza compiled them, by group and paranoia level, with how often each matched in the last 24 hours.",
        parameters: [SITE],
        responses: { "200": ok(ref("Crs")), "404": problem, "503": problem },
      }),
    },
    "/api/v1/events": {
      get: op("viewer", {
        operationId: "listEvents",
        tags: ["Events"],
        summary: "Requests the rules matched",
        description: "Newest first.",
        parameters: [
          SITE,
          query("action", "One or more of blocked, detected and logged, separated by commas."),
          query("q", "Part of the client address, path, query or message, a rule id or an event id."),
          RANGE,
          query("cursor", "From next of the page before."),
          query("limit", "At most this many, 1 to 500. 100 when left out.", { type: "integer", minimum: 1, maximum: 500 }),
        ],
        responses: { "200": ok(ref("EventList")), "404": problem, "422": problem },
      }),
    },
    "/api/v1/events/{id}": {
      get: op("viewer", {
        operationId: "getEvent",
        tags: ["Events"],
        summary: "A request the rules matched",
        description: "By the reference the blocked client was shown.",
        parameters: id("event"),
        responses: { "200": ok(ref("Event")), "404": problem },
      }),
    },
    "/api/v1/traffic": {
      get: op("viewer", {
        operationId: "getTraffic",
        tags: ["Events"],
        summary: "Traffic",
        description: "Every request over the range in buckets, with the attacks, rules and clients matched most.",
        parameters: [RANGE, SITE],
        responses: { "200": ok(ref("Traffic")), "404": problem, "422": problem },
      }),
    },
    "/api/v1/summary": {
      get: op("viewer", {
        operationId: "getSummary",
        tags: ["Product"],
        summary: "Overview",
        description: "The proxy's state, the sites by mode and the last 24 hours.",
        responses: { "200": ok(ref("Summary")) },
      }),
    },
    "/api/v1/products": {
      get: op("viewer", {
        operationId: "listProducts",
        tags: ["Product"],
        summary: "Other products of this install",
        responses: { "200": ok(ref("ProductList"), "From OPENASY_PRODUCTS, for the product switcher.") },
      }),
    },
    "/api/v1/version": {
      get: { operationId: "getVersion", tags: ["Product"], summary: "Version", security: [], responses: { "200": ok(ref("Version"), "The running version.") } },
    },
    "/healthz": {
      get: {
        operationId: "liveness",
        tags: ["Product"],
        summary: "Liveness",
        security: [],
        responses: { "200": ok(ref("Status"), "The process is running.") },
      },
    },
    "/readyz": {
      get: {
        operationId: "readiness",
        tags: ["Product"],
        summary: "Readiness",
        description: "Ready while the database answers and the proxy serves the rules last saved.",
        security: [],
        responses: { "200": ok(ref("Status"), "Ready to serve."), "503": ok(ref("Status"), "The database or the proxy is unavailable.") },
      },
    },
    "/metrics": {
      get: {
        operationId: "metrics",
        tags: ["Product"],
        summary: "Prometheus metrics",
        security: [],
        responses: { "200": { description: "Metrics in the Prometheus text format.", content: { "text/plain": { schema: str } } } },
      },
    },
  },
  components: {
    securitySchemes: {
      session: {
        type: "apiKey",
        in: "cookie",
        name: "__Host-openasy-session",
        description:
          "The browser session after signing in (`openasy-session` when WAF runs on plain http://localhost). Requests that change something must come from the WAF origin.",
      },
      apiToken: {
        type: "http",
        scheme: "bearer",
        description: "An API token created under Settings → API tokens (`oa_waf_...`): one role, always an expiry (ADR 0003).",
      },
      adminToken: {
        type: "http",
        scheme: "bearer",
        description: "Only when WAF is started by its tests or a local script: one shared token with the admin role. A production install does not have it.",
      },
    },
    responses: { Problem: { description: "An error, as RFC 9457 Problem Details.", content: { "application/problem+json": { schema: ref("Problem") } } } },
    schemas,
  },
};

export const OPENAPI = spec;
if (import.meta.url === `file://${process.argv[1]}`) writeFileSync(new URL("../openapi.json", import.meta.url), JSON.stringify(spec, null, 2) + "\n");
