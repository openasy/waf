// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Mode = "detection" | "blocking";
export type Action = "blocked" | "detected" | "logged";
export const RANGES = ["1h", "24h", "7d", "30d"] as const;
export type Range = (typeof RANGES)[number];

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Site {
  id: string;
  name: string;
  hosts: string[];
  upstream: string;
  mode: Mode;
  paranoia: number;
  inboundThreshold: number;
  disabledGroups: string[];
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface Exclusion {
  id: string;
  siteId: string;
  ruleId: string;
  target: string | null;
  path: string | null;
  reason: string;
  createdBy: string;
  createdAt: string;
}

export interface Rule {
  id: string;
  siteId: string | null;
  name: string;
  seclang: string;
  ruleIds: number[];
  disruptive: number[];
  enabled: boolean;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  hits24h?: number;
}

export interface Match {
  id: number;
  message: string;
  severity: string;
  tags: string[];
  variable: string;
  value: string;
  data: string;
}

export interface WafEvent {
  id: string;
  siteId: string;
  time: string;
  clientIp: string;
  method: string;
  host: string;
  path: string;
  query: string;
  userAgent: string;
  action: Action;
  score: number;
  threshold: number;
  status: number;
  ruleId: number | null;
  message: string;
  attack: string;
  matches: Match[];
}

export interface Counts {
  requests: number;
  blocked: number;
  detected: number;
  logged: number;
  upstreamErrors: number;
}

export interface Traffic {
  range: Range;
  bucketSeconds: number;
  buckets: Array<Counts & { time: string }>;
  totals: Counts;
  attacks: Array<{ attack: string; count: number }>;
  rules: Array<{ ruleId: number; count: number; message: string }>;
  clients: Array<{ clientIp: string; count: number }>;
}

export interface CrsRule {
  id: number;
  group: string;
  message: string;
  severity: string;
  paranoia: number;
  tags: string[];
  hits24h: number;
}

export interface Crs {
  coraza: string;
  crs: string;
  groups: Array<{ id: string; name: string; rules: number; byParanoia: number[]; hits24h: number }>;
  rules: CrsRule[];
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
  day: Counts;
  events: { stored: number; dropped: number };
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
