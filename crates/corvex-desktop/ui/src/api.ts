// Typed wrappers around the Tauri command + event bus.
//
// Keeping every invoke/listen call in one file means the rest of the UI
// sees only plain promises and callback registrations — no direct
// Tauri API imports scattered across components.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface PluginSummary {
  name: string;
  full_name: string;
  description: string;
  weight: number;
  default: boolean;
  extra: boolean;
  hooks: string[];
}

export interface DbSummary {
  summary: string;
  tests: number;
  outdated: number;
  favicon: number;
  server_msgs: number;
  realms: number;
  variables: number;
  content_search: number;
  headers_common: number;
  headers_suggested: number;
  multiple_index: number;
  options: number;
  useragents: number;
  dictionary: number;
  fourohfour: number;
}

export interface VersionInfo {
  product: string;
  version: string;
}

export interface ScanParams {
  host: string;
  ports?: string;
  ssl?: boolean;
  nossl?: boolean;
  ipv4?: boolean;
  ipv6?: boolean;
  nolookup?: boolean;
  tuning?: string;
  plugins?: string;
  format?: string;
  output?: string;
  evasion?: string;
  add_header?: string[];
  id?: string;
  useproxy?: string;
  vhost?: string;
  useragent?: string;
  timeout_secs?: number;
  pause_secs?: number;
  maxtime_secs?: number;
  max_concurrent_requests?: number;
  max_concurrent_hosts?: number;
  follow_redirects?: boolean;
  userdbs?: string;
  root?: string;
  four04_string?: string;
  four04_code?: number;
  // Active fuzzing
  active?: boolean;
  scope?: string;           // "domain" | "subdomains" | "folder" | "page"
  crawl_depth?: number;
  max_urls?: number;
  exclude_pattern?: string[];
  // SQL injection
  sqli_level?: number;      // 1-5
  sqli_risk?: number;       // 1-3
  sqli_techniques?: string; // "BEUST"
  sqli_dbms?: string;       // "mysql" | "postgresql" | "mssql" | etc.
  sqli_time_delay?: number;
  tamper?: string;           // comma-separated tamper module names
  sqli_enumerate?: string;   // "dbs,tables,columns,users,dump,passwords"
}

export interface ScanStats {
  id: string;
  total_requests: number;
  total_findings: number;
  total_errors: number;
  hosts_completed: number;
  elapsed_secs: number;
  cancelled: boolean;
}

export interface HostPayload {
  ident: string;
  hostname: string;
  ip: string | null;
  port: number;
  ssl: boolean;
  banner: string | null;
}

export interface FindingPayload {
  host: string;
  port: number;
  corvex_id: string;
  method: string;
  uri: string;
  message: string;
  refs: string;
  plugin: string;
}

export interface SummaryPayload {
  total_requests: number;
  total_findings: number;
  total_errors: number;
  hosts_completed: number;
  elapsed_secs: number;
}

// ---- Commands --------------------------------------------------------------

export function listPlugins(): Promise<PluginSummary[]> {
  return invoke<PluginSummary[]>("list_plugins");
}

export function dbSummary(): Promise<DbSummary> {
  return invoke<DbSummary>("db_summary");
}

export function versionInfo(): Promise<VersionInfo> {
  return invoke<VersionInfo>("version_info");
}

export function startScan(params: ScanParams): Promise<string> {
  return invoke<string>("scan_start", { params });
}

export function cancelScan(id: string): Promise<boolean> {
  return invoke<boolean>("scan_cancel", { id });
}

export function scanStats(id: string): Promise<ScanStats | null> {
  return invoke<ScanStats | null>("scan_stats", { id });
}

// ---- Event subscriptions ---------------------------------------------------

function scoped(id: string, kind: string): string {
  return `scan://${id}/${kind}`;
}

export function onHostStart(id: string, cb: (h: HostPayload) => void): Promise<UnlistenFn> {
  return listen<HostPayload>(scoped(id, "host-start"), (e) => cb(e.payload));
}

export function onHostEnd(id: string, cb: (h: HostPayload) => void): Promise<UnlistenFn> {
  return listen<HostPayload>(scoped(id, "host-end"), (e) => cb(e.payload));
}

export function onFinding(id: string, cb: (f: FindingPayload) => void): Promise<UnlistenFn> {
  return listen<FindingPayload>(scoped(id, "finding"), (e) => cb(e.payload));
}

export function onSummary(id: string, cb: (s: SummaryPayload) => void): Promise<UnlistenFn> {
  return listen<SummaryPayload>(scoped(id, "summary"), (e) => cb(e.payload));
}

export interface DoneEvent {
  cancelled: boolean;
  error: string | null;
}

export function onDone(id: string, cb: (d: DoneEvent) => void): Promise<UnlistenFn> {
  return listen<DoneEvent>(scoped(id, "done"), (e) => cb(e.payload));
}

// ---- Global log stream ----------------------------------------------------
//
// Every `tracing` event emitted by the engine (scan, plugins, HTTP
// errors, cancellation notices, …) arrives here formatted with its
// level and target.

export interface LogLine {
  level: "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR";
  target: string;
  message: string;
}

export function onLogLine(cb: (line: LogLine) => void): Promise<UnlistenFn> {
  return listen<LogLine>("log://line", (e) => cb(e.payload));
}

// ---- History (SQLite-backed) ----------------------------------------------

export interface HistoryEntry {
  id: number;
  host: string;
  params_json: string;
  started_at: number;        // unix seconds
  ended_at: number | null;
  status: "running" | "done" | "cancelled" | "error" | string;
  total_requests: number;
  total_findings: number;
  total_errors: number;
}

export function historyList(limit?: number): Promise<HistoryEntry[]> {
  return invoke<HistoryEntry[]>("history_list", { limit });
}

export function historyClear(): Promise<number> {
  return invoke<number>("history_clear");
}

export function historyDelete(id: number): Promise<number> {
  return invoke<number>("history_delete", { id });
}
