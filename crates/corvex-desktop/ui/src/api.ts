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
  // Port scanning
  portscan?: boolean;
  ports_range?: string;
  scan_mode?: "rapid" | "deep";
  jarm?: boolean;
  extra_probe_files?: string[];
  // DNS enumeration
  dns_brute?: boolean;
  // SQL injection
  sqli_level?: number;      // 1-5
  sqli_risk?: number;       // 1-3
  sqli_techniques?: string; // "BEUST"
  sqli_dbms?: string;       // "mysql" | "postgresql" | "mssql" | etc.
  sqli_time_delay?: number;
  tamper?: string;           // comma-separated tamper module names
  sqli_enumerate?: string;   // "dbs,tables,columns,users,dump,passwords"
  // SCA (Software Composition Analysis)
  scan_dir?: string;          // path to directory with dependency manifests
  sbom_input?: string;        // path to SBOM file (CycloneDX/SPDX)
  sbom_output?: string;       // generate SBOM at this path
  sbom_format?: string;       // "cyclonedx-json" | "cyclonedx-xml" | "spdx-json" | "spdx-tv"
  epss_threshold?: number;    // 0.0-1.0 EPSS probability filter
  show_fixes?: boolean;       // include fix info in output
  // Binary analysis
  binary_scan?: string;       // path to binary file or directory
  binary_recursive?: boolean; // recursive directory scanning
  binary_extract?: boolean;   // extract and scan archives
}

export interface ScanStats {
  id: string;
  total_requests: number;
  total_findings: number;
  total_errors: number;
  hosts_completed: number;
  elapsed_secs: number;
  cancelled: boolean;
  urls_crawled: number;
}

export interface HostPayload {
  ident: string;
  hostname: string;
  ip: string | null;
  port: number;
  ssl: boolean;
  banner: string | null;
}

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface FindingPayload {
  host: string;
  port: number;
  corvex_id: string;
  method: string;
  uri: string;
  message: string;
  refs: string;
  plugin: string;
  severity: SeverityLevel;
  cve: string | null;
  cvss: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  fix_version: string | null;
  component: string | null;
  component_version: string | null;
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

// ---- Vulnerability Database ------------------------------------------------

export interface VulnDbInfo {
  available: boolean;
  cve_count: number;
  cpe_match_count: number;
  epss_count: number;
  fix_count: number;
  last_nvd_update: string;
  last_epss_update: string;
}

export function vulndbSummary(): Promise<VulnDbInfo> {
  return invoke<VulnDbInfo>("vulndb_summary");
}

export function vulndbUpdate(mode: string): Promise<string> {
  return invoke<string>("vulndb_update", { mode });
}

// ---- Sonar (Service Probing) ------------------------------------------------

export interface SonarSummary {
  scripted_probes: string[];
  static_probes: string[];
  fingerprint_sets: string[];
  fingerprint_count: number;
  scripted_count: number;
  static_count: number;
  extra_files_loaded: number;
  extra_probes_loaded: number;
  extra_fps_loaded: number;
}

export function sonarSummary(
  extraProbeFiles: string[] = []
): Promise<SonarSummary> {
  return invoke<SonarSummary>("sonar_summary", {
    extraProbeFiles,
  });
}

export interface JarmKnownPayload {
  name: string;
  notes: string | null;
  confidence: string | null;
}

export interface JarmLookupResult {
  hash: string;
  known: JarmKnownPayload | null;
  cipher_version: string;
  extensions_digest: string;
}

export function jarmLookup(
  hash: string,
  extraProbeFiles: string[] = []
): Promise<JarmLookupResult> {
  return invoke<JarmLookupResult>("jarm_lookup", {
    hash,
    extraProbeFiles,
  });
}

// ---- Standalone probing runs ------------------------------------------------

export interface ProbeParams {
  targets: string[];
  scan_mode: "rapid" | "deep";
  ports_range: string;
  jarm?: boolean;
  extra_probe_files?: string[];
  host_concurrency?: number;
}

export interface ProbeHostStart {
  probe_id: string;
  display: string;
  hostname: string;
  ip: string;
  index: number;
  total: number;
}

export interface ProbeHostEnd {
  probe_id: string;
  display: string;
  ip: string;
  open_count: number;
  elapsed_ms: number;
}

export interface ProbeOpenPort {
  probe_id: string;
  display: string;
  hostname: string;
  ip: string;
  port: number;
  over_tls: boolean;
  service: string | null;
  product: string | null;
  vendor: string | null;
  version: string | null;
  info: string | null;
  cpe: string[];
  jarm: string | null;
  banner: string;
}

export interface ProbeSummary {
  probe_id: string;
  hosts_completed: number;
  hosts_total: number;
  open_ports_total: number;
  elapsed_ms: number;
  cancelled: boolean;
}

export interface ProbeTargetError {
  probe_id: string;
  target: string;
  message: string;
}

export function startProbe(params: ProbeParams): Promise<string> {
  return invoke<string>("probe_start", { params });
}

export function cancelProbe(id: string): Promise<boolean> {
  return invoke<boolean>("probe_cancel", { id });
}

export function probeEventName(
  probeId: string,
  kind: "host-start" | "host-end" | "open-port" | "summary" | "error"
): string {
  return `probe://${probeId}/${kind}`;
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

// ---- Probe-run event subscriptions ----------------------------------------

export function onProbeHostStart(
  id: string,
  cb: (p: ProbeHostStart) => void
): Promise<UnlistenFn> {
  return listen<ProbeHostStart>(probeEventName(id, "host-start"), (e) =>
    cb(e.payload)
  );
}

export function onProbeHostEnd(
  id: string,
  cb: (p: ProbeHostEnd) => void
): Promise<UnlistenFn> {
  return listen<ProbeHostEnd>(probeEventName(id, "host-end"), (e) =>
    cb(e.payload)
  );
}

export function onProbeOpenPort(
  id: string,
  cb: (p: ProbeOpenPort) => void
): Promise<UnlistenFn> {
  return listen<ProbeOpenPort>(probeEventName(id, "open-port"), (e) =>
    cb(e.payload)
  );
}

export function onProbeSummary(
  id: string,
  cb: (p: ProbeSummary) => void
): Promise<UnlistenFn> {
  return listen<ProbeSummary>(probeEventName(id, "summary"), (e) =>
    cb(e.payload)
  );
}

export function onProbeError(
  id: string,
  cb: (p: ProbeTargetError) => void
): Promise<UnlistenFn> {
  return listen<ProbeTargetError>(probeEventName(id, "error"), (e) =>
    cb(e.payload)
  );
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
