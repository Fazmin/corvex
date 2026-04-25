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
  full_version: string;
  build_id: string;
  build_date: string;
  build_profile: string;
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
  /** One-line live status published by long-running plugins
   *  (currently SCA). Updated ~750ms via the same polling loop. */
  stage: string | null;
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

// ---- Nuclei template engine -------------------------------------------------

export interface NucleiSummary {
  enabled: boolean;
  bundle_tag: string | null;
  bundle_commit: string | null;
  roots: string[];
  manifest_template_count: number | null;
  supported: number;
  skipped: number;
  by_bucket: [string, number][];
  by_severity: [string, number][];
  by_tag_top: [string, number][];
  extras_cached: boolean;
  extras_cache_path: string | null;
}

export function nucleiSummary(): Promise<NucleiSummary> {
  return invoke<NucleiSummary>("nuclei_summary");
}

export interface NucleiTemplateEntry {
  id: string;
  name: string;
  path: string;
  severity: string;
  tags: string[];
  authors: string[];
  cve_ids: string[];
  supported: boolean;
  skip_reason: string | null;
}

export function nucleiTemplateList(): Promise<NucleiTemplateEntry[]> {
  return invoke<NucleiTemplateEntry[]>("nuclei_template_list");
}

export interface NucleiExtrasStatus {
  cache_path: string;
  tag: string;
  http_template_count: number;
}

export function nucleiExtrasDownload(
  tag?: string
): Promise<NucleiExtrasStatus> {
  return invoke<NucleiExtrasStatus>("nuclei_extras_download", { tag });
}

export function nucleiExtrasRemove(): Promise<void> {
  return invoke<void>("nuclei_extras_remove");
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
  cb: (batch: ProbeOpenPort[]) => void
): Promise<UnlistenFn> {
  // The Rust side emits one event per host with every open port for
  // that host in a single payload, so the listener receives a batch.
  return listen<ProbeOpenPort[]>(probeEventName(id, "open-port"), (e) =>
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

// --- Proxy and Checks ----------------------------------------------------

export interface ProxyStatus {
  running: boolean;
  listen: string | null;
  session_id: string | null;
  ca_ready: boolean;
  exchanges_captured: number;
}

export interface ProxyConfig {
  listen: string; // "host:port"
  note?: string | null;
}

export type ProxyScope = "in" | "out" | "excluded";

export interface ExchangeSummary {
  id: string;
  session_id: string;
  origin_kind: string;
  method: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  status: number | null;
  mime: string | null;
  size_request: number;
  size_response: number;
  started_at: string;
  duration_ms: number | null;
  scope: ProxyScope;
  intercepted: number;
  tags: string[];
  query: string | null;
}

export interface ExchangeDetail {
  id: string;
  method: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  query: string | null;
  status: number | null;
  request_headers: [string, string][];
  request_body_base64: string | null;
  /** Full request body size in bytes before UI preview truncation. */
  request_body_size: number;
  response_headers: [string, string][];
  response_body_base64: string | null;
  /** Full response body size in bytes before UI preview truncation. */
  response_body_size: number;
  /** True when the exchange was captured with at least one side
   *  exceeding the 32 MB hard cap. The stored bytes are the initial
   *  prefix; the tail is gone. */
  body_truncated: boolean;
  started_at_unix: number;
  duration_ms: number | null;
}

export interface ExportedCa {
  path: string;
  pem: string;
}

export function proxyStatus(): Promise<ProxyStatus> {
  return invoke<ProxyStatus>("proxy_status");
}

export function proxyStart(config?: ProxyConfig): Promise<string> {
  return invoke<string>("proxy_start", { config: config ?? null });
}

export function proxyStop(): Promise<void> {
  return invoke<void>("proxy_stop");
}

export function proxyExportCaPem(): Promise<ExportedCa> {
  return invoke<ExportedCa>("proxy_export_ca_pem");
}

export interface ScopeRule {
  host: string;
  path_regex?: string | null;
  port?: number | null;
}

export interface ScopeRules {
  include: ScopeRule[];
  exclude: ScopeRule[];
}

export function scopeGet(): Promise<ScopeRules> {
  return invoke<ScopeRules>("scope_get");
}

export function scopeSet(rules: ScopeRules): Promise<void> {
  return invoke<void>("scope_set", { rules });
}

export interface HarExportReport {
  path: string;
  entry_count: number;
  bytes_written: number;
}

export function proxyExportHar(
  session: string,
  path: string,
): Promise<HarExportReport> {
  return invoke<HarExportReport>("proxy_export_har", { session, path });
}

export interface SpecImportReport {
  source: string;
  /** "openapi3" or "postman_v2" — the format the parser detected. */
  format: string;
  imported: number;
  skipped: number;
}

export function proxyImportSpec(path: string): Promise<SpecImportReport> {
  return invoke<SpecImportReport>("proxy_import_spec", { path });
}

export interface HostSeed {
  host: string;
  scheme?: string;
  port?: number;
  source: string;
}

/** Inject a synthetic `GET /` exchange for one host into the active
 *  proxy session — used by Recon's "Send to Checks" action. */
export function proxySeedHost(seed: HostSeed): Promise<string> {
  return invoke<string>("proxy_seed_host", { seed });
}

// --- Recon view ---------------------------------------------------------

export interface ReconStartInput {
  domain: string;
  passive_sources: string[];
  active: boolean;
  wordlist_path?: string | null;
  max_concurrent?: number;
}

export interface ReconRunSummary {
  id: string;
  domain: string;
  started_at_unix: number;
  ended_at_unix: number | null;
  status: string;
  passive_sources: string[];
  active_enabled: boolean;
  wildcard_ips: string[];
  found_subdomains: number;
  found_records: number;
  error: string | null;
}

export type ReconFindingKind = "subdomain" | "record" | "zone_transfer";

export interface ReconFindingRow {
  id: number;
  run_id: string;
  kind: ReconFindingKind;
  name: string;
  value: string | null;
  record_type: string | null;
  sources: string[];
  discovered_at_unix: number;
}

export type ReconEvent =
  | { run_id: string; kind: "source_started"; source: string }
  | {
      run_id: string;
      kind: "source_finished";
      source: string;
      found: number;
      error: string | null;
    }
  | { run_id: string; kind: "wildcard_detected"; ips: string[] }
  | {
      run_id: string;
      kind: "subdomain_discovered";
      host: string;
      sources: string[];
      ips: string[];
    }
  | {
      run_id: string;
      kind: "record_discovered";
      name: string;
      record_type: string;
      value: string;
    }
  | { run_id: string; kind: "zone_transfer"; records: number }
  | {
      run_id: string;
      kind: "brute_progress";
      tested: number;
      total: number;
      found: number;
    }
  | {
      run_id: string;
      kind: "complete";
      found_subdomains: number;
      found_records: number;
      duration_ms: number;
    }
  | { run_id: string; kind: "failed"; error: string }
  | { run_id: string; kind: "cancelled" };

export function reconStart(input: ReconStartInput): Promise<string> {
  return invoke<string>("recon_start", { input });
}

export function reconCancel(id: string): Promise<boolean> {
  return invoke<boolean>("recon_cancel", { id });
}

export function reconRunsList(limit?: number): Promise<ReconRunSummary[]> {
  return invoke<ReconRunSummary[]>("recon_runs_list", { limit });
}

export function reconRunGet(id: string): Promise<ReconRunSummary | null> {
  return invoke<ReconRunSummary | null>("recon_run_get", { id });
}

export function reconFindingsForRun(id: string): Promise<ReconFindingRow[]> {
  return invoke<ReconFindingRow[]>("recon_findings_for_run", { id });
}

export function reconRunDelete(id: string): Promise<number> {
  return invoke<number>("recon_run_delete", { id });
}

export function onReconEvent(
  cb: (event: ReconEvent) => void,
): Promise<UnlistenFn> {
  return listen<ReconEvent>("recon://event", (e) => cb(e.payload));
}

export interface RetentionPolicy {
  /** Maximum exchanges retained per session. 0 = unlimited. */
  max_exchanges_per_session: number;
}

export function retentionGet(): Promise<RetentionPolicy> {
  return invoke<RetentionPolicy>("retention_get");
}

export function retentionSet(policy: RetentionPolicy): Promise<void> {
  return invoke<void>("retention_set", { policy });
}

export type WsDirection = "client" | "server";

export interface WsFrame {
  exchange_id: string;
  sequence: number;
  direction: WsDirection;
  opcode: number;
  opcode_label:
    | "cont"
    | "text"
    | "binary"
    | "close"
    | "ping"
    | "pong"
    | "reserved";
  fin: boolean;
  payload_base64: string;
  payload_size: number;
  captured_at_unix: number;
}

export function wsFramesForExchange(id: string): Promise<WsFrame[]> {
  return invoke<WsFrame[]>("ws_frames_for_exchange", { id });
}

export function wsFrameCount(id: string): Promise<number> {
  return invoke<number>("ws_frame_count", { id });
}

/** Fires once per captured WebSocket frame. The payload shape matches
 *  the `WsFrame` type returned by `wsFramesForExchange`. */
export function onWsFrame(
  cb: (frame: WsFrame) => void,
): Promise<UnlistenFn> {
  return listen<WsFrame>("proxy://ws-frame", (e) => cb(e.payload));
}

export function exchangesList(
  session: string,
  limit = 200,
  offset = 0,
): Promise<ExchangeSummary[]> {
  return invoke<ExchangeSummary[]>("exchanges_list", { session, limit, offset });
}

export function exchangeGet(id: string): Promise<ExchangeDetail | null> {
  return invoke<ExchangeDetail | null>("exchange_get", { id });
}

/** Live exchange events emitted by the proxy listener once a session is
 *  active. Wiring lands with the listener milestone — the helper is
 *  here now so views can subscribe against the finalised channel name
 *  without a churn later. */
export function onProxyExchange(
  cb: (summary: ExchangeSummary) => void,
): Promise<UnlistenFn> {
  return listen<ExchangeSummary>("proxy://exchange-new", (e) => cb(e.payload));
}

// --- Phase 2: intercept + replay -----------------------------------------

export type InterceptMode = "off" | "request" | "response" | "both";
export type InterceptPhase = "request" | "response";

export interface PendingIntercept {
  id: string;
  phase: InterceptPhase;
  method: string;
  host: string;
  port: number;
  scheme: string;
  uri: string;
  raw_bytes_base64: string;
}

export type InterceptVerdictInput =
  | { kind: "forward" }
  | { kind: "forward_edited"; bytes_base64: string }
  | { kind: "drop" };

export interface ReplayResult {
  id: string;
  status: number | null;
  duration_ms: number | null;
  response_headers: [string, string][];
  response_body_base64: string | null;
}

export function interceptGetMode(): Promise<InterceptMode> {
  return invoke<InterceptMode>("intercept_get_mode");
}

export function interceptSetMode(mode: InterceptMode): Promise<void> {
  return invoke<void>("intercept_set_mode", { mode });
}

export function interceptPendingList(): Promise<PendingIntercept[]> {
  return invoke<PendingIntercept[]>("intercept_pending_list");
}

export function interceptResolve(
  id: string,
  verdict: InterceptVerdictInput,
): Promise<void> {
  return invoke<void>("intercept_resolve", { id, verdict });
}

export function interceptDropAll(): Promise<void> {
  return invoke<void>("intercept_drop_all");
}

export function replaySend(
  baseId: string,
  editedBytesBase64: string | null,
): Promise<ReplayResult> {
  return invoke<ReplayResult>("replay_send", {
    baseId,
    editedBytesBase64,
  });
}

export function onInterceptPending(
  cb: (pending: PendingIntercept) => void,
): Promise<UnlistenFn> {
  return listen<PendingIntercept>("proxy://intercept-pending", (e) =>
    cb(e.payload),
  );
}

// --- Phase 3: checks -----------------------------------------------------

export interface CheckDescriptor {
  id: string;
  name: string;
  category: string;       // "A01"..."A10" (codes come from the active taxonomy)
  category_label: string; // human-readable label
  category_description: string | null;
  kind: "passive" | "active";
  default_severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
}

export interface OwaspCategoryInfo {
  code: string;
  label: string;
  description: string | null;
  reference: string | null;
}

export interface OwaspTaxonomyInfo {
  version: string;           // e.g. "2025"
  released: string | null;
  source: string | null;
  categories: OwaspCategoryInfo[];
}

export function owaspTaxonomyInfo(): Promise<OwaspTaxonomyInfo> {
  return invoke<OwaspTaxonomyInfo>("owasp_taxonomy_info");
}

export interface FindingRow {
  id: string;
  exchange_id: string;
  check_id: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string | null;
  evidence: unknown;
  created_at_unix: number;
}

export interface ChecksRunSummary {
  ran: string[];
  findings: number;
}

export interface LiveFindingPayload {
  id: string;
  exchange_id: string;
  check_id: string;
  severity: string;
  title: string;
  description: string | null;
  evidence: unknown;
  host: string;
  path: string;
}

export function checksList(): Promise<CheckDescriptor[]> {
  return invoke<CheckDescriptor[]>("checks_list");
}

export function findingsForExchange(id: string): Promise<FindingRow[]> {
  return invoke<FindingRow[]>("findings_for_exchange", { id });
}

export function findingsForSession(
  session: string,
  limit = 500,
): Promise<FindingRow[]> {
  return invoke<FindingRow[]>("findings_for_session", { session, limit });
}

export function checksRun(
  targetIds: string[],
  checkIds: string[],
): Promise<ChecksRunSummary> {
  return invoke<ChecksRunSummary>("checks_run", {
    targetIds,
    checkIds,
  });
}

export function onScanFinding(
  cb: (finding: LiveFindingPayload) => void,
): Promise<UnlistenFn> {
  return listen<LiveFindingPayload>("proxy://scan-finding", (e) => cb(e.payload));
}

// --- Wappalyzer fingerprint dataset --------------------------------------

export interface WappalyzerSummary {
  loaded: boolean;
  root: string | null;
  loaded_count: number;
  seed_count: number;
  top_categories: [string, number][];
  upstream: string | null;
  upstream_ref: string | null;
  upstream_commit: string | null;
  refreshed_at: string | null;
  license: string | null;
}

export function wappalyzerSummary(): Promise<WappalyzerSummary> {
  return invoke<WappalyzerSummary>("wappalyzer_summary");
}

// --- Exploit-DB enrichment -----------------------------------------------
// CVE-bearing findings (FindingsTable + ScaView detail panes) enrich
// against a local SQLite snapshot of the Exploit-DB CSV index. The
// snapshot is seeded from a release-time bundle under
// `program/databases/exploitdb/` and can be re-synced from upstream
// via the Databases view.

export interface ExploitHit {
  edb_id: number;
  title: string;
  kind: string;
  platform: string;
  author: string | null;
  date_published: string | null;
  verified: boolean;
  exploitdb_url: string;
  raw_url: string;
  file: string;
}

export interface ExploitDbSummary {
  total: number;
  verified: number;
  origin: string | null;           // "bundled" | "user-synced"
  source_commit: string | null;
  refreshed_at_utc: string | null;
  by_type: [string, number][];
  by_platform_top: [string, number][];
}

export interface ExploitSource {
  edb_id: number;
  body: string;
  lang_hint: string | null;
  cached_path: string;
  source_url: string;
}

export function exploitdbSummary(): Promise<ExploitDbSummary> {
  return invoke<ExploitDbSummary>("exploitdb_summary");
}

export function exploitdbByCve(cve: string): Promise<ExploitHit[]> {
  return invoke<ExploitHit[]>("exploitdb_by_cve", { cve });
}

export function exploitdbUpdate(): Promise<ExploitDbSummary> {
  return invoke<ExploitDbSummary>("exploitdb_update");
}

export function exploitdbFetchSource(edbId: number): Promise<ExploitSource> {
  return invoke<ExploitSource>("exploitdb_fetch_source", { edbId });
}
