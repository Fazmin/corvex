/**
 * Standalone service-probing runner.
 *
 * Lives inside the Probing view. Takes one or more targets (IP, hostname,
 * or IPv4 CIDR) and streams open-port + service-identification results
 * back from the backend via `probe://<id>/...` Tauri events.
 */

import { useMemo } from "react";
import type {
  ProbeDeviceMatch,
  ProbeMacResolved,
  ProbeOpenPort,
  ProbeParams,
} from "../api";
import { useSettings } from "../settings";
import { useProbeRun, type HostStatus } from "../probe_running";
import { InfoTip } from "./InfoTip";
import { JarmInfo } from "./JarmInfo";
import { ScanIndicator, type MetricChip } from "./ScanIndicator";
import { AssetLink } from "./asset/AssetLink";

// Comma-separated ports or ranges, same grammar as ScanForm.
const PORT_LIST_REGEX =
  /^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$/;

function validatePorts(raw: string, max = 65535): string | null {
  if (!raw) return "Required";
  const stripped = raw.replace(/\s+/g, "");
  if (!PORT_LIST_REGEX.test(stripped))
    return "Use comma-separated ports or ranges (e.g. 80,443,8000-8100)";
  for (const segment of stripped.split(",")) {
    const parts = segment.split("-").map(Number);
    for (const n of parts) {
      if (!Number.isFinite(n) || n < 1 || n > max)
        return `Port ${n} is out of range (1-${max})`;
    }
    if (parts.length === 2 && parts[0] > parts[1])
      return `Range ${segment} is reversed`;
  }
  return null;
}

const TARGET_HELP = (
  <>
    One entry per line, or comma-separated on a single line. Each entry can be:
    <ul style={{ margin: "6px 0 0 18px", padding: 0 }}>
      <li>
        <strong>Single IP</strong> — <code>10.0.0.7</code>, <code>::1</code>
      </li>
      <li>
        <strong>Hostname</strong> — <code>example.com</code> (resolved via DNS)
      </li>
      <li>
        <strong>CIDR block</strong> (IPv4) — <code>192.168.1.0/24</code>.
        Network and broadcast addresses are skipped for prefixes narrower than
        /31.
      </li>
      <li>
        <strong>Full IP range</strong> — <code>10.0.0.5-10.0.0.40</code>.
        Inclusive on both ends.
      </li>
      <li>
        <strong>Short last-octet range</strong> —{" "}
        <code>192.168.1.10-40</code>. Shorthand for the same base IP with the
        last octet varying.
      </li>
      <li>
        <strong>Comma list</strong> —{" "}
        <code>10.0.0.1, 10.0.0.2-5, example.com</code>. Each element is parsed
        independently.
      </li>
    </ul>
    CIDRs and dash-ranges are each capped at 65,536 expanded hosts so a typo
    can't turn into a /8 sweep. Targets are probed in parallel up to the
    host-concurrency cap. Failures per entry (DNS miss, bad CIDR, reversed
    range) are reported to the error log without aborting the rest of the run.
  </>
);

function formatElapsed(ms: number | null): string {
  if (ms === null || ms === undefined) return "-";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function ProbeRunner() {
  const { extraProbeFiles } = useSettings();
  const run = useProbeRun();

  // Form state lives in the provider so the last values the user typed
  // or selected survive tab switches, sidebar navigation, and scan
  // completion. The only way to reset them is the "New probe" button.
  const {
    running,
    hosts,
    openPorts,
    deviceMatches,
    macResolved,
    errors,
    summary,
    startedAt,
    nowMs,
    form,
    setForm,
    start: startRun,
    stop,
    reset: resetRun,
  } = run;

  const {
    targetsText,
    scanMode,
    portsRange,
    jarm,
    snmpFingerprint,
    macLookup,
    concurrency,
  } = form;
  const setTargetsText = (v: string) => setForm({ targetsText: v });
  const setScanMode = (v: "rapid" | "deep") => setForm({ scanMode: v });
  const setPortsRange = (v: string) => setForm({ portsRange: v });
  const setJarm = (v: boolean) => setForm({ jarm: v });
  const setSnmpFingerprint = (v: boolean) => setForm({ snmpFingerprint: v });
  const setMacLookup = (v: boolean) => setForm({ macLookup: v });
  const setConcurrency = (v: number) => setForm({ concurrency: v });

  const hasResults =
    summary !== null ||
    Object.keys(hosts).length > 0 ||
    openPorts.length > 0 ||
    errors.length > 0;

  const newProbe = () => {
    // Wipe context-held run state and roll the form back to the
    // Configure tab's saved defaults. This is the only reset path —
    // scan completion itself does not clear the form.
    resetRun();
  };

  const targets = useMemo(
    () =>
      targetsText
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
    [targetsText]
  );

  const portsErr = useMemo(() => validatePorts(portsRange), [portsRange]);
  const concurrencyValid = concurrency >= 1 && concurrency <= 64;

  const canStart =
    !running &&
    targets.length > 0 &&
    portsErr === null &&
    concurrencyValid;

  const start = async () => {
    if (!canStart) return;
    const params: ProbeParams = {
      targets,
      scan_mode: scanMode,
      ports_range: portsRange.trim(),
      jarm: scanMode === "deep" ? jarm : false,
      extra_probe_files: scanMode === "deep" ? extraProbeFiles : [],
      host_concurrency: concurrency,
      // Deep scans always run SNMP fingerprinting; the backend ignores
      // the flag in that mode. In Rapid the user opts in via the
      // checkbox, defaulting off.
      snmp_fingerprint: scanMode === "deep" ? true : snmpFingerprint,
      // Same shape for MAC capture: forced on in Deep, opt-in in
      // Rapid.
      mac_lookup: scanMode === "deep" ? true : macLookup,
    };
    await startRun(params);
  };

  const hostStates = Object.values(hosts);
  const hostsRunning = hostStates.filter((h) => h.state === "running").length;
  const hostsDone = hostStates.filter((h) => h.state === "done").length;
  const runningTotal = hostStates.length > 0 ? hostStates.length : targets.length;
  const elapsedLive = running && startedAt !== null ? nowMs - startedAt : 0;

  const indicatorChips: MetricChip[] = running
    ? [
        { label: "hosts done", value: `${hostsDone}/${runningTotal}` },
        { label: "in flight", value: hostsRunning },
        { label: "open ports", value: openPorts.length },
        { label: "elapsed", value: formatElapsed(elapsedLive) },
      ]
    : [];

  return (
    <div className="single-pane" style={{ display: "grid", gap: 16 }}>
      {running && (
        <ScanIndicator
          label="Probing"
          progress={
            runningTotal > 0
              ? { current: hostsDone, total: runningTotal }
              : undefined
          }
          chips={indicatorChips}
          onCancel={stop}
        />
      )}

      <div className="form-panel" style={{ maxWidth: 960 }}>
        <div className="field">
          <label>
            Targets
            <InfoTip label="Target input help">{TARGET_HELP}</InfoTip>
          </label>
          <textarea
            value={targetsText}
            onChange={(e) => setTargetsText(e.target.value)}
            rows={5}
            spellCheck={false}
            placeholder={`10.0.0.7
example.com
192.168.1.0/24
10.0.0.5-10.0.0.40
192.168.1.10-40`}
            disabled={running}
            style={{ width: "100%", fontFamily: "monospace" }}
          />
          <div className="field-hint">
            {targets.length} target
            {targets.length === 1 ? "" : "s"} parsed · expand CIDR on the backend
            before probing.
          </div>
        </div>

        <div className="field">
          <label>
            Scan mode
            <InfoTip label="Scan mode help">
              <strong>Rapid</strong> — TCP connect sweep only. Open/closed per
              port, no fingerprinting. Best for discovering a host's attack
              surface across a wide range.
              <br />
              <br />
              <strong>Deep</strong> — TLS handshake + scripted and declarative
              probes + Recog fingerprint matching + optional JARM. Produces
              product / version / CPE so the results can be pivoted into the
              vulnerability database.
            </InfoTip>
          </label>
          <div role="radiogroup" style={{ display: "flex", gap: 14 }}>
            <label className="radio">
              <input
                type="radio"
                name="probeRunScanMode"
                checked={scanMode === "rapid"}
                onChange={() => setScanMode("rapid")}
                disabled={running}
              />
              Rapid (fast sweep)
            </label>
            <label className="radio">
              <input
                type="radio"
                name="probeRunScanMode"
                checked={scanMode === "deep"}
                onChange={() => setScanMode("deep")}
                disabled={running}
              />
              Deep (service fingerprint)
            </label>
          </div>
        </div>

        <div className="field">
          <label>
            Port range
            <InfoTip label="Port range help">
              Same grammar as the Scan form. Rapid mode covers large ranges
              (full 1-65535) comfortably; Deep mode allocates up to a 4-second
              probe budget per open port, so narrow the range if you're running
              Deep across a /24.
            </InfoTip>
          </label>
          <input
            type="text"
            value={portsRange}
            onChange={(e) => setPortsRange(e.target.value)}
            placeholder="1-1000"
            disabled={running}
            aria-invalid={portsErr !== null}
            style={{ fontFamily: "monospace" }}
          />
          {portsErr && <div className="field-error">{portsErr}</div>}
        </div>

        <div className="field" style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
          <label className="checkbox" style={{ flex: "0 0 auto" }}>
            <input
              type="checkbox"
              checked={jarm}
              onChange={(e) => setJarm(e.target.checked)}
              disabled={running || scanMode !== "deep"}
            />
            Collect JARM (Deep only)
            <InfoTip label="JARM help">
              Adds up to 10 TCP sessions × 800 ms per TLS-capable port. Useful
              for C2 attribution and grouping hosts behind the same TLS stack.
            </InfoTip>
          </label>

          <label className="checkbox" style={{ flex: "0 0 auto" }}>
            <input
              type="checkbox"
              checked={scanMode === "deep" ? true : snmpFingerprint}
              onChange={(e) => setSnmpFingerprint(e.target.checked)}
              disabled={running || scanMode === "deep"}
            />
            SNMP device fingerprint
            <InfoTip label="SNMP fingerprint help">
              Sends one SNMPv2c GET to UDP/161 per host (community{" "}
              <code>public</code>) asking for sysDescr and sysObjectID, then
              looks the response up in the bundled device-signature catalog
              to identify Cisco / Juniper / Mikrotik / APC / etc. devices.
              <br />
              <br />
              Always on in <strong>Deep</strong> mode; opt-in in{" "}
              <strong>Rapid</strong>. Adds up to one UDP round-trip per host
              (default 1.5s timeout) and runs in parallel with the TCP scan.
            </InfoTip>
          </label>

          <label className="checkbox" style={{ flex: "0 0 auto" }}>
            <input
              type="checkbox"
              checked={scanMode === "deep" ? true : macLookup}
              onChange={(e) => setMacLookup(e.target.checked)}
              disabled={running || scanMode === "deep"}
            />
            MAC address scan
            <InfoTip label="MAC address scan help">
              After the TCP scan completes, reads the OS ARP / neighbour
              cache for each host and resolves the MAC against the
              bundled IEEE OUI table for a vendor name. No extra packets,
              no privileged sockets — relies on the cache populated by
              the SYNs the scan already sent.
              <br />
              <br />
              Always on in <strong>Deep</strong> mode; opt-in in{" "}
              <strong>Rapid</strong>.
              <br />
              <br />
              <strong>Caveat:</strong> only L2-adjacent hosts (same
              broadcast domain as the scanner) return a meaningful MAC.
              For routed targets the cache holds the upstream router's
              MAC, not the target's — the same MAC will appear for many
              IPs, which is your hint to ignore the value.
            </InfoTip>
          </label>

          <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
            Host concurrency
            <input
              type="number"
              min={1}
              max={64}
              value={concurrency}
              onChange={(e) =>
                setConcurrency(Math.max(1, Math.min(64, Number(e.target.value) || 1)))
              }
              disabled={running}
              style={{ width: 72 }}
            />
            <InfoTip label="Concurrency help">
              How many targets are probed in parallel. Each target still uses
              the mode's internal concurrency (2000 for Rapid, 256 for Deep)
              within that single host, so a host-concurrency of 8 means up to
              8 hosts × 256 Deep-mode probes = 2,048 simultaneous sockets.
            </InfoTip>
          </label>

          {scanMode === "deep" && extraProbeFiles.length > 0 && (
            <div className="field-hint" style={{ color: "var(--accent)" }}>
              {extraProbeFiles.length} extra probe file
              {extraProbeFiles.length === 1 ? "" : "s"} will be merged in.
            </div>
          )}
        </div>

        {running ? (
          <button type="button" className="danger" onClick={stop}>
            Stop probing
          </button>
        ) : (
          <button
            type="button"
            className="primary"
            onClick={start}
            disabled={!canStart}
            title={
              !canStart
                ? targets.length === 0
                  ? "Add at least one target"
                  : portsErr ?? "Fix the highlighted fields above"
                : undefined
            }
          >
            Start probing
          </button>
        )}
        {!running && hasResults && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              marginTop: 8,
              flexWrap: "wrap",
            }}
          >
            {summary && (
              <span
                className="field-hint"
                style={{
                  margin: 0,
                  color: summary.cancelled ? "var(--warning)" : "var(--success)",
                }}
              >
                {summary.cancelled ? "Cancelled after " : "Completed in "}
                {formatElapsed(summary.elapsed_ms)} · {summary.hosts_completed}/
                {summary.hosts_total} hosts · {summary.open_ports_total} open
                port{summary.open_ports_total === 1 ? "" : "s"}
              </span>
            )}
            <button
              type="button"
              className="ghost-btn"
              onClick={newProbe}
              style={{ marginLeft: summary ? "auto" : 0 }}
              title="Clear results and form, ready for a fresh probe"
            >
              New probe
            </button>
          </div>
        )}
      </div>

      {(running || Object.keys(hosts).length > 0) && (
        <div className="form-panel" style={{ maxWidth: 1100 }}>
          <h3 style={{ margin: 0 }}>Hosts</h3>
          <HostTable
            hosts={hosts}
            deviceMatches={deviceMatches}
            macResolved={macResolved}
          />
        </div>
      )}

      {openPorts.length > 0 && (
        <div className="form-panel" style={{ maxWidth: 1200 }}>
          <h3 style={{ margin: 0 }}>
            Open ports ({openPorts.length})
          </h3>
          <OpenPortsTable rows={openPorts} />
        </div>
      )}

      {errors.length > 0 && (
        <div className="form-panel" style={{ maxWidth: 960 }}>
          <h3 style={{ margin: 0, color: "var(--danger)" }}>
            Target errors ({errors.length})
          </h3>
          <table className="sub" style={{ width: "100%", marginTop: 8, borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)" }}>
                <th style={{ textAlign: "left", padding: "6px 10px 6px 0" }}>Target</th>
                <th style={{ textAlign: "left", padding: "6px 0" }}>Error</th>
              </tr>
            </thead>
            <tbody>
              {errors.map((e, i) => (
                <tr key={i}>
                  <td
                    style={{
                      padding: "4px 10px 4px 0",
                      fontFamily: "monospace",
                      color: "var(--fg)",
                    }}
                  >
                    {e.target || "(run)"}
                  </td>
                  <td style={{ padding: "4px 0", color: "var(--muted)" }}>{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function HostTable({
  hosts,
  deviceMatches,
  macResolved,
}: {
  hosts: Record<string, HostStatus>;
  deviceMatches: Record<string, ProbeDeviceMatch>;
  macResolved: Record<string, ProbeMacResolved>;
}) {
  const rows = Object.values(hosts).sort((a, b) => a.ip.localeCompare(b.ip));
  return (
    <table className="sub" style={{ width: "100%", marginTop: 8, borderCollapse: "collapse" }}>
      <thead>
        <tr style={{ borderBottom: "1px solid var(--border)" }}>
          <th style={{ textAlign: "left", padding: "6px 10px 6px 0" }}>Target</th>
          <th style={{ textAlign: "left", padding: "6px 10px" }}>IP</th>
          <th style={{ textAlign: "left", padding: "6px 10px" }}>MAC · Vendor</th>
          <th style={{ textAlign: "left", padding: "6px 10px" }}>Device</th>
          <th style={{ textAlign: "left", padding: "6px 10px" }}>State</th>
          <th style={{ textAlign: "right", padding: "6px 10px" }}>Open</th>
          <th style={{ textAlign: "right", padding: "6px 0" }}>Elapsed</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((h) => (
          <tr key={h.display}>
            <td
              style={{
                padding: "4px 10px 4px 0",
                fontFamily: "monospace",
                color: "var(--fg)",
              }}
            >
              {h.display}
              <span style={{ marginLeft: 6, verticalAlign: "middle" }}>
                <AssetLink host={h.display} />
              </span>
            </td>
            <td
              style={{ padding: "4px 10px", fontFamily: "monospace", color: "var(--muted)" }}
            >
              {h.ip}
            </td>
            <td style={{ padding: "4px 10px" }}>
              <MacCell mac={macResolved[h.display]} />
            </td>
            <td style={{ padding: "4px 10px" }}>
              <DeviceCell match={deviceMatches[h.display]} />
            </td>
            <td style={{ padding: "4px 10px" }}>
              <span
                style={{
                  color:
                    h.state === "done"
                      ? "var(--success)"
                      : h.state === "running"
                        ? "var(--accent)"
                        : "var(--muted)",
                }}
              >
                {h.state}
              </span>
            </td>
            <td
              style={{
                padding: "4px 10px",
                textAlign: "right",
                fontFamily: "monospace",
                color: "var(--fg)",
              }}
            >
              {h.openCount}
            </td>
            <td
              style={{
                padding: "4px 0",
                textAlign: "right",
                fontFamily: "monospace",
                color: "var(--muted)",
              }}
            >
              {formatElapsed(h.elapsedMs)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function MacCell({ mac }: { mac: ProbeMacResolved | undefined }) {
  if (!mac) {
    return <em style={{ color: "var(--muted)", fontStyle: "normal" }}>—</em>;
  }
  return (
    <span
      style={{
        display: "inline-flex",
        flexDirection: "column",
        gap: 1,
        fontFamily: "monospace",
      }}
      title={
        mac.mac_vendor
          ? `${mac.mac} — ${mac.mac_vendor} (IEEE OUI)`
          : `${mac.mac} — no OUI match`
      }
    >
      <span style={{ color: "var(--fg)" }}>{mac.mac}</span>
      <span
        style={{
          color: mac.mac_vendor ? "var(--accent)" : "var(--muted)",
          fontSize: "0.85em",
        }}
      >
        {mac.mac_vendor ?? "unknown vendor"}
      </span>
    </span>
  );
}

function DeviceCell({ match }: { match: ProbeDeviceMatch | undefined }) {
  if (!match) {
    return <em style={{ color: "var(--muted)", fontStyle: "normal" }}>—</em>;
  }
  const tooltip = [
    match.sys_descr ? `sysDescr: ${match.sys_descr}` : null,
    match.sys_object_id ? `sysObjectID: ${match.sys_object_id}` : null,
    `matched via ${match.source}`,
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <span
      title={tooltip}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        fontFamily: "monospace",
        color: "var(--fg)",
      }}
    >
      <strong>{match.vendor}</strong>
      <span style={{ color: "var(--muted)" }}>·</span>
      <span>{match.os}</span>
      <span
        style={{
          padding: "1px 6px",
          borderRadius: 4,
          background: "var(--panel-alt, var(--panel))",
          border: "1px solid var(--border)",
          color: "var(--muted)",
          fontSize: "0.78em",
        }}
      >
        {match.device_type}
      </span>
    </span>
  );
}

function OpenPortsTable({ rows }: { rows: ProbeOpenPort[] }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table
        className="sub"
        style={{
          width: "100%",
          marginTop: 8,
          borderCollapse: "collapse",
          fontFamily: "monospace",
          fontSize: "calc(var(--font-base) - 2px)",
        }}
      >
        <thead>
          <tr style={{ borderBottom: "1px solid var(--border)" }}>
            <th style={{ textAlign: "left", padding: "6px 10px 6px 0" }}>Host</th>
            <th style={{ textAlign: "left", padding: "6px 10px" }}>Port</th>
            <th style={{ textAlign: "left", padding: "6px 10px" }}>TLS</th>
            <th style={{ textAlign: "left", padding: "6px 10px" }}>Service</th>
            <th style={{ textAlign: "left", padding: "6px 10px" }}>Product</th>
            <th style={{ textAlign: "left", padding: "6px 10px" }}>Version</th>
            <th style={{ textAlign: "left", padding: "6px 0" }}>CPE · JARM</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.ip}:${r.port}:${i}`}>
              <td style={{ padding: "4px 10px 4px 0", color: "var(--fg)" }}>{r.ip}</td>
              <td style={{ padding: "4px 10px", color: "var(--fg)" }}>{r.port}</td>
              <td style={{ padding: "4px 10px", color: r.over_tls ? "var(--accent)" : "var(--muted)" }}>
                {r.over_tls ? "tls" : "-"}
              </td>
              <td style={{ padding: "4px 10px", color: "var(--fg)" }}>{r.service ?? "-"}</td>
              <td style={{ padding: "4px 10px", color: "var(--fg)" }}>{r.product ?? "-"}</td>
              <td style={{ padding: "4px 10px", color: "var(--fg)" }}>{r.version ?? "-"}</td>
              <td style={{ padding: "4px 0", color: "var(--muted)" }}>
                {r.cpe.length > 0 ? (
                  <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
                    <span>{r.cpe.join(", ")}</span>
                    {r.jarm && <JarmInfo hash={r.jarm} />}
                  </span>
                ) : r.jarm ? (
                  <JarmInfo hash={r.jarm} />
                ) : (
                  "-"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
