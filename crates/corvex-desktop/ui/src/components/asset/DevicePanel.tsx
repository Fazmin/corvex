import type { AssetDeviceMatch, AssetHostMac } from "../../api";
import { InfoTip } from "../InfoTip";
import {
  accentChipStyle,
  emptyStateStyle,
  fmtRelative,
  monoChipStyle,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
} from "./panelStyles";

interface Props {
  device: AssetDeviceMatch | null;
  mac: AssetHostMac | null;
}

export function DevicePanel({ device, mac }: Props) {
  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <h3 style={panelTitleStyle}>Device</h3>
          <InfoTip label="What is the Device panel?">
            <p>
              <strong>What kind of device this host is.</strong> Populated by
              an SNMP v2c GET (UDP/161, community <code>public</code>) for
              <code>sysDescr.0</code> and <code>sysObjectID.0</code>, then
              looked up against the bundled device-signature catalog.
            </p>
            <p>
              <strong>When it fires:</strong> always during a Deep probe, and
              in Rapid probes when the "SNMP device fingerprint" checkbox is
              ticked. The panel stays empty if SNMP is closed or no
              signature matches.
            </p>
          </InfoTip>
        </span>
      </header>
      {!device && !mac ? (
        <div style={emptyStateStyle}>
          No SNMP device match or MAC observation yet. Run a probe with
          SNMP fingerprinting and / or MAC address scan enabled to
          populate this panel.
        </div>
      ) : !device ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <MacBlock mac={mac!} />
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <span style={accentChipStyle}>
              {device.vendor} · {device.os}
            </span>
            <span style={monoChipStyle}>{device.device_type}</span>
            <span style={{ ...monoChipStyle, color: "var(--muted)" }}>
              via {device.source}
            </span>
          </div>
          {device.sys_descr && (
            <div>
              <div
                style={{
                  fontSize: "0.78em",
                  color: "var(--muted)",
                  textTransform: "uppercase",
                  letterSpacing: 0.4,
                  marginBottom: 4,
                }}
              >
                sysDescr
              </div>
              <div
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: "0.88em",
                  color: "var(--fg)",
                  wordBreak: "break-word",
                }}
              >
                {device.sys_descr}
              </div>
            </div>
          )}
          {device.sys_object_id && (
            <div>
              <div
                style={{
                  fontSize: "0.78em",
                  color: "var(--muted)",
                  textTransform: "uppercase",
                  letterSpacing: 0.4,
                  marginBottom: 4,
                }}
              >
                sysObjectID
              </div>
              <div
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: "0.88em",
                  color: "var(--fg)",
                }}
              >
                {device.sys_object_id}
              </div>
            </div>
          )}
          {mac && <MacBlock mac={mac} />}
          <div style={{ color: "var(--muted)", fontSize: "0.82em" }}>
            Observed {fmtRelative(device.observed_at_unix)}
          </div>
        </div>
      )}
    </section>
  );
}

function MacBlock({ mac }: { mac: AssetHostMac }) {
  return (
    <div>
      <div
        style={{
          fontSize: "0.78em",
          color: "var(--muted)",
          textTransform: "uppercase",
          letterSpacing: 0.4,
          marginBottom: 4,
        }}
      >
        MAC address
      </div>
      <div
        style={{
          display: "flex",
          gap: 8,
          alignItems: "center",
          flexWrap: "wrap",
          fontFamily: "var(--mono)",
        }}
      >
        <span style={{ color: "var(--fg)", fontSize: "0.9em" }}>
          {mac.mac}
        </span>
        {mac.mac_vendor ? (
          <span style={accentChipStyle}>{mac.mac_vendor}</span>
        ) : (
          <span style={{ ...monoChipStyle, color: "var(--muted)" }}>
            no OUI match
          </span>
        )}
      </div>
      <div
        style={{ color: "var(--muted)", fontSize: "0.82em", marginTop: 4 }}
      >
        From OS ARP cache · resolved via IEEE OUI table · observed{" "}
        {fmtRelative(mac.observed_at_unix)}
      </div>
    </div>
  );
}
