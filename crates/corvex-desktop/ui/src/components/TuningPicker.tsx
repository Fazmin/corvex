import { useMemo } from "react";
import { InfoTip } from "./InfoTip";

// Category codes + upstream labels from the Corvex CLI docs.
const CATEGORIES: { code: string; label: string; hint: string }[] = [
  { code: "0", label: "File Upload", hint: "Tests that look for unrestricted file upload endpoints." },
  { code: "1", label: "Interesting File", hint: "Leftover or suspicious files commonly seen in logs." },
  { code: "2", label: "Misconfig / Default", hint: "Default installs, sample content, exposed admin endpoints." },
  { code: "3", label: "Info Disclosure", hint: "Sensitive data leaked through headers, errors or debug pages." },
  { code: "4", label: "Injection (XSS)", hint: "Cross-site scripting / HTML injection probes." },
  { code: "5", label: "RFR (Web root)", hint: "Remote file retrieval rooted inside the web root." },
  { code: "6", label: "DoS", hint: "Tests that may cause denial of service — use with caution." },
  { code: "7", label: "RFR (Server-wide)", hint: "Traversal / LFI tests outside the web root." },
  { code: "8", label: "Command Exec", hint: "Remote command execution / shell payloads." },
  { code: "9", label: "SQL Injection", hint: "SQLi probes against known parameters." },
  { code: "a", label: "Auth Bypass", hint: "Unauthenticated access to protected resources." },
  { code: "b", label: "Software ID", hint: "Fingerprinting of server / framework versions." },
  { code: "c", label: "RSI", hint: "Remote source inclusion vectors." },
  { code: "d", label: "WebService", hint: "SOAP / WSDL / REST-service specific checks." },
  { code: "e", label: "Admin Console", hint: "Exposed administrative consoles and dashboards." },
];

interface Props {
  value: string;
  onChange: (next: string) => void;
}

export function TuningPicker({ value, onChange }: Props) {
  const active = useMemo(() => new Set(value.split("")), [value]);

  const toggle = (code: string) => {
    const next = new Set(active);
    if (next.has(code)) {
      next.delete(code);
    } else {
      next.add(code);
    }
    onChange(
      CATEGORIES.filter((c) => next.has(c.code))
        .map((c) => c.code)
        .concat(next.has("x") ? ["x"] : [])
        .join("")
    );
  };

  return (
    <div className="field">
      <div className="label-row">
        <label>Tuning</label>
        <InfoTip label="Tuning help">
          <strong>Tuning categories</strong>
          Restrict which test categories run. Leave blank to run everything.
          Add <dt style={{ display: "inline" }}>x</dt> to invert the selection
          (run everything except the picked categories).
          <dl style={{ marginTop: 6 }}>
            {CATEGORIES.map((c) => (
              <span key={c.code} style={{ display: "contents" }}>
                <dt>{c.code}</dt>
                <dd>{c.label} — {c.hint}</dd>
              </span>
            ))}
          </dl>
        </InfoTip>
      </div>
      <div className="chip-row">
        {CATEGORIES.map((c) => (
          <span
            key={c.code}
            className={`chip${active.has(c.code) ? " active" : ""}`}
            onClick={() => toggle(c.code)}
            title={`${c.label} — ${c.hint}`}
          >
            {c.code}
          </span>
        ))}
        <span
          className={`chip${active.has("x") ? " active" : ""}`}
          onClick={() => toggle("x")}
          title="Invert — run everything except the selected categories"
        >
          x
        </span>
      </div>
    </div>
  );
}
