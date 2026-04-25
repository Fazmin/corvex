import { useEffect, useState } from "react";
import { versionInfo, type VersionInfo } from "../api";
import type { View } from "./Sidebar";

interface Props {
  onNavigate: (view: View) => void;
}

interface Capability {
  view: View;
  side: "defense" | "offense";
  title: string;
}

const CAPABILITIES: Capability[] = [
  { view: "dashboard", side: "offense", title: "Web vulnerability scan" },
  { view: "fuzzing",   side: "offense", title: "Active fuzzing" },
  { view: "proxy",     side: "offense", title: "Intercepting proxy" },
  { view: "probing",   side: "defense", title: "Service probing" },
  { view: "recon",     side: "defense", title: "Reconnaissance" },
  { view: "sca",       side: "defense", title: "Dependency analysis" },
];

export function LandingView({ onNavigate }: Props) {
  const [version, setVersion] = useState<VersionInfo | null>(null);

  useEffect(() => {
    versionInfo().then(setVersion).catch(() => {});
  }, []);

  const fullVersion =
    version?.full_version ?? (version?.version ? `v${version.version}` : "v0.1.0");
  const buildId = version?.build_id ?? "";
  const buildProfile = version?.build_profile ?? "";

  return (
    <div className="landing">
      <section className="landing-hero">
        <div className="landing-hero-glow" aria-hidden />
        <div className="landing-hero-grid">
          <div className="landing-hero-copy">
            <div className="landing-eyebrow">
              <span className="landing-eyebrow-dot landing-eyebrow-dot-defense" />
              Defence
              <span className="landing-eyebrow-sep">·</span>
              <span className="landing-eyebrow-dot landing-eyebrow-dot-offense" />
              Offence
            </div>
            <h1 className="landing-title">
              Your unified{" "}
              <span className="landing-title-accent">security workbench.</span>
            </h1>
            <p className="landing-tagline">
              One calm interface for both sides of the fight — every tool a
              security professional reaches for, without the juggle.
            </p>
            <div className="landing-cta-row">
              <button
                type="button"
                className="primary landing-cta-primary"
                onClick={() => onNavigate("dashboard")}
              >
                Start a scan
              </button>
              <button
                type="button"
                className="ghost-btn landing-cta-secondary"
                onClick={() => onNavigate("help")}
              >
                Read the manual
              </button>
            </div>
            <div className="landing-meta">
              <span className="landing-meta-item">
                <span className="landing-meta-label">Version</span>
                <code>{fullVersion}</code>
              </span>
              {buildId && (
                <span className="landing-meta-item">
                  <span className="landing-meta-label">Build</span>
                  <code>{buildId}</code>
                </span>
              )}
              {buildProfile && (
                <span className="landing-meta-item">
                  <span className="landing-meta-label">Profile</span>
                  <code>{buildProfile}</code>
                </span>
              )}
            </div>
          </div>
          <div className="landing-hero-emblem" aria-hidden>
            <img src="/logo.png" alt="" />
          </div>
        </div>
      </section>

      <section className="landing-capabilities">
        <h2 className="landing-section-title">
          Jump in
          <span className="landing-section-sub">Tap a tile to open the workbench</span>
        </h2>
        <div className="landing-cap-grid">
          {CAPABILITIES.map((c) => (
            <button
              key={c.view}
              type="button"
              className={`landing-cap landing-cap-${c.side}`}
              onClick={() => onNavigate(c.view)}
            >
              <span className="landing-cap-tag">
                {c.side === "offense" ? "Offence" : "Defence"}
              </span>
              <span className="landing-cap-title">{c.title}</span>
              <span className="landing-cap-arrow" aria-hidden>
                →
              </span>
            </button>
          ))}
        </div>
      </section>

      <section className="landing-disclaimer">
        <div className="landing-disclaimer-icon" aria-hidden>
          ⚠
        </div>
        <div className="landing-disclaimer-body">
          <strong>Use only on systems you own or have written authorisation
          to test.</strong>{" "}
          corvex-rust ships exploit lookups and active fuzzing because that's
          what real security work needs. Running these against unauthorised
          targets is illegal in most jurisdictions and an unambiguous breach
          of every responsible-disclosure norm. The tool surfaces information;
          actioning it is your responsibility. By using corvex-rust you agree
          that you are solely responsible for your own conduct, and that the
          authors accept no liability for misuse.
        </div>
      </section>
    </div>
  );
}
