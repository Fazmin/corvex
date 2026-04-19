/**
 * Inline chip + popover for a JARM fingerprint.
 *
 * Raw 62-character hashes don't communicate anything on their own. The
 * chip shows the first few characters as a handle, and clicking it
 * opens a popover that:
 *   - Re-prints the full hash with a copy-to-clipboard button.
 *   - Decomposes the hash into its two canonical parts (cipher/version
 *     fuzzy hash + extension-order SHA-256 digest).
 *   - Looks the hash up against the bundled `jarm_known.toml` database
 *     and surfaces any known product / notes / confidence level.
 *   - Includes a short explainer about what a JARM fingerprint actually
 *     identifies and how to expand the lookup database.
 */

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { jarmLookup, type JarmLookupResult } from "../api";
import { useSettings } from "../settings";

interface Props {
  hash: string;
}

interface PopoverPos {
  top: number;
  left: number;
}

export function JarmInfo({ hash }: Props) {
  const { extraProbeFiles } = useSettings();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<PopoverPos>({ top: 0, left: 0 });
  const [result, setResult] = useState<JarmLookupResult | null>(null);
  const [copied, setCopied] = useState(false);
  const btnRef = useRef<HTMLButtonElement | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);

  const place = useCallback(() => {
    const btn = btnRef.current;
    const pop = popRef.current;
    if (!btn || !pop) return;
    const r = btn.getBoundingClientRect();
    const popW = pop.offsetWidth || 420;
    const popH = pop.offsetHeight || 260;
    const margin = 8;
    let top = r.bottom + 6;
    let left = r.left;
    if (left + popW + margin > window.innerWidth) {
      left = Math.max(margin, window.innerWidth - popW - margin);
    }
    if (top + popH + margin > window.innerHeight) {
      const above = r.top - popH - 6;
      if (above >= margin) top = above;
    }
    if (left < margin) left = margin;
    setPos({ top, left });
  }, []);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  useEffect(() => {
    if (!open || result) return;
    let cancelled = false;
    jarmLookup(hash, extraProbeFiles)
      .then((r) => {
        if (!cancelled) setResult(r);
      })
      .catch(() => {
        if (!cancelled) setResult({
          hash,
          known: null,
          cipher_version: hash.slice(0, 30),
          extensions_digest: hash.slice(30, 62),
        });
      });
    return () => {
      cancelled = true;
    };
  }, [open, result, hash, extraProbeFiles]);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      const target = e.target as Node;
      if (btnRef.current?.contains(target) || popRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    const onScrollOrResize = () => place();
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
    };
  }, [open, place]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore — clipboard API may be unavailable in some contexts
    }
  };

  const knownLabel = result?.known ? result.known.name : null;
  const handle =
    hash.length > 12 ? `${hash.slice(0, 6)}…${hash.slice(-4)}` : hash;

  return (
    <span className="info-tip" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <button
        ref={btnRef}
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((prev) => !prev);
        }}
        title={knownLabel ? `JARM · ${knownLabel}` : "JARM fingerprint — click for detail"}
        style={{
          all: "unset",
          cursor: "pointer",
          fontFamily: "monospace",
          fontSize: "calc(var(--font-base) - 2px)",
          padding: "2px 8px",
          borderRadius: 4,
          background: knownLabel
            ? "color-mix(in srgb, var(--accent) 20%, transparent)"
            : "color-mix(in srgb, var(--muted) 14%, transparent)",
          color: knownLabel ? "var(--accent)" : "var(--fg)",
          border: "1px solid",
          borderColor: knownLabel
            ? "color-mix(in srgb, var(--accent) 45%, transparent)"
            : "color-mix(in srgb, var(--muted) 25%, transparent)",
        }}
      >
        JARM {handle}
        {knownLabel && (
          <span
            style={{
              marginLeft: 6,
              padding: "0 6px",
              borderRadius: 3,
              background: "var(--accent)",
              color: "#fff",
              fontSize: "calc(var(--font-base) - 4px)",
            }}
          >
            {knownLabel}
          </span>
        )}
      </button>
      {open && (
        <div
          ref={popRef}
          className="popover floating"
          role="tooltip"
          style={{
            top: pos.top,
            left: pos.left,
            width: 440,
            maxWidth: "calc(100vw - 16px)",
            padding: 14,
            lineHeight: 1.55,
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 8 }}>
            <strong>JARM fingerprint</strong>
            <button
              type="button"
              onClick={copy}
              className="ghost-btn"
              style={{ padding: "2px 8px", fontSize: "calc(var(--font-base) - 2px)" }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>

          <div style={{ marginTop: 8, fontFamily: "monospace", wordBreak: "break-all", fontSize: "calc(var(--font-base) - 2px)", color: "var(--fg)" }}>
            {hash}
          </div>

          {result?.known ? (
            <div
              style={{
                marginTop: 10,
                padding: 8,
                borderRadius: 4,
                background: "color-mix(in srgb, var(--accent) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--accent) 35%, transparent)",
              }}
            >
              <div style={{ color: "var(--accent)", fontWeight: 600 }}>
                Known match · {result.known.name}
              </div>
              {result.known.notes && (
                <div style={{ marginTop: 4, color: "var(--fg)", fontSize: "calc(var(--font-base) - 2px)" }}>
                  {result.known.notes}
                </div>
              )}
              {result.known.confidence && (
                <div
                  style={{
                    marginTop: 4,
                    color: "var(--muted)",
                    fontSize: "calc(var(--font-base) - 3px)",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                  }}
                >
                  confidence · {result.known.confidence}
                </div>
              )}
            </div>
          ) : result ? (
            <div
              style={{
                marginTop: 10,
                color: "var(--muted)",
                fontSize: "calc(var(--font-base) - 2px)",
                fontStyle: "italic",
              }}
            >
              No matching entry in the bundled JARM database. You can append
              this hash to <code>crates/corvex-sonar/data/jarm_known.toml</code>{" "}
              to name it in future scans.
            </div>
          ) : (
            <div style={{ marginTop: 10, color: "var(--muted)" }}>Looking up…</div>
          )}

          <div style={{ marginTop: 12 }}>
            <div className="sub" style={{ color: "var(--muted)", marginBottom: 4 }}>
              Hash anatomy
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "calc(var(--font-base) - 2px)" }}>
              <tbody>
                <tr>
                  <td style={{ padding: "3px 10px 3px 0", color: "var(--muted)", verticalAlign: "top", whiteSpace: "nowrap" }}>
                    Cipher + version
                  </td>
                  <td style={{ padding: "3px 0", fontFamily: "monospace", color: "var(--fg)", wordBreak: "break-all" }}>
                    {result ? result.cipher_version : hash.slice(0, 30)}
                  </td>
                </tr>
                <tr>
                  <td style={{ padding: "3px 10px 3px 0", color: "var(--muted)", verticalAlign: "top" }}>
                    Extensions digest
                  </td>
                  <td style={{ padding: "3px 0", fontFamily: "monospace", color: "var(--fg)", wordBreak: "break-all" }}>
                    {result ? result.extensions_digest : hash.slice(30, 62)}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div style={{ marginTop: 12, color: "var(--muted)", fontSize: "calc(var(--font-base) - 2px)" }}>
            <strong style={{ color: "var(--fg)" }}>What this identifies.</strong>{" "}
            JARM fingerprints the remote TLS stack — the combination of
            OpenSSL/BoringSSL/rustls/SChannel and its configured cipher
            preferences — not the hostname or the HTTP layer behind it. Two
            hosts running the same TLS stack produce the same hash, so they
            cluster well for C2 attribution, CDN detection, and grouping
            hosts behind a shared load balancer. See the Probing view's JARM
            tab for how the ten probes build the hash.
          </div>
        </div>
      )}
    </span>
  );
}
