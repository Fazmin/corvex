Feasibility

Medium-large effort, but highly tractable. The hard parts — a working raw HTTP/1.x client with OpenSSL TLS, a plugin + fuzzer engine, a Tauri command/event bus, and a React UI shell — already exist. The new work is predominantly a new Rust crate (corvex-proxy), CA/cert plumbing, SQLite tables for captured flows, and 3–4 new React views.

Architecture

flowchart LR
    Browser -->|"HTTP / CONNECT"| Listener
    subgraph corvexProxy["corvex-proxy (new crate)"]
        Listener --> CA["CA + leaf mint (OpenSSL)"]
        Listener --> H1["HTTP/1.x codec"]
        H1 --> Rules["Match and replace"]
        Rules --> Intercept["Intercept queue (oneshot)"]
        Intercept --> Upstream["Upstream send"]
        H1 --> Store["Flow store (SQLite)"]
        Listener --> WS["WebSocket relay"]
    end
    Upstream -->|"reuses HttpClient"| corvexCore["corvex-core::http"]
    Store -->|"emit proxy://*"| Tauri
    Intercept -->|"emit proxy://intercept"| Tauri
    Tauri --> React["React UI (Proxy / Repeater / Intruder)"]
    React -->|"Send to Scanner"| Plugins["corvex-plugins (incl. new BAC)"]
    Plugins --> corvexCore

New crate: corvex-proxy

Create crates/corvex-proxy/ with modules:





ca.rs — generate/load a root CA (RSA-2048 or P-256) under ~/.corvex/proxy/, persist ca.crt + ca.key; mint per-host leaf certs with SAN on demand, cached in memory, signed by the CA. Uses the existing openssl dep.



listener.rs — tokio::net::TcpListener accept loop, one task per connection; branches on CONNECT vs plain HTTP.



h1.rs — inbound HTTP/1.x request parser + response writer. We can reuse the wire response parser in crates/corvex-core/src/http/client.rs for upstream; we need a new inbound request parser (the current Request::to_wire() in crates/corvex-core/src/http/request.rs is outbound-only).



mitm.rs — on CONNECT host:443, respond 200, wrap client socket in an SslStream using an SslContext whose SNI callback returns the minted leaf; read plaintext request and forward upstream via corvex_core::http::HttpClient.



intercept.rs — per-message oneshot parks the in-flight request/response until the UI resolves it (forward / drop / edit).



rules.rs — match/replace rules (host regex, header ops, body regex) applied before and after intercept.



store.rs — SQLite tables proxy_flows(id, ts, host, method, url, status, duration_ms, tls_json, tags) + proxy_bodies(flow_id, kind, bytes, truncated); bodies chunked/capped (e.g. 1 MiB) with overflow flag.



ws.rs — detect Upgrade: websocket, pass through frames, log to proxy_ws_frames(flow_id, dir, opcode, bytes, ts).



engine.rs — public ProxyEngine { start(addr, event_sink), stop(), status() } wired into corvex-desktop.

Reuses: corvex_core::http::{Request, Response, HttpClient}, TLS utilities, IndexMap-based headers, Scope.

New Tauri commands (wire into corvex-desktop/src/commands.rs + main.rs invoke_handler!)





Proxy lifecycle: proxy_start(addr), proxy_stop(), proxy_status()



CA: proxy_ca_ensure(), proxy_ca_export(path, format: pem|der)



Flows: proxy_flows_list(filter), proxy_flow_get(id), proxy_flows_clear(), proxy_flow_delete(id)



Intercept: proxy_intercept_set(enabled, mode: all|scope|regex), proxy_intercept_pending(), proxy_intercept_resolve(id, action, modifiedBytes?)



Rules: proxy_rules_list(), proxy_rules_set(rules)



Repeater: repeater_send(req), repeater_save/list/get/delete



Intruder: intruder_start(req, positions, payloads, attackType), intruder_cancel(id)



Cross-tool: send_to_scanner(flow_id, plugins[]), send_to_repeater(flow_id), send_to_intruder(flow_id)



WS: ws_frames_list(flow_id)

New Tauri events





proxy://status, proxy://flow (created), proxy://flow/{id}/response (completed), proxy://intercept/pending, proxy://ws/{flow}/frame, repeater://response/{id}, intruder://{id}/result, intruder://{id}/summary.

Emission follows the pattern already in crates/corvex-desktop/src/event_sink.rs and crates/corvex-desktop/src/commands.rs (see ev() helper).

UI changes (React/TS)

Extend the View union in crates/corvex-desktop/ui/src/components/Sidebar.tsx with proxy, repeater, intruder. Add corresponding entries to titleByView in crates/corvex-desktop/ui/src/App.tsx.

New components under crates/corvex-desktop/ui/src/components/:





ProxyView.tsx — tabs: HTTP History, WebSockets, Intercept, Options (port, CA export button, scope, rules). Virtualized flow table with filter bar.



FlowDetail.tsx — split request/response raw viewer using CodeMirror 6 (lighter than Monaco). "Send to Repeater / Intruder / Scanner" buttons.



InterceptPane.tsx — current paused message with Forward / Drop / editable raw body.



RepeaterView.tsx — saved requests list + tabbed editors + response panel, calls repeater_send.



IntruderView.tsx — position markers (§payload§), payload sets, attack types (Sniper, Battering ram, Pitchfork, Cluster bomb), results grid with length/status diff highlighting.



Extend api.ts with thin wrappers + listen() subscriptions for the new events.

New plugin: Broken Access Control

crates/corvex-plugins/src/bac_plugin.rs, registered in crates/corvex-plugins/src/lib.rs alongside the existing active plugins. Takes a list of configured "sessions" (cookie/header sets) and, for each observed authenticated request, replays with each alternate session + unauthenticated, then diffs status/content-length/body-hash to flag IDOR, missing authz, and privilege-escalation issues. Sessions are edited in SettingsView or a new sidebar entry.

Phases

Keep each phase independently shippable.





Phase 1 — MVP Proxy (no intercept yet): corvex-proxy crate skeleton, CA gen/export, HTTP/1.x MITM for HTTP and HTTPS, SQLite flow store, ProxyView with live traffic table + FlowDetail, proxy_start/stop/status, CA export UX.



Phase 2 — Intercept + Edit: intercept.rs, pending queue, InterceptPane, raw request/response editors, Forward/Drop/Edit.



Phase 3 — Repeater: repeater_* commands, RepeaterView, "Send to Repeater" from FlowDetail. Reuses HttpClient.



Phase 4 — Match & Replace + Scope UX: rules.rs, rules editor in ProxyView Options, shared scope surface (lift ctx.scope to app-global settings), "Send to Scanner" wired to existing plugin registry.



Phase 5 — Intruder + BAC plugin + Sessions: IntruderView with the four attack types driven by corvex_core::fuzzer::FuzzRunner; add bac_plugin + Sessions UI.



Phase 6 — WebSockets: upgrade detection in h1.rs, ws.rs frame relay + log, WebSockets tab in ProxyView, optional WS intercept.

Key risks / gotchas





Inbound HTTP parsing: we lack an inbound request parser; write one using httparse (new dep) or extend corvex-core/http with a shared codec used by both client and proxy. Prefer the shared-codec route to avoid drift.



OpenSSL SNI callback + leaf minting requires SslContextBuilder::set_servername_callback and short-lived cached SslContexts keyed by hostname. Mint + sign with the CA key (already have openssl::x509).



CA trust UX on Windows/macOS/Linux differs. Ship an "Install CA" button that writes the PEM to disk and deep-links per-OS instructions in HelpView; don't attempt silent store modification.



Event volume: a busy browser produces thousands of events; batch proxy://flow emits (e.g. 50 ms debounce) and page proxy_flows_list server-side.



Body storage: cap per-body at ~1 MiB with a truncation flag; store large bodies as blobs in proxy_bodies.



HTTP/2 / HTTP/3: current HttpClient is HTTP/1.x only — acceptable for parity with Hetty v0.x; flag as future work.



Security: the CA private key is highly sensitive; store with 0600 perms (Windows ACL equivalent) and warn the user it is machine-local.

